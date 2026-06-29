/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 */

#include "n2n.h"
#include "random.h"

#ifdef _DARWIN_

#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if.h>       /* IFNAMSIZ, SIOCGIFADDR */
#include <sys/ioctl.h>    /* ioctl */
#include <netinet/in.h>   /* sockaddr_in */

/* ********************************** */

#define N2N_OSX_TAPDEVICE_SIZE 32

int tuntap_open(tuntap_dev *device, struct tuntap_config* config) {
    int i;
    char tap_device[N2N_OSX_TAPDEVICE_SIZE];
    char buf[512];
    unsigned char net_mac[6];
    int sys_ret;

    for (i = 0; i < 255; i++) {
        snprintf(tap_device, sizeof(tap_device), "/dev/tap%d", i);
        device->fd = open(tap_device, O_RDWR);
        if (device->fd > 0) {
            traceEvent(TRACE_NORMAL, "Successfully opened %s", tap_device);
            break;
        }
    }

    if (device->fd < 0) {
        traceEvent(TRACE_ERROR, "Unable to open tap device");
        return -1;
    }

    /* Store device name early for use in system() calls */
    {
        char ifname[16];
        snprintf(ifname, sizeof(ifname), "tap%d", i);
        strncpy(device->dev_name, ifname, N2N_IFNAMSIZ - 1);
        device->dev_name[N2N_IFNAMSIZ - 1] = '\0';
    }

    /* ---- MAC address ---- */

    if (config->device_mac[0] != 0 || config->device_mac[1] != 0 ||
        config->device_mac[2] != 0 || config->device_mac[3] != 0 ||
        config->device_mac[4] != 0 || config->device_mac[5] != 0) {
        memcpy(net_mac, config->device_mac, 6);
    } else {
        struct ifaddrs *ifap, *ifa;
        int found = 0;
        if (getifaddrs(&ifap) == 0) {
            for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_LINK) continue;
                if (strncmp(ifa->ifa_name, "lo", 3) == 0) continue;
                if (strncmp(ifa->ifa_name, "tap", 3) == 0) continue;
                if (strncmp(ifa->ifa_name, "n2n", 3) == 0) continue;
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (sdl->sdl_alen == 6) {
                    memcpy(net_mac, LLADDR(sdl), 6);
                    found = 1;
                    break;
                }
            }
            freeifaddrs(ifap);
        }
        if (found) {
            net_mac[0] = (net_mac[0] & 0xFE) | 0x02;
            /* mix in community name so each community gets a distinct MAC */
            if (config->community_name) {
                const char *c = config->community_name;
                for (int k = 0; c[k]; k++)
                    net_mac[2 + (k % 4)] ^= (uint8_t)c[k];
            }
        } else {
            traceEvent(TRACE_WARNING, "Could not read physical NIC MAC, using random");
            random_bytes_buf(net_mac, 6);
            net_mac[0] = (net_mac[0] & 0xFE) | 0x02;
        }
    }
    memcpy(device->mac_addr, net_mac, 6);

    /* Step 1: set MAC (separate command, macOS doesn't allow ether+netmask together) */
    snprintf(buf, sizeof(buf), "ifconfig %s ether %02x:%02x:%02x:%02x:%02x:%02x",
             device->dev_name,
             net_mac[0], net_mac[1], net_mac[2],
             net_mac[3], net_mac[4], net_mac[5]);
    sys_ret = system(buf);
    if (sys_ret != 0) {
        traceEvent(TRACE_WARNING, "Failed to set MAC on %s (ret=%d)", device->dev_name, sys_ret);
    }

    /* Store remaining device configuration fields */
    device->ip_addr = config->ip_addr;
    device->ip_prefixlen = config->ip_prefixlen;
    memcpy(&device->ip6_addr, &config->ip6_addr, sizeof(config->ip6_addr));
    device->ip6_prefixlen = config->ip6_prefixlen;
    device->mtu = config->mtu;
    device->routes_count = config->routes_count;
    device->routes = config->routes;

    /* Step 2: configure IP and routes, or just bring up for dynamic/delayed mode */
    if (!(config->dyn_ip4 || (config->delay_ip_config && config->ip_addr == 0))) {
        set_ipaddress(device, 1);
    } else {
        /* Dynamic/delayed mode: bring up the interface without IP */
        snprintf(buf, sizeof(buf), "ifconfig %s mtu %d up",
                 device->dev_name, config->mtu);
        sys_ret = system(buf);
        if (sys_ret != 0) {
            traceEvent(TRACE_WARNING, "Failed to bring up %s (ret=%d)", device->dev_name, sys_ret);
        }

        traceEvent(TRACE_NORMAL, "Interface %s up (no IP, waiting for assignment) mac %02x:%02x:%02x:%02x:%02x:%02x",
                   device->dev_name,
                   net_mac[0], net_mac[1], net_mac[2],
                   net_mac[3], net_mac[4], net_mac[5]);
    }

    /* Set non-blocking */
    if (fcntl(device->fd, F_SETFL, O_NONBLOCK) < 0) {
        traceEvent(TRACE_WARNING, "Failed to set %s to non-blocking (%s)", device->dev_name, strerror(errno));
    }

    return device->fd;
}

/* ********************************** */

ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    return read(tuntap->fd, buf, len);
}

/* ********************************** */

ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    return write(tuntap->fd, buf, len);
}

/* ********************************** */

void tuntap_close(struct tuntap_dev *tuntap) {
    close(tuntap->fd);
}

/* ********************************** */

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. (FIX: issue 7) */
void tuntap_get_address(struct tuntap_dev *tuntap)
{
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) != 0)
        return;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, tuntap->dev_name) != 0)
            continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        tuntap->ip_addr = sin->sin_addr.s_addr;
        break;
    }

    freeifaddrs(ifap);
}

/* ********************************** */

/* Configure IP, routes on the interface. Called at startup (static mode)
 * or later when REGISTER_SUPER_ACK provides an auto-assigned IP.
 * (FIX: issue 7 - was a stub) */
int set_ipaddress(const tuntap_dev *device, int static_address) {
    if (!static_address) {
        return 0;
    }

    char buf[512];
    int sys_ret;

    /* Set IP/netmask/MTU and bring up */
    {
        struct in_addr nm;
        nm.s_addr = ip4_prefixlen_to_netmask(device->ip_prefixlen);
        char mask_str[32], ip_str[32];
        inet_ntop(AF_INET, &nm, mask_str, sizeof(mask_str));

        struct in_addr in;
        in.s_addr = device->ip_addr;
        inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));

        snprintf(buf, sizeof(buf), "ifconfig %s %s netmask %s mtu %u up",
                 device->dev_name, ip_str, mask_str, device->mtu);
        sys_ret = system(buf);
        if (sys_ret != 0) {
            traceEvent(TRACE_WARNING, "set_ipaddress: failed to configure %s (ret=%d)",
                       device->dev_name, sys_ret);
            return -1;
        }

        traceEvent(TRACE_NORMAL, "Interface %s configured with IP %s/%u",
                   device->dev_name, ip_str, device->ip_prefixlen);
    }

    /* Add n2n network route */
    {
        struct in_addr nm2, net;
        nm2.s_addr = ip4_prefixlen_to_netmask(device->ip_prefixlen);
        char net_str[32], mask_str2[32];
        inet_ntop(AF_INET, &nm2, mask_str2, sizeof(mask_str2));
        net.s_addr = device->ip_addr & nm2.s_addr;
        inet_ntop(AF_INET, &net, net_str, sizeof(net_str));

        snprintf(buf, sizeof(buf),
                 "route -n add -net %s -netmask %s -interface %s 2>/dev/null",
                 net_str, mask_str2, device->dev_name);
        sys_ret = system(buf);
        if (sys_ret != 0) {
            traceEvent(TRACE_WARNING, "Failed to add n2n route on %s (ret=%d)",
                       device->dev_name, sys_ret);
        }
    }

    /* Add user-specified static routes */
    {
        unsigned int ri;
        for (ri = 0; ri < device->routes_count; ri++) {
            route *r = &device->routes[ri];
            if (r->family == AF_INET) {
                char dst_str[INET_ADDRSTRLEN], gw_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, r->dest, dst_str, sizeof(dst_str));
                inet_ntop(AF_INET, r->gateway, gw_str, sizeof(gw_str));
                snprintf(buf, sizeof(buf),
                         "route -n add -net %s/%u %s 2>/dev/null",
                         dst_str, r->prefixlen, gw_str);
                sys_ret = system(buf);
                if (sys_ret != 0) {
                    traceEvent(TRACE_WARNING, "Failed to add route %s/%u via %s (ret=%d)",
                               dst_str, r->prefixlen, gw_str, sys_ret);
                }
            } else if (r->family == AF_INET6) {
                char dst_str[INET6_ADDRSTRLEN], gw_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, r->dest, dst_str, sizeof(dst_str));
                inet_ntop(AF_INET6, r->gateway, gw_str, sizeof(gw_str));
                snprintf(buf, sizeof(buf),
                         "route -n add -inet6 %s/%u %s 2>/dev/null",
                         dst_str, r->prefixlen, gw_str);
                sys_ret = system(buf);
                if (sys_ret != 0) {
                    traceEvent(TRACE_WARNING, "Failed to add IPv6 route %s/%u via %s (ret=%d)",
                               dst_str, r->prefixlen, gw_str, sys_ret);
                }
            }
        }
    }

    return 0;
}

#endif /* _DARWIN_ */
