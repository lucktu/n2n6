/*
  (C) 2007-09 - Luca Deri <deri@ntop.org>
*/

#include "../src/n2n.h"
#include "n2n_win32.h"

#ifdef _WIN32

/* 1500 bytes payload + 14 bytes ethernet header + 4 bytes VLAN tag */
#define MTU 1518
/* TODO error messages using the same framework as the rest of the program */
void initWin32() {
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData );
    if( err != 0 ) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        W32_ERROR(GetLastError(), error)
        traceEvent(TRACE_ERROR, "Unable to initialise Winsock 2.x: %ls", error);
        W32_ERROR_FREE(error);
        exit(-1);
    }
}

static int get_adapter_luid(PWSTR device_name, NET_LUID* luid) {
    CLSID guid;

    if (CLSIDFromString(device_name, &guid) != NO_ERROR)
        return -1;

    if (ConvertInterfaceGuidToLuid(&guid, luid) != NO_ERROR)
        return -1;

    return 0;
}

static uint32_t set_dhcp(struct tuntap_dev* device) {
    wchar_t if_name[MAX_ADAPTER_NAME_LENGTH];
    /* lets hope that these are big enough */
    wchar_t windows_path[128], cmd[128], netsh[256];
    uint32_t rc = 0;

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    ConvertInterfaceLuidToNameW(&device->luid, if_name, MAX_ADAPTER_NAME_LENGTH);
    GetEnvironmentVariable(L"SystemRoot", windows_path, sizeof(windows_path));

    swprintf(cmd, 256, L"%s\\system32\\netsh.exe", windows_path);
    swprintf(netsh, 1024, L"interface ipv4 set address %s dhcp", if_name);

    rc = CreateProcess(cmd, netsh, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);
    // print_windows_message(GetLastError());
    if (rc == NO_ERROR) {
        WaitForSingleObject( pi.hProcess, INFINITE );
        GetExitCodeProcess( pi.hProcess, &rc);
        CloseHandle( pi.hProcess );
        CloseHandle( pi.hThread );
    }

    return rc;
}

static uint32_t set_static_ip_address(struct tuntap_dev* device) {
    uint32_t rc;
    MIB_UNICASTIPADDRESS_ROW ip_row;
    PMIB_UNICASTIPADDRESS_TABLE ip_address_table = NULL;

    /* clear previous address configuration */
    GetUnicastIpAddressTable(AF_UNSPEC, &ip_address_table);
    for (size_t i = ip_address_table->NumEntries; i--;) {
        PMIB_UNICASTIPADDRESS_ROW row = &ip_address_table->Table[i];
        if (row->InterfaceIndex == device->ifIdx) {
            DeleteUnicastIpAddressEntry(row);
        }
    }

    FreeMibTable(ip_address_table);

    InitializeUnicastIpAddressEntry(&ip_row);
    memcpy(&ip_row.InterfaceLuid, &device->luid, sizeof(NET_LUID));
    ip_row.Address.si_family = AF_INET;
    ip_row.Address.Ipv4.sin_family = AF_INET;
    memcpy(&ip_row.Address.Ipv4.sin_addr, &device->ip_addr, IPV4_SIZE);
    ip_row.OnLinkPrefixLength = device->ip_prefixlen;
    rc = CreateUnicastIpAddressEntry(&ip_row);

    if (rc != 0)
        return rc;

    if (device->ip6_prefixlen > 0) {
        InitializeUnicastIpAddressEntry(&ip_row);
        memset(&ip_row, 0, sizeof(ip_row));
        memcpy(&ip_row.InterfaceLuid, &device->luid, sizeof(NET_LUID));
        ip_row.Address.si_family = AF_INET6;
        ip_row.Address.Ipv6.sin6_family = AF_INET6;
        memcpy(&ip_row.Address.Ipv6.sin6_addr, &device->ip6_addr, IPV6_SIZE);
        ip_row.OnLinkPrefixLength = device->ip6_prefixlen;
        ip_row.DadState = IpDadStatePreferred;
        rc = CreateUnicastIpAddressEntry(&ip_row);
    }

    return rc;
}

static uint32_t set_static_routes(struct tuntap_dev* device) {
    MIB_IPFORWARD_ROW2 route;
    uint32_t rc = 0;

    for(int i = 0; i < device->routes_count; i++) {
        struct route* r = &device->routes[i];

        InitializeIpForwardEntry(&route);
        memset(&route, 0, sizeof(route));
        memcpy(&route.InterfaceLuid, &device->luid, sizeof(NET_LUID));
        if (r->family == AF_INET) {
            route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            memcpy(&route.DestinationPrefix.Prefix.Ipv4.sin_addr, r->dest, sizeof(struct in_addr));

            route.NextHop.Ipv6.sin6_family = AF_INET;
            memcpy(&route.NextHop.Ipv4.sin_addr, r->gateway, sizeof(struct in_addr));
        } else if (r->family == AF_INET6) {
            route.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            memcpy(&route.DestinationPrefix.Prefix.Ipv6.sin6_addr, r->dest, sizeof(struct in6_addr));

            route.NextHop.Ipv6.sin6_family = AF_INET6;
            memcpy(&route.NextHop.Ipv6.sin6_addr, r->gateway, sizeof(struct in6_addr));
        }
        route.DestinationPrefix.PrefixLength = r->prefixlen;
        route.SitePrefixLength = r->prefixlen;
        route.ValidLifetime = 0xffffffff;
        route.PreferredLifetime = 0xffffffff;

        rc |= CreateIpForwardEntry2(&route);
    }

    return rc;
}

int tuntap_open(struct tuntap_dev *device, struct tuntap_config* config) {
    HKEY key, key2;
    LONG rc;
    wchar_t regpath[MAX_PATH];
    wchar_t adapterid[40]; /* legnth of a CLSID is 38 */
    wchar_t adaptername[MAX_ADAPTER_NAME_LENGTH];
    wchar_t adaptername_target[MAX_ADAPTER_NAME_LENGTH] = L"";
    wchar_t tapname[MAX_PATH];
    long len;
    int found = 0;
    int i, err;
    ULONG status = TRUE;
    macstr_t mac_addr_buf;
    int has_target = 0;
    int target_tried = 0;

    memset(device, 0, sizeof(struct tuntap_dev));
    device->device_handle = INVALID_HANDLE_VALUE;
    device->device_name[0] = L'\0';
    device->ifIdx = NET_IFINDEX_UNSPECIFIED;

    if (config->if_name && config->if_name[0] != '\0') {
        mbstowcs(adaptername_target, config->if_name, MAX_ADAPTER_NAME_LENGTH);
        has_target = 1;
    }

    memset(&device->luid, 0, sizeof(NET_LUID));

    /* Open registry and look for network adapters */
    if((rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key))) {
        W32_ERROR(GetLastError(), error)
        traceEvent(TRACE_ERROR, "Could not open key HKLM\\%ls: %ls", NETWORK_CONNECTIONS_KEY, error);
        W32_ERROR_FREE(error)
        exit(-1);
    }

    for (i = 0; ; i++) {
        len = sizeof(adapterid);
        if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
            break;

        /* Find out more about this adapter */
        swprintf(regpath, sizeof(regpath), NETWORK_CONNECTIONS_KEY L"\\%s\\Connection", adapterid);
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2))
            continue;

        len = sizeof(adaptername);
        err = RegQueryValueExW(key2, L"Name", NULL, NULL, (LPBYTE) adaptername, &len);

        RegCloseKey(key2);
        if (err != 0)
            continue;

        /* If user specified a target adapter, try it first */
        if (has_target && !target_tried) {
            if (wcscmp(adaptername_target, adaptername))
                continue;
            target_tried = 1;
        }

        /* Try to open this adapter */
        swprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR L"%s" TAP_WIN_SUFFIX, adapterid);
        HANDLE h = CreateFile(
            tapname, GENERIC_WRITE | GENERIC_READ,
            0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0
        );
        if (h == INVALID_HANDLE_VALUE) {
            if (has_target) {
                traceEvent(TRACE_WARNING, "Cannot open specified TAP '%ls', trying next...", adaptername_target);
                has_target = 0;
            }
            continue;
        }

        /* Get MAC address */
        uint8_t mac[6];
        if (!DeviceIoControl(h, TAP_WIN_IOCTL_GET_MAC, mac, sizeof(mac), mac, sizeof(mac), &len, 0)) {
            CloseHandle(h);
            if (has_target) {
                traceEvent(TRACE_WARNING, "Cannot get MAC from specified TAP '%ls', trying next...", adaptername_target);
                has_target = 0;
            }
            continue;
        }

        /* Save adapter info to device */
        wcscpy(device->device_name, adapterid);
        device->device_handle = h;
        memcpy(device->mac_addr, mac, sizeof(mac));

        if (get_adapter_luid(adapterid, &device->luid) == 0) {
            IF_INDEX index = NET_IFINDEX_UNSPECIFIED;
            if (ConvertInterfaceLuidToIndex(&device->luid, &index) == 0) {
                device->ifIdx = index;
            }
        }

        memcpy(&device->ip_addr, &config->ip_addr, sizeof(config->ip_addr));
        device->ip_prefixlen = config->ip_prefixlen;
        memcpy(&device->ip6_addr, &config->ip6_addr, sizeof(config->ip6_addr));
        device->ip6_prefixlen = config->ip6_prefixlen;
        device->mtu = config->mtu;
        device->dyn_ip4 = config->dyn_ip4;
        device->routes = config->routes;
        device->routes_count = config->routes_count;

        traceEvent(TRACE_NORMAL, "Interface %ls has MAC %s", adaptername, macaddr_str(mac_addr_buf, device->mac_addr));

        /* Configure IP address */
        if (config->delay_ip_config && device->ip_addr == 0) {
            traceEvent(TRACE_NORMAL, "Delaying IP configuration until REGISTER_SUPER_ACK");
            rc = 0;
        } else {
            if (device->dyn_ip4) {
                rc = set_dhcp(device);
            } else {
                rc = set_static_ip_address(device);
            }
        }

        if (rc != 0) {
            W32_ERROR(rc, error)
            traceEvent(TRACE_WARNING, "Unable to set device %ls IP address: %u", adaptername, error);
            W32_ERROR_FREE(error)
            CloseHandle(device->device_handle);
            device->device_handle = INVALID_HANDLE_VALUE;
            if (has_target) {
                traceEvent(TRACE_WARNING, "Specified TAP '%ls' failed, trying next...", adaptername_target);
                has_target = 0;
            }
            continue;
        }

        if (device->routes_count > 0) {
            rc = set_static_routes(device);
            if (rc != 0) {
                W32_ERROR(rc, error)
                traceEvent(TRACE_WARNING, "Unable to set device %ls static route: %u", adaptername, error);
                W32_ERROR_FREE(error)
                CloseHandle(device->device_handle);
                device->device_handle = INVALID_HANDLE_VALUE;
                if (has_target) {
                    has_target = 0;
                }
                continue;
            }
        }

        tuntap_get_address(device);

        if(device->mtu != DEFAULT_MTU)
            traceEvent(TRACE_WARNING, "MTU set is not supported on Windows");

        /* set driver media status to 'connected' */
        if (!DeviceIoControl(
            device->device_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status, sizeof (status),
            &status, sizeof (status), &len, NULL
        )) {
            W32_ERROR(GetLastError(), error)
            traceEvent(TRACE_ERROR, "Unable to enable TAP adapter %ls: %ls", adaptername, error);
            W32_ERROR_FREE(error)
        }

        /*
        * Initialize overlapped structures
        */
        device->overlap_read.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        device->overlap_write.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!device->overlap_read.hEvent || !device->overlap_write.hEvent) {
            CloseHandle(device->device_handle);
            device->device_handle = INVALID_HANDLE_VALUE;
            continue;
        }

        InitializeCriticalSection(&device->write_lock);

        found = 1;
        break;
    }

    RegCloseKey(key);

    if (!found) {
        if (adaptername_target[0] != L'\0')
            traceEvent(TRACE_ERROR, "Specified TAP device '%ls' not found or not usable, and no fallback available!", adaptername_target);
        else
            traceEvent(TRACE_ERROR, "No Windows TAP device found!");
        exit(0);
    }

    return 0;
}

/* ************************************************ */

ssize_t tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    uint32_t read_size = 0, last_err;

    ResetEvent(tuntap->overlap_read.hEvent);
    if (ReadFile(tuntap->device_handle, buf, (uint32_t) len, &read_size, &tuntap->overlap_read)) {
        return (ssize_t) read_size;
    }
    switch (last_err = GetLastError()) {
    case ERROR_IO_PENDING:
        if (WaitForSingleObject(tuntap->overlap_read.hEvent, 1000) != WAIT_OBJECT_0) {
            /* No data available within 1 second. Cancel the pending read
             * so the OVERLAPPED structure is clean for the next call,
             * then return -1 so the caller can re-check keep_running. */
            CancelIo(tuntap->device_handle);
            WaitForSingleObject(tuntap->overlap_read.hEvent, INFINITE);
            return -1;
        }
        if (!GetOverlappedResult(tuntap->device_handle, &tuntap->overlap_read, &read_size, FALSE)) {
            DWORD last_err2 = GetLastError();
            if (last_err2 != ERROR_OPERATION_ABORTED && last_err2 != ERROR_INVALID_HANDLE) {
                W32_ERROR(last_err2, error)
                traceEvent(TRACE_ERROR, "GetOverlappedResult TAP: %ls", error);
                W32_ERROR_FREE(error)
            }
            return -1;
        }
        return (ssize_t) read_size;
    default: {
        /* Non-critical errors are normal when the TAP device is idle
         * or during shutdown. The caller handles this silently. */
        break;
    }
    }

  return -1;
}
/* ************************************************ */

ssize_t tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, size_t len) {
    uint32_t write_size;

    EnterCriticalSection(&tuntap->write_lock);

    ResetEvent(tuntap->overlap_write.hEvent);
    if (WriteFile(tuntap->device_handle,
        buf,
        (uint32_t) len,
        &write_size,
        &tuntap->overlap_write))
    {
        LeaveCriticalSection(&tuntap->write_lock);
        return (ssize_t) write_size;
    }

    switch (GetLastError()) {
    case ERROR_IO_PENDING:
        WaitForSingleObject(tuntap->overlap_write.hEvent, INFINITE);
        if (!GetOverlappedResult(tuntap->device_handle, &tuntap->overlap_write, &write_size, FALSE))
            write_size = 0;
        LeaveCriticalSection(&tuntap->write_lock);
        return (ssize_t) write_size;
    default:
        break;
    }

    LeaveCriticalSection(&tuntap->write_lock);
    return -1;
}

/* ************************************************ */

void tuntap_close(struct tuntap_dev *tuntap) {
    if (tuntap->device_name) {
        tuntap->device_name[0] = '\0';
    }
    if (tuntap->device_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(tuntap->device_handle);
        tuntap->device_handle = INVALID_HANDLE_VALUE;
    }
}

int tuntap_restart( tuntap_dev* device ) {
    wchar_t tapname[MAX_PATH];
    uint32_t status = true;
    uint32_t rc;
    long len;

    if (device->device_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(device->device_handle);
        device->device_handle = INVALID_HANDLE_VALUE;
    }

    ResetEvent(device->overlap_write.hEvent);
    ResetEvent(device->overlap_read.hEvent);

    swprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAP_WIN_SUFFIX, device->device_name);
    device->device_handle = CreateFile(
        tapname, GENERIC_WRITE | GENERIC_READ,
        0, /* Don't let other processes share or open the resource until the handle's been closed */
        0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0
    );
    if(device->device_handle == INVALID_HANDLE_VALUE) {
        W32_ERROR(GetLastError(), error)
        traceEvent(TRACE_ERROR, "Unable to reopen TAP adapter %ls: %ls", device->device_name, error);
        W32_ERROR_FREE(error)
        return -1;
    }

    if (device->dyn_ip4) {
        rc = set_dhcp(device);
    } else {
        rc = set_static_ip_address(device);
    }

    if (rc != 0) {
        W32_ERROR(rc, error)
        traceEvent(TRACE_WARNING, "Unable to set device %ls IP address: %u", device->device_name, error);
        W32_ERROR_FREE(error)

        return -1;
    }

    if (device->routes_count > 0) {
        rc = set_static_routes(device);

        if (rc != 0) {
            W32_ERROR(rc, error)
            traceEvent(TRACE_WARNING, "Unable to set device %ls static route: %u", device->device_name, error);
            W32_ERROR_FREE(error)

            return -1;
        }
    }

    tuntap_get_address(device);

    if(device->mtu != DEFAULT_MTU)
        traceEvent(TRACE_WARNING, "MTU set is not supported on Windows");

    if (!DeviceIoControl(
        device->device_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof (status),
        &status, sizeof (status), &len, NULL
    )) {
        W32_ERROR(GetLastError(), error);
        traceEvent(TRACE_ERROR, "Unable to enable TAP adapter %ls: %ls", device->device_name, error);
        W32_ERROR_FREE(error);
        return -1;
    }

    return 0;
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap) {
    IP_ADAPTER_ADDRESSES* adapter_list;
    uint32_t size = 0;

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW)
        return;
    adapter_list = malloc(size);

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, adapter_list, &size) != NO_ERROR) {
        free(adapter_list);
        return;
    }

    IP_ADAPTER_ADDRESSES* adapter = adapter_list;
    while (adapter) {
        if (adapter->IfIndex == tuntap->ifIdx) {
            IP_ADAPTER_UNICAST_ADDRESS* uni = adapter->FirstUnicastAddress;
            while (uni) {
                /* skip LL-addresses */
                if (uni->SuffixOrigin == IpSuffixOriginLinkLayerAddress) {
                    uni = uni->Next;
                    continue;
                }

                memcpy(&tuntap->ip_addr, &((struct sockaddr_in*) uni->Address.lpSockaddr)->sin_addr, 4);
                uint32_t mask = 0x0000;
                for (int i = uni->OnLinkPrefixLength; i--;)
                    mask = ((mask | 0x8000) | mask >> 1);
                uni = uni->Next;
            }

            break;
        }
        adapter = adapter->Next;
    }

    free(adapter_list);
    /*printf("Device %ls set to %s/%s\n", tuntap->device_name, inet_ntop(AF_INET, &tuntap->ip_addr, buffer, 16), inet_ntop(AF_INET, &tuntap->device_mask, buffer2, 16)); */
}

int set_ipaddress(const tuntap_dev* device, int static_address) {
    if (static_address) {
        return set_static_ip_address((struct tuntap_dev*)device);
    } else {
        return set_dhcp((struct tuntap_dev*)device);
    }
}

/* ************************************************ */

#if 0
int main(int argc, char* argv[]) {
    struct tuntap_dev tuntap;
    int i;
    int mtu = 1400;

    printf("Welcome to n2n\n");
    initWin32();
    open_wintap(&tuntap, "dhcp", "0.0.0.0", NULL, NULL, mtu);
    tuntap_get_address(&tuntap);
    for(i=0; i<10; i++) {
        u_char buf[MTU];
        int rc;

        rc = tuntap_read(&tuntap, buf, sizeof(buf));
        buf[0]=2;
        buf[1]=3;
        buf[2]=4;

        printf("tun_read returned %d\n", rc);
        rc = tuntap_write(&tuntap, buf, rc);
        printf("tun_write returned %d\n", rc);
    }
    Sleep(10000);
    // rc = tun_open (device->device_name, IF_MODE_TUN);
    WSACleanup ();
    return(0);
}

#endif

#endif /* _WIN32 */
