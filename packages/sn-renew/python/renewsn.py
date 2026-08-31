#!/usr/bin/env python3
# renewsn.py: Renew n2n supernode via DNS failover
# Dual-probe: TCP port check + n2n REGISTER_SUPER business-layer check
# Sliding window health evaluation, DNSPod API update
#
# Usage:
#   1. Edit renewsn.ini
#   2. python3 renewsn.py
#   3. Or install as a systemd service

import socket
import struct
import time
import logging
import sys
import os
import json
import configparser
import hashlib
import threading
import urllib.request
from collections import deque
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ============================================================
# Config
# ============================================================

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "renewsn.ini")

# ============================================================
# N2N protocol constants (minimal subset)
# ============================================================

N2N_PKT_REGISTER_SUPER = 5
N2N_PKT_REGISTER_SUPER_ACK = 6
N2N_PKT_REGISTER_SUPER_NAK = 7
N2N_COMMUNITY_SIZE = 16  # n2n v2.3/v3 wire community field length

# ============================================================
# Logging
# ============================================================

class SizedLogHandler(logging.Handler):
    """Log handler that keeps a maximum number of lines."""
    def __init__(self, filename, max_lines=1000):
        super().__init__()
        self.filename = filename
        self.max_lines = max_lines
        self.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                                            datefmt='%Y-%m-%d %H:%M:%S'))

    def emit(self, record):
        if self.filename:
            try:
                lines = []
                if os.path.exists(self.filename):
                    with open(self.filename, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                lines.append(self.format(record) + '\n')
                if len(lines) > self.max_lines and self.max_lines > 0:
                    lines = lines[-self.max_lines:]
                with open(self.filename, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
            except Exception:
                pass


def setup_logging(config):
    """Setup logging based on config."""
    log_level = config.get('log', 'level', fallback='INFO').upper()
    log_file = config.get('log', 'file', fallback='')
    max_entries = config.getint('log', 'max_log_entries', fallback=1000)

    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level, logging.INFO))

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S'))
    root.addHandler(ch)

    # File handler with size limit
    if log_file:
        fh = SizedLogHandler(log_file, max_entries)
        root.addHandler(fh)


# ============================================================
# SN probing
# ============================================================

def probe_sn_tcp(host, port, timeout=3):
    """Probe SN via TCP port check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True, 0
    except socket.timeout:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "refused"
    except Exception as e:
        return False, str(e)


def probe_sn_udp(host, port, community, timeout=3):
    """Probe SN via UDP REGISTER_SUPER business-layer check.

    Builds the real n2n v2.3/v3 wire packet (same as an edge sends):
      common: version(1)=2 + ttl(1)=255 + flags(2)=type|opts + community(16)  = 20B
      reg:    cookie(4) + edgeMac(6)=0 + net_addr(4)=0 + net_bitlen(1)=0
              + num_local(1)=0 + aflags(2)=0 + scheme(2)=0 + toksize(2)=0     = 22B
    Total 42 bytes. A live SN answers with ACK(6)/NAK(7).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout + 1)

        community_bytes = community.encode('utf-8').ljust(N2N_COMMUNITY_SIZE, b'\x00')[:N2N_COMMUNITY_SIZE]

        pkt = bytes([2, 255])                     # version=2, ttl=255
        pkt += struct.pack('!H', N2N_PKT_REGISTER_SUPER)  # flags=5 big-endian (REGISTER_SUPER)
        pkt += community_bytes
        pkt += struct.pack('!I', int(time.time()) & 0xFFFFFFFF)  # cookie in big-endian
        pkt += b'\x00' * 6                        # edgeMac = 00:...:00
        pkt += b'\x00' * 4                        # dev_addr.net_addr = 0 (auto)
        pkt += b'\x00'                            # net_bitlen = 0
        pkt += b'\x00'                            # num_local = 0
        pkt += b'\x00\x00'                        # aflags = 0
        pkt += b'\x00\x00'                        # auth.scheme = 0 (no auth)
        pkt += b'\x00\x00'                        # auth.toksize = 0

        s.sendto(pkt, (host, port))

        try:
            data, addr = s.recvfrom(1500)
            if len(data) >= 2:
                # First byte after version: reply flags (type is in low 5 bits)
                hdr_flags = struct.unpack('!H', data[2:4])[0]
                pkt_type = hdr_flags & 0x001f
                if pkt_type == N2N_PKT_REGISTER_SUPER_ACK:
                    return True, 0
                elif pkt_type == N2N_PKT_REGISTER_SUPER_NAK:
                    return False, "nak"
        except socket.timeout:
            return False, "no_ack"

        s.close()
        return False, "unknown"
    except Exception as e:
        return False, str(e)


def get_latency(host, port, timeout=3):
    """Get TCP connection latency to a host:port."""
    try:
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return (time.time() - start) * 1000  # ms
    except Exception:
        return float('inf')


# ============================================================
# DNSPod API
# ============================================================

def dnspod_call(token, method, data):
    """Call DNSPod API."""
    url = f"https://dnsapi.cn/{method}"
    post_data = f"login_token={token}&format=json&{data}"
    req = Request(url, data=post_data.encode('utf-8'),
                  headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {'status': {'code': -1, 'message': str(e)}}


def get_txt_record_ids(token, domain, sub_domain):
    """List all TXT record IDs for the given subdomain (multi-machine safe)."""
    result = dnspod_call(token, 'Record.List',
                         f"domain={domain}&sub_domain={sub_domain}&record_type=TXT")
    return [r.get('id', '') for r in result.get('records', []) if r.get('id')]


def dedupe_txt_records(token, domain, sub_domain):
    """Keep exactly ONE TXT record: smallest id survives, duplicates removed.

    Even when several machines run concurrently, every machine deletes the
    copies it does not own, so the record set always collapses back to one.
    Returns the surviving record id (or '' if none exists).
    """
    ids = get_txt_record_ids(token, domain, sub_domain)
    if not ids:
        return ''

    keep = min(ids, key=int)
    for rid in ids:
        if rid != keep:
            dnspod_call(token, 'Record.Remove',
                        f"domain={domain}&record_id={rid}")
            logging.info(f"Removed duplicate TXT record id={rid}")
    return keep


def update_txt(token, domain, sub_domain, value, ttl=60):
    """Update TXT record to the given value (dedupes first, then modifies)."""
    record_id = dedupe_txt_records(token, domain, sub_domain)
    if not record_id:
        # Create new record
        result = dnspod_call(token, 'Record.Create',
                             f"domain={domain}&sub_domain={sub_domain}&record_type=TXT&value={value}&record_line=默认&ttl={ttl}")
        logging.info(f"Created TXT record: {value} (code={result.get('status', {}).get('code')})")
    else:
        # Modify existing record
        result = dnspod_call(token, 'Record.Modify',
                             f"domain={domain}&record_id={record_id}&sub_domain={sub_domain}&record_type=TXT&value={value}&record_line=默认&ttl={ttl}")
        logging.info(f"Updated TXT record: {value} (code={result.get('status', {}).get('code')})")

    return result.get('status', {}).get('code') == '1'


# ============================================================
# SN health evaluation
# ============================================================

class SnHealth:
    """Sliding window health evaluation for a single SN."""

    def __init__(self, name, host, port, window_size=5, http_url=''):
        self.name = name
        self.host = host
        self.port = port
        self.http_url = http_url  # non-empty if this is an HTTP redirect candidate
        self.window_size = window_size
        self.results = deque(maxlen=window_size)
        self.latency = float('inf')

    def _resolve_http(self, timeout=3):
        """Resolve HTTP redirect URL to host:port via pure Python (no curl/wget)."""
        import http.client
        try:
            url = self.http_url
            if url.startswith('http://'):
                url = url[7:]
            path = '/'
            if '/' in url:
                host_part, path = url.split('/', 1)
                path = '/' + path
            else:
                host_part = url
            if ':' in host_part:
                host, port_str = host_part.split(':')
                port = int(port_str)
            else:
                host = host_part
                port = 80

            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request('HEAD', path)
            resp = conn.getresponse()
            location = resp.getheader('Location')
            conn.close()
            if not location:
                return False

            loc = location.strip()
            if loc.startswith('http://'):
                loc = loc[7:]
            if loc.startswith('https://'):
                return False
            if '/' in loc:
                loc = loc.split('/')[0]
            if ':' in loc:
                host, port_str = loc.rsplit(':', 1)
                try:
                    self.host = host
                    self.port = int(port_str)
                    return True
                except ValueError:
                    pass
            return False
        except Exception:
            return False

    def probe(self, method='both', community='', timeout=3):
        """Probe this SN. Returns True if alive."""
        # Resolve HTTP redirect first if applicable
        if self.http_url and not self._resolve_http(timeout):
            self.results.append(False)
            return False

        tcp_ok = False
        udp_ok = False

        if method in ('tcp', 'both'):
            tcp_ok, _ = probe_sn_tcp(self.host, self.port, timeout)

        if method in ('udp', 'both'):
            udp_ok, _ = probe_sn_udp(self.host, self.port, community, timeout)

        if method == 'tcp':
            alive = tcp_ok
        elif method == 'udp':
            alive = udp_ok
        else:
            alive = tcp_ok and udp_ok

        self.results.append(alive)
        self.latency = get_latency(self.host, self.port, timeout)
        return alive

    @property
    def health_percent(self):
        if not self.results:
            return 0
        return sum(self.results) / len(self.results) * 100

    def is_healthy(self, threshold=50):
        return self.health_percent >= threshold


# ============================================================
# Main loop
# ============================================================

def main():
    # Load config
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    setup_logging(config)

    interval = config.getint('sn-watch', 'interval', fallback=30)
    probe_timeout = config.getint('sn-watch', 'probe_timeout', fallback=3)
    probe_method = config.get('sn-watch', 'probe_method', fallback='both')
    window_size = config.getint('sn-watch', 'window_size', fallback=5)
    fail_threshold = config.getint('sn-watch', 'fail_threshold', fallback=50)

    # Parse SN candidates
    candidates = []
    for key in config.options('supernodes'):
        val = config.get('supernodes', key)
        if val.startswith('http://') or val.startswith('https://'):
            candidates.append({
                'name': key,
                'host': '',
                'port': 0,
                'http_url': val
            })
        elif ':' in val:
            host, port_str = val.rsplit(':', 1)
            try:
                port = int(port_str)
                candidates.append({
                    'name': key,
                    'host': host,
                    'port': port,
                    'http_url': ''
                })
            except ValueError:
                pass

    if not candidates:
        logging.error("No supernode candidates configured")
        sys.exit(1)

    logging.info(f"Loaded {len(candidates)} candidate supernode(s):")
    for c in candidates:
        if c['http_url']:
            logging.info(f"  {c['name']} = {c['http_url']}")
        else:
            logging.info(f"  {c['name']} = {c['host']}:{c['port']}")

    # DNSPod config
    token = config.get('dnspod', 'token', fallback='')
    domain = config.get('dnspod', 'domain', fallback='')
    sub_domain = config.get('dnspod', 'sub_domain', fallback='')
    record_ttl = config.getint('dnspod', 'record_ttl', fallback=60)

    # Community name for UDP probe
    community = config.get('sn-watch', 'community', fallback='n2n')

    # Sliding window health evaluators
    health_map = {}
    for c in candidates:
        health_map[c['name']] = SnHealth(c['name'], c['host'], c['port'], window_size, c['http_url'])

    # State
    last_dns_update = 0
    last_dns_value = ''
    min_dns_interval = 60  # minimum seconds between DNS updates (anti-flapping)

    logging.info(f"Starting SN watch (interval={interval}s, method={probe_method}, "
                 f"window={window_size}, threshold={fail_threshold}%)")

    while True:
        try:
            loop_start = time.time()

            # Probe all candidates
            for c in candidates:
                health = health_map[c['name']]
                alive = health.probe(probe_method, community, probe_timeout)
                latency_str = f"{health.latency:.0f}ms" if health.latency != float('inf') else "N/A"
                addr_str = c['http_url'] if c['http_url'] else f"{c['host']}:{c['port']}"
                logging.debug(f"Probe {c['name']} ({addr_str}): "
                              f"{'ALIVE' if alive else 'DEAD'}, "
                              f"latency={latency_str}, health={health.health_percent:.0f}%")

            # Select best SN
            # Priority follows list order: the first healthy candidate in
            # the config is always chosen, serving as a natural primary.
            # Subsequent entries are fallbacks used only when the primary
            # (or earlier fallbacks) are unhealthy.
            best = None
            for c in candidates:
                if health_map[c['name']].is_healthy(fail_threshold):
                    best = c
                    break

            if best is None:
                logging.warning("No healthy supernode found")
                time.sleep(interval)
                continue

            best_health = health_map[best['name']]
            best_addr = best['http_url'] if best['http_url'] else f"{best_health.host}:{best_health.port}"
            best_label = f"{best_health.host}:{best_health.port}" if best['http_url'] else best_addr

            logging.info(f"Best SN: {best['name']} ({best_label}), "
                         f"health={best_health.health_percent:.0f}%")

            # Check if DNS update is needed
            now = time.time()
            if best_addr != last_dns_value and now - last_dns_update > min_dns_interval:
                if token and domain and sub_domain:
                    logging.info(f"Updating DNS: {sub_domain}.{domain} = {best_addr}")
                    success = update_txt(token, domain, sub_domain, best_addr, record_ttl)
                    if success:
                        last_dns_update = now
                        last_dns_value = best_addr
                        logging.info(f"DNS update successful")
                    else:
                        logging.warning(f"DNS update failed, will retry next cycle")
                else:
                    logging.warning(f"DNSPod not configured, would update DNS to: {best_addr}")
                    last_dns_value = best_addr
            else:
                if best_addr != last_dns_value:
                    remaining = int(min_dns_interval - (now - last_dns_update))
                    logging.debug(f"DNS update throttled ({remaining}s remaining)")

            # Sleep for remaining interval time
            elapsed = time.time() - loop_start
            sleep_time = max(1, interval - elapsed)
            time.sleep(sleep_time)

        except KeyboardInterrupt:
            logging.info("Shutting down...")
            break
        except Exception as e:
            logging.error(f"Error in main loop: {e}", exc_info=True)
            time.sleep(interval)


if __name__ == '__main__':
    main()