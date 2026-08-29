# sn-renew

renewsn: Renew n2n supernode via DNS failover.

## What does it do?

1. Probe all candidate supernodes
2. Select the healthiest one (lowest latency + pass both TCP/UDP checks)
3. Automatically update DNSPod TXT record
4. Always guarantee that your domain (e.g. `n2n6.ouno.eu.org`) points to an available supernode

This tool works with n2n's built-in `query_txt_record` feature:
- Your n2n edge always uses `-l n2n6.ouno.eu.org`
- renewsn keeps the TXT record updated automatically
- No changes needed to the n2n edge itself

## Features

- Dual-probe: TCP port check + n2n REGISTER_SUPER business-layer check
- Sliding window health evaluation (not just instantaneous check)
- Switch debouncing: at least 60s between DNS changes to avoid API thrashing
- Log rotation with max line limit
- Two versions for different platforms:
  - **Python**: full features (sliding window, latency selection, dual-layer probing)
  - **Shell**: for embedded systems without Python (Padavan, OpenWRT, etc.)
- Multiple instances: deploy 2-3 copies at different locations for redundancy

## Requirements

### Python version
- Python 3.6+
- DNSPod account (https://www.dnspod.cn/)

### Shell version (for Padavan, OpenWRT, etc.)
- `wget` (for DNSPod API calls and TCP probing)
- `logger` (optional, for syslog)

## Installation

### Clone / Copy

Copy all files from the `sn-renew/` directory to your target machine.

```
sn-renew/
├── README.md
├── README.zh.md
├── python/
│   ├── renewsn.py          # Main program (Python version)
│   ├── renewsn.ini         # Config file (Python version)
│   ├── renewsn.service     # Linux systemd service file
│   └── start_windows.bat   # Windows startup script
└── shell/
    ├── renewsn.sh          # Shell version (for Padavan/OpenWRT)
    └── renewsn.conf        # Config file (Shell version)
```

### Edit renewsn.ini (Python version)

Edit the config file to match your setup:

```ini
[sn-watch]
interval = 30
probe_timeout = 3
probe_method = both
window_size = 5
fail_threshold = 50
community = n2n

[supernodes]
sn1 = 1.2.3.4:10084
sn2 = 5.6.7.8:10087
sn3 = 9.10.11.12:10091

[dnspod]
token = 12345,abcdef1234567890abcdef1234567890
domain = ouno.eu.org
sub_domain = n2n6
record_ttl = 60

[log]
level = INFO
file = renewsn.log
max_log_entries = 1000
```

### Edit renewsn.conf (Shell version)

Edit the config file to match your setup:

```sh
INTERVAL=30
PROBE_TIMEOUT=3
CANDIDATES="1.2.3.4:10084 5.6.7.8:10087 9.10.11.12:10091"
DNS_TOKEN="12345,abcdef1234567890abcdef1234567890"
DNS_DOMAIN="ouno.eu.org"
DNS_SUB_DOMAIN="n2n6"
DNS_TTL=60
LOG_ENABLED=1
```

## Usage

### Python version

```bash
python3 renewsn.py
```

### Shell version (Padavan/OpenWRT)

```bash
# Copy files
scp shell/renewsn.sh admin@192.168.1.1:/tmp/
scp shell/renewsn.conf admin@192.168.1.1:/etc/

# SSH to router
ssh admin@192.168.1.1

# Make executable
chmod +x /tmp/renewsn.sh

# Edit config
vi /etc/renewsn.conf

# Run
/tmp/renewsn.sh &

# Add to startup
echo '/tmp/renewsn.sh &' >> /etc/firewall.user
```

### systemd service (Linux)

```bash
sudo cp python/renewsn.py /usr/local/bin/
sudo cp python/renewsn.ini /etc/renewsn.ini
sudo cp python/renewsn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable renewsn
sudo systemctl start renewsn
```

### Windows

```batch
start_windows.bat
```

Or use Task Scheduler to run at startup.

## Log output example

```
2026-08-27 15:30:00 [INFO] Starting SN watch (interval=30s, method=both, window=5, threshold=50%)
2026-08-27 15:30:00 [INFO] Loaded 3 candidate supernode(s):
2026-08-27 15:30:00 [INFO]   sn1 = 1.2.3.4:10084
2026-08-27 15:30:00 [INFO]   sn2 = 5.6.7.8:10087
2026-08-27 15:30:00 [INFO]   sn3 = 9.10.11.12:10091
2026-08-27 15:30:01 [INFO] Best SN: sn2 (5.6.7.8:10087), latency=12ms, health=100%
2026-08-27 15:30:01 [INFO] Updating DNS: n2n6.ouno.eu.org = 5.6.7.8:10087
2026-08-27 15:30:02 [INFO] DNS update successful
```

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|  renewsn instance |     |  renewsn instance |     |  renewsn instance |
|  (location A)     |     |  (location B)     |     |  (location C)     |
+--------+----------+     +--------+----------+     +--------+----------+
         |                          |                          |
         +--------------------------+--------------------------+
                                    |
                                    v
                    +-------------------------------+
                    |  DNSPod TXT record            |
                    |  n2n6.ouno.eu.org => 1.2.3.4  |
                    +-------------------------------+
                                    |
                                    v
                    +-------------------------------+
                    |  n2n edge nodes               |
                    |  -l n2n6.ouno.eu.org          |
                    |  (query_txt_record)           |
                    +-------------------------------+
```