# n2n6 - A Peer-to-Peer VPN

[English](README.md) | [中文版](README.zh.md)

---

n2n6 is forked from [mxre's n2n](https://github.com/mxre/n2n), adding STUN hole-punching, bypass proxy, WebSocket transport, traffic statistics and control, optimized transfer speed, and simplified usage.

### Quick Start

**Supernode server (support for IPv4/IPv6 dual-stack is required)**

```bash
supernode -l 1234
```

**Edge node 1**

```bash
edge -a 10.64.0.2 -c mynetwork -k secret -A4 -l supernode.example.com:1234
```

**Edge node 2**

```bash
edge -a 10.64.0.3 -c mynetwork -k secret -A4 -l supernode.example.com:1234
```

That's it — node 1 and node 2 can now communicate.
By default, P2P direct connection is preferred; if that fails, traffic automatically falls back to relay through the supernode.
If UDP is blocked on your network, add `-w` to enable WebSocket relay.

### Key Features

| Feature | Description |
|---|---|
| **WebSocket mode** (`-w`) | Connect via supernode over TCP/WS, bypass NAT |
| **Multiple ciphers** | `-A1` (none), `-A2` (Twofish), `-A3` (AES), `-A4` (ChaCha20), `-A5` (Speck) |
| **Peer-to-Peer** | Direct connection after hole-punching (default) |
| **IPv4/IPv6 dual stack** | Transport and inner addressing |
| **Auto IP assignment** | Per-community IP pool (10.64.0.x), no DHCP needed |
| **Packet forwarding** (`-r`) | Route traffic through the n2n community |
| **Traffic stats & rate limiting** (`-L`) | Supernode per-community 24h/30d stats |

### Management Interface

**Edge** (default port 5664)

```bash
edge -Q 5664 # or nc -u 127.0.0.1 5664
```

**Supernode** (default port 5646)

```bash
supernode -Q 5646 # or nc -u 127.0.0.1 5646
```

### Build from Source

```bash
git clone https://github.com/lucktu/n2n6.git
cd n2n6 && mkdir build && cd build
cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Release ../
make
sudo make install
```

### Platform Notes

**Linux**
- Drop privileges with `-u <uid>` `-g <gid>`
- Systemd service examples in `packages/systemd/`
- Foreground: `-f`; daemon logs go to syslog

**Windows**
- Requires [OpenVPN TAP driver](https://openvpn.net/index.php/open-source/downloads.html)

**macOS**
- Uses built-in utun interface, no extra TAP driver needed
- `setcap` not supported on macOS; requires root

**Android**
- Port available from [lmq8267's hin2n](https://github.com/lmq8267/hin2n-Redir)

### Documentation

- Man pages: `doc/edge.8`, `doc/supernode.1`, `doc/n2n_v2.7`
- Changelog: `NEW_FEATURES.md`

### Related

- [mxre/n2n](https://github.com/mxre/n2n) - Upstream
- [ntop/n2n](https://github.com/ntop/n2n) - Official n2n project
