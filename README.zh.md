# n2n6 - P2P VPN

[English](README.md) | [中文版](README.zh.md)

---

n2n6 是由 [mxre's n2n](https://github.com/mxre/n2n) 发展而来的，增加了 stun 打洞、旁路、WebSocket 传输、流量统计及控制，优化了传输速度，简化了使用方法。

### 快速开始

**Supernode 服务器（要求支持ipv4和ipv6双栈）**

```bash
supernode -l 1234
```

**Edge 节点 1**

```bash
edge -a 10.64.0.2 -c mynetwork -k secret -A4 -l supernode.example.com:1234
```

**Edge 节点 2**

```bash
edge -a 10.64.0.3 -c mynetwork -k secret -A4 -l supernode.example.com:1234
```

这样设置以后，节点 1、节点 2 之间就能通讯啦。
默认状态下，优先直连，不能直连则自动通过服务器转发。
如果网络 udp 受限，你还可以使用 -w 开启 WebSocket 转发。

### 主要功能

| 功能 | 说明 |
|---|---|
| **WebSocket 模式** (`-w`) | 通过 supernode 走 TCP/WS 中继，穿透 NAT |
| **多加密算法** | `-A1`(无), `-A2`(Twofish), `-A3`(AES), `-A4`(ChaCha20), `-A5`(Speck) |
| **P2P 直连** | 打洞成功后直接通信（默认模式） |
| **IPv4/IPv6 双栈** | 支持传输层和内网层双协议 |
| **自动 IP 分配** | 每社区独立 IP 池，无需 DHCP |
| **包转发** (`-r`) | 通过 n2n 社区转发流量 |
| **流量统计与限速** (`-L`) | Supernode 端 24h/30d 统计 |

### 管理接口

**Edge**（默认端口 5664）

```bash
edge -Q 5664 # or nc -u 127.0.0.1 5664
```

**Supernode**（默认端口 5646）

```bash
supernode -Q 5646 # or nc -u 127.0.0.1 5646
```

### 编译安装

```bash
git clone https://github.com/lucktu/n2n6.git
cd n2n6 && mkdir build && cd build
cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Release ../
make
sudo make install
```

### 平台说明

**Linux**
- 可通过 `-u <uid>` `-g <gid>` 降权运行
- Systemd 服务示例见 `packages/systemd/`
- 前台模式 `-f`；守护进程日志输出到 syslog

**Windows**
- 需要 [OpenVPN TAP 驱动](https://openvpn.net/index.php/open-source/downloads.html)

**MacOS**
- 使用内置 utun 接口，无需额外安装 TAP 驱动
- 不支持 `setcap`，需要 root 权限运行

**Android**
- 程序来自于[lmq8267's hin2n](https://github.com/lmq8267/hin2n-Redir)

### 文档

- 手册页：`doc/edge.8`、`doc/supernode.1`、`doc/n2n_v2.7`
- 更新日志：`NEW_FEATURES.md`

### 相关项目

- [mxre/n2n](https://github.com/mxre/n2n) - 上游项目
- [ntop/n2n](https://github.com/ntop/n2n) - n2n官方项目
