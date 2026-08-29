# sn-renew

renewsn: 通过 DNS 故障切换 (failover) 维护 n2n 超节点 (supernode) 可用性。

## 功能

1. 探测所有候选 SN
2. 选择最健康的 SN（最低延迟 + 通过 TCP/UDP 双检测）
3. 自动更新 DNSPod TXT 记录
4. 始终保证你的域名（如 `n2n6.ouno.eu.org`）指向一个可用的 SN

此工具配合 n2n 内置的 `query_txt_record` 功能使用：
- 你的 edge 始终使用 `-l n2n6.ouno.eu.org`
- renewsn 自动保持 TXT 记录更新
- edge 本身无需任何修改

## 特性

- 双探测：TCP 端口检测 + n2n REGISTER_SUPER 业务层检测
- 滑动窗口健康评估（非单次瞬态检测）
- 切换消抖：DNS 变更间隔至少 60 秒，避免 API 抖动
- 日志轮转：限制最大日志行数
- 两个版本适用于不同平台：
  - **Python 版**：全部功能（滑动窗口、延迟选择、双层探测）
  - **Shell 版**：适用于无 Python 的嵌入式系统（Padavan、OpenWRT 等）
- 多实例部署：在不同位置部署 2-3 个副本实现冗余

## 依赖

### Python 版本
- Python 3.6+
- DNSPod 账号 (https://www.dnspod.cn/)

### Shell 版本（Padavan、OpenWRT 等）
- `wget`（用于 DNSPod API 调用和 TCP 探测）
- `logger`（可选，用于 syslog）

## 安装

### 复制文件

将 `sn-renew/` 目录下的所有文件复制到目标机器。

```
sn-renew/
├── README.md
├── README.zh.md
├── python/
│   ├── renewsn.py          # 主程序（Python 版本）
│   ├── renewsn.ini         # 配置文件（Python 版本）
│   ├── renewsn.service     # Linux systemd 服务文件
│   └── start_windows.bat   # Windows 启动脚本
└── shell/
    ├── renewsn.sh          # Shell 版本（适用于 Padavan/OpenWRT）
    └── renewsn.conf        # 配置文件（Shell 版本）
```

### 编辑 renewsn.ini（Python 版本）

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

### 编辑 renewsn.conf（Shell 版本）

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

## 使用方法

### Python 版本

```bash
python3 renewsn.py
```

### Shell 版本（Padavan/OpenWRT）

```bash
# 复制文件
scp shell/renewsn.sh admin@192.168.1.1:/tmp/
scp shell/renewsn.conf admin@192.168.1.1:/etc/

# SSH 登录路由器
ssh admin@192.168.1.1

# 添加执行权限
chmod +x /tmp/renewsn.sh

# 编辑配置
vi /etc/renewsn.conf

# 运行
/tmp/renewsn.sh &

# 添加到开机启动
echo '/tmp/renewsn.sh &' >> /etc/firewall.user
```

### systemd 服务（Linux）

```bash
sudo cp python/renewsn.py /usr/local/bin/
sudo cp python/renewsn.ini /etc/renewsn.ini
sudo cp python/renewsn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable renewsn
sudo systemctl start renewsn
```

### Windows

双击 `start_windows.bat`，或使用任务计划程序设置开机启动。

## 架构

```
+-------------------+     +-------------------+     +-------------------+
|  renewsn 实例     |     |  renewsn 实例     |     |  renewsn 实例     |
|  (地点 A)         |     |  (地点 B)         |     |  (地点 C)         |
+--------+----------+     +--------+----------+     +--------+----------+
         |                          |                          |
         +--------------------------+--------------------------+
                                    |
                                    v
                    +-------------------------------+
                    |  DNSPod TXT 记录              |
                    |  n2n6.ouno.eu.org => 1.2.3.4  |
                    +-------------------------------+
                                    |
                                    v
                    +-------------------------------+
                    |  n2n edge 节点                |
                    |  -l n2n6.ouno.eu.org          |
                    |  (query_txt_record)           |
                    +-------------------------------+
```