# n2n6

## 项目简介

`n2n6` 是一个基于 `n2n` 的覆盖网络 VPN 分支，重点在于：

- `edge` 与 `supernode` 之间同时支持 IPv4 和 IPv6 传输
- 隧道内部同时承载 IPv4 和 IPv6 流量
- 增强 Windows 支持，包括 TAP 适配器选择和服务安装
- 更适合 Linux 服务化部署

本仓库主要生成两个程序：

- `supernode`：负责协调各个 `edge` 节点的中心节点
- `edge`：负责创建本地隧道接口并加入指定 community 的边缘节点

## 主要特性

结合当前仓库中的代码和说明文档，可以确认本分支包含这些对用户可见的能力：

- `supernode` 和 `edge` 的 IPv6 外层传输支持
- 通过 `-A <IPv6>/<prefixlen>` 配置隧道内 IPv6
- Windows 下使用 `-d` 选择 TAP 适配器
- Windows SCM 服务支持以及 Windows Event Log 日志集成
- Linux 下基于 `CAP_NET_ADMIN` 的能力感知运行方式
- 根据平台和构建配置选择不同的加密后端

历史补充说明可参考 `NEW_FEATURES.md`。

## 构建

项目使用 CMake 构建。下面的命令按 `.github/workflows/cd.yml` 中的实际流程整理，只保留 Windows x86 和 Linux x86 两类构建方式。

### Linux x86

CI 中 Linux x86 使用 musl 工具链，并通过 `make` 构建。

```sh
mkdir -p build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-O2 -ffunction-sections -fdata-sections -fno-strict-aliasing" \
  -DCMAKE_EXE_LINKER_FLAGS="-Wl,--gc-sections" \
  -DCMAKE_C_COMPILER=${CC}
make -j$(nproc)
```

如果你需要 CI 中对应的 Linux x86 静态版本，可使用：

```sh
mkdir -p build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-O2 -ffunction-sections -fdata-sections -fno-strict-aliasing" \
  -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--gc-sections -static-libgcc" \
  -DCMAKE_C_COMPILER=${CC}
make -j$(nproc)
```

### Windows x86

CI 中 Windows x86 使用 MSVC 和 `NMake Makefiles`。

动态运行时版本：

```powershell
mkdir build
cd build
cmake .. `
  -G "NMake Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_FLAGS_RELEASE="/MD /O2 /DWIN32 /D_WIN32_WINNT=0x0601" `
  -DCMAKE_EXE_LINKER_FLAGS="/SUBSYSTEM:CONSOLE,6.01 /MACHINE:x86" `
  -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreadedDLL"
nmake
```

静态运行时版本：

```powershell
mkdir build
cd build
cmake .. `
  -G "NMake Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_FLAGS_RELEASE="/MT /O2 /DWIN32 /D_WIN32_WINNT=0x0601" `
  -DCMAKE_EXE_LINKER_FLAGS="/SUBSYSTEM:CONSOLE,6.01 /MACHINE:x86" `
  -DCMAKE_MSVC_RUNTIME_LIBRARY="MultiThreaded"
nmake
```

构建完成后，会在构建输出目录中生成对应平台下的 `edge`、`supernode`、`edge.exe` 或 `supernode.exe`。

## 快速开始

推荐的启动顺序是：

1. 先启动一个 `supernode`
2. 再启动一个或多个 `edge`，并确保它们使用相同的 community 和加密配置

### 启动 supernode

下面的例子会启动一个监听 UDP `1234` 端口、并保持前台运行的 `supernode`：

```sh
./supernode -l 1234 -v -f
```

说明：

- `-l` 设置主监听 UDP 端口
- `-4` 强制仅使用 IPv4
- `-6` 强制仅使用 IPv6
- 不指定 `-4` 或 `-6` 时，在支持的环境下使用双栈模式
- `-f` 让进程保持前台运行

### 通过命令行直接启动 edge

每一台需要加入虚拟网络的主机都需要启动一个 `edge`，并且这些 `edge` 必须使用相同的 community。

示例：

```sh
./edge -f -d n2n0 -c mynetwork -u 99 -g 99 -k encryptme -m 00:FF:12:34:56:78 -a static:192.168.254.1/24 -l a.b.c.d:1234
```

如果不想在命令行中直接写 `-k`，也可以使用 `N2N_KEY` 环境变量：

```sh
N2N_KEY=encryptme ./edge -f -d n2n0 -c mynetwork -u 99 -g 99 -m 00:FF:12:34:56:78 -a static:192.168.254.1/24 -l a.b.c.d:1234
```

说明：

- `-c` 设置 community 名称
- `-l` 指定 `supernode` 地址，格式为 `host:port`
- `-a` 设置隧道 IPv4 地址和模式，例如 `static:192.168.254.1/24`
- `-A` 设置隧道 IPv6 地址
- `-d` 选择本地 tunnel/TAP 设备名
- `-f` 让 `edge` 保持前台运行；不加时，Unix 构建通常会在初始化成功后转入 daemon 模式
- `-u` 和 `-g` 是 Unix 下用于降权运行的选项

## 配置文件用法

`edge` 支持从配置文件读取参数。

根据 `edge.c` 中的实际行为：

- 如果第一个参数不是以 `-` 开头
- 并且这个参数对应一个可读文件
- `edge` 会把它当作配置文件处理
- 配置文件解析出来的参数会插入到剩余命令行参数之前

因此下面这些写法都是有效的：

```sh
./edge edge.conf
./edge edge.conf -v
```

### 推荐的配置文件格式

当前最稳妥、最容易与实现保持一致的写法是：一行一个参数，或者一行一个“选项 / 选项值”项。

示例 `edge.conf`：

```text
-d
n2n0
-c
mynetwork
-k
encryptme
-m
00:FF:12:34:56:78
-a
static:192.168.254.1/24
-l
a.b.c.d:1234
```

通过配置文件启动 `edge`：

```sh
./edge edge.conf
```

如果需要，仍然可以在配置文件路径后继续追加命令行参数：

```sh
./edge edge.conf -v
```

### 密钥处理方式

加密密钥可以通过以下两种方式提供：

- 在配置文件中使用 `-k`
- 使用环境变量 `N2N_KEY`

例如：

```sh
N2N_KEY=encryptme ./edge edge.conf
```

如果 Windows 文本文件使用默认的 CRLF 换行，当前仓库的配置读取路径也应能正确处理。

## Windows 服务用法

Windows 服务安装示例位于 `win32/install.ps1`。

这个脚本演示了以下行为：

- 将 `edge.exe` 和 `supernode.exe` 复制到 `%ProgramFiles%\n2n`
- 创建 Windows 服务
- 将服务参数写入注册表
- 配置 Windows Event Log 消息资源

服务参数会写入以下路径：

```text
HKLM:\SOFTWARE\n2n\edge\Arguments
HKLM:\SOFTWARE\n2n\supernode\Arguments
```

如果是额外实例，则路径模式相同：

```text
HKLM:\SOFTWARE\n2n\<instance>\Arguments
```

安装脚本使用 `MultiString` 类型保存参数。对于包含空格的参数值，例如 TAP 适配器的 Friendly Name，这种方式尤其合适。

当 `edge` 或 `supernode` 以 Windows 服务方式运行时，它们不会附着在控制台上，日志会写入 Windows Event Log。

## IPv6 支持

本仓库里的 IPv6 使用场景分成两类。

### 1. 到 supernode 的 IPv6 外层传输

以 IPv6-only 模式启动 `supernode`：

```sh
./supernode -6 -f
```

以双栈模式启动 `supernode`：

```sh
./supernode -4 -6 -f
```

在 `edge` 中直接使用 IPv6 的 `supernode` 地址：

```sh
./edge -f -v [ other options ] -l [2001:aa00:bb00::1]:1234
```

如果你希望域名解析时强制使用 IPv6，可以额外指定 `-6`：

```sh
./edge -f -v [ other options ] -6 -l example.com:1234
```

### 2. 在隧道内部承载 IPv6 流量

如果要为隧道接口分配 IPv6 地址，可以在静态 IPv4 配置基础上加上 `-A`：

```sh
./edge -f -v [ other options ] -a static:192.168.254.1/24 -A fdf0:aa01:bb02::1/64
```

## 平台与安全说明

### Linux capabilities

这个分支在 Linux 下支持基于 capability 的运行方式，在可用时可使用 `NET_ADMIN`。

示例：

```sh
setcap cap_net_admin+p ./edge
```

这样可以在完成必要初始化后，避免长期保留完整 root 权限，具体仍取决于你的系统策略。

### Unix daemon 行为

在 Unix 平台上，如果没有指定 `-f`，`edge` 一般会在初始化成功后转为后台 daemon 运行。

### systemd 示例

仓库的 `systemd/` 目录下提供了示例服务文件：

- `systemd/edge@.service`
- `systemd/supernode.service`
- `systemd/cf0.conf`

其中 `edge@.service` 使用类似 `/etc/n2n/%i.conf` 的环境文件，示例 `cf0.conf` 里可以看到 `SUPERNODE`、`COMMUNITY`、`N2N_DEVICE`、`N2N_KEY` 等变量写法。

### Windows 注意事项

在 Windows 上：

- `-u`、`-g`、`-f` 不可用
- 需要安装兼容的 TAP 适配器
- 如果系统里有多个 TAP 适配器，可通过 `-d` 按 Friendly Name 选择
- 如果适配器名称包含空格，建议优先使用服务 `MultiString` 参数，或者在直接命令行调用时正确加引号

TAP 驱动通常可以随 OpenVPN 一起安装。

## 仓库内相关文件

下面这些文件对使用和部署比较有帮助：

- `NEW_FEATURES.md`：本分支新增能力说明
- `win32/install.ps1`：Windows 服务安装示例
- `systemd/`：Linux 服务单元和环境文件示例
- `edge.troff`、`supernode.troff`、`n2n_v2.troff`：man 手册源文件
