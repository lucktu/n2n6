# n2n6

## Overview

`n2n6` is an `n2n`-based overlay VPN fork with a practical focus on:

- IPv4 and IPv6 transport between `edge` and `supernode`
- carrying IPv4 and IPv6 traffic inside the tunnel
- better Windows support, including TAP adapter selection and service installation
- Linux service-friendly deployment

This repository builds two main programs:

- `supernode`: the coordination node that listens for `edge` clients
- `edge`: the node that creates the local tunnel interface and joins a community

## Features

Compared with older `n2n` variants, the code and notes in this repository document these user-visible capabilities:

- IPv6 transport support for `supernode` and `edge`
- inner-tunnel IPv6 support through `-A <IPv6>/<prefixlen>`
- Windows TAP adapter selection with `-d`
- Windows SCM service support and Windows Event Log integration
- Linux capability-aware operation with `CAP_NET_ADMIN`
- multiple crypto backends depending on platform and build configuration

See also `NEW_FEATURES.md` for the historical notes in this fork.

## Build

The project uses CMake. The commands below are aligned with `.github/workflows/cd.yml` and cover only Windows x86 and Linux x86 builds.

### Linux x86

The workflow builds Linux x86 with the musl toolchain and `make`.

```sh
mkdir -p build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-O2 -ffunction-sections -fdata-sections -fno-strict-aliasing" \
  -DCMAKE_EXE_LINKER_FLAGS="-Wl,--gc-sections" \
  -DCMAKE_C_COMPILER=${CC}
make -j$(nproc)
```

If you want the static Linux x86 variant used by CI, use:

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

The workflow uses MSVC with `NMake Makefiles`.

Dynamic runtime build:

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

Static runtime build:

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

After the build, the generated `edge`, `supernode`, `edge.exe`, and `supernode.exe` binaries will be available in the build output directory, depending on platform.

## Quick Start

The normal startup order is:

1. Start one `supernode`
2. Start one or more `edge` nodes using the same community and encryption settings

### Start a supernode

Run one `supernode` that listens on UDP port `1234` and stays in the foreground:

```sh
./supernode -l 1234 -v -f
```

Useful notes:

- `-l` sets the main UDP listen port
- `-4` forces IPv4-only mode
- `-6` forces IPv6-only mode
- using neither `-4` nor `-6` keeps dual-stack behavior where available
- `-f` keeps the process in the foreground

### Start an edge from command-line options

Each host that should join the virtual network needs an `edge` using the same community.

Example:

```sh
./edge -f -d n2n0 -c mynetwork -u 99 -g 99 -k encryptme -m 00:FF:12:34:56:78 -a static:192.168.254.1/24 -l a.b.c.d:1234
```

Equivalent startup using the `N2N_KEY` environment variable instead of `-k`:

```sh
N2N_KEY=encryptme ./edge -f -d n2n0 -c mynetwork -u 99 -g 99 -m 00:FF:12:34:56:78 -a static:192.168.254.1/24 -l a.b.c.d:1234
```

Useful notes:

- `-c` sets the community name
- `-l` points to the `supernode` as `host:port`
- `-a` sets the tunnel IPv4 address and mode, for example `static:192.168.254.1/24`
- `-A` sets the tunnel IPv6 address
- `-d` selects the local tunnel/TAP device name
- `-f` keeps `edge` in the foreground; without it, Unix builds normally detach after setup
- `-u` and `-g` are Unix-only privilege drop options

## Configuration File Usage

`edge` supports reading options from a configuration file.

Behavior implemented in `edge.c`:

- if the first argument does not start with `-`
- and it is a readable file
- `edge` treats it as a config file
- the parsed options from that file are inserted before any remaining command-line arguments

In practice, this means these forms are valid:

```sh
./edge edge.conf
./edge edge.conf -v
```

### Recommended config-file format

The safest documented format is one option or one option/value pair item per line.

Example `edge.conf`:

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

Start `edge` from the config file:

```sh
./edge edge.conf
```

Add extra runtime flags after the config file path if needed:

```sh
./edge edge.conf -v
```

### Key handling

You can provide the encryption key in either of these ways:

- inside the config file with `-k`
- through the environment variable `N2N_KEY`

Example:

```sh
N2N_KEY=encryptme ./edge edge.conf
```

## Windows Service Usage

Windows service installation examples are provided in `win32/install.ps1`.

The script demonstrates these behaviors:

- copying `edge.exe` and `supernode.exe` into `%ProgramFiles%\n2n`
- creating Windows services
- storing service arguments in the registry
- enabling Windows Event Log message support

Service arguments are stored under:

```text
HKLM:\SOFTWARE\n2n\edge\Arguments
HKLM:\SOFTWARE\n2n\supernode\Arguments
```

For additional instances, the path follows the same pattern:

```text
HKLM:\SOFTWARE\n2n\<instance>\Arguments
```

The installer uses `MultiString` values for arguments. That is especially useful when an argument contains spaces, such as a TAP adapter friendly name.

When running as a Windows service, `edge` and `supernode` are not attached to a console. Logs go to the Windows Event Log.

## IPv6 Support

This repository documents two separate IPv6 use cases.

### 1. IPv6 transport to the supernode

Start `supernode` in IPv6-only mode:

```sh
./supernode -6 -f
```

Start `supernode` in dual-stack mode:

```sh
./supernode -4 -6 -f
```

Use an IPv6 supernode address from `edge`:

```sh
./edge -f -v [ other options ] -l [2001:aa00:bb00::1]:1234
```

If you want a DNS name resolved specifically as IPv6, add `-6`:

```sh
./edge -f -v [ other options ] -6 -l example.com:1234
```

### 2. Carrying IPv6 traffic inside the tunnel

To assign an IPv6 address to the tunnel interface, use `-A` together with a static IPv4 setup:

```sh
./edge -f -v [ other options ] -a static:192.168.254.1/24 -A fdf0:aa01:bb02::1/64
```

## Platform and Security Notes

### Linux capabilities

This fork is capability-aware on Linux and can use `NET_ADMIN` when available.

Example:

```sh
setcap cap_net_admin+p ./edge
```

That allows running `edge` without keeping full root privileges after setup, subject to the rest of your system policy.

### Unix daemon behavior

Unless `-f` is used, Unix builds of `edge` normally detach and continue as a daemon after successful setup.

### systemd examples

Example service files are provided under `systemd/`:

- `systemd/edge@.service`
- `systemd/supernode.service`
- `systemd/cf0.conf`

The shipped `edge@.service` uses an environment file like `/etc/n2n/%i.conf`, and the example `cf0.conf` shows variables such as `SUPERNODE`, `COMMUNITY`, `N2N_DEVICE`, and `N2N_KEY`.

### Windows notes

On Windows:

- `-u`, `-g`, and `-f` are not available
- a compatible TAP adapter is required
- if multiple TAP adapters exist, use `-d` to select the adapter by friendly name
- if the adapter name contains spaces, prefer service `MultiString` arguments or proper quoting in direct command use

The TAP driver is commonly installed together with OpenVPN.

## Repository References

Useful files in this repository:

- `NEW_FEATURES.md`: notes about added capabilities in this fork
- `win32/install.ps1`: Windows service installation example
- `systemd/`: example Linux service units and environment files
- `edge.troff`, `supernode.troff`, `n2n_v2.troff`: manual-page sources

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/lucktu/n2n6)
