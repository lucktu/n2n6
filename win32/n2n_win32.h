/*

	(C) 2007-09 - Luca Deri <deri@ntop.org>

*/

#ifndef _N2N_WIN32_H_
#define _N2N_WIN32_H_

#ifdef _WIN32

/* use our own definition for min/max */
#define NOMINMAX

/* use windows unicode API */
#define UNICODE
#define _UNICODE

#if defined(__MINGW32__)
/* should be defined here and before winsock gets included */
#define _WIN32_WINNT 0x501 //Otherwise the linker doesnt find getaddrinfo
#include <inttypes.h>
#endif /* #if defined(__MINGW32__) */

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mswsock.h>

/* Fallback if SIO_UDP_CONNRESET is not defined by the SDK */
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

/* ip helper api */
#include <iphlpapi.h>

#include <VersionHelpers.h>

/* for CLSIDFromString */
#include <objbase.h>

/* for _access */
#include <io.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#endif

#include "wintap.h"

#include <stdbool.h>
#include <stdint.h>
#ifdef _MSC_VER
#include "getopt.h"

#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef long ssize_t;
#endif
#endif /* #ifdef _MSC_VER */

#define reallocarray(p, n, s) realloc((p), ((n)*(s)))

#define access _access
#define R_OK 4

typedef unsigned long in_addr_t;

#ifdef EAFNOSUPPORT
#undef EAFNOSUPPORT
#endif
#define EAFNOSUPPORT   WSAEAFNOSUPPORT

#define socklen_t int

/* ************************************* */

#define N2N_IFNAMSIZ MAX_ADAPTER_NAME_LENGTH /* 256 */

typedef struct tuntap_dev {
	HANDLE device_handle;
	wchar_t  device_name[40]; /* legnth of a CLSID is 38 */
	NET_IFINDEX  ifIdx;
	NET_LUID luid;
	OVERLAPPED overlap_read, overlap_write;
	CRITICAL_SECTION write_lock;
	uint8_t      read_pending;     /* non-zero if an overlapped TAP read is in flight */
	uint8_t      read_buf[2000]; /* persistent buffer for pending overlapped read */
	bool         dyn_ip4;
	uint8_t      mac_addr[6];
	uint32_t     ip_addr;
	uint8_t      ip_prefixlen;
	struct in6_addr ip6_addr;
	uint8_t      ip6_prefixlen;
	uint32_t     mtu;
    uint8_t      routes_count;
    struct route* routes;
} tuntap_dev;

#define W32_ERROR(rc, error_string) \
        LPTSTR error_string = NULL; \
        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | \
			FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY ,\
            L"%0", rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &error_string, 0, NULL );
#define W32_ERROR_FREE(error_string) LocalFree( error_string );

extern HANDLE event_log;

#define _SCM_NAME_LENGTH 128
extern wchar_t scm_name[_SCM_NAME_LENGTH];

void initWin32();

int scm_startup(wchar_t* name);

int tuntap_restart( tuntap_dev* device );

#endif /* _WIN32 */
#endif
