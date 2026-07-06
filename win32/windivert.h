/**
 * WinDivert API structures and function types (minimal subset for n2n bypass).
 * Original: https://github.com/basil00/WinDivert (LGPL)
 */
#ifndef N2N_WINDIVERT_H
#define N2N_WINDIVERT_H

#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Layer ===== */
typedef enum {
    WINDIVERT_LAYER_NETWORK        = 0,
    WINDIVERT_LAYER_NETWORK_FORWARD = 1,
    WINDIVERT_LAYER_FLOW           = 2,
    WINDIVERT_LAYER_SOCKET         = 3,
    WINDIVERT_LAYER_REFLECT        = 4,
} WINDIVERT_LAYER;

/* ===== Parameters ===== */
typedef enum {
    WINDIVERT_PARAM_QUEUE_LENGTH = 0,
    WINDIVERT_PARAM_QUEUE_TIME   = 1,
    WINDIVERT_PARAM_QUEUE_SIZE   = 2,
    WINDIVERT_PARAM_VERSION_MAJOR = 3,
    WINDIVERT_PARAM_VERSION_MINOR = 4,
} WINDIVERT_PARAM;

/*
 * WinDivert NETWORK and NETWORK_FORWARD layer data.
 */
typedef struct
{
    UINT32 IfIdx;                       /* Packet's interface index. */
    UINT32 SubIfIdx;                    /* Packet's sub-interface index. */
} WINDIVERT_DATA_NETWORK, *PWINDIVERT_DATA_NETWORK;

/*
 * WinDivert FLOW layer data.
 */
typedef struct
{
    UINT64 EndpointId;                  /* Endpoint ID. */
    UINT64 ParentEndpointId;            /* Parent endpoint ID. */
    UINT32 ProcessId;                   /* Process ID. */
    UINT32 LocalAddr[4];                /* Local address. */
    UINT32 RemoteAddr[4];               /* Remote address. */
    UINT16 LocalPort;                   /* Local port. */
    UINT16 RemotePort;                  /* Remote port. */
    UINT8  Protocol;                    /* Protocol. */
} WINDIVERT_DATA_FLOW, *PWINDIVERT_DATA_FLOW;

/*
 * WinDivert SOCKET layer data.
 */
typedef struct
{
    UINT64 EndpointId;                  /* Endpoint ID. */
    UINT64 ParentEndpointId;            /* Parent Endpoint ID. */
    UINT32 ProcessId;                   /* Process ID. */
    UINT32 LocalAddr[4];                /* Local address. */
    UINT32 RemoteAddr[4];               /* Remote address. */
    UINT16 LocalPort;                   /* Local port. */
    UINT16 RemotePort;                  /* Remote port. */
    UINT8  Protocol;                    /* Protocol. */
} WINDIVERT_DATA_SOCKET, *PWINDIVERT_DATA_SOCKET;

/*
 * WinDivert REFLECTION layer data.
 */
typedef struct
{
    INT64  Timestamp;                   /* Handle open time. */
    UINT32 ProcessId;                   /* Handle process ID. */
    WINDIVERT_LAYER Layer;              /* Handle layer. */
    UINT64 Flags;                       /* Handle flags. */
    INT16  Priority;                    /* Handle priority. */
} WINDIVERT_DATA_REFLECT, *PWINDIVERT_DATA_REFLECT;

/*
 * WinDivert address.
 */
#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct
{
    INT64  Timestamp;                   /* Packet's timestamp. */
    UINT32 Layer:8;                     /* Packet's layer. */
    UINT32 Event:8;                     /* Packet event. */
    UINT32 Sniffed:1;                   /* Packet was sniffed? */
    UINT32 Outbound:1;                  /* Packet is outound? */
    UINT32 Loopback:1;                  /* Packet is loopback? */
    UINT32 Impostor:1;                  /* Packet is impostor? */
    UINT32 IPv6:1;                      /* Packet is IPv6? */
    UINT32 IPChecksum:1;                /* Packet has valid IPv4 checksum? */
    UINT32 TCPChecksum:1;               /* Packet has valid TCP checksum? */
    UINT32 UDPChecksum:1;               /* Packet has valid UDP checksum? */
    UINT32 Reserved1:8;
    UINT32 Reserved2;
    union
    {
        WINDIVERT_DATA_NETWORK Network; /* Network layer data. */
        WINDIVERT_DATA_FLOW Flow;       /* Flow layer data. */
        WINDIVERT_DATA_SOCKET Socket;   /* Socket layer data. */
        WINDIVERT_DATA_REFLECT Reflect; /* Reflect layer data. */
        UINT8 Reserved3[64];
    };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;
#pragma warning(pop)

/* ===== IPv4 header ===== */
typedef struct {
    UINT8  HdrLength : 4;
    UINT8  Version   : 4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;

/* ===== TCP header ===== */
typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1 : 4;
    UINT16 HdrLength : 4;
    UINT16 Fin  : 1;
    UINT16 Syn  : 1;
    UINT16 Rst  : 1;
    UINT16 Psh  : 1;
    UINT16 Ack  : 1;
    UINT16 Urg  : 1;
    UINT16 Reserved2 : 2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;

/* ===== Flags ===== */
#define WINDIVERT_FLAG_SNIFF        1
#define WINDIVERT_FLAG_DROP         2
#define WINDIVERT_FLAG_RECV_ONLY    4
#define WINDIVERT_FLAG_READ_ONLY    8

/* ===== Function pointer types ===== */
typedef HANDLE (WINAPI *pfnWinDivertOpen)
    (const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
typedef BOOL (WINAPI *pfnWinDivertRecv)
    (HANDLE handle, void *pkt, UINT pktLen, UINT *recvLen, WINDIVERT_ADDRESS *addr);
typedef BOOL (WINAPI *pfnWinDivertSend)
    (HANDLE handle, void *pkt, UINT pktLen, UINT *sendLen, WINDIVERT_ADDRESS *addr);
typedef BOOL (WINAPI *pfnWinDivertClose)(HANDLE handle);
typedef BOOL (WINAPI *pfnWinDivertSetParam)
    (HANDLE handle, WINDIVERT_PARAM param, UINT64 value);
typedef BOOL (WINAPI *pfnWinDivertHelperCalcChecksums)
    (void *pkt, UINT pktLen, WINDIVERT_ADDRESS *addr, UINT64 flags);

/* ===== Context ===== */
#define WINDIVERT_MAP_SIZE 1024

typedef struct windivert_ctx_s {
    HMODULE dll;

    pfnWinDivertOpen                  pOpen;
    pfnWinDivertRecv                  pRecv;
    pfnWinDivertSend                  pSend;
    pfnWinDivertClose                 pClose;
    pfnWinDivertSetParam              pSetParam;
    pfnWinDivertHelperCalcChecksums   pHelperCalcChecksums;

    HANDLE handle;       /* WinDivert capture handle */
    HANDLE thread;       /* capture thread */
    CRITICAL_SECTION lock;
    volatile int running;

    uint16_t proxy_port;
    uint32_t n2n_net;    /* host order */
    uint32_t n2n_mask;

    struct {
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t orig_src_ip;
        uint32_t orig_dst_ip;
        uint16_t orig_dst_port;
        time_t   time;
        uint8_t  used;
    } map[WINDIVERT_MAP_SIZE];
    int map_count;
    int driver_installed;

    void *bypass_ctx;    /* back-pointer to bypass_context_t for peer state checks */
} windivert_ctx_t;

/* ===== API ===== */
int  windivert_init(windivert_ctx_t *ctx, uint16_t proxy_port,
                     uint32_t n2n_ip_n, uint32_t n2n_mask_n);
void windivert_deinit(windivert_ctx_t *ctx);
int  windivert_lookup_orig_dst(windivert_ctx_t *ctx,
                                uint32_t src_ip, uint16_t src_port,
                                uint32_t *out_dst_ip, uint16_t *out_dst_port);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* N2N_WINDIVERT_H */
