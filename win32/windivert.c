/**
 * WinDivert-based transparent TCP redirect for n2n bypass (Windows only).
 */

#ifdef _WIN32

#include "n2n.h"
#include "windivert.h"

#define WINDIVERT_SERVICE_NAME L"WinDivert"
#define WINDIVERT_TEMP_DIR     L"\\n2n-windivert"
#define WINDIVERT_RES_DLL      L"WINDIVERT_DLL"
#define WINDIVERT_RES_SYS64    L"WINDIVERT_SYS"
#define WINDIVERT_RES_SYS32    L"WINDIVERT32_SYS"

/* ===== helpers ===== */

static void get_temp_path(WCHAR *buf, size_t buflen, const WCHAR *name)
{
    WCHAR tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    _snwprintf(buf, buflen, L"%s%s\\%s", tmp, WINDIVERT_TEMP_DIR, name);
}

static int extract_resource(const WCHAR *res_name, const WCHAR *out_path)
{
    HRSRC hrs = FindResourceW(NULL, res_name, RT_RCDATA);
    if (!hrs) return -1;
    HGLOBAL hmem = LoadResource(NULL, hrs);
    if (!hmem) return -1;
    DWORD size = SizeofResource(NULL, hrs);
    void *data = LockResource(hmem);
    if (!data) return -1;

    /* Ensure directory exists */
    WCHAR dir[MAX_PATH];
    wcsncpy(dir, out_path, MAX_PATH);
    WCHAR *p = wcsrchr(dir, L'\\');
    if (p) { *p = L'\0'; CreateDirectoryW(dir, NULL); }

    HANDLE f = CreateFileW(out_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;
    DWORD written;
    BOOL ok = WriteFile(f, data, size, &written, NULL);
    CloseHandle(f);
    return ok ? 0 : -1;
}

static int is_driver_installed(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceW(scm, WINDIVERT_SERVICE_NAME, SERVICE_QUERY_STATUS);
    int installed = (svc != NULL);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return installed;
}

static int start_driver(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return -1;
    SC_HANDLE svc = OpenServiceW(scm, WINDIVERT_SERVICE_NAME,
                                  SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return -1; }

    SERVICE_STATUS ss;
    if (!QueryServiceStatus(svc, &ss) || ss.dwCurrentState == SERVICE_STOPPED)
        StartServiceW(svc, 0, NULL);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int stop_driver(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return -1;
    SC_HANDLE svc = OpenServiceW(scm, WINDIVERT_SERVICE_NAME,
                                  SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return -1; }

    SERVICE_STATUS ss;
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int delete_driver(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return -1;
    SC_HANDLE svc = OpenServiceW(scm, WINDIVERT_SERVICE_NAME, DELETE);
    if (!svc) { CloseServiceHandle(scm); return -1; }
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* Install driver via SCM API */
static int install_driver(const WCHAR *sys_path)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        traceEvent(TRACE_WARNING, "WinDivert: OpenSCManager failed GLE=%lu", GetLastError());
        return -1;
    }

    SC_HANDLE svc = CreateServiceW(scm, WINDIVERT_SERVICE_NAME, WINDIVERT_SERVICE_NAME,
                                    SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                    sys_path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        DWORD gle = GetLastError();
        traceEvent(TRACE_WARNING, "WinDivert: CreateService failed GLE=%lu", gle);
        CloseServiceHandle(scm);
        return -1;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* ===== DLL loading ===== */

static void unload_dll(windivert_ctx_t *ctx)
{
    if (ctx->dll) { FreeLibrary(ctx->dll); ctx->dll = NULL; }
    memset(&ctx->pOpen, 0, sizeof(ctx->pOpen));
}

static int load_dll(windivert_ctx_t *ctx)
{
    WCHAR path[MAX_PATH];
    get_temp_path(path, MAX_PATH, L"WinDivert.dll");

    /* Extract if not already on disk */
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        if (extract_resource(WINDIVERT_RES_DLL, path) != 0)
            return -1;
    }

    ctx->dll = LoadLibraryW(path);
    if (!ctx->dll) return -1;

#   define LOAD_FN(name) \
        ctx->p##name = (pfnWinDivert##name)GetProcAddress(ctx->dll, "WinDivert" #name); \
        if (!ctx->p##name) { unload_dll(ctx); return -1; }

    LOAD_FN(Open);
    LOAD_FN(Recv);
    LOAD_FN(Send);
    LOAD_FN(Close);
    LOAD_FN(SetParam);
    LOAD_FN(HelperCalcChecksums);

    return 0;
}

/* ===== Mapping table ===== */

static int map_add(windivert_ctx_t *ctx, uint32_t src_ip, uint16_t src_port,
                    uint32_t orig_src_ip,
                    uint32_t dst_ip, uint16_t dst_port)
{
    EnterCriticalSection(&ctx->lock);

    /* Reuse oldest entry if full */
    int idx = -1, oldest = 0;
    time_t oldest_t = ctx->map[0].time;
    for (int i = 0; i < WINDIVERT_MAP_SIZE; i++) {
        if (!ctx->map[i].used) { idx = i; break; }
        if (ctx->map[i].time < oldest_t) { oldest = i; oldest_t = ctx->map[i].time; }
    }
    if (idx < 0) idx = oldest;

    ctx->map[idx].src_ip      = src_ip;
    ctx->map[idx].src_port    = src_port;
    ctx->map[idx].orig_src_ip = orig_src_ip;
    ctx->map[idx].orig_dst_ip = dst_ip;
    ctx->map[idx].orig_dst_port = dst_port;
    ctx->map[idx].time        = time(NULL);
    ctx->map[idx].used        = 1;
    if (ctx->map_count < WINDIVERT_MAP_SIZE) ctx->map_count++;

    LeaveCriticalSection(&ctx->lock);
    return 0;
}

int windivert_lookup_orig_dst(windivert_ctx_t *ctx,
                               uint32_t src_ip, uint16_t src_port,
                               uint32_t *out_dst_ip, uint16_t *out_dst_port)
{
    if (!ctx) return -1;
    int found = 0;

    EnterCriticalSection(&ctx->lock);
    for (int i = 0; i < WINDIVERT_MAP_SIZE; i++) {
        if (ctx->map[i].used &&
            ctx->map[i].src_ip == src_ip &&
            ctx->map[i].src_port == src_port) {
            *out_dst_ip   = ctx->map[i].orig_dst_ip;
            *out_dst_port = ctx->map[i].orig_dst_port;
            found = 1;
            break;
        }
    }
    LeaveCriticalSection(&ctx->lock);
    return found ? 0 : -1;
}

static void map_gc(windivert_ctx_t *ctx)
{
    time_t now = time(NULL);
    EnterCriticalSection(&ctx->lock);
    for (int i = 0; i < WINDIVERT_MAP_SIZE; i++) {
        if (ctx->map[i].used && (now - ctx->map[i].time) > 30) {
            ctx->map[i].used = 0;
            ctx->map_count--;
        }
    }
    LeaveCriticalSection(&ctx->lock);
}

/* ===== Capture thread ===== */

static DWORD WINAPI capture_thread(LPVOID lpParam)
{
    windivert_ctx_t *ctx = (windivert_ctx_t *)lpParam;
    uint8_t pkt_buf[2048];
    WINDIVERT_ADDRESS addr;

    while (ctx->running) {
        UINT recvLen = 0;
        if (!ctx->pRecv(ctx->handle, pkt_buf, sizeof(pkt_buf), &recvLen, &addr)) {
            if (GetLastError() == ERROR_INVALID_HANDLE) break;
            Sleep(10);
            continue;
        }

        if (recvLen < sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR))
            continue;

        WINDIVERT_IPHDR *ip = (WINDIVERT_IPHDR *)pkt_buf;
        if (ip->Version != 4 || ip->Protocol != IPPROTO_TCP) continue;
        UINT ip_hdr_len = (ip->HdrLength) * 4;
        if (ip_hdr_len < 20 || recvLen < ip_hdr_len + sizeof(WINDIVERT_TCPHDR))
            continue;

        WINDIVERT_TCPHDR *tcp = (WINDIVERT_TCPHDR *)(pkt_buf + ip_hdr_len);
        uint32_t dst_ip = ntohl(ip->DstAddr);

        /* Outbound: app connecting to n2n subnet (only intercept if peer supports bypass) */
        if ((dst_ip & ctx->n2n_mask) == (ctx->n2n_net & ctx->n2n_mask)) {
            if (ctx->bypass_ctx && bypass_is_peer_active(
                    (bypass_context_t *)ctx->bypass_ctx, dst_ip)) {
                if (tcp->Syn && !tcp->Ack) {
                    map_add(ctx, htonl(0x7f000001), tcp->SrcPort,
                            ip->SrcAddr,
                            ip->DstAddr, tcp->DstPort);
                }
                ip->DstAddr = htonl(0x7f000001);
                tcp->DstPort = htons(ctx->proxy_port);
                ip->SrcAddr = htonl(0x7f000001);
            }
            /* else: peer not bypass-capable, let packet go through normal n2n path */
        }
        /* Inbound: proxy responding to app */
        else if ((ntohl(ip->SrcAddr) == 0x7f000001) && ntohs(tcp->SrcPort) == ctx->proxy_port) {
            uint32_t app_ip, orig_ip;
            uint16_t orig_port;
            if (lookup_orig_dst(ctx, tcp->DstPort, &app_ip, &orig_ip, &orig_port) == 0) {
                /* Rewrite: proxy_response → original_destination_response */
                ip->SrcAddr = orig_ip;
                tcp->SrcPort = orig_port;
                ip->DstAddr = app_ip;
            }
        }

        /* All packets re-injected: modified or unchanged */
        addr.Timestamp = 0;
        ctx->pHelperCalcChecksums(pkt_buf, recvLen, &addr,
                             0);  /* fix both IP and TCP checksums */
        UINT sendLen = 0;
        ctx->pSend(ctx->handle, pkt_buf, recvLen, &sendLen, &addr);
    }

    return 0;
}

/* ===== API ===== */

/* Non-removing lookup for capture thread (multiple packets per conn).
 * Returns app_ip (real client IP), orig_ip (real destination), orig_port. */
static int lookup_orig_dst(windivert_ctx_t *ctx, uint16_t src_port,
                            uint32_t *out_app_ip, uint32_t *out_orig_ip,
                            uint16_t *out_orig_port)
{
    int found = 0;
    EnterCriticalSection(&ctx->lock);
    for (int i = 0; i < WINDIVERT_MAP_SIZE; i++) {
        if (ctx->map[i].used &&
            ctx->map[i].src_ip == htonl(0x7f000001) &&
            ctx->map[i].src_port == src_port) {
            *out_app_ip    = ctx->map[i].orig_src_ip;
            *out_orig_ip   = ctx->map[i].orig_dst_ip;
            *out_orig_port = ctx->map[i].orig_dst_port;
            found = 1;
            break;
        }
    }
    LeaveCriticalSection(&ctx->lock);
    return found ? 0 : -1;
}

int windivert_init(windivert_ctx_t *ctx, uint16_t proxy_port,
                    uint32_t n2n_ip_n, uint32_t n2n_mask_n)
{
    char filter[256];
    uint32_t net_start, net_end;

    memset(ctx, 0, sizeof(*ctx));
    ctx->proxy_port = proxy_port;
    ctx->n2n_net    = n2n_ip_n;
    ctx->n2n_mask   = n2n_mask_n;
    InitializeCriticalSection(&ctx->lock);

    /* Load DLL from embedded resource */
    if (load_dll(ctx) != 0) {
        traceEvent(TRACE_WARNING,
                   "WinDivert: failed to load WinDivert.dll from embedded resource");
        return -1;
    }

    /* Check / install driver */
    ctx->driver_installed = is_driver_installed();
    if (!ctx->driver_installed) {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        int is_64bit_os = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                           si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
        const WCHAR *sys_name = is_64bit_os ? L"WinDivert64.sys" : L"WinDivert32.sys";
        const WCHAR *sys_res  = is_64bit_os ? WINDIVERT_RES_SYS64 : WINDIVERT_RES_SYS32;
        const char *sys_label = is_64bit_os ? "WinDivert64.sys" : "WinDivert32.sys";

        WCHAR sys_path[MAX_PATH];
        get_temp_path(sys_path, MAX_PATH, sys_name);

        if (extract_resource(sys_res, sys_path) != 0) {
            traceEvent(TRACE_WARNING, "failed to extract %s", sys_label);
            unload_dll(ctx);
            return -1;
        }

        traceEvent(TRACE_NORMAL, "WinDivert: installing %s driver...", sys_label);
        if (install_driver(sys_path) != 0) {
            traceEvent(TRACE_WARNING,
                       "WinDivert: driver install failed (try running as Administrator)");
            unload_dll(ctx);
            return -1;
        }

        ctx->driver_installed = 1;
        traceEvent(TRACE_NORMAL,
                   "%s driver installed successfully", sys_label);
    } else {
        traceEvent(TRACE_NORMAL, "driver already installed");
    }

    /* Start driver */
    start_driver();

    /* Build filter: bidirectional TCP capture */
    net_start = n2n_ip_n & n2n_mask_n;
    net_end   = net_start | ~n2n_mask_n;

    _snprintf(filter, sizeof(filter),
              "(tcp and ip.DstAddr >= %u.%u.%u.%u and ip.DstAddr <= %u.%u.%u.%u)"
              " or (ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == %u)",
              (net_start >> 24) & 0xFF, (net_start >> 16) & 0xFF,
              (net_start >>  8) & 0xFF,  net_start        & 0xFF,
              (net_end   >> 24) & 0xFF, (net_end   >> 16) & 0xFF,
              (net_end   >>  8) & 0xFF,  net_end          & 0xFF,
              proxy_port);

    ctx->handle = ctx->pOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (!ctx->handle || ctx->handle == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        /* ERROR_ALREADY_EXISTS: device object left by a previous crash.
         * stop+start alone doesn't clear it; need delete+reinstall. */
        if (gle == ERROR_ALREADY_EXISTS) {
            SYSTEM_INFO si;
            GetNativeSystemInfo(&si);
            const WCHAR *sys_name = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                                     si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
                                    ? L"WinDivert64.sys" : L"WinDivert32.sys";
            traceEvent(TRACE_WARNING, "WinDivert: device in use, reinstalling driver...");
            WCHAR sys_path[MAX_PATH];
            get_temp_path(sys_path, MAX_PATH, sys_name);
            stop_driver();
            delete_driver();
            Sleep(1000);
            install_driver(sys_path);
            start_driver();
            ctx->handle = ctx->pOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
        }
    }
    if (!ctx->handle || ctx->handle == INVALID_HANDLE_VALUE) {
        DWORD gle = GetLastError();
        char errmsg[256] = {0};
        WCHAR werr[256] = {0};
        if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL, gle, 0, werr, 256, NULL)) {
            WideCharToMultiByte(CP_UTF8, 0, werr, -1, errmsg, sizeof(errmsg), NULL, NULL);
        }
        size_t elen = strlen(errmsg);
        while (elen > 0 && (errmsg[elen-1] == '\r' || errmsg[elen-1] == '\n'))
            errmsg[--elen] = '\0';
        traceEvent(TRACE_WARNING, "WinDivert: failed to open filter handle - %s (GLE=%lu)", errmsg, gle);
        unload_dll(ctx);
        return -1;
    }

    /* Set queue params */
    ctx->pSetParam(ctx->handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    ctx->pSetParam(ctx->handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    /* Start capture thread */
    ctx->running = 1;
    ctx->thread = CreateThread(NULL, 0, capture_thread, ctx, 0, NULL);
    if (!ctx->thread) {
        traceEvent(TRACE_WARNING, "WinDivert: failed to create capture thread");
        ctx->pClose(ctx->handle);
        ctx->handle = NULL;
        unload_dll(ctx);
        return -1;
    }

    traceEvent(TRACE_INFO, "WinDivert: connected, proxy port %u", proxy_port);
    return 0;
}

void windivert_deinit(windivert_ctx_t *ctx)
{
    if (!ctx || !ctx->dll) return;

    ctx->running = 0;
    if (ctx->handle) {
        ctx->pClose(ctx->handle);
        ctx->handle = NULL;
    }
    if (ctx->thread) {
        WaitForSingleObject(ctx->thread, 3000);
        CloseHandle(ctx->thread);
        ctx->thread = NULL;
    }

    stop_driver();
    DeleteCriticalSection(&ctx->lock);
    unload_dll(ctx);

    traceEvent(TRACE_DEBUG, "WinDivert: stopped");
}

#endif /* _WIN32 */
