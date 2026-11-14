#pragma once

/*
 * Linux control channel between kfilterd and its clients (kfilterctl, msmon-agent).
 * It replaces the \\.\KFilter device: one request per round trip over a root-only
 * SOCK_STREAM Unix socket. The payloads are the same structs the Windows IOCTLs
 * carry (kfilter.h), in their Linux layout (32-bit fields, 4-byte wchar_t).
 *
 *   request: KFILTER_SOCKET_REQUEST, then InputLength bytes
 *   reply:   KFILTER_SOCKET_REPLY,   then OutputLength bytes
 *
 * Code is the IOCTL function number (KFILTER_OP_*). Error is 0 or a positive errno.
 * OutputCapacity bounds the reply payload, as the IOCTL output buffer did.
 */

#include <stdint.h>

#define KFILTER_SOCKET_PATH "/run/kfilter.sock"
#define KFILTER_SOCKET_MAX_INPUT (64u * 1024u * 1024u)

#define KFILTER_OP_GET_STATUS 0x800u
#define KFILTER_OP_SET_CONFIG 0x801u
#define KFILTER_OP_READ_EVENTS 0x802u
#define KFILTER_OP_CLEAR_EVENTS 0x803u
#define KFILTER_OP_TRACK_PID 0x804u
#define KFILTER_OP_CLEAR_TRACKING 0x805u
#define KFILTER_OP_GET_CONFIG 0x806u
#define KFILTER_OP_ADMIT_PROCESS 0x807u
#define KFILTER_OP_REGISTER_LAUNCHER 0x808u
#define KFILTER_OP_ALLOW_LAUNCH 0x809u
#define KFILTER_OP_BLOCK_CONNECTION 0x80Au   /* Linux only: KFILTER_CONNECTION_REQUEST */
#define KFILTER_OP_SET_SESSION 0x80Bu       /* Linux only: KFILTER_SESSION_REQUEST */
/* Linux only, no payload: mode off, BPF links unpinned, saved policy removed, kfilterd exits.
 * Any other exit in block mode leaves enforcement in place (pinned links, nftables table). */
#define KFILTER_OP_SHUTDOWN 0x80Cu

typedef struct _KFILTER_SOCKET_REQUEST {
    uint32_t Code;
    uint32_t InputLength;
    uint32_t OutputCapacity;
    uint32_t Reserved;
} KFILTER_SOCKET_REQUEST;

typedef struct _KFILTER_SOCKET_REPLY {
    uint32_t Error;
    uint32_t OutputLength;
} KFILTER_SOCKET_REPLY;

/* KFILTER_EVENT.Timestamp on Linux keeps the Windows FILETIME unit (100 ns since
 * 1601-01-01 UTC) so msmon's session-start comparison is unchanged. */
#define KFILTER_UNIX_EPOCH_AS_FILETIME 116444736000000000ull
