#pragma once
/* Socket byte capture (payload upgrade): shared by payload.bpf.h (kernel) and bpf_payload.inc (agent). */

#define MM_CHUNK 4096               /* payload bytes per mm_chunk record (< MSMON_PAYLOAD_CHUNK_BYTES) */
#define MM_PAYLOAD_MAX (1u << 20)   /* bytes captured per call; the rest is counted (payload_partial) */
#define MM_CAP_WALK 4096            /* bpf_loop bound of one call's walk: message, iovec and chunk steps */
#define MM_IOV_MAX 1024             /* UIO_MAXIOV: iovecs per message, mmsghdr entries per call */

/* mm_event.cap_stop: why fewer than ret bytes were captured */
#define MM_CAP_LIMIT 0x1     /* MM_PAYLOAD_MAX reached */
#define MM_CAP_DROP 0x2      /* payload_ring was full; capture stopped at that chunk */
#define MM_CAP_FAULT 0x4     /* a user buffer or iovec could not be read (not resident) */
#define MM_CAP_STEPS 0x8     /* the MM_CAP_WALK steps ran out (very many iovecs or messages) */

/* mm_sysinfo.data: where a send/receive call's bytes are; read at sys_exit, bounded by ret */
#define MM_DATA_NONE 0
#define MM_DATA_BUF 1        /* buffer arg1, length arg2 (read, write, sendto, recvfrom) */
#define MM_DATA_IOV 2        /* iovec array arg1, count arg2 (readv, writev) */
#define MM_DATA_MSG 3        /* user_msghdr arg1 (sendmsg, recvmsg) */
#define MM_DATA_MMSG 4       /* mmsghdr array arg1, ret entries (sendmmsg, recvmmsg) */

/* payload_ring record: up to MM_CHUNK bytes of one message of one call. (tid, ts_ns) names the
 * call: ts_ns equals the MM_SYSCALL record's ts_ns. Chunks of a call are in order and contiguous;
 * capture stops at the first chunk that does not fit. Variable size: header + len bytes. */
struct mm_chunk {
    __u32 tid;
    __u32 tgid;
    __u64 ts_ns;
    __u32 msg;           /* mmsghdr index (sendmmsg/recvmmsg), else 0 */
    __u32 off;           /* offset of data[0] in that message */
    __u32 len;           /* bytes in data */
    __u32 msg_len;       /* bytes the call moved for that message (ret, or mmsghdr.msg_len) */
    char data[MM_CHUNK];
};
