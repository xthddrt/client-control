#pragma once
/*
 * Desktop services over AF_UNIX (unix.bpf.h walks the streams, bpf.cpp names what they carry): the X11, D-Bus and
 * PulseAudio connections a tracked process makes while tracked. Included by monitor_bpf.h. The framing below is plain C
 * shared with the agent's offline test (tests/linux_unix_test.cpp), so the kernel's walk is checked there.
 */

#define MM_UNIX_HEAD 4096         /* bytes of one call walked, and sent to the agent with a head */
#define MM_UNIX_PART 256          /* bytes of a message header carried to the socket's next call (an X11 event's 32, a
                                   * D-Bus message's fixed header and fields, so a reader of the 16 bytes alone still
                                   * has them named) */
#define MM_UNIX_SAMPLED 32        /* sampled requests (D-Bus: messages) one head lists */
#define MM_UNIX_STEPS 1024        /* messages walked per call */
#define MM_UNIX_DBUS_HEADS 64     /* D-Bus heads per socket and second; the messages past them are counted by type */

/* mm_unix_sock.svc, and an agg nr's low bits (MM_COUNT_UNIX | svc | MM_UNIX_RX) */
#define MM_UNIX_X11 1
#define MM_UNIX_DBUS 2
#define MM_UNIX_PULSE 3
#define MM_UNIX_PENDING 4         /* connected while tracked: its first send says which service, if any */
#define MM_UNIX_RX 0x10           /* a receive (else a send) */
#define MM_UNIX_BIG 0x20          /* mm_unix_head.svc: an X11 client in big-endian order */

/* Ops beside the protocols' own (an agg key is the socket's inode << 32 | op). X11 sends: major << 8, | minor for an
 * extension (major >= 128). X11 receives: type << 24 (| MM_UNIX_X11_SENT for a SendEvent); an error code << 16 | major
 * << 8 | minor's low byte; a GenericEvent's extension << 8 | evtype's low byte. PulseAudio: the command, or below.
 * D-Bus: the message type (1 call, 2 return, 3 error, 4 signal), or MM_UNIX_DBUS_SASL. */
#define MM_UNIX_OP_UNPARSED 0xffffffffu   /* bytes past the walk: past MM_UNIX_HEAD or MM_UNIX_STEPS, or a lost stream */
#define MM_UNIX_DBUS_SASL 0               /* a call of the SASL handshake's text lines */
#define MM_UNIX_PULSE_MEMBLOCK 0xffff     /* audio (a packet on a channel other than the control one) */
#define MM_UNIX_PULSE_OTHER 0xfffe        /* a control packet that is no tagstruct command */
#define MM_UNIX_X11_SENT 0x800000

/* mm_unix_sock.flags */
#define MM_UNIX_S_BIG 0x1         /* an X11 client in big-endian order ('B') */
#define MM_UNIX_S_RX_SETUP 0x2    /* X11: the server's setup reply is the next thing received */
#define MM_UNIX_S_RX_LOST 0x4     /* a receive went past the walk: its framing is lost, receives are counted unparsed */
#define MM_UNIX_S_TEXT_TX 0x8     /* D-Bus: the SASL handshake's lines still to be sent (until a call ends in BEGIN) */
#define MM_UNIX_S_TEXT_RX 0x10    /* D-Bus: ... to be received (until a call starts a message) */

/* unix_svc value, key the socket's inode: a service connection's state across calls. [0] sends, [1] receives. */
struct mm_unix_sock {
    __u32 svc;
    __u32 flags;
    __u32 skip[2];        /* bytes of the last message the previous call did not hold */
    __u32 part_len[2];    /* bytes of a message header the previous call ended in, carried in part */
    __u8 part[2][MM_UNIX_PART];
    __u64 window_ns;      /* D-Bus: the second heads are counted in */
    __u32 heads;
    __u32 pad;
};

/* MM_UNIX record (a head), sent before its call's MM_SYSCALL record (MM_F_UNIX_HEAD): the call's bytes, a carried
 * header part first, and for X11 and PulseAudio sends the requests that were the first of their op since the agent
 * last drained agg (their summaries count the rest); for D-Bus every message starting in it (op: offset << 16 | type),
 * none for a call of the SASL handshake. The ring record ends after len bytes of data. */
struct mm_unix_head {
    __u32 kind;           /* MM_UNIX */
    __u32 tgid;
    __u32 tid;
    __u32 svc;            /* MM_UNIX_X11 / DBUS / PULSE, | MM_UNIX_RX, | MM_UNIX_BIG */
    __u64 ts_ns;          /* the call's record's */
    __u64 ino;            /* the socket */
    __u32 len;            /* bytes in data */
    __u32 sampled;        /* entries in op[] */
    __u32 op[MM_UNIX_SAMPLED];   /* the request's offset in data << 16 | its op's low 16 bits */
    /* Only MM_UNIX_HEAD + MM_UNIX_PART bytes are used; the rest keeps every copy's end in bounds for the verifier. */
    __u8 data[2 * MM_UNIX_HEAD + 2 * MM_UNIX_PART];
};

#define MM_UNIX_INLINE static inline __attribute__((always_inline))

MM_UNIX_INLINE __u32 mm_unix_u16(const __u8* b, __u32 big)
{
    return big ? (__u32)b[0] << 8 | b[1] : (__u32)b[1] << 8 | b[0];
}

MM_UNIX_INLINE __u32 mm_unix_u32(const __u8* b, __u32 big)
{
    return big ? (__u32)b[0] << 24 | (__u32)b[1] << 16 | (__u32)b[2] << 8 | b[3]
               : (__u32)b[3] << 24 | (__u32)b[2] << 16 | (__u32)b[1] << 8 | b[0];
}

/* 1 when the Avail bytes at B start a D-Bus message: its byte order ('l' or 'B'), a type 1-4, protocol version 1.
 * SASL lines never do ("BEGIN" is 'B' then 'E'). */
MM_UNIX_INLINE __u32 mm_unix_dbus_start(const __u8* b, __u32 avail)
{
    return avail >= 4 && (b[0] == 'l' || b[0] == 'B') && b[1] >= 1 && b[1] <= 4 && b[3] == 1;
}

/* 1 when the 7 bytes at B are the SASL handshake's last client line, "BEGIN\r\n": a send ending in it ends the text. */
MM_UNIX_INLINE __u32 mm_unix_dbus_begin(const __u8* b)
{
    return b[0] == 'B' && b[1] == 'E' && b[2] == 'G' && b[3] == 'I' && b[4] == 'N' && b[5] == '\r' && b[6] == '\n';
}

/* The message starting at B (Avail bytes there, at least MM_UNIX_PART readable): its length in bytes, its op in *Op; 0
 * when its header is not wholly in Avail (carried to the next call), ~0 when the bytes are no such message (the
 * stream is lost). X11 sends: a request (4 bytes, 8 with a BIG-REQUESTS length). X11 receives: a reply, error or event
 * (32 bytes; a reply and a GenericEvent 4 * their length more). PulseAudio either way: a 20-byte descriptor (big-endian
 * length, channel), then a tagstruct ('L' + a big-endian command) on the control channel (~0), else audio. D-Bus either
 * way (each message in its own byte order): a 16-byte header (body length at 4, header fields' length at 12), the
 * fields padded to 8, the body; a header whose fields fit MM_UNIX_PART is wanted whole (carried) so they are named. */
MM_UNIX_INLINE __u64 mm_unix_frame(__u32 svc, __u32 rx, __u32 big, const __u8* b, __u32 avail, __u32* op)
{
    if (svc == MM_UNIX_DBUS) {
        if (avail < 16) return avail < 4 || mm_unix_dbus_start(b, avail) ? 0 : ~0ull;
        if (!mm_unix_dbus_start(b, avail)) return ~0ull;
        const __u32 order = b[0] == 'B';
        const __u64 header = 16 + (((__u64)mm_unix_u32(b + 12, order) + 7) & ~7ull);
        if (avail < header && header <= MM_UNIX_PART) return 0;
        *op = b[1];
        return header + mm_unix_u32(b + 4, order);
    }
    if (svc == MM_UNIX_X11 && !rx) {
        if (avail < 4) return 0;
        __u64 size = (__u64)mm_unix_u16(b + 2, big) * 4;
        if (size == 0) {   /* BIG-REQUESTS: the length follows the header */
            if (avail < 8) return 0;
            size = (__u64)mm_unix_u32(b + 4, big) * 4;
            if (size < 8) return ~0ull;
        }
        if (b[0] == 0) return ~0ull;   /* no request has major opcode 0 */
        *op = (__u32)b[0] << 8 | (b[0] >= 128 ? b[1] : 0);
        return size;
    }
    if (svc == MM_UNIX_X11) {
        if (avail < 32) return 0;
        const __u32 type = b[0] & 0x7f;
        if (b[0] == 0) {   /* error: code, sequence, bad value, minor (u16), major */
            *op = (__u32)b[1] << 16 | (__u32)b[10] << 8 | b[8];
            return 32;
        }
        *op = type << 24 | (b[0] & 0x80 ? MM_UNIX_X11_SENT : 0);
        if (b[0] == 1) return 32 + (__u64)mm_unix_u32(b + 4, big) * 4;
        if (type == 35) {   /* GenericEvent: extension, sequence, length, evtype (u16) */
            *op |= (__u32)b[1] << 8 | b[8];
            return 32 + (__u64)mm_unix_u32(b + 4, big) * 4;
        }
        return 32;
    }
    if (svc == MM_UNIX_PULSE) {
        if (avail < 20) return 0;
        const __u64 size = 20 + (__u64)mm_unix_u32(b, 1);
        if (mm_unix_u32(b + 4, 1) != 0xffffffffu) {
            *op = MM_UNIX_PULSE_MEMBLOCK;
            return size;
        }
        if (size < 25) {
            *op = MM_UNIX_PULSE_OTHER;
            return size;
        }
        if (avail < 25) return 0;
        *op = b[20] == 'L' ? mm_unix_u32(b + 21, 1) : MM_UNIX_PULSE_OTHER;
        return size;
    }
    return ~0ull;
}

/* The service a newly connected socket's first send (Len bytes at B, at least MM_UNIX_PART readable) opens, and where
 * its first request starts (*Start: past X11's connection setup, past D-Bus's NUL), *Big for a big-endian X11 client; 0
 * for none of them. X11: 'l' or 'B', 0, protocol 11.0, then the authorization name and data lengths, each padded to 4.
 * D-Bus: the credentials NUL byte its SASL handshake starts with. PulseAudio: a control packet's descriptor (offsets and
 * flags 0). */
MM_UNIX_INLINE __u32 mm_unix_classify(const __u8* b, __u32 len, __u32* start, __u32* big)
{
    *start = 0;
    *big = b[0] == 'B';
    if (len >= 12 && (b[0] == 'l' || b[0] == 'B') && b[1] == 0 && mm_unix_u16(b + 2, *big) == 11 &&
        mm_unix_u16(b + 4, *big) == 0) {
        *start = 12 + ((mm_unix_u16(b + 6, *big) + 3) & ~3u) + ((mm_unix_u16(b + 8, *big) + 3) & ~3u);
        return MM_UNIX_X11;
    }
    *big = 0;
    if (len >= 1 && b[0] == 0 && (len == 1 || (len >= 5 && b[1] == 'A' && b[2] == 'U' && b[3] == 'T' && b[4] == 'H'))) {
        *start = 1;
        return MM_UNIX_DBUS;
    }
    if (len >= 20 && mm_unix_u32(b + 4, 1) == 0xffffffffu && mm_unix_u32(b + 8, 1) == 0 && mm_unix_u32(b + 12, 1) == 0 &&
        mm_unix_u32(b + 16, 1) == 0 && mm_unix_u32(b, 1) != 0 && mm_unix_u32(b, 1) < (1u << 24))
        return MM_UNIX_PULSE;
    return 0;
}

/* Where the walk of one call left its socket's direction. At: the end of the last message it framed (it may lie past
 * the call). Head: the bytes it had (a carried part, then at most MM_UNIX_HEAD of the call's). Part: the carried ones,
 * Bytes: the call's, Asked: a send's requested bytes (a partial write sent fewer). Incomplete: 1 when it stopped at a
 * message header the bytes it had did not hold. Sets *Skip (bytes of the last message still to come) and *Carry (1:
 * the call ended inside the header at At, carried to the next) and returns the bytes left unparsed: 0 in step; a send
 * past the walk keeps step when it was whole (clients write whole requests, so the next starts one) or by its unsent
 * rest; a receive past the walk (or a message past 4 GiB) is lost, ~0. */
MM_UNIX_INLINE __u64 mm_unix_after(__u32 rx, __u64 at, __u32 head, __u32 part, __u64 bytes, __u64 asked,
                                   __u32 incomplete, __u32* skip, __u32* carry)
{
    const __u64 end = part + bytes;   /* the stream position just past this call */
    *skip = 0;
    *carry = 0;
    if (at >= end) {
        if (at - end > 0xffffffffull) return ~0ull;
        *skip = (__u32)(at - end);
        return 0;
    }
    if (incomplete && head == end && end - at < MM_UNIX_PART) {
        *carry = 1;
        return 0;
    }
    if (rx) return ~0ull;
    if (asked > bytes && asked - bytes <= 0xffffffffull) *skip = (__u32)(asked - bytes);
    return end - at;
}
