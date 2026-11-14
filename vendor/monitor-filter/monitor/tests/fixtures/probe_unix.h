/* The unixproto upgrade's probe actions (checks in tests/ebpf_checks/check_unixproto.py): an X11 client speaking to the
 * display socket it is given (a private Xvfb's): its setup, then QueryExtension("XTEST") split over three iovecs (header,
 * name, padding, as xcb writes it) with a GetInputFocus in the same writev; then an 8 KiB ChangeProperty of WM_NAME on
 * the root window followed by a GetInputFocus in one writev (past the 4 KiB walk); then a QueryPointer alone (framed:
 * the walk kept step); every reply read; then six NoOperation in one write. And a SIOCGIFHWADDR of "lo" (its argument
 * struct, with --log-content).
 * Returns 0 or an exit code 50-59. */
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/un.h>

static int unix_read(int fd, void* data, size_t size)
{
    for (size_t done = 0; done < size;) {
        ssize_t got = read(fd, (char*)data + done, size - done);
        if (got <= 0) return -1;
        done += (size_t)got;
    }
    return 0;
}

/* The next reply (32 bytes and its length), events and errors skipped. */
static int unix_reply(int fd)
{
    unsigned char head[32];
    for (;;) {
        if (unix_read(fd, head, sizeof(head))) return -1;
        if (head[0] != 1) continue;
        unsigned length = head[4] | head[5] << 8 | head[6] << 16 | (unsigned)head[7] << 24;
        static char rest[1 << 16];
        if (length * 4 > sizeof(rest) || unix_read(fd, rest, length * 4)) return -1;
        return 0;
    }
}

static int probe_unix(const char* display)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(display);
    if (length >= sizeof(address.sun_path)) return 50;
    memcpy(address.sun_path, display, length);
    if (display[0] == '@') address.sun_path[0] = 0;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr*)&address, offsetof(struct sockaddr_un, sun_path) + length + (display[0] != '@')))
        return 51;
    unsigned char setup[12] = {'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0}, reply[8];
    if (write(fd, setup, sizeof(setup)) != sizeof(setup) || unix_read(fd, reply, sizeof(reply)) || reply[0] != 1) return 52;
    static unsigned char info[1 << 16];
    const size_t more = (size_t)(reply[6] | reply[7] << 8) * 4;
    if (more > sizeof(info) || more < 40 || unix_read(fd, info, more)) return 53;
    const size_t vendor = (size_t)(info[16] | info[17] << 8), formats = info[21];
    const size_t screen = 32 + ((vendor + 3) & ~(size_t)3) + 8 * formats;   /* info starts at the reply's byte 8 */
    if (screen + 4 > more) return 54;
    unsigned root;
    memcpy(&root, info + screen, 4);
    /* QueryExtension("XTEST") over three iovecs, then GetInputFocus */
    unsigned char query[8] = {98, 0, 4, 0, 5, 0, 0, 0}, pad[3] = {0}, focus[4] = {43, 0, 1, 0};
    struct iovec first[] = {{query, 8}, {"XTEST", 5}, {pad, 3}, {focus, 4}};
    if (writev(fd, first, 4) != 20 || unix_reply(fd) || unix_reply(fd)) return 55;
    /* ChangeProperty(Replace, root, WM_NAME 39, STRING 31, format 8, 8192 bytes), then GetInputFocus: past 4 KiB */
    static unsigned char change[24 + 8192];
    const unsigned units = (24 + 8192) / 4, atoms[3] = {root, 39, 31}, count = 8192;
    change[0] = 18, change[2] = (unsigned char)units, change[3] = (unsigned char)(units >> 8);
    memcpy(change + 4, atoms, 12);
    change[16] = 8;
    memcpy(change + 20, &count, 4);
    memset(change + 24, 'm', 8192);
    struct iovec second[] = {{change, 24}, {change + 24, 8192}, {focus, 4}};
    if (writev(fd, second, 3) != (ssize_t)sizeof(change) + 4 || unix_reply(fd)) return 56;
    /* QueryPointer(root) alone */
    unsigned char pointer[8] = {38, 0, 2, 0};
    memcpy(pointer + 4, &root, 4);
    if (write(fd, pointer, 8) != 8 || unix_reply(fd)) return 57;
    /* six NoOperation (4 bytes each, no reply) in one write: the first sampled, five in its summary with 20 bytes */
    unsigned char nothing[24] = {127, 0, 1, 0, 127, 0, 1, 0, 127, 0, 1, 0, 127, 0, 1, 0, 127, 0, 1, 0, 127, 0, 1, 0};
    if (write(fd, nothing, sizeof(nothing)) != sizeof(nothing)) return 59;
    close(fd);
    struct ifreq request = {0};
    strcpy(request.ifr_name, "lo");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0 || ioctl(s, SIOCGIFHWADDR, &request) != 0) return 58;
    close(s);
    return 0;
}
