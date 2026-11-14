/*
 * Pins the kfilter ABI that kfilter.sys/kfilterd, kfilterctl and msmon-agent share
 * (filter/driver/kfilter.h, filter/linux/kfilter_socket.h). Compile-time only: abi/check.sh
 * builds it for the Linux layout (32-bit fields, 4-byte wchar_t) and, with
 * clang --target=x86_64-pc-windows-msvc -fshort-wchar, for the Windows layout (ULONG,
 * 2-byte wchar_t) without a WDK. A changed number here is an ABI change: bump
 * KFILTER_ABI_VERSION and review msmon's parser (monitor/agent/integrations.cpp).
 */
#include <stddef.h>
#include "../filter/driver/kfilter.h"
#ifndef _WIN32
#include "../filter/linux/kfilter_socket.h"
#endif

#ifdef __cplusplus
#define CHECK(expression) static_assert(expression, #expression)
#else
#define CHECK(expression) _Static_assert(expression, #expression)
#endif

CHECK(KFILTER_ABI_VERSION == 12);
/* ABI 12's unix message rules: the family that names KFILTER_NET_RULE.Unix (4 and 6 are IP's, 0 any address). */
CHECK(KFILTER_NET_FAMILY_UNIX == 1);
/* ABI 11's peer pseudo-rights: the generic rights' bits, which no process or thread access decision carries; the flag
 * of a rule naming them. */
CHECK(KFILTER_ACCESS_INPUT == 0x10000000 && KFILTER_ACCESS_WINDOW_QUERY == 0x20000000 &&
      KFILTER_ACCESS_WINDOW_SET == 0x40000000 && KFILTER_ACCESS_WINDOW_MESSAGE == 0x80000000 && KFILTER_RULE_PSEUDO == 0x40);
/* ABI 11's rights and switches. */
CHECK(KFILTER_RIGHT_LOCK == 0x8000 && KFILTER_RIGHT_CHDIR == 0x10000 && KFILTER_RIGHT_TOUCH == 0x20000 &&
      KFILTER_CFG_BLOCK_PROCESS_SIGNALS == 0x4000 && KFILTER_CFG_BLOCK_PROCESS_QUERIES == 0x8000);
/* What keeps ABI 11 off old rules: a rule without rights= covers KFILTER_RIGHTS_ALL, which holds neither the named file
 * rights nor the message ones, and the pseudo-rights are the four generic bits alone. */
CHECK(KFILTER_RIGHTS_ALL == 0x1FFF && (KFILTER_RIGHTS_ALL & (KFILTER_RIGHTS_FILE_NAMED | KFILTER_RIGHTS_MESSAGE)) == 0 &&
      KFILTER_RIGHTS_FILE_NAMED == 0x38000 && KFILTER_ACCESS_PSEUDO == 0xF0000000);
/* ABI 10's addr= rules: the flag and the ranges a rule carries. */
CHECK(KFILTER_RULE_ADDRESS == 0x20 && KFILTER_MAX_ADDRESS == 16 && sizeof(KFILTER_ADDRESS_RANGE) == 16);
/* ABI 9's allocation: targets, rule flags, event flag and degraded classes. */
CHECK(KFILTER_TARGET_PEER == 0x2000 && KFILTER_TARGET_THREAD_PEER == 0x4000 && KFILTER_TARGET_SYSTEM == 0x8000 &&
      KFILTER_TARGET_DNS == 0x10000 && KFILTER_TARGET_THREAD == 0x20000);
CHECK(KFILTER_RULE_HIDE == 0x8 && KFILTER_RULE_MODULE == 0x10 && KFILTER_EVENT_FLAG_DIRECT == 0x2000);
CHECK(KFILTER_STATUS_DEGRADED_QUERY == 0x800 && KFILTER_STATUS_DEGRADED_SYSTEM == 0x1000 &&
      KFILTER_STATUS_DEGRADED_THREAD == 0x2000 && KFILTER_CFG_BLOCK_FILE_QUERIES == 0x1000 &&
      KFILTER_CFG_BLOCK_DIRECT_SYSCALL == 0x2000);
/* The degraded wine class (0x4000, added before ABI 11): older readers show it as an unknown bit. */
CHECK(KFILTER_STATUS_DEGRADED_WINE == 0x4000);
CHECK(sizeof(KF_ULONG) == 4 && sizeof(KF_LONG) == 4 && sizeof(KF_UINT64) == 8);

#ifdef _WIN32
CHECK(sizeof(wchar_t) == 2);
#define W(windows, linux) (windows)
#else
#define W(windows, linux) (sizeof(wchar_t) == 2 ? (windows) : (linux))
#endif

CHECK(sizeof(KFILTER_EVENT) == W(1192, 2344));
CHECK(offsetof(KFILTER_EVENT, Timestamp) == 0);
CHECK(offsetof(KFILTER_EVENT, Generation) == 36);
CHECK(offsetof(KFILTER_EVENT, Path) == 40);
CHECK(offsetof(KFILTER_EVENT, Image) == W(1064, 2088));
CHECK(sizeof(KFILTER_STATUS) == 80);
CHECK(offsetof(KFILTER_STATUS, SessionTag) == 72);
CHECK(sizeof(KFILTER_READ_REQUEST) == 8);
CHECK(sizeof(KFILTER_TRACK_REQUEST) == 16);
CHECK(sizeof(KFILTER_ADMIT_REQUEST) == W(1108, 2132));
CHECK(sizeof(KFILTER_ALLOW_LAUNCH_REQUEST) == W(1032, 2056));
CHECK(sizeof(KFILTER_CONNECTION_REQUEST) == 16);
CHECK(sizeof(KFILTER_SESSION_REQUEST) == 16);
CHECK(sizeof(KFILTER_RULE) == W(1848, 3384));
CHECK(offsetof(KFILTER_RULE, AddressCount) == W(1568, 3104));
CHECK(offsetof(KFILTER_RULE, Address) == W(1592, 3128));
CHECK(sizeof(KFILTER_NET_RULE) == W(728, 1368));
CHECK(offsetof(KFILTER_NET_RULE, Unix) == W(472, 856));
CHECK(offsetof(KFILTER_CONFIG, Network) == W(17508, 34916));
CHECK(KFILTER_CONFIG_SIZE(0) == W(203880, 385128));
CHECK(sizeof(KFILTER_CONFIG) == W(30481512, 55828584));

#ifndef _WIN32
CHECK(sizeof(KFILTER_SOCKET_REQUEST) == 16 && sizeof(KFILTER_SOCKET_REPLY) == 8);
CHECK(KFILTER_OP_GET_STATUS == 0x800 && KFILTER_OP_READ_EVENTS == 0x802 && KFILTER_OP_GET_CONFIG == 0x806);
#endif
