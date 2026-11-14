#include "wineserver.h"
#include "../rpc_names.h"
#include "sysagg.h"   /* AggSummary */
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <cwctype>
#include <string_view>

/*
 * Protocol 930 (wine-11.0 include/wine/server_protocol.h, server/protocol.def). Every number and
 * offset of the protocol lives in this file only; ws.bpf.h gets what it needs through ws_cfg.
 * Requests are decoded when their reply arrives (the record carries the reply's status), or without
 * it (detail ";no_reply") when the thread sends another request or the process ends first.
 */

namespace {

enum Request : uint32_t {
    NewProcess = 0, NewThread = 2, CloseHandleReq = 21, DupHandle = 23, OpenProcess = 27, OpenThread = 28, CreateFile = 44, OpenFileObject = 45,
    GetVolumeInfo = 52, CreateMapping = 63, OpenMapping = 64, ListProcesses = 76, DebugProcess = 82,
    ReadProcessMemory = 84, WriteProcessMemory = 85, CreateKey = 86, OpenKey = 87, DeleteKey = 88,
    EnumKey = 90, SetKeyValue = 91, GetKeyValue = 92, EnumKeyValue = 93, DeleteKeyValue = 94, RenameKey = 99,
    Read = 136, Write = 137, Ioctl = 138, CreateNamedPipe = 140, GetWindowList = 151, GetWindowTree = 154,
    GetWindowText = 157, GetSystemHandles = 234, GetTcpConnections = 235, GetUdpEndpoints = 236,
    CreateDeviceManager = 250, CreateDevice = 251, GetNextDeviceRequest = 253, SetKernelObjectPtr = 255,
    GetNextProcess = 293, GetNextThread = 294,
    /* Process and thread control (msmon-gaps 5) */
    TerminateProcess = 7, TerminateThread = 8, GetProcessInfo = 9, GetProcessDebugInfo = 10, GetProcessImageName = 11,
    GetProcessVmCounters = 12, SetProcessInfo = 13, GetThreadInfo = 14, GetThreadTimes = 15, SetThreadInfo = 16,
    SuspendThread = 17, ResumeThread = 18, QueueApc = 19, GetApcResult = 20, CreateDebugObj = 77, ContinueDebugEvent = 81,
    GetThreadContext = 105, SetThreadContext = 106, SuspendProcess = 291, ResumeProcess = 292,
    /* Named objects, tokens, security, atoms, jobs (msmon-gaps 8) */
    CreateEvent = 30, OpenEvent = 33, CreateKeyedEvent = 34, OpenKeyedEvent = 35, CreateMutex = 36, OpenMutex = 38,
    CreateSemaphore = 40, OpenSemaphore = 43, CreateTimer = 100, OpenTimer = 101, AddAtom = 107, FindAtom = 109,
    AddUserAtom = 111, OpenWinstation = 171, EnumWinstation = 176, OpenDesktop = 178, CreateToken = 219, OpenToken = 220,
    AdjustTokenPrivileges = 222, GetTokenPrivileges = 223, DuplicateToken = 225, FilterToken = 226,
    SetSecurityObject = 232, GetSecurityObject = 233, CreateMailslot = 237, CreateDirectory = 239, OpenDirectory = 240,
    GetDirectoryEntries = 241, CreateSymlink = 242, OpenSymlink = 243, QuerySymlink = 244, GetObjectName = 246,
    GetObjectType = 247, GetObjectTypes = 248, MakeProcessSystem = 259, GrantProcessAdminToken = 260, GetTokenInfo = 261,
    CreateLinkedToken = 262, CreateCompletion = 263, OpenCompletion = 264, CreateJob = 283, OpenJob = 284,
    AssignJob = 285, TerminateJob = 290,
    /* Input, hooks, clipboard (msmon-gaps 6) */
    SendHardwareMessage = 121, RegisterHotkey = 185, AttachThreadInput = 187, GetLastInputTime = 189, GetKeyState = 190,
    SetKeyState = 191, SetHook = 198, SetClipboardData = 210, GetClipboardData = 211, SetClipboardViewer = 216,
    AddClipboardListener = 217, SetCursor = 279, GetCursorHistory = 280, GetRawinputBuffer = 281,
    UpdateRawinputDevices = 282,
    /* Other programs' windows: owner lookups, styles, rectangles, hit tests, properties, focus, clipboard owner */
    GetWindowInfo = 146, GetWindowParents = 150, GetClassWindows = 152, GetWindowChildrenFromPoint = 153,
    GetWindowRectangles = 156, GetWindowProperty = 168, GetThreadInput = 188, GetClipboardInfo = 215,
    /* Files, sections, registry moved into wineserver (msmon-gaps 9, 14) */
    AllocFileHandle = 46, GetHandleUnixName = 47, ReadDirectoryChanges = 61, MapView = 67, MapImageView = 68,
    UnmapView = 71, GetMappingFilename = 75, LoadRegistry = 95, UnloadRegistry = 96, SaveRegistry = 97,
    SetRegistryNotification = 98, SetFdDispInfo = 272, SetFdNameInfo = 273, SetFdEofInfo = 274,
    /* Messages, windows, async results, IRP results (M1) and the kernel-aggregated hot requests */
    SendMessage = 119, GetMessage = 122, GetAsyncResult = 134, SetIrpResult = 139, CreateWindow = 142,
    DestroyWindow = 143, Select = 29, EventOp = 31, GetHandleFd = 48, RecvSocket = 55, SendSocket = 56,
    GetMappingInfo = 65, SetQueueMask = 116, GetQueueStatus = 117, AcceptHardwareMessage = 124,
    SetAsyncDirectResult = 135, StartHookChain = 200, FinishHookChain = 201, GetHookInfo = 202,
    AddCompletion = 265, RemoveCompletion = 266, GetThreadCompletion = 267,
};

/* Requests whose reply data the decoder reads (ws_cfg data bits; WsCaptureConfig adds the replies the generic decoder
 * prints: a UTF-16 string as their only vararg). */
constexpr uint32_t kReplyData[] = {GetVolumeInfo, EnumKey, GetKeyValue, EnumKeyValue, Read, Ioctl, GetWindowText,
                                   GetNextDeviceRequest, GetProcessImageName, GetThreadContext, GetDirectoryEntries,
                                   QuerySymlink, GetObjectName, GetObjectType, GetHandleUnixName, GetMappingFilename,
                                   GetMessage, GetAsyncResult};

/* Requests the kernel counts per key in agg instead of capturing them, all but the first call of each key between two
 * drains of agg (about a second): Wine's waits, async I/O plumbing, queue polls, hook chains and input moves (select
 * 12M, get_async_result 3.9M and ioctl 3.9M calls in 4.5 minutes of the game). Key: the u32 request fields named, hi
 * << 32 | lo (an async_data_t's handle). */
const struct {
    uint32_t request;
    const char* hi;
    const char* lo;
} kAggregated[] = {
    {Select, nullptr, "flags"}, {EventOp, "handle", "op"}, {GetAsyncResult, nullptr, nullptr}, {Ioctl, "async", "code"},
    {RemoveCompletion, nullptr, "handle"}, {AddCompletion, nullptr, "handle"}, {GetThreadCompletion, nullptr, nullptr},
    {SetAsyncDirectResult, nullptr, nullptr}, {SetQueueMask, nullptr, nullptr}, {GetQueueStatus, nullptr, nullptr},
    {StartHookChain, nullptr, "id"}, {FinishHookChain, nullptr, "id"}, {GetHookInfo, nullptr, "handle"},
    {RecvSocket, nullptr, "async"}, {SendSocket, nullptr, "async"}, {GetHandleFd, nullptr, "handle"},
    {GetMappingInfo, nullptr, "handle"}, {AcceptHardwareMessage, nullptr, nullptr},
    {SendHardwareMessage, "flags", "type"}, {SetCursor, nullptr, "flags"},
};

/*
 * Every request of protocol 930, one line each in request-number order: its name, the fixed fields of the request,
 * '|', those of the reply, each name@<hex offset>[:type] (from the start of the 64-byte part), and the varargs +name
 * ('$' a UTF-16 string, '@' object attributes). Taken from the request and reply dumpers of /opt/wine-stable's
 * wineserver (3-wineserver-protocol.md Appendix A) with Wine's field types:
 *   x u32 hex (the default), u u32, i int, 2 u16 hex, 8 u64 hex, I i64 (timeouts, times), r rectangle (four ints),
 *   a async_data_t (40 bytes; its handle), h object handle, w window, t Windows thread id, p Windows process id,
 *   z a union a decoder of its own prints.
 * '*' marks the field a generic record is collapsed by (default the first), '!' collapses per request.
 */
const char kProtocol930[] = R"(
new_process token@c:h debug@10:h parent_process@14:h flags@18 socket_fd@1c:i access@20 machine@24 info_size@28:u handles_size@2c:u jobs_size@30:u +objattr@ +handles +jobs +env | info@8:h pid@c:p handle@10:h
get_new_process_info info@c:h | success@8:i exit_code@c:i
new_thread process@c:h access@10 flags@14 request_fd@18:i +objattr@ | tid@8:t handle@c:h
get_startup_info | info_size@8:u machine@c +env
init_process_done teb@10:8 peb@18:8 | suspend@8:i
init_first_thread unix_pid@c:i unix_tid@10:i debug_level@14:i reply_fd@18:i wait_fd@1c:i | pid@8:p tid@c:t server_start@10:I session_id@18 inproc_device@1c:h info_size@20:u +machines
init_thread unix_tid@c:i reply_fd@10:i wait_fd@14:i teb@18:8 entry@20:8 | suspend@8:i
terminate_process handle@c:h exit_code@10:i | self@8:i
terminate_thread handle@c:h exit_code@10:i | self@8:i
get_process_info handle@c:h | pid@8:p ppid@c:p affinity@10:8 peb@18:8 start_time@20:I end_time@28:I session_id@30 exit_code@34:i priority@38:2 base_priority@3a:2 disable_boost@3c:2 machine@3e:2 +image
get_process_debug_info handle@c:h | debug@8:h debug_children@c:i +image
get_process_image_name handle@c:h pid@10:p win32@14:i | len@8:u +name$
get_process_vm_counters handle@c:h | peak_virtual_size@8:8 virtual_size@10:8 peak_working_set_size@18:8 working_set_size@20:8 pagefile_usage@28:8 peak_pagefile_usage@30:8
set_process_info handle@c:h affinity@10:8 priority@18 base_priority@1c disable_boost@20 token@24:h mask@28:i |
get_thread_info handle@c:h access@10 | pid@8:p tid@c:t teb@10:8 entry_point@18:8 affinity@20:8 exit_code@28:i priority@2c base_priority@30 suspend_count@34:i flags@38 desc_len@3c:u +desc$
get_thread_times handle@c:h | creation_time@8:I exit_time@10:I unix_pid@18:i unix_tid@1c:i
set_thread_info handle@c:h priority@10 base_priority@14 affinity@18:8 entry_point@20:8 token@28:h disable_boost@2c mask@30 +desc$ |
suspend_thread handle@c:h | count@8:i
resume_thread handle@c:h | count@8:i
queue_apc handle@c:h reserve_handle@10:h +call | handle@8:h self@c:i
get_apc_result handle@c:h | result@8:z
close_handle ! handle@c:h |
set_handle_info handle@c:h flags@10:i mask@14:i | old_flags@8:i
dup_handle src_process@c:h src_handle@10:h dst_process@14:h access@18 attributes@1c options@20 | handle@8:h
allocate_reserve_object type@c +objattr@ | handle@8:h
compare_objects first@c:h second@10:h |
set_object_permanence handle@c:h permanent@10:i |
open_process pid@c:p access@10 attributes@14 | handle@8:h
open_thread tid@c:t access@10 attributes@14 | handle@8:h
select flags@c:i cookie@10:8 timeout@18:I size@20:u prev_apc@24:h +result +select_op +contexts | apc_handle@8:h signaled@c:i +call +contexts
create_event access@c manual_reset@10:i initial_state@14:i +objattr@ | handle@8:h
event_op handle@c:h op@10:i | state@8
query_event handle@c:h | manual_reset@8:i state@c
open_event access@c attributes@10 rootdir@14:h +name$ | handle@8:h
create_keyed_event access@c +objattr@ | handle@8:h
open_keyed_event access@c attributes@10 rootdir@14:h +name$ | handle@8:h
create_mutex access@c owned@10:i +objattr@ | handle@8:h
release_mutex handle@c:h | prev_count@8
open_mutex access@c attributes@10 rootdir@14:h +name$ | handle@8:h
query_mutex handle@c:h | count@8 owned@c:i abandoned@10:i
create_semaphore access@c initial@10 max@14 +objattr@ | handle@8:h
release_semaphore handle@c:h count@10 | prev_count@8
query_semaphore handle@c:h | current@8 max@c
open_semaphore access@c attributes@10 rootdir@14:h +name$ | handle@8:h
create_file access@c sharing@10 create@14:i options@18 attrs@1c +objattr@ +filename | handle@8:h
open_file_object access@c attributes@10 rootdir@14:h sharing@18 options@1c +filename$ | handle@8:h
alloc_file_handle access@c attributes@10 fd@14:i | handle@8:h
get_handle_unix_name handle@c:h | name_len@8:u +name
get_handle_fd handle@c:h | type@8 cacheable@c:i access@10 options@14
get_directory_cache_entry handle@c:h | entry@8:i +free
flush async@10:a | event@8:h
get_file_info handle@c:h info_class@10 | +data
get_volume_info handle@c:h async@10:a info_class@38 | wait@8:h +data
lock_file handle@c:h offset@10:8 count@18:8 shared@20:i wait@24:i | handle@8:h overlapped@c:i
unlock_file handle@c:h offset@10:8 count@18:8 |
recv_socket oob@c:i *async@10:a force_async@38:i | wait@8:h options@c nonblocking@10:i
send_socket flags@c *async@10:a | wait@8:h options@c nonblocking@10:i
socket_get_events handle@c:h event@10:h | flags@8 +status
socket_send_icmp_id handle@c:h icmp_id@10:2 icmp_seq@12 |
socket_get_icmp_id handle@c:h icmp_seq@10 | icmp_id@8
get_next_console_request handle@c:h signal@10:i read@14:i status@18 +out_data | code@8 output@c out_size@10:u +in_data
read_directory_changes filter@c subtree@10:i want_data@14:i async@18:a |
read_change handle@c:h | +events
create_mapping access@c flags@10 file_access@14 size@18:8 file_handle@20:h +objattr@ | handle@8:h
open_mapping access@c attributes@10 rootdir@14:h +name$ | handle@8:h
get_mapping_info handle@c:h access@10 | size@8:8 flags@10 shared_file@14:h name_len@18:u total@1c:u +image +name$ +exp_name
get_image_map_address handle@c:h | addr@8:8
map_view mapping@c:h access@10 base@18:8 size@20:8 start@28:8 |
map_image_view mapping@c:h base@10:8 size@18:8 offset@20:8 entry@28 machine@2c |
map_builtin_view +image +name |
get_image_view_info process@c:h addr@10:8 | base@8:8 size@10:8
unmap_view base@10:8 |
get_mapping_committed_range base@10:8 offset@18:8 | size@8:8 committed@10:i
add_mapping_committed_range base@10:8 offset@18:8 size@20:8 |
is_same_mapping base1@10:8 base2@18:8 |
get_mapping_filename process@c:h addr@10:8 | len@8:u +filename$
list_processes | info_size@8:u process_count@c:i total_thread_count@10:i total_name_len@14:u +data
create_debug_obj access@c flags@10 +objattr@ | handle@8:h
wait_debug_event debug@c:h | pid@8:p tid@c:t +event
queue_exception_event first@c:i *code@10 flags@14 record@18:8 address@20:8 len@28:u +params | handle@8:h
get_exception_status handle@c:h |
continue_debug_event debug@c:h pid@10:p tid@14:t status@18 |
debug_process handle@c:h debug@10:h attach@14:i |
set_debug_obj_info debug@c:h flags@10 |
read_process_memory handle@c:h addr@10:8 | +data
write_process_memory handle@c:h addr@10:8 +data | written@8:u
create_key access@c options@10 +objattr@ +class$ | hkey@8:h
open_key parent@c:h access@10 attributes@14 +name$ | hkey@8:h
delete_key hkey@c:h |
flush_key hkey@c:h |
enum_key hkey@c:h index@10:i info_class@14:i | subkeys@8:i max_subkey@c:i max_class@10:i values@14:i max_value@18:i max_data@1c:i modif@20:I total@28:u namelen@2c:u +name$ +class$
set_key_value hkey@c:h type@10 namelen@14:u +name$ +data |
get_key_value hkey@c:h +name$ | type@8 total@c:u +data
enum_key_value hkey@c:h index@10:i info_class@14:i | type@8 total@c:u namelen@10:u +name$ +data
delete_key_value hkey@c:h +name$ |
load_registry file@c:h +objattr@ |
unload_registry parent@c:h attributes@10 +name$ |
save_registry hkey@c:h file@10:h |
set_registry_notification hkey@c:h event@10:h subtree@14:i filter@18 |
rename_key hkey@c:h +name$ |
create_timer access@c manual@10:i +objattr@ | handle@8:h
open_timer access@c attributes@10 rootdir@14:h +name$ | handle@8:h
set_timer handle@c:h expire@10:I callback@18:8 arg@20:8 period@28:i | signaled@8:i
cancel_timer handle@c:h | signaled@8:i
get_timer_info handle@c:h | when@8:I signaled@10:i
get_thread_context handle@c:h context@10:h flags@14 native_flags@18 machine@1c | self@8:i handle@c:h +contexts
set_thread_context handle@c:h native_flags@10 +contexts | self@8:i
add_atom +name$ | atom@8
delete_atom atom@c |
find_atom +name$ | atom@8
get_atom_information atom@c | count@8:i pinned@c:i total@10:u +name$
add_user_atom +name$ | atom@8
get_user_atom_name atom@c | total@8:u +name$
get_msg_queue_handle | handle@8:h idle_event@c:h
get_msg_queue | +locator
set_queue_fd handle@c:h |
set_queue_mask wake_mask@c changed_mask@10 poll_events@14:i | wake_bits@8 changed_bits@c
get_queue_status clear_bits@c | wake_bits@8 changed_bits@c
get_process_idle_event handle@c:h | event@8:h
send_message id@c:t type@10:i flags@14:i win@18:w msg@1c wparam@20:8 lparam@28:8 timeout@30:I +data |
post_quit_message exit_code@c:i |
send_hardware_message win@c:w type@10 input@14:z flags@38 +report | wait@8:i prev_x@c:i prev_y@10:i new_x@14:i new_y@18:i
get_message flags@c get_win@10:w get_first@14 get_last@18 hw_id@1c wake_mask@20 changed_mask@24 internal@28 | win@8:w msg@c wparam@10:8 lparam@18:8 type@20 x@24:i y@28:i time@2c total@30:u +data
reply_message remove@c:i result@10:8 +data |
accept_hardware_message ! hw_id@c |
get_message_reply cancel@c:i | result@8:8 +data
set_win_timer win@c:w msg@10 rate@14 id@18:8 lparam@20:8 | id@8:8
kill_win_timer win@c:w id@10:8 msg@18 |
is_window_hung win@c:w | is_hung@8:i
get_serial_info handle@c:h flags@10:i | eventmask@8 pending_write@c
set_serial_info handle@c:h flags@10:i |
cancel_sync handle@c:h iosb@10:8 |
register_async type@c async@10:a count@38:i |
cancel_async handle@c:h iosb@10:8 only_thread@18:i | cancel_handle@8:h
get_async_result ! user_arg@10:8 | +out_data
set_async_direct_result handle@c:h information@10:8 status@18 mark_pending@1c:i | handle@8:h
read async@10:a pos@38:8 | wait@8:h options@c +data
write async@10:a pos@38:8 +data | wait@8:h options@c size@10:u
ioctl code@c async@10:a +in_data | wait@8:h options@c +out_data
set_irp_result handle@c:h status@10 size@14:u +data |
create_named_pipe access@c options@10 sharing@14 disposition@18 maxinstances@1c outsize@20 insize@24 timeout@28:I flags@30 +objattr@ | handle@8:h created@c:i
set_named_pipe_info handle@c:h flags@10 |
create_window parent@c:w owner@10:w atom@14 class_instance@18:8 instance@20:8 dpi_context@28 style@2c ex_style@30 +class$ | handle@8:w parent@c:w owner@10:w extra@14:i class_ptr@18:8
destroy_window handle@c:w |
get_desktop_window force@c:i | top_window@8:w msg_window@c:w
set_window_owner handle@c:w owner@10:w | full_owner@8:w prev_owner@c:w
get_window_info handle@c:w offset@10:i size@14:u | last_active@8:w is_unicode@c:i info@10:8
init_window_info handle@c:w style@10 ex_style@14 is_unicode@18:i |
set_window_info handle@c:w offset@10:i size@14:u new_info@18:8 | old_info@8:8
set_parent handle@c:w parent@10:w | old_parent@8:w full_parent@c:w
get_window_parents handle@c:w | count@8:i +parents
get_window_list desktop@c:h handle@10:w tid@14:t children@18:i | count@8:i +windows
get_class_windows parent@c:w child@10:w atom@14 +class$ | count@8:i +children
get_window_children_from_point parent@c:w x@10:i y@14:i dpi@18:i | count@8:i +children
get_window_tree handle@c:w | parent@8:w owner@c:w next_sibling@10:w prev_sibling@14:w first_sibling@18:w last_sibling@1c:w first_child@20:w last_child@24:w
set_window_pos swp_flags@c:2 paint_flags@e:2 monitor_dpi@10 *handle@14:w previous@18:w window@1c:r client@2c:r +valid | new_style@8 new_ex_style@c surface_win@10:w
get_window_rectangles handle@c:w relative@10:i dpi@14:i | window@8:r client@18:r
get_window_text handle@c:w | length@8:u +text$
set_window_text handle@c:w +text$ |
get_windows_offset from@c:w to@10:w dpi@14:i | x@8:i y@c:i mirror@10:i
get_visible_region window@c:w flags@10 | top_win@8:w top_rect@c:r win_rect@1c:r paint_flags@2c total_size@30:u +region
get_window_region window@c:w surface@10:i | visible_rect@8:r total_size@18:u +region
set_window_region window@c:w redraw@10:i +region |
get_update_region window@c:w from_child@10:w flags@14 | child@8:w flags@c total_size@10:u +region
update_window_zorder window@c:w rect@10:r |
redraw_window window@c:w flags@10 +region |
set_window_property window@c:w data@10:8 atom@18 +name$ |
remove_window_property window@c:w atom@10 +name$ | data@8:8
get_window_property window@c:w atom@10 +name$ | data@8:8
get_window_properties window@c:w | total@8:i +props
create_winstation flags@c access@10 attributes@14 rootdir@18:h +name$ | handle@8:h
open_winstation access@c attributes@10 rootdir@14:h +name$ | handle@8:h
close_winstation handle@c:h |
set_winstation_monitors increment@c:i +infos | serial@8:8
get_process_winstation | handle@8:h
set_process_winstation handle@c:h |
enum_winstation handle@c:h | count@8:u total@c:u +names
create_desktop flags@c access@10 attributes@14 +name$ | handle@8:h
open_desktop winsta@c:h flags@10 access@14 attributes@18 +name$ | handle@8:h
open_input_desktop flags@c access@10 attributes@14 | handle@8:h
set_input_desktop handle@c:h |
close_desktop handle@c:h |
get_thread_desktop tid@c:t | locator_id@8:8 locator_offset@10:8 handle@18:h
set_thread_desktop handle@c:h | +locator
set_user_object_info handle@c:h flags@10 obj_flags@14 | is_desktop@8:i old_obj_flags@c +name$
register_hotkey window@c:w id@10:i flags@14 vkey@18 | replaced@8:i flags@c vkey@10
unregister_hotkey window@c:w id@10:i | flags@8 vkey@c
attach_thread_input tid_from@c:t tid_to@10:t attach@14:i |
get_thread_input tid@c:t | +locator
get_last_input_time | time@8
get_key_state async@c:i key@10:i | state@8
set_key_state async@c:i +keystate |
set_foreground_window handle@c:w internal@10:i | previous@8:w send_msg_old@c:i send_msg_new@10:i
set_focus_window handle@c:w | previous@8:w
set_active_window handle@c:w | previous@8:w
set_capture_window handle@c:w flags@10 | previous@8:w full_handle@c:w
set_caret_window handle@c:w width@10:i height@14:i | previous@8:w old_rect@c:r old_hide@1c:i old_state@20:i
set_caret_info flags@c *handle@10:w x@14:i y@18:i hide@1c:i state@20 | full_handle@8:w old_rect@c:r old_hide@1c:i old_state@20:i
set_hook id@c:i pid@10:p tid@14:t event_min@18:i event_max@1c:i proc@20:8 flags@28:i unicode@2c:i +module$ | handle@8
remove_hook handle@c proc@10:8 id@18:i |
start_hook_chain id@c:i event@10:i window@14:w object_id@18:i child_id@1c:i | handle@8 pid@c:p tid@10:t unicode@14:i proc@18:8 +module$
finish_hook_chain id@c:i |
get_hook_info handle@c get_next@10:i event@14:i window@18:w object_id@1c:i child_id@20:i | handle@8 id@c:i pid@10:p tid@14:t proc@18:8 unicode@20:i +module$
create_class local@c:i atom@10 style@14 instance@18:8 client_ptr@20:8 cls_extra@28:2 win_extra@2a:2 name_offset@2c:u +name$ | locator_id@8:8 locator_offset@10:8 atom@18
destroy_class atom@c instance@10:8 +name$ | client_ptr@8:8
set_class_info window@c:w offset@10:i size@14:u new_info@18:8 | old_info@8:8
get_class_info window@c:w offset@10:i size@14:u | info@8:8
open_clipboard window@c:w | owner@8:w
close_clipboard | viewer@8:w owner@c:w
empty_clipboard |
set_clipboard_data format@c lcid@10 +data | seqno@8
get_clipboard_data format@c render@10:i cached@14:i seqno@18 | from@8:w owner@c:w seqno@10 total@14:u +data
get_clipboard_formats format@c | count@8 +formats
enum_clipboard_formats previous@c | format@8
release_clipboard owner@c:w | viewer@8:w owner@c:w
get_clipboard_info | window@8:w owner@c:w viewer@10:w seqno@14
set_clipboard_viewer viewer@c:w previous@10:w | old_viewer@8:w owner@c:w
add_clipboard_listener window@c:w |
remove_clipboard_listener window@c:w |
create_token token_id@c:8 access@14 primary@18:i impersonation_level@1c:i expire@20:I group_count@28:i primary_group@2c:i priv_count@30:i | token@8:h
open_token handle@c:h access@10 attributes@14 flags@18 | token@8:h
set_desktop_shell_windows flags@c shell_window@10:w shell_listview@14:w progman_window@18:w taskman_window@1c:w | old_shell_window@8:w old_shell_listview@c:w old_progman_window@10:w old_taskman_window@14:w
adjust_token_privileges handle@c:h disable_all@10:i get_modified_state@14:i +privileges | len@8 +privileges
get_token_privileges handle@c:h | len@8 +privileges
check_token_privileges handle@c:h all_required@10:i +privileges | has_privileges@8:i +privileges
duplicate_token handle@c:h access@10 primary@14:i impersonation_level@18:i +objattr@ | new_handle@8:h
filter_token handle@c:h flags@10 privileges_size@14:u +privileges +disable_sids | new_handle@8:h
access_check handle@c:h desired_access@10 map_read@14 map_write@18 map_execute@1c map_all@20 +sd | access_granted@8 access_status@c privileges_len@10 +privileges
get_token_sid handle@c:h which_sid@10 | sid_len@8:u +sid
get_token_groups handle@c:h attr_mask@10 | attr_len@8:u sid_len@c:u +attrs +sids
get_token_default_dacl handle@c:h | acl_len@8:u +acl
set_token_default_dacl handle@c:h +acl |
set_security_object handle@c:h security_info@10 +sd |
get_security_object handle@c:h security_info@10 | sd_len@8 +sd
get_system_handles | count@8 +data
get_tcp_connections state_filter@c | count@8 +connections
get_udp_endpoints | count@8 +endpoints
create_mailslot access@c options@10 read_timeout@18:I max_msgsize@20 +objattr@ | handle@8:h
set_mailslot_info handle@c:h read_timeout@10:I flags@18 | read_timeout@8:I max_msgsize@10
create_directory access@c +objattr@ | handle@8:h
open_directory access@c attributes@10 rootdir@14:h +directory_name$ | handle@8:h
get_directory_entries handle@c:h index@10 max_count@14 | total_len@8:u count@c +entries
create_symlink access@c +objattr@ +target_name$ | handle@8:h
open_symlink access@c attributes@10 rootdir@14:h +name$ | handle@8:h
query_symlink handle@c:h | total@8:u +target_name$
get_object_info handle@c:h | access@8 ref_count@c handle_count@10
get_object_name handle@c:h | total@8:u +name$
get_object_type handle@c:h | +info
get_object_types | count@8:i +info
allocate_locally_unique_id | luid@8:8
create_device_manager access@c attributes@10 | handle@8:h
create_device rootdir@c:h user_ptr@10:8 manager@18:h +name$ |
delete_device manager@c:h device@10:8 |
get_next_device_request manager@c:h prev@10:h status@14 user_ptr@18:8 pending@20:i iosb_status@24 result@28:u +data | params@8:z next@28:h client_tid@2c:t client_thread@30:8 in_size@38:u +next_data
get_kernel_object_ptr manager@c:h handle@10:h | user_ptr@8:8
set_kernel_object_ptr manager@c:h handle@10:h user_ptr@18:8 |
grab_kernel_object manager@c:h user_ptr@10:8 |
release_kernel_object manager@c:h user_ptr@10:8 |
get_kernel_object_handle manager@c:h user_ptr@10:8 access@18 | handle@8:h
make_process_system handle@c:h | event@8:h
grant_process_admin_token handle@c:h |
get_token_info handle@c:h | token_id@8:8 modified_id@10:8 session_id@18 primary@1c:i impersonation_level@20:i elevation_type@24:i is_elevated@28:i group_count@2c:i privilege_count@30:i
create_linked_token handle@c:h | linked@8:h
create_completion access@c concurrent@10 +objattr@ | handle@8:h
open_completion access@c attributes@10 rootdir@14:h +filename$ | handle@8:h
add_completion handle@c:h ckey@10:8 cvalue@18:8 information@20:8 reserve_handle@28:h status@2c |
remove_completion handle@c:h alertable@10:i | ckey@8:8 cvalue@10:8 information@18:8 status@20 wait_handle@24:h
get_thread_completion | ckey@8:8 cvalue@10:8 information@18:8 status@20
query_completion handle@c:h | depth@8
set_completion_info handle@c:h ckey@10:8 chandle@18:h |
add_fd_completion handle@c:h cvalue@10:8 information@18:8 status@20 async@24:i |
set_fd_completion_mode handle@c:h flags@10 |
set_fd_disp_info handle@c:h flags@10 |
set_fd_name_info handle@c:h rootdir@10:h namelen@14:u link@18:i flags@1c +name$ +filename |
set_fd_eof_info handle@c:h eof@10:8 |
get_window_layered_info handle@c:w | color_key@8 alpha@c flags@10
set_window_layered_info handle@c:w color_key@10 alpha@14 flags@18 |
alloc_user_handle type@c | handle@8
free_user_handle type@c handle@10 |
set_cursor flags@c handle@10 show_count@14:i x@18:i y@1c:i clip@20:r | prev_handle@8 prev_count@c:i prev_x@10:i prev_y@14:i new_x@18:i new_y@1c:i new_clip@20:r last_change@30
get_cursor_history | +history
get_rawinput_buffer header_size@c:u read_data@10:i | next_size@8:u time@c count@10 +data
update_rawinput_devices +devices |
create_job access@c +objattr@ | handle@8:h
open_job access@c attributes@10 rootdir@14:h +name$ | handle@8:h
assign_job job@c:h process@10:h |
process_in_job job@c:h process@10:h |
set_job_limits handle@c:h limit_flags@10 |
set_job_completion_port job@c:h port@10:h key@18:8 |
get_job_info handle@c:h | total_processes@8:i active_processes@c:i +pids
terminate_job handle@c:h status@10:i |
suspend_process handle@c:h |
resume_process handle@c:h |
get_next_process last@c:h access@10 attributes@14 flags@18 | handle@8:h
get_next_thread process@c:h last@10:h access@14 attributes@18 flags@1c | handle@8:h
set_keyboard_repeat enable@c:i delay@10:i period@14:i | enable@8:i
get_inproc_sync_fd handle@c:h | type@8 access@c
get_inproc_alert_fd | handle@8:h
d3dkmt_object_create type@c fd@10:i value@14 +runtime | global@8 handle@c:h
d3dkmt_object_update type@c global@10 +runtime |
d3dkmt_object_query type@c global@10 handle@14:h | runtime_size@8:u
d3dkmt_object_open type@c global@10 handle@14:h | global@8 handle@c:h runtime_size@10:u +runtime
d3dkmt_share_objects resource@c mutex@10 sync@14 access@18 +objattr@ | handle@8:h
d3dkmt_object_open_name type@c access@10 attributes@14 rootdir@18:h +name$ | handle@8:h
d3dkmt_mutex_acquire mutex@c key_value@10 wait_handle@14:h wait_status@18 | fence_value@8:8 runtime_size@10:u wait_handle@14:h +runtime
d3dkmt_mutex_release mutex@c abandon@10:i key_value@14 fence_value@18:8 runtime_size@20:u +runtime |
)";

/* A fixed field of kProtocol930: where it is, its size and how it prints. */
struct Field {
    std::string name;
    uint8_t offset = 0, size = 4;
    char type = 'x';
};
struct Proto {
    std::string name;
    std::vector<Field> request, reply;
    std::vector<std::string> varargs, replyVarargs;   /* with their '$' / '@' mark */
    int key = 0;                                     /* index in request of the collapse field (-1: none) */
};

/* kProtocol930 parsed once, by request number. */
const std::vector<Proto>& Protocol()
{
    static const std::vector<Proto> table = [] {
        std::vector<Proto> out;
        std::istringstream lines(kProtocol930);
        for (std::string line; std::getline(lines, line);) {
            std::istringstream words(line);
            Proto proto;
            if (!(words >> proto.name)) continue;
            bool reply = false;
            for (std::string word; words >> word;) {
                if (word == "|" || word == "!") {
                    reply |= word == "|";
                    if (word == "!") proto.key = -1;
                    continue;
                }
                if (word[0] == '+') {
                    (reply ? proto.replyVarargs : proto.varargs).push_back(word.substr(1));
                    continue;
                }
                std::vector<Field>& fields = reply ? proto.reply : proto.request;
                const bool key = word[0] == '*';
                const size_t at = word.find('@'), colon = word.find(':');
                if (key) proto.key = static_cast<int>(fields.size());
                Field field;
                field.name = word.substr(key, at - key);
                field.offset = static_cast<uint8_t>(std::stoul(word.substr(at + 1, colon - at - 1), nullptr, 16));
                field.type = colon == std::string::npos ? 'x' : word[colon + 1];
                fields.push_back(field);
            }
            for (std::vector<Field>* fields : {&proto.request, &proto.reply}) {
                for (size_t index = 0; index < fields->size(); index++) {
                    Field& field = (*fields)[index];
                    const size_t end = index + 1 < fields->size() ? (*fields)[index + 1].offset : MM_WS_FIXED;
                    const size_t size = field.type == '2' ? 2 : field.type == '8' || field.type == 'I' ? 8
                                      : field.type == 'r'                         ? 16
                                      : field.type == 'a'                         ? 40
                                      : field.type == 'z'                         ? end - field.offset
                                                                                  : 4;
                    field.size = static_cast<uint8_t>(std::min<size_t>(size, MM_WS_FIXED - field.offset));
                }
            }
            out.push_back(std::move(proto));
        }
        return out;
    }();
    return table;
}

/* A request number's line; past the table "unknown", without fields. */
const Proto& ProtoOf(uint32_t request)
{
    static const Proto unknown{"unknown", {}, {}, {}, {}, -1};
    return request < Protocol().size() ? Protocol()[request] : unknown;
}

/* A request field's offset by name (0: none). */
uint8_t FieldOffset(uint32_t request, const char* name)
{
    for (const Field& field : ProtoOf(request).request) {
        if (name != nullptr && field.name == name) return field.offset;
    }
    return 0;
}

/* include/wine/afd.h: CTL_CODE(FILE_DEVICE_BEEP = 1, 0x800/0x802, METHOD_NEITHER, 0) and
 * WINE_AFD_IOC(n) = CTL_CODE(FILE_DEVICE_NETWORK = 0x12, n, METHOD_BUFFERED, 0). */
constexpr uint32_t kAfdBind = 0x12003, kAfdListen = 0x1200b, kAfdAccept = 0x120324, kAfdAcceptInto = 0x120328,
                   kAfdConnect = 0x12032c;
/* FSCTL_PIPE_TRANSCEIVE: CTL_CODE(FILE_DEVICE_NAMED_PIPE, 5, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA). */
constexpr uint32_t kPipeTransceive = 0x11c017;
constexpr uint32_t kSecImage = 0x1000000;            /* create_mapping flags: NtCreateSection(SEC_IMAGE) */
constexpr uint32_t kDuplicateSameAccess = 2;         /* dup_handle options */

constexpr uint32_t kCurrentProcess = 0xffffffff;   /* GetCurrentProcess() pseudo handle */
constexpr uint32_t kCurrentThread = 0xfffffffe;    /* GetCurrentThread() pseudo handle */
constexpr uint32_t kAllAccess = 0x1fffff;          /* PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS: a pseudo handle's */
constexpr uint32_t kStatusPending = 0x103;
constexpr uint32_t kCtxDebugRegisters = 0x10;   /* SERVER_CTX_DEBUG_REGISTERS */
constexpr size_t kContextBytes = 1720;          /* sizeof(struct context_data); its debug union is at +824 */
constexpr uint32_t kHideFromDebugger = 0x40;    /* SET_THREAD_INFO_DBG_HIDDEN */
constexpr uint32_t kInjected = 1;               /* SEND_HWMSG_INJECTED */
constexpr uint32_t kCursorPosClip = 0x0c;       /* SET_CURSOR_POS | SET_CURSOR_CLIP */
constexpr uint32_t kInheritHandles = 4;         /* PROCESS_CREATE_FLAGS_INHERIT_HANDLES */
constexpr uint32_t kOpenTokenThread = 1;        /* OPEN_TOKEN_THREAD */
/* FILE_INFORMATION_CLASS, as the minifilter's IRP_MJ_SET_INFORMATION records */
constexpr uint64_t kFileRename = 10, kFileLink = 11, kFileDisposition = 13, kFileEndOfFile = 20;
constexpr uint32_t kNotifyChangeDirectory = 2;  /* IRP_MN_NOTIFY_CHANGE_DIRECTORY */
constexpr uint32_t kSvcctlOpenService = 16, kSvcctlCreateService = 12;
constexpr size_t kRpcStubBytes = 1024;          /* bytes of an RPC request stub kept as its payload */
constexpr size_t kResultBytes = 1024;           /* bytes of an IRP, async or ioctl answer kept as its payload */
constexpr uint32_t kMsgHookLowLevel = 9;        /* MSG_HOOK_LL: a low-level hook's call (msg is the hook id) */
constexpr uint32_t kWhKeyboardLowLevel = 13;    /* WH_KEYBOARD_LL */

uint32_t U32(const uint8_t* bytes, size_t offset)
{
    uint32_t value;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

uint64_t U64(const uint8_t* bytes, size_t offset)
{
    uint64_t value;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

std::wstring Hex(uint64_t value)
{
    wchar_t text[24];
    swprintf(text, 24, L"0x%llx", static_cast<unsigned long long>(value));
    return text;
}

std::wstring Num(uint64_t value) { return std::to_wstring(value); }

/* ";sha256=<of the bytes captured>", with ";hashed_bytes=<n>" when fewer than Total were. */
std::wstring Hashed(const uint8_t* bytes, size_t captured, uint64_t total)
{
    captured = std::min<uint64_t>(captured, total);
    return L";sha256=" + LinuxWide(Sha256Bytes(bytes, captured)) + (captured < total ? L";hashed_bytes=" + Num(captured) : L"");
}

/* UTF-16LE (no NUL) as UTF-32; an unpaired surrogate becomes U+FFFD. */
std::wstring Utf16(const uint8_t* bytes, size_t length)
{
    std::wstring text;
    for (size_t index = 0; index + 1 < length; index += 2) {
        uint32_t unit = bytes[index] | (bytes[index + 1] << 8);
        if (unit >= 0xd800 && unit < 0xdc00 && index + 3 < length) {
            const uint32_t low = bytes[index + 2] | (bytes[index + 3] << 8);
            if (low >= 0xdc00 && low < 0xe000) {
                text += static_cast<wchar_t>(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00));
                index += 2;
                continue;
            }
        }
        text += static_cast<wchar_t>(unit >= 0xd800 && unit < 0xe000 ? 0xfffd : unit);
    }
    return text;
}

/* VARARG(objattr,object_attributes): u32 rootdir, attributes, sd_len, name_len, the security descriptor,
 * the UTF-16 name. Returns the bytes it takes (what follows is the next vararg), 0 if malformed. */
size_t ObjectAttributes(const uint8_t* data, size_t length, uint32_t& rootdir, std::wstring& name)
{
    if (length < 16) return 0;
    rootdir = U32(data, 0);
    const uint32_t sd = U32(data, 8), nameBytes = U32(data, 12);
    if (16ull + sd + nameBytes > length) {
        /* Captured cut inside the name: keep what arrived. */
        if (16ull + sd < length) name = Utf16(data + 16 + sd, length - 16 - sd);
        return length;
    }
    name = Utf16(data + 16 + sd, nameBytes);
    return std::min<size_t>(length, (16ull + (sd & ~1u) + (nameBytes & ~1u) + 3) & ~3ull);
}

/* A Windows sockaddr (ws2def.h: AF_INET 2, AF_INET6 23) as "a.b.c.d:port" / "[v6]:port"; Family and
 * Port get the Linux family number (2, 10) and the host-order port. */
std::wstring Endpoint(const uint8_t* address, size_t length, unsigned& family, uint16_t& port)
{
    family = 0;
    port = 0;
    if (length < 4) return {};
    const uint16_t windowsFamily = static_cast<uint16_t>(address[0] | (address[1] << 8));
    port = static_cast<uint16_t>((address[2] << 8) | address[3]);
    wchar_t text[64];
    if (windowsFamily == 2 && length >= 8) {
        family = 2;
        swprintf(text, 64, L"%u.%u.%u.%u:%u", address[4], address[5], address[6], address[7], port);
        return text;
    }
    if (windowsFamily == 23 && length >= 24) {
        family = 10;
        std::wstring out = L"[";
        for (int group = 0; group < 8; group++) {
            swprintf(text, 64, L"%s%x", group ? L":" : L"", (address[8 + group * 2] << 8) | address[9 + group * 2]);
            out += text;
        }
        return out + L"]:" + Num(port);
    }
    family = windowsFamily;
    return L"family=" + Num(windowsFamily);
}

bool Failed(uint32_t status) { return static_cast<int32_t>(status) < 0; }

std::wstring Lower(std::wstring text)
{
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return text;
}

/* The last component of an NT or unix path. */
std::wstring BaseName(const std::wstring& path) { return path.substr(path.find_last_of(L"\\/") + 1); }

/* A field's value as its kProtocol930 type prints it. */
std::wstring FieldText(const Field& field, const uint8_t* bytes)
{
    const uint8_t* at = bytes + field.offset;
    auto i32 = [&](size_t offset) { return std::to_wstring(static_cast<int32_t>(U32(at, offset))); };
    switch (field.type) {
    case 'u':
    case 't':
    case 'p':
        return Num(U32(at, 0));
    case 'i':
        return i32(0);
    case '2':
        return Hex(at[0] | (at[1] << 8));
    case '8':
        return Hex(U64(at, 0));
    case 'I':
        return std::to_wstring(static_cast<int64_t>(U64(at, 0)));
    case 'r':
        return i32(0) + L"," + i32(4) + L"," + i32(8) + L"," + i32(12);
    default:   /* x, h, w, a (an async_data_t starts with its handle) */
        return Hex(U32(at, 0));
    }
}

/* ";<prefix>unknown@0x<offset>=0x<word>" for each 4-byte word of the fixed part from First on with a nonzero byte no
 * field covers (Wine zeroes the rest): a field the table lacks, or what a hand-made request (wine_server_call) carries. */
std::wstring Unknown(const std::vector<Field>& fields, const uint8_t* bytes, size_t first, const wchar_t* prefix)
{
    uint64_t covered = 0;
    for (const Field& field : fields) covered |= ((1ull << field.size) - 1) << field.offset;
    std::wstring out;
    for (size_t at = first; at < MM_WS_FIXED; at += 4) {
        bool loose = false;
        for (size_t byte = at; byte < at + 4; byte++) loose |= ((covered >> byte) & 1) == 0 && bytes[byte] != 0;
        if (loose) out += L";" + std::wstring(prefix) + L"unknown@" + Hex(at) + L"=" + Hex(U32(bytes, at));
    }
    return out;
}

/* enum message_type (server/protocol.def) by name. */
std::wstring MessageType(uint32_t type)
{
    static const wchar_t* const kTypes[] = {L"ascii",         L"unicode", L"notify",   L"callback", L"callback_result",
                                            L"other_process", L"posted",  L"hardware", L"winevent", L"hook_ll"};
    return type < std::size(kTypes) ? kTypes[type] : Num(type);
}

/* A message that carries keys: WM_KEYDOWN..WM_UNICHAR, the IME's composition, characters and keys, raw input, a
 * low-level keyboard hook's call. */
bool KeyboardMessage(uint32_t msg, uint32_t type)
{
    return (msg >= 0x100 && msg <= 0x109) || (msg >= 0x10d && msg <= 0x10f) || msg == 0x286 || msg == 0x290 ||
           msg == 0x291 || msg == 0xff || (type == kMsgHookLowLevel && msg == kWhKeyboardLowLevel);
}

/* The WMI COM class whose CLSID key Path names (CoCreateInstance reads HKCR\CLSID\{...}\InprocServer32
 * before loading wbemprox / wbemdisp / wmiutils in-process), or nullptr. */
const wchar_t* WmiClass(const std::wstring& path)
{
    static const struct {
        const wchar_t* clsid;
        const wchar_t* name;
    } kClasses[] = {
        {L"{4590f811-1d3a-11d0-891f-00aa004b2e24}", L"WbemLocator"},
        {L"{cb8555cc-9128-11d1-ad9b-00c04fd8fdff}", L"WbemAdministrativeLocator"},
        {L"{674b6698-ee92-11d0-ad71-00c04fd8fdff}", L"WbemContext"},
        {L"{76a64158-cb41-11d1-8b02-00600806d9b6}", L"SWbemLocator"},
        {L"{172bddf8-ceea-11d1-8b05-00600806d9b6}", L"WinMgmts"},
        {L"{cf4cc405-e2c5-4ddd-b3ce-5e7582d8c9fa}", L"WbemDefPath"},
    };
    if (path.size() < 38 || path[path.size() - 1] != L'}') return nullptr;
    const std::wstring tail = Lower(path.substr(path.size() - 38));
    for (const auto& known : kClasses) {
        if (tail == known.clsid) return known.name;
    }
    return nullptr;
}

/* An RPC endpoint from a pipe's NT name, as ETW names it: Wine's rpcrt4 runs ncalrpc over
 * \\.\pipe\lrpc\<endpoint> and ncacn_np over \\.\pipe\<name>. */
std::wstring RpcEndpoint(const std::wstring& name, std::wstring& protocol)
{
    const std::wstring lower = Lower(name);
    for (const wchar_t* prefix : {L"\\??\\pipe\\", L"\\device\\namedpipe\\"}) {
        const size_t length = std::wcslen(prefix);
        if (lower.compare(0, length, prefix) != 0) continue;
        if (lower.compare(length, 5, L"lrpc\\") == 0) {
            protocol = L"ncalrpc";
            return name.substr(length + 5);
        }
        protocol = L"ncacn_np";
        return L"\\pipe\\" + name.substr(length);
    }
    protocol = L"unknown";
    return name;
}

/* ";dr0=..;dr1=..;dr2=..;dr3=..;dr6=..;dr7=.." of the first context_data in Data (VARARG contexts) that holds
 * the debug registers, else "". */
std::wstring DebugRegisters(const uint8_t* data, size_t length)
{
    static const wchar_t* const kNames[] = {L"dr0", L"dr1", L"dr2", L"dr3", L"dr6", L"dr7"};
    for (size_t at = 0; at + kContextBytes <= length; at += kContextBytes) {
        const uint8_t* context = data + at;
        if ((U32(context, 4) & kCtxDebugRegisters) == 0) continue;
        const bool x64 = U32(context, 0) == 0x8664;   /* IMAGE_FILE_MACHINE_AMD64; i386 (0x14c) has u32 registers */
        std::wstring out;
        for (size_t index = 0; index < 6; index++)
            out += L";" + std::wstring(kNames[index]) + L"=" + Hex(x64 ? U64(context, 824 + 8 * index) : U32(context, 824 + 4 * index));
        return out;
    }
    return {};
}

/* union apc_call (queue_apc's vararg, 64 bytes) as ";type=<name>;<its fields>". */
std::wstring ApcCall(const uint8_t* c, size_t length, uint32_t& type)
{
    static const wchar_t* const kTypes[] = {L"none", L"user", L"async_io", L"virtual_alloc", L"virtual_alloc_ex",
                                            L"virtual_free", L"virtual_query", L"virtual_protect", L"virtual_flush",
                                            L"virtual_lock", L"virtual_unlock", L"map_view", L"map_view_ex", L"unmap_view",
                                            L"create_thread", L"dup_handle"};
    type = length >= 4 ? U32(c, 0) : 0;
    std::wstring out = L";type=" + (type < std::size(kTypes) ? std::wstring(kTypes[type]) : Num(type));
    if (length < 64) return out;
    const std::wstring addr = L";addr=" + Hex(U64(c, 8)), size = L";size=" + Hex(U64(c, 16));
    switch (type) {
    case 1: return out + L";func=" + Hex(U64(c, 8)) + L";arg=" + Hex(U64(c, 16));
    case 3: return out + addr + size + L";op=" + Hex(U32(c, 4)) + L";prot=" + Hex(U32(c, 32));
    case 4: return out + addr + size + L";op=" + Hex(U32(c, 4)) + L";prot=" + Hex(U32(c, 48));
    case 5: return out + addr + size + L";op=" + Hex(U32(c, 4));
    case 6: case 13: return out + addr;
    case 7: return out + addr + size + L";prot=" + Hex(U32(c, 4));
    case 8: case 9: case 10: return out + addr + size;
    case 11: return out + L";section=" + Hex(U32(c, 4)) + addr + size + L";offset=" + Hex(U64(c, 24)) + L";prot=" + Hex(U32(c, 44));
    case 12: return out + L";section=" + Hex(U32(c, 4)) + addr + size + L";offset=" + Hex(U64(c, 24)) + L";prot=" + Hex(U32(c, 52));
    case 14: return out + L";func=" + Hex(U64(c, 8)) + L";arg=" + Hex(U64(c, 16)) + L";flags=" + Hex(U32(c, 4));
    case 15: return out + L";src_handle=" + Hex(U32(c, 4)) + L";dst_process=" + Hex(U32(c, 8)) + L";access=" + Hex(U32(c, 12));
    default: return out;
    }
}

/* VARARG luid_attr (LUID low, high, attributes: 12 bytes each) as "SeDebugPrivilege(enabled),...". */
std::wstring Privileges(const uint8_t* data, size_t length)
{
    static const wchar_t* const kNames[] = {
        nullptr, nullptr, L"SeCreateToken", L"SeAssignPrimaryToken", L"SeLockMemory", L"SeIncreaseQuota",
        L"SeMachineAccount", L"SeTcb", L"SeSecurity", L"SeTakeOwnership", L"SeLoadDriver", L"SeSystemProfile",
        L"SeSystemtime", L"SeProfileSingleProcess", L"SeIncreaseBasePriority", L"SeCreatePagefile", L"SeCreatePermanent",
        L"SeBackup", L"SeRestore", L"SeShutdown", L"SeDebug", L"SeAudit", L"SeSystemEnvironment", L"SeChangeNotify",
        L"SeRemoteShutdown", L"SeUndock", L"SeSyncAgent", L"SeEnableDelegation", L"SeManageVolume", L"SeImpersonate",
        L"SeCreateGlobal", L"SeTrustedCredManAccess", L"SeRelabel", L"SeIncreaseWorkingSet", L"SeTimeZone",
        L"SeCreateSymbolicLink", L"SeDelegateSessionUserImpersonate"};
    std::wstring out;
    for (size_t at = 0; at + 12 <= length; at += 12) {
        const uint32_t luid = U32(data, at), attributes = U32(data, at + 8);
        out += (out.empty() ? L"" : L",") +
               (U32(data, at + 4) == 0 && luid < std::size(kNames) && kNames[luid] ? kNames[luid] + std::wstring(L"Privilege")
                                                                                    : L"luid:" + Hex(luid)) +
               ((attributes & 4) ? L"(removed)" : (attributes & 2) ? L"(enabled)" : L"(disabled)");
    }
    return out;
}

/* An NDR conformant varying UTF-16 string at At (4-aligned: max_count, offset, actual_count, the characters); At
 * moves past it. */
std::wstring NdrString(const uint8_t* stub, size_t length, size_t& at)
{
    at = (at + 3) & ~size_t(3);
    if (at + 12 > length) return {};
    const uint64_t bytes = 2ull * U32(stub, at + 8);
    at += 12;
    std::wstring text = Utf16(stub + at, std::min<uint64_t>(bytes, length - at));
    at += bytes;
    while (!text.empty() && text.back() == 0) text.pop_back();
    return text;
}

/* svcctl (MS-SCMR) arguments of an RCreateServiceW / ROpenServiceW stub: ";service=..;access=.." [";binary=.."]. */
std::wstring SvcctlArguments(uint32_t opnum, const uint8_t* stub, size_t length)
{
    size_t at = 20;   /* the SC_RPC_HANDLE context handle */
    const std::wstring service = NdrString(stub, length, at);
    if (service.empty()) return {};
    std::wstring out = L";service=" + service;
    at = (at + 3) & ~size_t(3);
    if (opnum == kSvcctlOpenService) return at + 4 <= length ? out + L";access=" + Hex(U32(stub, at)) : out;
    /* RCreateServiceW: [unique] display name, access, type, start type, error control, binary path. */
    if (at + 4 > length) return out;
    const bool display = U32(stub, at) != 0;
    at += 4;
    if (display) NdrString(stub, length, at);
    at = (at + 3) & ~size_t(3);
    if (at + 16 > length) return out;
    out += L";access=" + Hex(U32(stub, at)) + L";service_type=" + Hex(U32(stub, at + 4)) + L";start_type=" + Num(U32(stub, at + 8));
    at += 16;
    return out + L";binary=" + NdrString(stub, length, at);
}

std::wstring GuidText(const uint8_t* bytes)
{
    GUID guid{};
    guid.Data1 = U32(bytes, 0);
    guid.Data2 = static_cast<unsigned short>(bytes[4] | (bytes[5] << 8));
    guid.Data3 = static_cast<unsigned short>(bytes[6] | (bytes[7] << 8));
    std::memcpy(guid.Data4, bytes + 8, 8);
    return RpcGuidText(guid);
}

}  // namespace

bool WsParseRpc(const uint8_t* data, size_t length, WsRpcPdu& pdu)
{
    /* common header: rpc_vers 5, rpc_vers_minor 0, PTYPE, pfc_flags, drep[4], frag_length, auth_length,
     * call_id; drep[0] & 0x10 is little-endian (Wine's rpcrt4 always is). */
    if (length < 16 || data[0] != 5 || data[1] != 0 || (data[4] & 0xf0) != 0x10) return false;
    pdu = {};
    pdu.ptype = data[2];
    pdu.callId = U32(data, 12);
    if (pdu.ptype == 0) {   /* request: alloc_hint, p_cont_id, opnum */
        if (length < 24) return false;
        pdu.context = static_cast<uint32_t>(data[20] | (data[21] << 8));
        pdu.opnum = static_cast<uint32_t>(data[22] | (data[23] << 8));
        return true;
    }
    if (pdu.ptype == 11 || pdu.ptype == 14) {
        /* bind / alter_context: max_xmit_frag, max_recv_frag, assoc_group_id, n_context_elem (+24), then
         * p_cont_elem_t: p_cont_id u16, n_transfer_syn u8, reserved, abstract syntax (uuid, u16 major,
         * u16 minor), n_transfer_syn transfer syntaxes of 20 bytes. */
        if (length < 28) return false;
        size_t offset = 28;
        for (unsigned element = 0; element < data[24] && offset + 24 <= length; element++) {
            const uint32_t context = static_cast<uint32_t>(data[offset] | (data[offset + 1] << 8));
            pdu.binds.emplace_back(context, GuidText(data + offset + 4));
            if (element == 0) {
                pdu.version = Num(data[offset + 20] | (data[offset + 21] << 8)) + L"." +
                              Num(data[offset + 22] | (data[offset + 23] << 8));
            }
            offset += 24 + 20ull * data[offset + 2];
        }
        return !pdu.binds.empty();
    }
    return true;
}

const char* WsRequestName(uint32_t request)
{
    static const std::vector<std::string> names = [] {
        std::vector<std::string> out;
        for (const Proto& proto : Protocol()) out.push_back("wineserver:" + proto.name);
        return out;
    }();
    return request < names.size() ? names[request].c_str() : "wineserver:unknown";
}

mm_ws_config WsCaptureConfig(bool realInput, bool content)
{
    mm_ws_config config{};
    for (__u64& word : config.want) word = ~0ull;   /* every request, numbers past the table too */
    auto set = [](__u64* bits, uint32_t request) { bits[request >> 6] |= 1ull << (request & 63); };
    for (const uint32_t request : kReplyData) set(config.data, request);
    if (content) set(config.data, GetClipboardData);
    config.window_req[0] = CreateWindow;
    config.window_req[1] = DestroyWindow;
    for (uint32_t request = 0; request < MM_WS_REQUESTS; request++) {
        const std::vector<std::string>& replies = ProtoOf(request).replyVarargs;
        if (replies.size() == 1 && replies[0].back() == '$') set(config.data, request);
    }
    for (const auto& hot : kAggregated) {
        /* --log-real-input: each of the user's keys is a record, so their message is not aggregated */
        if (realInput && hot.request == SendHardwareMessage) continue;
        set(config.agg, hot.request);
        config.key[hot.request][0] = FieldOffset(hot.request, hot.hi);
        config.key[hot.request][1] = FieldOffset(hot.request, hot.lo);
    }
    /* Never aggregated: the AFD socket ioctls and pipe transceive, injected input (SendInput, flags +56), cursor moves
     * and clips (flags +12). */
    config.ioctl_req = Ioctl;
    const uint32_t codes[] = {kAfdBind, kAfdListen, kAfdAccept, kAfdAcceptInto, kAfdConnect, kPipeTransceive};
    std::copy(std::begin(codes), std::end(codes), config.ioctl_codes);
    config.filter[0] = {SendHardwareMessage, 56, kInjected};
    config.filter[1] = {SetCursor, 12, kCursorPosClip};
    return config;
}

bool WsKeyboardMessage(uint32_t msg, uint32_t type)
{
    return KeyboardMessage(msg, type);
}

LinuxRecord WsAggSummary(uint32_t request, uint64_t key, const mm_agg& total)
{
    LinuxRecord record = AggSummary(WsRequestName(request), nullptr, 0, total);
    record.sensor = MSMON_SENSOR_LINUX_EBPF_WINESERVER;
    record.text = L"system:" + LinuxWide(ProtoOf(request).name);
    std::wstring keys;
    for (const auto& hot : kAggregated) {
        if (hot.request != request) continue;
        /* an async_data_t's handle is the file's */
        auto name = [&](const char* field) { return std::strcmp(field, "async") == 0 ? std::wstring(L"handle") : LinuxWide(field); };
        if (hot.hi != nullptr) keys += L";" + name(hot.hi) + L"=" + Hex(key >> 32);
        if (hot.lo != nullptr) keys += L";" + name(hot.lo) + L"=" + Hex(key & 0xffffffffu);
    }
    /* ws=, as the request's own records have it (system:select also names the Linux call's summaries) */
    const std::wstring kernel = L";aggregate=kernel";
    const size_t at = record.detail.find(kernel);
    if (at != std::wstring::npos) record.detail.insert(at + kernel.size(), L";ws=" + LinuxWide(ProtoOf(request).name) + keys);
    return record;
}

unsigned WsProtocolForBuild(const std::string& build)
{
    /* Wine refuses a server of any other version, so the client's build names the protocol. */
    return build == "wine-11.0" ? kWsProtocol : 0;
}

namespace {
std::unordered_map<std::string, std::string> gBuilds;   /* ntdll.so path -> build string */
}

void WsNtdllReset() { gBuilds.clear(); }

std::string WsNtdllBuild(uint32_t pid, std::string& path)
{
    path.clear();
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line, range;
    while (std::getline(maps, line)) {
        const size_t slash = line.find('/');
        if (slash == std::string::npos || line.size() < 9 || line.compare(line.size() - 9, 9, "/ntdll.so") != 0) continue;
        path = line.substr(slash);
        range = line.substr(0, line.find(' '));
        break;
    }
    if (path.empty()) return {};
    auto cached = gBuilds.find(path);
    if (cached != gBuilds.end()) return cached->second;
    /* map_files reaches the file the process mapped even in another mount namespace (root only). */
    int fd = open(("/proc/" + std::to_string(pid) + "/map_files/" + range).c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) fd = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    std::string build;
    struct stat info {};
    constexpr off_t kMaxBytes = 64 << 20;
    if (fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_size <= kMaxBytes) {
        std::string bytes(static_cast<size_t>(info.st_size), '\0');
        size_t done = 0;
        while (done < bytes.size()) {
            const ssize_t got = read(fd, &bytes[done], bytes.size() - done);
            if (got <= 0) break;
            done += static_cast<size_t>(got);
        }
        bytes.resize(done);
        /* wine_get_build_id(): "wine-<version>" as a NUL-terminated string. */
        static const char kKnown[] = "wine-11.0";
        if (bytes.find(std::string(kKnown, sizeof(kKnown))) != std::string::npos) build = kKnown;
        else if (bytes.find("wine-") != std::string::npos) build = "wine-other";
    }
    if (fd >= 0) close(fd);
    gBuilds[path] = build;
    return build;
}

void WsDecoder::Reset()
{
    pending_.clear();
    irps_.clear();
    processes_.clear();
    winPids_.clear();
    winTids_.clear();
    inherits_.clear();
    windows_.clear();
}

std::wstring WsDecoder::KeyPath(uint32_t tgid, uint32_t handle)
{
    const auto& keys = processes_[tgid].keys;
    auto known = keys.find(handle);
    /* shortcut: keys opened before the agent watched are named by handle. */
    return known != keys.end() ? known->second : L"hkey:" + Hex(handle);
}

void WsDecoder::Target(uint32_t winPid, WsRecord& out)
{
    auto known = winPids_.find(winPid);
    if (known != winPids_.end()) out.record.target = known->second.tgid;
}

WsDecoder::Process* WsDecoder::Of(uint32_t winPid)
{
    const auto known = winPids_.find(winPid);
    if (winPid == 0 || known == winPids_.end()) return nullptr;
    const auto process = processes_.find(known->second.tgid);
    return process != processes_.end() ? &process->second : nullptr;
}

void WsDecoder::Emit(WsRecord& record, const WsSink& sink)
{
    record.record.sensor = MSMON_SENSOR_LINUX_EBPF_WINESERVER;
    /* winedevice.exe works for a driver, as BlackCat64.sys works in the kernel on Windows: its records name the
     * driver (component) and, inside an IRP, the client that sent it. */
    const auto process = processes_.find(record.request->tgid);
    if (process != processes_.end() && process->second.winedevice) {
        const auto irp = irps_.find(record.request->tid);
        LinuxRecord& out = record.record;
        if (out.component.empty()) out.component = irp != irps_.end() ? irp->second.driver : process->second.driver;
        out.flags |= MsMonFlagServiceCorrelated;
        if (out.detail.find(L"attribution=brokered_winedevice") == std::wstring::npos) {
            out.detail += std::wstring(out.detail.empty() ? L"" : L";") + L"attribution=brokered_winedevice";
            if (irp != irps_.end())
                out.detail += L";client_pid=" + Num(irp->second.clientTgid) + L";client_win_tid=" + Num(irp->second.clientWinTid);
        }
    }
    /* The first call of a kernel aggregate's key: the others of its second are in that aggregate's summary. */
    if ((record.request->flags & MM_WS_F_SAMPLED) != 0) record.record.detail += L";aggregate=sampled";
    sink(record);
}

void WsDecoder::Event(const mm_ws_event& event, const WsSink& sink)
{
    if ((event.flags & MM_WS_F_REJECTED) != 0) return Rejected(event, sink);
    if (event.kind == MM_WS_REQUEST) {
        if (event.win_pid != 0 && winPids_.insert_or_assign(event.win_pid, Unix{event.tgid, event.start_ns}).second) {
            /* A child's first request: the handles it inherited name what its parent's named (same values). */
            const auto inherited = inherits_.find(event.win_pid);
            if (inherited != inherits_.end()) {
                Process& child = processes_[event.tgid];
                child.keys.insert(inherited->second.keys.begin(), inherited->second.keys.end());
                child.files.insert(inherited->second.files.begin(), inherited->second.files.end());
                child.processes.insert(inherited->second.processes.begin(), inherited->second.processes.end());
                child.threads.insert(inherited->second.threads.begin(), inherited->second.threads.end());
                child.access.insert(inherited->second.access.begin(), inherited->second.access.end());
                inherits_.erase(inherited);
            }
        }
        if (event.win_tid != 0) winTids_[event.win_tid] = {event.tgid, event.start_ns};
        auto& slot = pending_[event.tid];
        if (slot.event) Decode(slot, nullptr, sink);   /* its reply never came (or was not read whole) */
        if (!slot.event) slot.event = std::make_unique<mm_ws_event>();
        std::memcpy(slot.event.get(), &event, offsetof(mm_ws_event, data) + std::min<uint32_t>(event.data_len, MM_WS_DATA));
        Resolve(slot);
        return;
    }
    auto found = pending_.find(event.tid);
    if (found == pending_.end() || !found->second.event || found->second.event->req != event.req) return;
    Pending request = std::move(found->second);
    pending_.erase(found);
    Decode(request, &event, sink);
}

void WsDecoder::Resolve(Pending& pending)
{
    /* At request time wineserver has not read the request yet, so a handle it closes cannot have been given
     * out again, and a handle it uses still names what it named. New handles (open_process, open_key,
     * create_key, new_process) are mapped when their reply arrives. */
    const mm_ws_event& request = *pending.event;
    const uint8_t* q = request.fixed;
    Process& process = processes_[request.tgid];
    auto pid = [&](uint32_t handle) {
        const auto known = process.processes.find(handle);
        return known != process.processes.end() ? known->second : 0;
    };
    pending.winPid = pending.peer = 0;
    pending.key.clear();
    pending.name.clear();
    pending.root.clear();
    pending.object = pending.granted = 0;
    pending.fieldTarget = 0;
    pending.fields = Fields(request, process, pending.fieldTarget);
    const Proto& proto = ProtoOf(request.req);
    const Field* collapse = proto.key >= 0 && proto.key < static_cast<int>(proto.request.size()) ? &proto.request[proto.key] : nullptr;
    pending.collapseKey = collapse == nullptr ? 0
                          : collapse->type == '8' || collapse->type == 'I' ? U64(q, collapse->offset)
                                                                           : U32(q, collapse->offset);
    auto name = [&](uint32_t handle) {
        const auto known = process.files.find(handle);
        return known != process.files.end() ? known->second : std::wstring();
    };
    /* The request's handle: a process, thread or token (object, winPid, granted), and the name of a file, key or
     * named object. */
    auto classify = [&](uint32_t handle) {
        const auto thread = process.threads.find(handle);
        const auto token = process.tokens.find(handle);
        const auto access = process.access.find(handle);
        const auto key = process.keys.find(handle);
        if (handle == kCurrentProcess || handle == kCurrentThread) {
            pending.object = handle == kCurrentProcess ? 1 : 2;
            pending.winPid = handle == kCurrentProcess ? request.win_pid : request.win_tid;
            pending.granted = kAllAccess;
            return;
        }
        if (process.processes.count(handle) != 0) {
            pending.object = 1;
            pending.winPid = process.processes[handle];
        } else if (thread != process.threads.end()) {
            pending.object = 2;
            pending.winPid = thread->second;
        } else if (token != process.tokens.end() || (handle >= 0xfffffffa && handle <= 0xfffffffc)) {
            pending.object = 3;   /* -4..-6: GetCurrentProcessToken() and the thread pseudo tokens */
            pending.winPid = token != process.tokens.end() ? token->second : request.win_pid;
        }
        if (access != process.access.end()) pending.granted = access->second;
        pending.name = key != process.keys.end() ? key->second : name(handle);
    };
    /* The objattr rootdir of a create_* request (its first vararg). */
    const uint32_t objattrRoot = std::min<uint32_t>(request.data_len, MM_WS_DATA) >= 16 ? U32(request.data, 0) : 0;
    switch (request.req) {
    case CloseHandleReq:
        process.Handed(U32(q, 12));
        break;
    case DupHandle: {
        const uint32_t source = U32(q, 12), handle = U32(q, 16);
        pending.winPid = pid(source != kCurrentProcess ? source : U32(q, 20));
        if (handle == kCurrentProcess || handle == kCurrentThread) {
            /* wineserver: a pseudo handle is the requester's own process or thread, whatever the source. */
            pending.object = handle == kCurrentProcess ? 1 : 2;
            pending.winPid = handle == kCurrentProcess ? request.win_pid : request.win_tid;
            pending.granted = kAllAccess;
        } else if (source == kCurrentProcess) {
            /* The object duplicated: one of this process's process or thread handles (the Ob callback's object). */
            const auto thread = process.threads.find(handle);
            if (process.processes.count(handle) != 0) {
                pending.object = 1;
                pending.winPid = process.processes[handle];
            } else if (thread != process.threads.end()) {
                pending.object = 2;
                pending.winPid = thread->second;   /* the Windows tid; Decode maps it to its process */
            }
            const auto access = process.access.find(handle);
            if (access != process.access.end()) pending.granted = access->second;
        }
        /* What the copy names: also a file, key or named object, also into or out of another tracked process. */
        const uint32_t destination = U32(q, 20);
        pending.peer = destination == kCurrentProcess ? 0 : pid(destination);
        if (const Process* from = source == kCurrentProcess ? &process : Of(pid(source))) {
            const auto key = from->keys.find(handle);
            const auto file = from->files.find(handle);
            if (key != from->keys.end()) pending.key = key->second;
            else if (file != from->files.end()) pending.name = file->second;
        }
        if (source == kCurrentProcess && (U32(q, 32) & 1)) process.Handed(handle);   /* DUPLICATE_CLOSE_SOURCE */
        break;
    }
    case TerminateProcess:
    case TerminateThread:
    case GetProcessInfo:
    case GetProcessDebugInfo:
    case GetProcessImageName:
    case GetProcessVmCounters:
    case SetProcessInfo:
    case GetThreadInfo:
    case GetThreadTimes:
    case SetThreadInfo:
    case SuspendThread:
    case ResumeThread:
    case QueueApc:
    case SetThreadContext:
    case SuspendProcess:
    case ResumeProcess:
    case GetMappingFilename:
    case OpenToken:
    case AdjustTokenPrivileges:
    case GetTokenPrivileges:
    case DuplicateToken:
    case FilterToken:
    case GetTokenInfo:
    case CreateLinkedToken:
    case MakeProcessSystem:
    case GrantProcessAdminToken:
    case SetSecurityObject:
    case GetSecurityObject:
    case GetDirectoryEntries:
    case QuerySymlink:
    case GetObjectName:
    case GetObjectType:
    case GetHandleUnixName:
    case SetFdDispInfo:
    case SetFdEofInfo:
    case MapView:
    case MapImageView:
        classify(U32(q, 12));
        break;
    case GetThreadContext:   /* the second call of a pending one passes the context handle the first got */
        classify(U32(q, 12) != 0 ? U32(q, 12) : U32(q, 16));
        break;
    case GetApcResult: {
        const auto apc = process.apcs.find(U32(q, 12));
        if (apc != process.apcs.end()) {
            pending.winPid = apc->second.first;
            pending.granted = apc->second.second;   /* the APC type */
        }
        break;
    }
    case SetFdNameInfo:
        classify(U32(q, 12));
        pending.root = name(U32(q, 16));
        break;
    case ReadDirectoryChanges:
        classify(U32(q, 24));   /* async.handle */
        break;
    case AssignJob:
        classify(U32(q, 16));
        pending.root = name(U32(q, 12));
        break;
    case TerminateJob:
        pending.name = name(U32(q, 12));
        break;
    case SaveRegistry:
        pending.key = KeyPath(request.tgid, U32(q, 12));
        pending.name = name(U32(q, 16));
        break;
    case SetRegistryNotification:
        pending.key = KeyPath(request.tgid, U32(q, 12));
        break;
    case UnloadRegistry:
        if (U32(q, 12) != 0) pending.key = KeyPath(request.tgid, U32(q, 12));
        break;
    case LoadRegistry:
        pending.name = name(U32(q, 12));
        if (objattrRoot != 0) pending.key = KeyPath(request.tgid, objattrRoot);
        break;
    case UnmapView: {
        const auto view = process.views.find(U64(q, 16));
        if (view != process.views.end()) pending.name = view->second;
        break;
    }
    case CreateEvent:
    case CreateKeyedEvent:
    case CreateMutex:
    case CreateSemaphore:
    case CreateTimer:
    case CreateMailslot:
    case CreateDirectory:
    case CreateSymlink:
    case CreateCompletion:
    case CreateJob:
        if (objattrRoot != 0) pending.root = name(objattrRoot);
        break;
    case OpenEvent:
    case OpenKeyedEvent:
    case OpenMutex:
    case OpenSemaphore:
    case OpenTimer:
    case OpenDirectory:
    case OpenSymlink:
    case OpenCompletion:
    case OpenJob:
    case OpenWinstation:
        pending.root = name(U32(q, 20));
        break;
    case OpenDesktop:   /* relative to its window station */
        pending.root = name(U32(q, 12));
        break;
    case Read:
    case Write:
    case Ioctl:
        pending.name = name(U32(q, 16));   /* async.handle */
        break;
    case CreateMapping:
        pending.name = name(U32(q, 32));   /* file_handle: closed right after, as the loader does */
        if (objattrRoot != 0) pending.root = name(objattrRoot);
        break;
    case OpenMapping:
        pending.root = name(U32(q, 20));
        break;
    case GetNextDeviceRequest:
        irps_.erase(request.tid);          /* it completes the IRP the thread was dispatching */
        break;
    case ReadProcessMemory:
    case WriteProcessMemory:
    case DebugProcess:
        pending.winPid = pid(U32(q, 12));
        break;
    case NewThread:
    case GetNextThread:   /* the process the thread is in */
        pending.winPid = U32(q, 12) == kCurrentProcess ? request.win_pid : pid(U32(q, 12));
        break;
    case CreateKey: {   /* the parent is the objattr rootdir */
        const uint32_t parent = std::min<uint32_t>(request.data_len, MM_WS_DATA) >= 16 ? U32(request.data, 0) : 0;
        if (parent != 0) pending.key = KeyPath(request.tgid, parent);
        break;
    }
    case OpenKey:
        if (U32(q, 12) != 0) pending.key = KeyPath(request.tgid, U32(q, 12));
        break;
    case DeleteKey:
    case DeleteKeyValue:
    case RenameKey:
    case SetKeyValue:
    case GetKeyValue:
    case EnumKey:
    case EnumKeyValue:
        pending.key = KeyPath(request.tgid, U32(q, 12));
        break;
    default:
        break;
    }
}

void WsDecoder::Forget(uint32_t tgid, const WsSink& sink)
{
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (!it->second.event || it->second.event->tgid != tgid) {
            ++it;
            continue;
        }
        Decode(it->second, nullptr, sink);
        it = pending_.erase(it);
    }
    processes_.erase(tgid);
    for (auto* map : {&winPids_, &winTids_}) {
        for (auto it = map->begin(); it != map->end();) it = it->second.tgid == tgid ? map->erase(it) : std::next(it);
    }
    for (auto it = windows_.begin(); it != windows_.end();) it = it->second.tgid == tgid ? windows_.erase(it) : std::next(it);
}

std::vector<uint32_t> WsDecoder::DropWindows(uint32_t tgid, uint32_t winTid)
{
    std::vector<uint32_t> handles;
    for (auto it = windows_.begin(); it != windows_.end();) {
        if (it->second.tgid != tgid || (winTid != 0 && it->second.winTid != winTid)) {
            ++it;
            continue;
        }
        handles.push_back(it->second.gen << 16 | it->first);
        it = windows_.erase(it);
    }
    return handles;
}

void WsDecoder::Decode(const Pending& pending, const mm_ws_event* reply, const WsSink& sink)
{
    const mm_ws_event& request = *pending.event;
    const uint8_t* q = request.fixed;
    const uint8_t* data = request.data;
    const size_t length = std::min<uint32_t>(request.data_len, MM_WS_DATA);
    const uint8_t* r = reply != nullptr ? reply->fixed : nullptr;
    const uint8_t* replyData = reply != nullptr ? reply->data : nullptr;
    const size_t replyLength = reply != nullptr ? std::min<uint32_t>(reply->data_len, MM_WS_DATA) : 0;
    const uint32_t status = r != nullptr ? U32(r, 0) : 0;
    const bool ok = r != nullptr && !Failed(status);
    const uint32_t tgid = request.tgid;
    Process& process = processes_[tgid];

    WsRecord out;
    out.request = &request;
    out.tsNs = reply != nullptr ? reply->ts_ns : request.ts_ns;
    LinuxRecord& record = out.record;
    record.status = static_cast<int32_t>(status);
    const std::wstring tail = reply != nullptr ? L"" : L";no_reply";
    std::wstring valueName;   /* the registry value a payload belongs to */
    /* wineserver answers a client buffer (reply_size, +8) smaller than the value with success, the value's
     * size and what fits; ntdll turns that into STATUS_BUFFER_OVERFLOW. A size probe (or a
     * KeyValueBasicInformation query): no payload, and not payload_truncated. */
    const bool probe = ok && (request.req == GetKeyValue || request.req == EnumKeyValue) && U32(q, 8) < U32(r, 12);
    const std::wstring buffer = probe ? L";buffer=" + Num(U32(q, 8)) : L"";
    /* wineserver gives out the lowest free handle: a handle closed or given out again no longer names
     * the key or process it named before (unknown beats a wrong target). */
    auto handed = [&](uint32_t handle) { process.Handed(handle); };

    /* Payload of a registry value or volume information (as MsMonLogRegistryValue / MsMonRegistryUnavailable
     * on Windows): Captured bytes of a value of Total bytes. */
    auto payload = [&](ULONG kind, uint64_t total, const uint8_t* bytes, size_t captured, const wchar_t* failure) {
        if (!payloads_ || r == nullptr) return;
        auto unavailable = [&](const wchar_t* reason) {
            record.flags |= MsMonFlagPayloadUnavailable;
            record.detail = std::wstring(reason) + L";value=" + valueName;
        };
        if (Failed(status)) {
            if (failure != nullptr) unavailable(failure);
            return;
        }
        if (total > MSMON_MAX_PAYLOAD_TOTAL_BYTES) return unavailable(L"payload_too_large");
        /* shortcut: values longer than about 8 KiB minus the name are payload_truncated for set_key_value
         * and enum_key_value (one MM_WS_DATA chunk is captured); upgrade by capturing more. */
        if (captured >= total) {
            out.bytes.assign(bytes, bytes + total);
        } else if (captured >= MSMON_PAYLOAD_CHUNK_BYTES) {
            out.bytes.assign(bytes, bytes + MSMON_PAYLOAD_CHUNK_BYTES);   /* chunk 0 of N: a partial series */
        } else {
            return unavailable(L"payload_truncated");
        }
        out.payload = true;
        out.payloadKind = kind;
        out.payloadTotal = total;
    };

    /* Bytes a pipe, device or RPC call moved (an ipc_data payload): all of them, or the first 8-KiB chunk of more. */
    auto ipc = [&](const uint8_t* bytes, size_t captured, uint64_t total) {
        if (!payloads_ || total == 0 || total > MSMON_MAX_PAYLOAD_TOTAL_BYTES ||
            (captured < total && captured < MSMON_PAYLOAD_CHUNK_BYTES))
            return;
        out.bytes.assign(bytes, bytes + std::min<uint64_t>({captured, total, MSMON_PAYLOAD_CHUNK_BYTES}));
        out.payload = true;
        out.payloadKind = MsMonPayloadIpcData;
        out.payloadTotal = total;
    };
    const std::wstring requestName = LinuxWide(WsRequestName(request.req) + std::strlen("wineserver:"));
    /* Every request a case below does not record (no case, or its own-process, unnamed or bookkeeping branch):
     * file_query_information system:<request> with the table's fields (Fields, ReplyFields), collapsed per its
     * collapse field. Forget: the reply's handles were not mapped by a case (they no longer name anything known). */
    auto generic = [&](bool forget = false) {
        LinuxRecord fresh;
        fresh.status = record.status;
        record = fresh;
        out.payload = false;
        out.bytes.clear();
        record.type = MsMonFileQueryInformation;
        record.text = L"system:" + requestName;
        record.value0 = request.req;
        record.target = pending.fieldTarget;
        record.detail = L"ws=" + requestName + (request.req >= Protocol().size() ? L";req=" + Num(request.req) : L"") +
                        pending.fields + ReplyFields(request, reply, process, forget) + tail;
        out.collapse = true;
        out.repeatKey = pending.collapseKey;
        Emit(out, sink);
    };

    switch (request.req) {
    case CloseHandleReq:   /* applied by Resolve when it was sent, which named it */
        return generic();
    case NewProcess: {   /* reply: info handle +8, Windows pid +12, process handle +16 */
        if (ok) {
            handed(U32(r, 8));
            handed(U32(r, 16));
            process.processes[U32(r, 16)] = U32(r, 12);
        }
        /* As the creator's handle to its child on Windows (process create notify: CommandLine, CreatingThreadId):
         * request token +12, debug +16, parent_process +20, flags +24, access +32, info_size +40,
         * handles_size +44, jobs_size +48; data objattr, handles, jobs, startup_info (96 bytes: 16 u32, then the
         * lengths of curdir, dllpath, imagepath, cmdline, title, desktop, ...), then the environment. */
        record.type = MsMonProcessHandle;
        record.desiredAccess = U32(q, 32);
        record.value0 = 1;
        record.value1 = ok ? record.desiredAccess : 0;
        uint32_t rootdir = 0;
        std::wstring ignored;
        const size_t attributes = ObjectAttributes(data, length, rootdir, ignored);
        size_t at = attributes + U32(q, 44) + U32(q, 48);
        if (ok && (U32(q, 24) & kInheritHandles) != 0) {
            /* The child inherits handles at the same values (all inheritable ones, or those of a handle list), so it
             * starts with this process's names for them. shortcut: OBJ_INHERIT is not tracked, so every named handle
             * is taken for inheritable; the child's own handles replace them as they are given out (not one from a
             * request this decoder does not capture: track OBJ_INHERIT if that matters). */
            const size_t list = std::min<size_t>(U32(q, 44), length > attributes ? length - attributes : 0) / 4;
            auto inherited = [&](uint32_t handle) {
                if (handle == U32(r, 8) || handle == U32(r, 16)) return false;   /* this reply's own handles */
                for (size_t index = 0; index < list; index++)
                    if (U32(data, attributes + 4 * index) == handle) return true;
                return list == 0;
            };
            if (inherits_.size() >= 64) inherits_.erase(inherits_.begin());   /* children never tracked */
            Process& child = inherits_[U32(r, 12)];
            for (const auto& [handle, path] : process.keys) if (inherited(handle)) child.keys[handle] = path;
            for (const auto& [handle, path] : process.files) if (inherited(handle)) child.files[handle] = path;
            for (const auto& [handle, id] : process.processes) if (inherited(handle)) child.processes[handle] = id;
            for (const auto& [handle, id] : process.threads) if (inherited(handle)) child.threads[handle] = id;
            for (const auto& [handle, access] : process.access) if (inherited(handle)) child.access[handle] = access;
        }
        const uint32_t parent = U32(q, 20);
        record.detail = L"new_process;win_pid=" + (ok ? Num(U32(r, 12)) : L"0") + L";process_flags=" + Hex(U32(q, 24)) +
                        (parent != 0 ? L";parent_override=" + (process.processes.count(parent) ? Num(process.processes[parent])
                                                                                              : L"handle:" + Hex(parent))
                                     : L"") +
                        (U32(q, 16) != 0 ? L";debug=1" : L"") + (U32(q, 12) != 0 ? L";token=1" : L"");
        record.detail += tail;
        if (at + 96 <= length) {
            const uint8_t* info = data + at;
            std::wstring strings[6];   /* curdir, dllpath, imagepath, cmdline, title, desktop */
            at += 96;
            for (int index = 0; index < 6; index++) {
                const size_t bytes = std::min<size_t>(U32(info, 64 + 4 * index), at < length ? length - at : 0);
                strings[index] = Utf16(data + at, bytes);
                at += U32(info, 64 + 4 * index);
            }
            /* The command line last: it may hold ';' (redact_session.py cuts the detail there). */
            record.detail += L";win_image=" + strings[2] + L";curdir=" + strings[0] + L";desktop=" + strings[5] +
                             (at > length ? L";truncated" : L"") + L";win_cmdline=" + strings[3];
        }
        break;
    }
    case OpenKey:
    case CreateKey: {
        std::wstring path;
        uint32_t parent = 0;
        if (request.req == OpenKey) {
            parent = U32(q, 12);
            path = Utf16(data, length);
            record.desiredAccess = U32(q, 16);
        } else {
            ObjectAttributes(data, length, parent, path);
            record.desiredAccess = U32(q, 12);
            record.value0 = U32(q, 16);   /* create options */
        }
        /* parent 0: an absolute name (\Registry\Machine\...). */
        if (parent != 0) path = path.empty() ? pending.key : pending.key + L"\\" + path;
        if (ok) {
            handed(U32(r, 8));
            process.keys[U32(r, 8)] = path;
        }
        record.type = request.req == OpenKey ? MsMonRegistryOpen : MsMonRegistryCreate;
        record.text = path;
        record.detail = tail.empty() ? L"" : tail.substr(1);
        out.collapse = request.req == OpenKey;
        out.repeatKey = record.desiredAccess;
        /* Wine's WMI runs in-process (wbemprox), so ETW WMI-Activity has no Linux source: the COM activation
         * (the CLSID key CoCreateInstance reads) is the visible WMI use. The WQL text is not. */
        if (const wchar_t* wmi = request.req == OpenKey ? WmiClass(path) : nullptr) {
            WsRecord activation;
            activation.request = &request;
            activation.tsNs = out.tsNs;
            activation.collapse = true;
            activation.repeatKey = std::hash<std::wstring>()(wmi);
            activation.record.type = MsMonEtwWmi;
            activation.record.status = record.status;
            activation.record.text = L"com:" + std::wstring(wmi);
            activation.record.detail = L"operation=com_activation;clsid=" + path.substr(path.size() - 38) +
                                       L";source=registry;query=unavailable" + tail;
            Emit(activation, sink);
        }
        break;
    }
    case DeleteKey:
        record.type = MsMonRegistryDelete;
        record.text = pending.key;
        record.detail = tail.empty() ? L"" : tail.substr(1);
        break;
    case DeleteKeyValue:
    case RenameKey:
        record.type = request.req == RenameKey ? MsMonRegistryRename : MsMonRegistryDelete;
        record.text = pending.key;
        record.detail = Utf16(data, length) + tail;
        break;
    case SetKeyValue: {
        const uint32_t nameBytes = std::min<uint32_t>(U32(q, 20), static_cast<uint32_t>(length));
        const uint64_t total = request.total >= U32(q, 20) ? request.total - U32(q, 20) : 0;
        record.type = MsMonRegistrySetValue;
        record.text = pending.key;
        valueName = Utf16(data, nameBytes);
        record.detail = valueName + tail;
        record.value0 = total;
        record.value1 = U32(q, 16);
        record.flags |= MsMonFlagPayloadInput;
        payload(MsMonPayloadRegistryValue, total, data + nameBytes, length - nameBytes, nullptr);
        if (!out.payload && (record.flags & MsMonFlagPayloadUnavailable) == 0) record.flags &= ~MsMonFlagPayloadInput;
        break;
    }
    case GetKeyValue:
        record.type = MsMonRegistryQuery;
        record.text = pending.key;
        valueName = Utf16(data, length);
        record.detail = valueName + tail + buffer;
        /* value0: the information class is applied by ntdll, wineserver never sees it (0). */
        if (r != nullptr) {
            record.value1 = U32(r, 8);
            if (!probe) payload(MsMonPayloadRegistryValue, U32(r, 12), replyData, replyLength, L"query_failed");
        }
        out.collapse = true;
        /* The value bytes and the probe bit are in the key: the read after a size probe, or a changed
         * value, is never counted as a repeat. */
        out.repeatKey = std::hash<std::wstring>()(valueName) ^
                        (std::hash<std::string_view>()(std::string_view(reinterpret_cast<const char*>(out.bytes.data()),
                                                                        out.bytes.size())) << 1) ^
                        (probe ? 1 : 0);
        break;
    case EnumKey:
    case EnumKeyValue:
        record.type = MsMonRegistryEnumerate;
        record.text = pending.key;
        record.value0 = U32(q, 16);   /* index */
        record.value1 = U32(q, 20);   /* information class */
        if (ok && request.req == EnumKey) {
            valueName = Utf16(replyData, std::min<size_t>(U32(r, 44), replyLength));
        } else if (ok) {
            const uint32_t nameBytes = std::min<uint32_t>(U32(r, 16), static_cast<uint32_t>(replyLength));
            const uint32_t infoClass = U32(q, 20);   /* 0 basic (name), 1 full (name + data), 2 partial (data) */
            valueName = Utf16(replyData, nameBytes);
            record.value1 = U32(r, 8);   /* value type */
            if ((infoClass == 1 || infoClass == 2) && !probe) {
                const uint64_t total = infoClass == 1 && U32(r, 12) >= nameBytes ? U32(r, 12) - nameBytes : U32(r, 12);
                payload(MsMonPayloadRegistryValue, total, replyData + nameBytes, replyLength - nameBytes, nullptr);
            }
        }
        if ((record.flags & MsMonFlagPayloadUnavailable) == 0) record.detail = valueName + tail + buffer;
        break;
    case OpenProcess:
    case OpenThread: {
        const uint32_t id = U32(q, 12);
        record.type = request.req == OpenProcess ? MsMonProcessHandle : MsMonThreadHandle;
        record.desiredAccess = U32(q, 16);
        record.value0 = 1;   /* a handle create, as OB_OPERATION_HANDLE_CREATE */
        /* GrantedAccess: wineserver grants what was asked (no Ob callback strips rights) or fails. */
        record.value1 = ok ? record.desiredAccess : 0;
        if (ok) {
            handed(U32(r, 8));
            (request.req == OpenProcess ? process.processes : process.threads)[U32(r, 8)] = id;
            process.access[U32(r, 8)] = record.desiredAccess;
        }
        if (request.req == OpenProcess) {
            Target(id, out);
        } else {
            auto known = winTids_.find(id);
            if (known != winTids_.end()) record.target = known->second.tgid;
        }
        /* As MsMonObjectPre: a handle to the caller's own process is not an outside access. */
        if (request.req == OpenProcess ? id == request.win_pid : record.target == tgid) return generic();
        record.detail = (request.req == OpenProcess ? L"open_process;win_pid=" : L"open_thread;win_tid=") + Num(id) +
                        (ok ? L";handle=" + Hex(U32(r, 8)) : L"") + tail;
        out.collapse = true;
        out.repeatKey = (static_cast<uint64_t>(record.desiredAccess) << 32) | id;   /* a stronger open is logged */
        break;
    }
    case ReadProcessMemory:
    case WriteProcessMemory: {
        const uint32_t handle = U32(q, 12);
        const uint32_t winPid = handle == kCurrentProcess ? request.win_pid : pending.winPid;
        record.type = MsMonProcessHandle;
        record.value0 = request.req == ReadProcessMemory ? 1 : 2;
        record.value1 = request.req == ReadProcessMemory ? U32(q, 8) : request.total;   /* bytes asked for */
        Target(winPid, out);
        record.detail = std::wstring(request.req == ReadProcessMemory ? L"read_process_memory" : L"write_process_memory") +
                        L";handle=" + Hex(handle) + (winPid ? L";win_pid=" + Num(winPid) : L"") +
                        L";address=" + Hex(U64(q, 16)) + tail;
        /* Collapsed only when the same range is read again: each address another process reads keeps its record. */
        out.collapse = true;
        out.repeatKey = std::hash<std::string_view>()(std::string_view(reinterpret_cast<const char*>(q + 8), 16));
        break;
    }
    case DupHandle: {
        const uint32_t source = U32(q, 12), destination = U32(q, 20);
        /* As the Ob duplicate callback: desired_access, value0 2, value1 the granted access, the target the
         * process the duplicated process / thread object is (else the process the handle moves from or to). */
        const uint32_t options = U32(q, 32);
        record.type = pending.object == 2 ? MsMonThreadHandle : MsMonProcessHandle;
        record.desiredAccess = U32(q, 24);
        record.value0 = 2;   /* a duplicate, as OB_OPERATION_HANDLE_DUPLICATE */
        record.value1 = !ok ? 0 : (options & kDuplicateSameAccess) ? pending.granted : record.desiredAccess;
        /* The copy names what the source named (get_next_thread and later copies resolve it), also in another tracked
         * process it is duplicated into (a file or pipe handed to a child or a broker). */
        Process* to = destination == kCurrentProcess ? &process : Of(pending.peer);
        if (ok && to != nullptr) {
            to->Handed(U32(r, 8));
            if (pending.object != 0) {
                (pending.object == 1 ? to->processes : to->threads)[U32(r, 8)] = pending.winPid;
                to->access[U32(r, 8)] = record.value1;
            } else if (!pending.key.empty()) {
                to->keys[U32(r, 8)] = pending.key;   /* crypt32 duplicates its certificate store keys */
            } else if (!pending.name.empty()) {
                to->files[U32(r, 8)] = pending.name;
            }
        }
        bool self;
        if (pending.object == 2) {
            const auto known = winTids_.find(pending.winPid);
            if (known != winTids_.end()) record.target = known->second.tgid;
            self = pending.winPid == request.win_tid || record.target == tgid;
        } else {
            Target(pending.winPid, out);
            self = pending.object == 0 || pending.winPid == request.win_pid;
        }
        /* Within the process, as MsMonObjectPre: only a copy of another process's or thread's handle. */
        if (source == kCurrentProcess && destination == kCurrentProcess && self) return generic();
        record.detail = L"dup_handle;object=" +
                        std::wstring(pending.object == 1 ? L"process" : pending.object == 2 ? L"thread" : L"unknown") +
                        L";src_process=" + Hex(source) + L";src_handle=" + Hex(U32(q, 16)) +
                        L";dst_process=" + Hex(destination) + L";options=" + Hex(options) +
                        (pending.winPid ? (pending.object == 2 ? L";win_tid=" : L";win_pid=") + Num(pending.winPid) : L"") +
                        tail;
        break;
    }
    case DebugProcess: {
        record.type = MsMonProcessHandle;
        record.value1 = U32(q, 20);   /* attach */
        Target(pending.winPid, out);
        record.detail = L"debug_process;handle=" + Hex(U32(q, 12)) + L";attach=" + Num(U32(q, 20)) + tail;
        break;
    }
    case GetNextProcess:
        if (ok) handed(U32(r, 8));   /* its Windows pid is not in the reply */
        record.type = MsMonProcessHandle;
        record.desiredAccess = U32(q, 16);
        record.value0 = 1;
        record.detail = L"get_next_process;last=" + Hex(U32(q, 12)) + (ok ? L";handle=" + Hex(U32(r, 8)) : L"") + tail;
        out.collapse = true;
        break;
    case NewThread:
    case GetNextThread: {
        /* A thread handle create, as the Ob callback: new_thread (process +12, access +16; reply tid +8, handle
         * +12), get_next_thread (process +12, last +16, access +20; reply handle +8). kfilter decides both. */
        const bool created = request.req == NewThread;
        const uint32_t processHandle = U32(q, 12), handle = ok ? U32(r, created ? 12 : 8) : 0;
        const bool self = processHandle == kCurrentProcess || (pending.winPid != 0 && pending.winPid == request.win_pid);
        record.type = MsMonThreadHandle;
        record.desiredAccess = U32(q, created ? 16 : 20);
        record.value0 = 1;
        record.value1 = ok ? record.desiredAccess : 0;
        if (self) record.target = tgid;
        else Target(pending.winPid, out);
        if (ok) {
            handed(handle);
            process.access[handle] = record.desiredAccess;
            /* get_next_thread's reply names no tid: 0 until a get_thread_info reply names it. shortcut: a copy made
             * before that keeps no target; learn copies too if that matters. */
            if (created || !self) process.threads[handle] = created ? U32(r, 8) : 0;
            const auto owner = winPids_.find(pending.winPid);
            if (created && self) winTids_[U32(r, 8)] = {tgid, request.start_ns};
            else if (created && owner != winPids_.end()) winTids_[U32(r, 8)] = owner->second;
        }
        if (self) return generic();   /* As MsMonObjectPre: a thread of the caller's own process. */
        record.detail = std::wstring(created ? L"new_thread" : L"get_next_thread") + L";process=" + Hex(processHandle) +
                        (pending.winPid ? L";win_pid=" + Num(pending.winPid) : L"") +
                        (created ? (ok ? L";win_tid=" + Num(U32(r, 8)) : L"") : L";last=" + Hex(U32(q, 16))) +
                        (ok ? L";handle=" + Hex(handle) : L"") + tail;
        out.collapse = !created;
        out.repeatKey = (static_cast<uint64_t>(record.desiredAccess) << 32) | pending.winPid;
        break;
    }
    case CreateFile: {
        uint32_t root = 0;
        std::wstring nt;
        const size_t used = ObjectAttributes(data, length, root, nt);
        const std::string unixPath(reinterpret_cast<const char*>(data) + used, length - used);
        record.type = MsMonFileCreate;
        record.text = !unixPath.empty() ? LinuxWide(unixPath) : nt;
        record.desiredAccess = U32(q, 12);
        record.value0 = (static_cast<uint64_t>(U32(q, 20)) << 24) | U32(q, 24);   /* disposition << 24 | options */
        record.value1 = ok ? U32(r, 8) : 0;   /* the handle */
        if (record.text.empty()) record.flags |= MsMonFlagMissingPath;
        if (request.total > length) record.flags |= MsMonFlagTruncatedPath;
        record.detail = L"create_file;nt=" + nt + L";sharing=" + Hex(U32(q, 16)) + L";attrs=" + Hex(U32(q, 28)) + tail;
        if (ok) {
            handed(U32(r, 8));
            process.files[U32(r, 8)] = nt;
        }
        out.collapse = true;
        out.repeatKey = record.value0;
        break;
    }
    case OpenFileObject: {
        const uint32_t root = U32(q, 20);
        record.type = MsMonFileCreate;
        record.text = (root ? L"handle:" + Hex(root) + L"\\" : L"") + Utf16(data, length);
        record.desiredAccess = U32(q, 12);
        record.value0 = U32(q, 28);
        record.value1 = ok ? U32(r, 8) : 0;
        record.detail = L"open_file_object;rootdir=" + Hex(root) + L";sharing=" + Hex(U32(q, 24)) + tail;
        if (ok) {
            handed(U32(r, 8));
            process.files[U32(r, 8)] = record.text;   /* \??\pipe\..., \Device\...: read/write and RPC name it */
        }
        out.collapse = true;
        out.repeatKey = record.value0;
        break;
    }
    case CreateNamedPipe: {
        uint32_t root = 0;
        std::wstring name;
        ObjectAttributes(data, length, root, name);
        record.type = MsMonFileCreate;
        record.text = name;
        record.desiredAccess = U32(q, 12);
        record.value0 = (static_cast<uint64_t>(U32(q, 24)) << 24) | U32(q, 16);
        record.value1 = ok ? U32(r, 8) : 0;
        if (name.empty()) record.flags |= MsMonFlagMissingPath;
        record.detail = L"create_named_pipe;rootdir=" + Hex(root) + L";sharing=" + Hex(U32(q, 20)) +
                        L";max_instances=" + Num(U32(q, 28)) + tail;
        if (ok) {
            handed(U32(r, 8));
            process.files[U32(r, 8)] = name;
        }
        break;
    }
    case CreateMapping:
    case OpenMapping: {
        uint32_t root = 0;
        std::wstring name;
        if (request.req == CreateMapping) {
            ObjectAttributes(data, length, root, name);
            if (name.empty() && (U32(q, 16) & kSecImage) != 0 && process.winedevice && pending.name.size() > 4 &&
                Lower(pending.name.substr(pending.name.size() - 4)) == L".sys") {
                /* A driver image winedevice.exe maps to load (ntoskrnl ZwLoadDriver): Linux has no WDAC, so the
                 * CodeIntegrity record says which .sys was loaded and that nothing decided it. */
                if (ok) process.driver = BaseName(pending.name);
                record.type = MsMonEtwCodeIntegrity;
                record.text = pending.name;
                record.detail = L"decision=not_enforced;driver_load;driver=" + BaseName(pending.name) +
                                L";file_handle=" + Hex(U32(q, 32)) + tail;
                out.collapse = true;   /* a fake .sys in the prefix is mapped first, then the builtin */
                out.repeatKey = std::hash<std::wstring>()(pending.name);
                break;
            }
            if (name.empty()) {   /* an unnamed section: not shared by name; its views name its file */
                if (ok) handed(U32(r, 8));
                if (ok && !pending.name.empty()) process.files[U32(r, 8)] = pending.name;
                return generic();
            }
            record.value0 = U32(q, 16);   /* SEC_* flags */
            /* +20 is file_access (FILE_READ_DATA [| FILE_WRITE_DATA]) ntdll derives from the page
             * protection, not the protection itself: detail only, value1 stays 0. */
            record.detail = L"create_mapping;size=" + Num(U64(q, 24)) + L";file_handle=" + Hex(U32(q, 32)) +
                            L";file_access=" + Hex(U32(q, 20));
        } else {
            root = U32(q, 20);
            name = Utf16(data, length);
            record.detail = L"open_mapping";
        }
        record.type = MsMonFileSection;
        record.text = (root ? (pending.root.empty() ? L"handle:" + Hex(root) : pending.root) + L"\\" : L"") + name;
        record.desiredAccess = U32(q, 12);
        record.detail += L";rootdir=" + Hex(root) + tail;
        if (ok) {
            handed(U32(r, 8));
            process.files[U32(r, 8)] = record.text;   /* its views name it */
        }
        break;
    }
    case Read:
    case Write: {
        /* Named pipes, mailslots and device files have no unix fd under Wine: wineserver moves their bytes, so
         * this is where the minifilter's NPFS read/write records come from. RPC rides on these pipes. */
        const uint32_t handle = U32(q, 16);
        const bool read = request.req == Read;
        record.type = read ? MsMonFileRead : MsMonFileWrite;
        record.text = !pending.name.empty() ? pending.name : L"handle:" + Hex(handle);
        record.value0 = read ? (reply != nullptr ? reply->total : 0) : request.total;   /* bytes moved */
        record.value1 = U64(q, 56);   /* pos */
        record.detail = std::wstring(read ? L"read" : L"write") + L";ws=" + (read ? L"read" : L"write") + L";handle=" +
                        Hex(handle) + (status == kStatusPending && r != nullptr ? L";pending" : L"") + tail;
        out.collapse = true;
        out.repeatKey = handle;
        if (read ? ok && replyLength != 0 : length != 0)
            Rpc(pending, read ? replyData : data, read ? replyLength : length, read ? L"read" : L"write", sink);
        /* The bytes the minifilter never had. shortcut: only a written record carries them (a collapsed repeat's are
         * dropped); exempt pipe records from collapsing if every message matters. */
        if (read ? ok : true) ipc(read ? replyData : data, read ? replyLength : length, record.value0);
        if (out.payload && !read) record.flags |= MsMonFlagPayloadInput;   /* bytes the client sent, as a socket send */
        break;
    }
    case CreateDeviceManager:
        if (ok) process.winedevice = true;
        return generic();
    case CreateDevice: {
        /* IoCreateDevice in a driver's DriverEntry: rootdir +12, DEVICE_OBJECT +16, manager +24, the name. */
        const std::wstring name = (U32(q, 12) ? L"handle:" + Hex(U32(q, 12)) + L"\\" : L"") + Utf16(data, length);
        if (ok) process.devices[U64(q, 16)] = {name, process.driver};
        record.type = MsMonFileCreate;
        record.text = name;
        record.value0 = U64(q, 16);
        record.detail = L"create_device;driver=" + process.driver + tail;
        break;
    }
    case SetKernelObjectPtr: {
        /* ntoskrnl's dispatch_create gives the create IRP's file handle its FILE_OBJECT. */
        const auto create = process.creates.find(U32(q, 16));
        if (ok && create != process.creates.end()) process.fileObjects[U64(q, 24)] = create->second;
        if (create != process.creates.end()) process.creates.erase(create);
        return generic();
    }
    case GetNextDeviceRequest:
        /* The previous IRP's result when it travels with this call (prev +16, pending +32, iosb_status +36, result
         * +40, its output as the data); else set_irp_result brings it. */
        if (U32(q, 16) != 0 && U32(q, 32) == 0) IrpResult(request, U32(q, 16), U32(q, 36), U32(q, 40), data, length, request.total, sink);
        if (!ok || U32(r, 8) == 0 || U32(r, 8) > 7) return generic();   /* none, free, cancel: no IRP record */
        DeviceRequest(pending, *reply, sink);
        return;
    case GetVolumeInfo:
        record.type = MsMonFileQueryVolumeInformation;
        record.text = L"handle:" + Hex(U32(q, 12));
        record.value0 = U32(q, 56);   /* FS_INFORMATION_CLASS */
        record.detail = L"get_volume_info" + tail;
        valueName = L"get_volume_info";
        if (reply != nullptr) payload(MsMonPayloadVolumeInformation, reply->total, replyData, replyLength, nullptr);
        break;
    case ListProcesses:
    case GetSystemHandles:
    case GetWindowList:
    case GetWindowTree:
    case GetWindowText:
    case GetTcpConnections:
    case GetUdpEndpoints: {
        /* Enumerations, as the eBPF sensor's system:<call> records: value0 the request, value1 the count
         * (get_window_text: the text length; get_window_tree: 0, it returns no count). */
        const char* name = WsRequestName(request.req) + std::strlen("wineserver:");
        record.type = MsMonFileQueryInformation;
        record.text = L"system:" + LinuxWide(name);
        record.value0 = request.req;
        record.detail = L"ws=" + LinuxWide(name);
        if (request.req == GetWindowList || request.req == GetWindowTree || request.req == GetWindowText) {
            out.repeatKey = U32(q, request.req == GetWindowList ? 16 : 12);
            record.detail += L";handle=" + Hex(out.repeatKey);
        }
        if (ok) {
            if (request.req == GetWindowTree) record.detail += L";parent=" + Hex(U32(r, 8));   /* +8 is parent, not a count */
            else record.value1 = U32(r, request.req == ListProcesses ? 12 : 8);
            /* Another application's window title is content: only with payloads on. */
            if (request.req == GetWindowText)
                record.detail += payloads_ ? L";text=" + Utf16(replyData, replyLength) : L";text_bytes=" + Num(replyLength);
        }
        record.detail += tail;
        out.collapse = true;
        break;
    }
    case Ioctl: {
        /* AFD socket ioctls (ws2_32 -> ntdll unix/socket.c -> server/sock.c): the request that makes
         * wineserver bind/listen/connect/accept for the client. async.handle (+16) is the socket. */
        const uint32_t code = U32(q, 12), socket = U32(q, 16);
        unsigned family = 0;
        uint16_t port = 0;
        std::wstring what;
        record.type = MsMonNetworkAccept;
        if (code == kAfdConnect) {
            record.type = MsMonNetworkConnect;
            if (length >= 8) record.text = Endpoint(data + 8, std::min<size_t>(U32(data, 0), length - 8), family, port);
            what = L"connect;family=" + Num(family) + L";ws=ioctl;afd=connect;synchronous=" +
                   Num(length >= 8 ? U32(data, 4) : 0);
        } else if (code == kAfdBind) {
            if (length >= 4) record.text = Endpoint(data + 4, length - 4, family, port);
            what = L"bind;family=" + Num(family) + L";ws=ioctl;afd=bind";
        } else if (code == kAfdListen) {
            port = length >= 8 ? static_cast<uint16_t>(U32(data, 4)) : 0;   /* backlog */
            what = L"listen;ws=ioctl;afd=listen;backlog=" + Num(port);
        } else if (code == kAfdAccept || code == kAfdAcceptInto) {
            what = L"accept;ws=ioctl;afd=accept";
            if (code == kAfdAcceptInto && length >= 4) what += L";accept_handle=" + Hex(U32(data, 0));
        } else if (code == kPipeTransceive) {
            /* TransactNamedPipe: the write half carries an RPC request as a pipe write does. */
            record.type = MsMonFileSystemControl;
            record.text = !pending.name.empty() ? pending.name : L"handle:" + Hex(socket);
            record.value0 = code;
            record.value1 = request.total;   /* InputBufferLength, as the minifilter's FSCTL record */
            record.detail = L"fsctl_pipe_transceive;ws=ioctl;handle=" + Hex(socket) + tail;
            Rpc(pending, data, length, L"transceive", sink);
            break;
        } else {
            /* Any other DeviceIoControl / NtFsControlFile (most are kernel aggregates per handle and code, the first
             * of a second captured): the minifilter's device control on the handle's file, value0 the code, value1
             * the input bytes, with what a synchronous answer gave back (an asynchronous one: get_async_result). */
            record.type = MsMonFileDeviceControl;
            record.text = !pending.name.empty() ? pending.name : L"handle:" + Hex(socket);
            record.value0 = code;
            record.value1 = request.total;
            record.detail = L"ioctl;ws=ioctl;handle=" + Hex(socket) + L";code=" + Hex(code) + L";out_size=" + Num(U32(q, 8)) +
                            (status == kStatusPending && r != nullptr ? L";pending" : L"") +
                            (ok && reply->total != 0 ? Result(out, replyData, replyLength, reply->total) : L"") + tail;
            out.collapse = true;
            out.repeatKey = (static_cast<uint64_t>(socket) << 32) | code;
            break;
        }
        record.value1 = port;   /* value0 0: the flow is the syscall record's (wineserver's) */
        if (record.text.empty() && code != kAfdListen && code != kAfdAccept && code != kAfdAcceptInto)
            record.flags |= MsMonFlagMissingPath;
        /* A pending connect completes through an APC_ASYNC_IO in a select reply (no get_async_result:
         * it has no output data), so the record carries the ioctl's status; netattr's
         * network_flow_established gives the outcome. */
        record.detail = what + L";socket=" + Hex(socket) + L";ioctl=" + Hex(code) +
                        (status == kStatusPending && r != nullptr ? L";pending" : L"") + tail;
        break;
    }
    /* Another process's or thread's control and queries (msmon-gaps 5): process_handle / thread_handle with the target
     * from the handle table, value0 the request, desired_access the handle's access, detail
     * "<request>;handle=..;win_pid=|win_tid=..;...". As the Ob callbacks, the caller's own process and threads write
     * nothing, except debug-register context, hide-from-debugger and APC/context requests that cross processes. */
    case TerminateProcess:
    case TerminateThread:
    case GetProcessInfo:
    case GetProcessDebugInfo:
    case GetProcessImageName:
    case GetProcessVmCounters:
    case SetProcessInfo:
    case GetThreadInfo:
    case GetThreadTimes:
    case SetThreadInfo:
    case SuspendThread:
    case ResumeThread:
    case SuspendProcess:
    case ResumeProcess:
    case GetThreadContext:
    case SetThreadContext:
    case QueueApc:
    case GetMappingFilename: {
        const uint32_t handle = U32(q, 12);
        uint32_t apc = 0;
        bool always = false;
        std::wstring extra;
        uint32_t object = pending.object, winPid = pending.winPid;   /* possibly learned from the reply */
        switch (request.req) {
        case GetProcessInfo:   /* a get_next_process/get_next_thread handle (or one from before tracking) learns its id */
        case GetThreadInfo:
            if (ok && handle != 0 && (pending.object == 0 || (pending.object == 2 && pending.winPid == 0))) {
                object = request.req == GetProcessInfo ? 1 : 2;
                winPid = U32(r, request.req == GetProcessInfo ? 8 : 12);
                (object == 1 ? process.processes : process.threads)[handle] = winPid;
                const auto owner = winPids_.find(U32(r, 8));   /* get_thread_info: the thread's process */
                if (object == 2 && owner != winPids_.end()) winTids_[winPid] = owner->second;
            }
            break;
        case GetProcessImageName:
            if (handle == 0) {   /* by Windows pid (SystemProcessIdInformation) */
                object = 1;
                winPid = U32(q, 16);
            }
            if (ok) extra = L";image=" + Utf16(replyData, std::min<size_t>(U32(r, 8), replyLength));
            break;
        case SetProcessInfo:
            extra = L";mask=" + Hex(U32(q, 40)) + L";priority=" + Num(U32(q, 24)) + L";affinity=" + Hex(U64(q, 16));
            break;
        case SetThreadInfo:
            always = (U32(q, 48) & kHideFromDebugger) != 0;
            extra = L";mask=" + Hex(U32(q, 48)) + (always ? L";hide_from_debugger=1" : L"") + L";entry=" + Hex(U64(q, 32)) +
                    L";affinity=" + Hex(U64(q, 24));
            break;
        case TerminateProcess:
        case TerminateThread:
            if (handle == 0) return generic();   /* NtTerminateProcess(0): the caller's other threads, as it exits */
            extra = L";exit_code=" + Hex(U32(q, 16));
            break;
        case SuspendThread:
        case ResumeThread:
            if (ok) extra = L";count=" + Num(U32(r, 8));
            break;
        case GetThreadContext:
            if (status == kStatusPending && r != nullptr) {
                /* The thread is not stopped yet: the client waits on the reply's handle and asks again with it. */
                handed(U32(r, 12));
                if (pending.object == 2) process.threads[U32(r, 12)] = pending.winPid;
                return generic();
            }
            if (handle == 0) handed(U32(q, 16));   /* wineserver closes the context handle */
            always = (U32(q, 20) & kCtxDebugRegisters) != 0;
            extra = L";flags=" + Hex(U32(q, 20)) + (ok ? DebugRegisters(replyData, replyLength) : L"") +
                    (r != nullptr && U32(r, 8) ? L";self=1" : L"");
            break;
        case SetThreadContext:
            extra = DebugRegisters(data, length);
            always = !extra.empty();
            extra = L";native_flags=" + Hex(U32(q, 16)) + extra;
            break;
        case QueueApc:
            extra = ApcCall(data, length, apc);
            if (ok && apc > 1) process.apcs[U32(r, 8)] = {pending.winPid, apc};   /* get_apc_result's handle */
            break;
        default:   /* GetMappingFilename: GetMappedFileName / NtQueryVirtualMemory on another process */
            extra = L";address=" + Hex(U64(q, 16)) +
                    (ok ? L";name=" + Utf16(replyData, std::min<size_t>(U32(r, 8), replyLength)) : L"");
            break;
        }
        const bool thread = request.req == TerminateThread || request.req == GetThreadInfo || request.req == GetThreadTimes ||
                            request.req == SetThreadInfo || request.req == SuspendThread || request.req == ResumeThread ||
                            request.req == GetThreadContext || request.req == SetThreadContext || apc == 1;
        record.type = thread ? MsMonThreadHandle : MsMonProcessHandle;
        bool own = false;
        if (object == 2) {
            const auto known = winTids_.find(winPid);
            if (known != winTids_.end()) record.target = known->second.tgid;
            own = winPid == request.win_tid || record.target == tgid;
        } else if (object == 1) {
            Target(winPid, out);
            own = winPid == request.win_pid || record.target == tgid;
        }
        if (own && !always) return generic();
        record.desiredAccess = pending.granted;
        record.value0 = request.req;
        record.value1 = apc;
        record.detail = requestName + L";handle=" + Hex(handle) +
                        (winPid ? (object == 2 ? L";win_tid=" : L";win_pid=") + Num(winPid) : L"") + extra +
                        tail;
        /* Queries collapse per target and result; control requests keep every record. */
        out.collapse = request.req != SetThreadContext && request.req != QueueApc && request.req != SetThreadInfo &&
                       request.req != SetProcessInfo && request.req != TerminateProcess && request.req != TerminateThread;
        out.repeatKey = std::hash<std::wstring>()(record.detail);
        break;
    }
    case GetApcResult: {
        /* union apc_result at +8: type, status, then the address and size (virtual_*, map_view*) or the thread
         * (create_thread: tid +20). */
        if (pending.granted == 0) return generic();   /* not an APC this decoder recorded */
        record.type = MsMonProcessHandle;
        Target(pending.winPid, out);
        record.value0 = request.req;
        record.value1 = pending.granted;
        uint32_t type = pending.granted;
        std::wstring kind = ApcCall(reinterpret_cast<const uint8_t*>(&type), 4, type);
        record.detail = L"apc_result;handle=" + Hex(U32(q, 12)) + (pending.winPid ? L";win_pid=" + Num(pending.winPid) : L"") +
                        kind;
        if (ok) {
            record.detail += L";status=" + Hex(U32(r, 12));
            record.detail += type == 14 ? L";win_tid=" + Num(U32(r, 20)) : L";addr=" + Hex(U64(r, 16)) + L";size=" + Hex(U64(r, 24));
        }
        record.detail += tail;
        break;
    }
    case CreateDebugObj:
        record.type = MsMonProcessHandle;
        record.desiredAccess = U32(q, 12);
        record.value0 = request.req;
        record.detail = L"create_debug_obj;flags=" + Hex(U32(q, 16)) + (ok ? L";handle=" + Hex(U32(r, 8)) : L"") + tail;
        if (ok) handed(U32(r, 8));
        break;
    case ContinueDebugEvent:
        record.type = MsMonProcessHandle;
        Target(U32(q, 16), out);
        record.value0 = request.req;
        record.detail = L"continue_debug_event;win_pid=" + Num(U32(q, 16)) + L";win_tid=" + Num(U32(q, 20)) + L";status=" +
                        Hex(U32(q, 24)) + tail;
        out.collapse = true;
        out.repeatKey = (static_cast<uint64_t>(U32(q, 16)) << 32) | U32(q, 24);
        break;
    /* Tokens (msmon-gaps 8): process_handle of the token's process (the caller's own too), detail
     * "<request>;handle=..;...", adjust_token_privileges with the privileges by name. */
    case CreateToken:
    case OpenToken:
    case AdjustTokenPrivileges:
    case GetTokenPrivileges:
    case DuplicateToken:
    case FilterToken:
    case GetTokenInfo:
    case CreateLinkedToken:
    case MakeProcessSystem:
    case GrantProcessAdminToken: {
        const uint32_t handle = request.req == CreateToken ? 0 : U32(q, 12);
        uint32_t owner = pending.winPid;   /* the token's process */
        std::wstring extra;
        switch (request.req) {
        case OpenToken: {
            const bool threadToken = (U32(q, 24) & kOpenTokenThread) != 0;
            if (threadToken) owner = pending.winPid == request.win_tid ? request.win_pid : 0;
            record.desiredAccess = U32(q, 16);
            extra = L";access=" + Hex(U32(q, 16)) + (threadToken ? L";thread=1" : L"");
            break;
        }
        case CreateToken:
            owner = request.win_pid;
            break;
        case DuplicateToken:
            record.desiredAccess = U32(q, 16);
            extra = L";primary=" + Num(U32(q, 20)) + L";level=" + Num(U32(q, 24));
            break;
        case FilterToken:
            extra = L";flags=" + Hex(U32(q, 16));
            break;
        case AdjustTokenPrivileges:
            extra = L";disable_all=" + Num(U32(q, 16)) + L";privs=" + Privileges(data, length);
            break;
        case GetTokenPrivileges:
            if (ok) extra = L";count=" + Num(U32(r, 8) / 12);
            break;
        case GetTokenInfo:
            if (ok) extra = L";elevation_type=" + Num(U32(r, 36)) + L";elevated=" + Num(U32(r, 40));
            break;
        default:
            break;
        }
        const bool newToken = request.req == OpenToken || request.req == CreateToken || request.req == DuplicateToken ||
                              request.req == FilterToken || request.req == CreateLinkedToken;
        if (ok && newToken) {
            handed(U32(r, 8));
            process.tokens[U32(r, 8)] = owner;
            extra += L";token=" + Hex(U32(r, 8));
        }
        record.type = MsMonProcessHandle;
        Target(owner, out);   /* the caller's own too: target == its own pid marks its own token */
        record.value0 = request.req;
        record.detail = requestName + L";handle=" + Hex(handle) + (owner ? L";win_pid=" + Num(owner) : L"") + extra + tail;
        out.collapse = request.req != AdjustTokenPrivileges;
        out.repeatKey = (static_cast<uint64_t>(owner) << 32) ^ record.desiredAccess ^ std::hash<std::wstring>()(extra);
        break;
    }
    case GetSecurityObject:
    case SetSecurityObject: {
        /* A file's or named object's security as IRP_MJ_QUERY/SET_SECURITY (value0 the SECURITY_INFORMATION); a
         * process's or thread's as a process_handle / thread_handle. */
        const bool set = request.req == SetSecurityObject;
        const uint32_t handle = U32(q, 12);
        if (pending.object == 1 || pending.object == 2) {
            record.type = pending.object == 1 ? MsMonProcessHandle : MsMonThreadHandle;
            if (pending.object == 1) Target(pending.winPid, out);
            if (pending.winPid == (pending.object == 1 ? request.win_pid : request.win_tid)) return generic();
        } else {
            record.type = set ? MsMonFileSetSecurity : MsMonFileQuerySecurity;
            record.text = !pending.name.empty() ? pending.name : L"handle:" + Hex(handle);
        }
        record.value0 = U32(q, 16);
        record.value1 = set ? request.total : ok ? U32(r, 8) : 0;   /* descriptor bytes */
        record.detail = requestName + L";handle=" + Hex(handle) + L";security_info=" + Hex(U32(q, 16)) + tail;
        out.collapse = !set;
        out.repeatKey = U32(q, 16);
        break;
    }
    /* Named objects (msmon-gaps 8): file_create as IRP_MJ_CREATE / CREATE_MAILSLOT would be, text the full object
     * path (the rootdir's name + the name), value0 FILE_OPEN_IF (create) or FILE_OPEN (open) << 24, value1 the
     * handle. Unnamed objects are not shared by name: no record. */
    case CreateEvent:
    case CreateKeyedEvent:
    case CreateMutex:
    case CreateSemaphore:
    case CreateTimer:
    case CreateMailslot:
    case CreateDirectory:
    case CreateSymlink:
    case CreateCompletion:
    case CreateJob:
    case OpenEvent:
    case OpenKeyedEvent:
    case OpenMutex:
    case OpenSemaphore:
    case OpenTimer:
    case OpenDirectory:
    case OpenSymlink:
    case OpenCompletion:
    case OpenJob:
    case OpenWinstation:
    case OpenDesktop: {
        const bool create = requestName.compare(0, 7, L"create_") == 0;
        uint32_t root = 0;
        std::wstring name, extra;
        if (create) {
            const size_t used = ObjectAttributes(data, length, root, name);
            if (request.req == CreateSymlink) extra = L";target=" + Utf16(data + used, length - used);
            if (request.req == CreateMailslot) extra = L";max_msgsize=" + Num(U32(q, 32));
        } else {
            root = U32(q, request.req == OpenDesktop ? 12 : 20);
            name = Utf16(data, length);
        }
        if (name.empty()) {
            if (ok) handed(U32(r, 8));   /* an unnamed object still takes the handle value */
            return generic();
        }
        const std::wstring path =
            root != 0 ? (pending.root.empty() ? L"handle:" + Hex(root) : pending.root) + L"\\" + name : name;
        if (ok) {
            handed(U32(r, 8));
            process.files[U32(r, 8)] = path;   /* get_object_name, security, directory queries name it */
        }
        record.type = MsMonFileCreate;
        record.text = path;
        record.desiredAccess = U32(q, request.req == OpenDesktop ? 20 : 12);
        record.value0 = static_cast<uint64_t>(create ? 3 : 1) << 24;
        record.value1 = ok ? U32(r, 8) : 0;
        record.detail = requestName + L";object=" + requestName.substr(requestName.find(L'_') + 1) + extra + tail;
        out.collapse = true;   /* Wine and its apps create the same events and mutexes again and again */
        out.repeatKey = request.req;
        break;
    }
    /* Object-manager, atom and input/clipboard/hook requests (msmon-gaps 6, 8): file_query_information, text
     * system:<request>, value0 the request, as the enumeration records. */
    case GetDirectoryEntries:
    case QuerySymlink:
    case GetObjectName:
    case GetObjectType:
    case GetObjectTypes:
    case EnumWinstation:
    case GetHandleUnixName:
    case AddAtom:
    case FindAtom:
    case AddUserAtom:
    case SendHardwareMessage:
    case RegisterHotkey:
    case AttachThreadInput:
    case GetLastInputTime:
    case GetKeyState:
    case SetKeyState:
    case SetHook:
    case SetClipboardData:
    case GetClipboardData:
    case SetClipboardViewer:
    case AddClipboardListener:
    case SetCursor:
    case GetCursorHistory:
    case GetRawinputBuffer:
    case UpdateRawinputDevices:
    case GetWindowInfo:
    case GetWindowParents:
    case GetClassWindows:
    case GetWindowChildrenFromPoint:
    case GetWindowRectangles:
    case GetWindowProperty:
    case GetThreadInput:
    case GetClipboardInfo: {
        const uint32_t handle = U32(q, 12);
        const std::wstring object = L";object=" + (!pending.name.empty() ? pending.name : L"handle:" + Hex(handle));
        std::wstring extra, result;   /* result: what the reply said, outside the collapse key */
        auto i32 = [](const uint8_t* bytes, size_t at) { return std::to_wstring(static_cast<int32_t>(U32(bytes, at))); };
        auto rect = [&](const uint8_t* bytes, size_t at) {
            return i32(bytes, at) + L"," + i32(bytes, at + 4) + L"," + i32(bytes, at + 8) + L"," + i32(bytes, at + 12);
        };
        switch (request.req) {
        case GetDirectoryEntries:
            extra = object + L";index=" + Num(U32(q, 16));
            if (!ok) break;
            record.value1 = U32(r, 12);
            if (payloads_) {   /* directory_entry: name_len, type_len, the name, the type, padded to 4 */
                extra += L";names=";
                for (size_t at = 0, index = 0; at + 8 <= replyLength && index < record.value1; index++) {
                    const uint32_t nameBytes = U32(replyData, at), typeBytes = U32(replyData, at + 4);
                    if (at + 8ull + nameBytes + typeBytes > replyLength) break;
                    extra += (index ? L"," : L"") + Utf16(replyData + at + 8, nameBytes) + L"(" +
                             Utf16(replyData + at + 8 + nameBytes, typeBytes) + L")";
                    at += 8 + ((nameBytes + typeBytes + 3) & ~3u);
                }
            }
            break;
        case QuerySymlink:
            extra = object + (ok ? L";target=" + Utf16(replyData, replyLength) : L"");
            break;
        case GetObjectName:
            if (ok && pending.name.empty() && replyLength != 0) process.files[handle] = Utf16(replyData, replyLength);
            extra = object + (ok ? L";name=" + Utf16(replyData, replyLength) : L"");
            break;
        case GetObjectType:   /* object_type_info: name_len +0, 44 bytes, then the name */
            extra = object + (ok && replyLength >= 44 ? L";type=" + Utf16(replyData + 44, std::min<size_t>(U32(replyData, 0), replyLength - 44)) : L"");
            break;
        case GetObjectTypes:
        case EnumWinstation:
            if (ok) record.value1 = U32(r, 8);
            break;
        case GetHandleUnixName:
            if (ok) {
                const std::wstring unixName = LinuxWide(std::string(reinterpret_cast<const char*>(replyData),
                                                                     std::min<size_t>(U32(r, 8), replyLength)));
                if (pending.name.empty()) process.files[handle] = unixName;
                extra = object + L";unix=" + unixName;
            }
            break;
        case AddAtom:
        case FindAtom:
        case AddUserAtom:
            extra = L";atom=" + Utf16(data, length) + (ok ? L";atom_id=" + Hex(U32(r, 8)) : L"");
            break;
        case SendHardwareMessage: {
            /* Injected input (SendInput) per key or move; winex11's real keys and mouse moves (kernel aggregates per
             * type, the first of a second captured) per type, their keys only with --log-real-input (the user's
             * typing; then each key is captured). */
            const bool injected = (U32(q, 56) & kInjected) != 0, keys = injected || realInput_;
            const uint32_t type = U32(q, 16);
            extra = type == 1 ? L";input=keyboard" : type == 0 ? L";input=mouse" : L";input=hardware";
            std::wstring& rest = injected || (type == 1 && realInput_) ? extra : result;   /* real input: per type */
            if (type == 1)
                rest += (keys ? L";vkey=" + Hex(q[20] | (q[21] << 8)) + L";scan=" + Hex(q[22] | (q[23] << 8)) : L"") +
                        L";flags=" + Hex(U32(q, 24));
            else if (type == 0)
                rest += L";x=" + i32(q, 20) + L";y=" + i32(q, 24) + L";data=" + Hex(U32(q, 28)) + L";flags=" + Hex(U32(q, 32));
            else
                rest += L";msg=" + Hex(U32(q, 20));
            rest += L";window=" + Hex(handle) + L";injected=" + Num(injected);
            break;
        }
        case RegisterHotkey:
            extra = L";window=" + Hex(handle) + L";id=" + Num(U32(q, 16)) + L";modifiers=" + Hex(U32(q, 20)) + L";vkey=" +
                    Hex(U32(q, 24));
            break;
        case AttachThreadInput: {
            /* Only across processes (AttachThreadInput into another process's input queue). */
            auto owner = [&](uint32_t tid) {
                const auto known = winTids_.find(tid);
                return tid == request.win_tid ? tgid : known != winTids_.end() ? known->second.tgid : 0;
            };
            const uint32_t from = owner(U32(q, 12)), to = owner(U32(q, 16));
            if (from == tgid && to == tgid) return generic();
            record.target = from != tgid ? from : to;
            extra = L";from_tid=" + Num(U32(q, 12)) + L";to_tid=" + Num(U32(q, 16)) + L";attach=" + Num(U32(q, 20));
            break;
        }
        case GetKeyState:
            extra = L";key=" + Hex(U32(q, 16)) + L";async=" + Num(U32(q, 12));
            break;
        case SetKeyState:
            extra = L";async=" + Num(U32(q, 12)) + L";bytes=" + Num(request.total);
            break;
        case SetHook: {
            static const wchar_t* const kHooks[] = {L"msgfilter", L"journalrecord", L"journalplayback", L"keyboard",
                                                    L"getmessage", L"callwndproc", L"cbt", L"sysmsgfilter", L"mouse",
                                                    L"hardware", L"debug", L"shell", L"foregroundidle", L"callwndprocret",
                                                    L"keyboard_ll", L"mouse_ll", L"winevent"};
            const int32_t id = static_cast<int32_t>(handle);
            const uint32_t pid = U32(q, 16), tid = U32(q, 20);
            extra = L";id=" + std::to_wstring(id) + L";hook=" +
                    (id >= -1 && id + 1 < static_cast<int32_t>(std::size(kHooks)) ? kHooks[id + 1] : L"unknown") +
                    L";scope=" + (tid ? L"thread:" + Num(tid) : pid ? L"process:" + Num(pid) : std::wstring(L"global")) +
                    L";proc=" + Hex(U64(q, 32)) + L";flags=" + Hex(U32(q, 40)) + L";module=" + Utf16(data, length);
            break;
        }
        case SetClipboardData:
            /* the contents are never logged (what the user copied, passwords included); --log-content hashes them */
            extra = L";format=" + Num(U32(q, 12)) + L";bytes=" + Num(request.total) + (content_ ? Hashed(data, length, request.total) : L"");
            break;
        case GetClipboardData:
            extra = L";format=" + Num(U32(q, 12)) +
                    (ok ? L";owner=" + Hex(U32(r, 12)) + L";bytes=" + Num(U32(r, 20)) +
                              (content_ ? Hashed(replyData, replyLength, reply->total) : L"")
                        : L"");
            break;
        case SetClipboardViewer:
        case AddClipboardListener:
            extra = L";window=" + Hex(handle);
            break;
        case SetCursor: {   /* SetCursorPos / ClipCursor each; a shape or show-count change (per mouse move) per second */
            const uint32_t flags = U32(q, 12);
            extra = L";flags=" + Hex(flags);
            if (flags & 1) result += L";handle=" + Hex(U32(q, 16));
            if (flags & 2) result += L";show_count=" + i32(q, 20);
            if (flags & 4) extra += L";x=" + i32(q, 24) + L";y=" + i32(q, 28);
            if (flags & 8) extra += L";clip=" + rect(q, 32);
            break;
        }
        case GetRawinputBuffer:
            if (ok) extra = L";count=" + Num(U32(r, 16));
            break;
        case UpdateRawinputDevices:   /* rawinput_device: usage (page << 16 | usage), flags (RIDEV_INPUTSINK 0x100), target */
            extra = L";devices=";
            for (size_t at = 0; at + 12 <= length; at += 12)
                extra += (at ? L"," : L"") + Hex(U32(data, at)) + L"/flags=" + Hex(U32(data, at + 4));
            break;
        /* Wine 11 asks these mostly for windows of other processes (its own are answered in-process): GetWindowLong,
         * GetAncestor, FindWindow, WindowFromPoint, GetWindowRect, GetProp, GetGUIThreadInfo, GetClipboardOwner. */
        case GetWindowInfo:   /* offset: GWL_* (-16 style, -20 exstyle, -4 wndproc, -6 hinstance, -12 id, -21 userdata) */
            extra = L";window=" + Hex(handle) + L";offset=" + std::to_wstring(static_cast<int32_t>(U32(q, 16)));
            if (ok) result = L";info=" + Hex(U64(r, 16)) + L";last_active=" + Hex(U32(r, 8));
            break;
        case GetWindowParents:
            extra = L";window=" + Hex(handle);
            if (ok) record.value1 = U32(r, 8);
            break;
        case GetClassWindows:
            extra = L";window=" + Hex(handle) + L";child=" + Hex(U32(q, 16)) + L";atom=" + Hex(U32(q, 20)) +
                    (length ? L";class=" + Utf16(data, length) : L"");
            if (ok) record.value1 = U32(r, 8);
            break;
        case GetWindowChildrenFromPoint:   /* the point stays out of the key: a hit test per mouse move */
            extra = L";window=" + Hex(handle);
            result = L";x=" + i32(q, 16) + L";y=" + i32(q, 20);
            if (ok) record.value1 = U32(r, 8);
            break;
        case GetWindowRectangles:
            extra = L";window=" + Hex(handle) + L";relative=" + Num(U32(q, 16));
            if (ok) result = L";window_rect=" + rect(r, 8) + L";client_rect=" + rect(r, 24);
            break;
        case GetWindowProperty:
            extra = L";window=" + Hex(handle) + L";atom=" + Hex(U32(q, 16)) + (length ? L";name=" + Utf16(data, length) : L"");
            if (ok) result = L";data=" + Hex(U64(r, 8));
            break;
        case GetThreadInput: {   /* tid 0: the foreground thread's */
            const auto known = winTids_.find(handle);
            if (handle != 0 && handle != request.win_tid && known != winTids_.end() && known->second.tgid != tgid)
                record.target = known->second.tgid;
            extra = L";tid=" + Num(handle);
            break;
        }
        case GetClipboardInfo:
            if (ok) result = L";window=" + Hex(U32(r, 8)) + L";owner=" + Hex(U32(r, 12)) + L";viewer=" + Hex(U32(r, 16)) +
                             L";seqno=" + Num(U32(r, 20));
            break;
        default:   /* GetLastInputTime, GetCursorHistory */
            break;
        }
        record.type = MsMonFileQueryInformation;
        record.text = L"system:" + requestName;
        record.value0 = request.req;
        if (record.target == 0) record.target = pending.fieldTarget;   /* another process's window, thread or hook */
        record.detail = L"ws=" + requestName + extra + result + tail;
        out.collapse = request.req != SetHook && request.req != RegisterHotkey;
        out.repeatKey = std::hash<std::wstring>()(extra);
        break;
    }
    /* Files and sections whose work wineserver does (msmon-gaps 9): the client's record of a delete, rename, link,
     * truncate, directory watch or view, as the minifilter's. */
    case SetFdDispInfo:
    case SetFdEofInfo:
    case SetFdNameInfo: {
        const uint32_t handle = U32(q, 12);
        const std::wstring from = !pending.name.empty() ? pending.name : L"handle:" + Hex(handle);
        record.type = MsMonFileSetInformation;
        record.text = from;
        if (request.req == SetFdDispInfo) {
            record.value0 = kFileDisposition;
            record.value1 = U32(q, 16);
            record.detail = std::wstring(U32(q, 16) & 1 ? L"delete" : L"undelete") + L";ws=set_fd_disp_info;flags=" + Hex(U32(q, 16));
        } else if (request.req == SetFdEofInfo) {
            record.value0 = kFileEndOfFile;
            record.value1 = U64(q, 16);
            record.detail = L"ws=set_fd_eof_info";
        } else {
            /* the new NT name (namelen bytes, relative to rootdir), then its unix name */
            const size_t nameBytes = std::min<size_t>(U32(q, 20), length);
            std::wstring to = Utf16(data, nameBytes);
            if (U32(q, 16) != 0) to = (pending.root.empty() ? L"handle:" + Hex(U32(q, 16)) : pending.root) + L"\\" + to;
            const std::wstring unixName = LinuxWide(std::string(reinterpret_cast<const char*>(data) + nameBytes, length - nameBytes));
            const bool link = U32(q, 24) != 0;
            record.value0 = link ? kFileLink : kFileRename;
            record.value1 = U32(q, 28);   /* FILE_RENAME_REPLACE_IF_EXISTS, ... */
            if (!link) {   /* two records, as the syscall sensors write a rename: the old name, then the new one */
                WsRecord old = out;
                old.record.detail = L"rename;from;ws=set_fd_name_info;handle=" + Hex(handle) + tail;
                Emit(old, sink);
                if (ok) process.files[handle] = to;
            }
            record.text = to;
            record.detail = (link ? L"link;target=" + from : std::wstring(L"rename;to")) + L";ws=set_fd_name_info;unix=" + unixName;
        }
        record.detail += L";handle=" + Hex(handle) + tail;
        break;
    }
    case ReadDirectoryChanges:
        record.type = MsMonFileDirectoryControl;
        record.text = !pending.name.empty() ? pending.name : L"handle:" + Hex(U32(q, 24));
        record.value0 = kNotifyChangeDirectory;
        record.value1 = U32(q, 12);   /* FILE_NOTIFY_CHANGE_* */
        record.detail = L"notify_change_directory;ws=read_directory_changes;filter=" + Hex(U32(q, 12)) + L";subtree=" +
                        Num(U32(q, 16)) + L";handle=" + Hex(U32(q, 24)) + tail;
        out.collapse = true;   /* re-armed after every change */
        out.repeatKey = U32(q, 12);
        break;
    case AllocFileHandle:
        /* A unix fd the client hands wineserver (stdio, server_fd_to_handle): the handle names its file. */
        if (ok) {
            char link[4096];
            const ssize_t got =
                readlink(("/proc/" + std::to_string(tgid) + "/fd/" + std::to_string(static_cast<int32_t>(U32(q, 20)))).c_str(),
                         link, sizeof(link));
            handed(U32(r, 8));
            if (got > 0) process.files[U32(r, 8)] = LinuxWide(std::string(link, static_cast<size_t>(got)));
        }
        return generic();
    case MapView:
    case MapImageView:
    case UnmapView: {
        /* A view of a section (file_section, value0 the base, value1 the size): map_image_view is an image's
         * load as the loader does it, with the section's file. */
        const bool image = request.req == MapImageView, unmap = request.req == UnmapView;
        const uint64_t base = U64(q, unmap ? 16 : image ? 16 : 24);
        record.type = MsMonFileSection;
        record.text = !pending.name.empty() ? pending.name : unmap ? L"view:" + Hex(base) : L"handle:" + Hex(U32(q, 12));
        record.value0 = base;
        record.value1 = unmap ? 0 : U64(q, image ? 24 : 32);
        record.detail = requestName + L";base=" + Hex(base);
        if (image) record.detail += L";size=" + Hex(record.value1) + L";entry=" + Hex(U32(q, 40)) + L";machine=" + Hex(q[44] | (q[45] << 8));
        else if (!unmap) record.detail += L";size=" + Hex(record.value1) + L";offset=" + Hex(U64(q, 40)) + L";access=" + Hex(U32(q, 16));
        if (!unmap) record.detail += L";mapping=" + Hex(U32(q, 12));
        /* Unmapping an image view unloads that module (FreeLibrary): never collapsed, as its load. */
        const bool unload = unmap && process.imageViews.count(base) != 0;
        if (unload) record.detail += L";image_unload=1";
        record.detail += tail;
        if (ok && unmap) {
            process.views.erase(base);
            process.imageViews.erase(base);
        } else if (ok) {
            process.views[base] = record.text;
            if (image) process.imageViews.insert(base);
        }
        /* Views of data sections come and go thousands of times a minute (a game's shared buffers): counted per
         * section, size and access each second, as repeated syscalls are. An image view is a load: never. */
        if (!image && !unload) {
            out.collapse = true;
            out.repeatKey = (static_cast<uint64_t>(request.req) << 56) ^ record.value1 ^ (static_cast<uint64_t>(U32(q, 16)) << 40);
        }
        break;
    }
    /* Registry work wineserver does for the client (msmon-gaps 9): hive save/load/unload and change notifications. */
    case SaveRegistry:
        record.type = MsMonRegistryQuery;
        record.text = pending.key;
        record.detail = L"save_registry;file=" + (!pending.name.empty() ? pending.name : L"handle:" + Hex(U32(q, 16))) + tail;
        break;
    case LoadRegistry:
    case UnloadRegistry: {
        uint32_t root = 0;
        std::wstring name;
        if (request.req == LoadRegistry) ObjectAttributes(data, length, root, name);
        else root = U32(q, 12), name = Utf16(data, length);
        record.type = request.req == LoadRegistry ? MsMonRegistryCreate : MsMonRegistryDelete;
        record.text = root != 0 ? pending.key + L"\\" + name : name;
        record.detail = requestName + (request.req == LoadRegistry ? L";file=" + (!pending.name.empty() ? pending.name : L"handle:" + Hex(U32(q, 12))) : L"") + tail;
        break;
    }
    case SetRegistryNotification:
        record.type = MsMonRegistryQuery;
        record.text = pending.key;
        record.value1 = U32(q, 24);   /* REG_NOTIFY_CHANGE_* */
        record.detail = L"notify;filter=" + Hex(U32(q, 24)) + L";subtree=" + Num(U32(q, 20)) + tail;
        out.collapse = true;   /* re-armed after every change */
        out.repeatKey = U32(q, 24);
        break;
    case AssignJob:
    case TerminateJob: {
        const std::wstring job = request.req == AssignJob ? pending.root : pending.name;
        const uint32_t jobHandle = U32(q, 12);
        record.type = MsMonProcessHandle;
        record.value0 = request.req;
        if (request.req == AssignJob && pending.object == 1 && pending.winPid != request.win_pid) Target(pending.winPid, out);
        record.detail = requestName + L";job=" + (!job.empty() ? job : L"handle:" + Hex(jobHandle)) +
                        (request.req == AssignJob ? L";process=" + Hex(U32(q, 16)) + (pending.winPid ? L";win_pid=" + Num(pending.winPid) : L"")
                                                  : L";status=" + Hex(U32(q, 16))) +
                        tail;
        break;
    }
    case SendMessage: {
        /* SendMessage, PostMessage, SendNotifyMessage, PostThreadMessage (type): the destination process from the thread
         * id (the window's owner thread), else the window; none when it is the sender's own. Collapsed per destination
         * and message. */
        const uint32_t to = U32(q, 12), window = U32(q, 24), msg = U32(q, 28), type = U32(q, 16);
        const auto thread = winTids_.find(to);
        const auto owner = windows_.find(window & 0xffff);
        const uint32_t destination = thread != winTids_.end() ? thread->second.tgid : owner != windows_.end() ? owner->second.tgid : 0;
        record.type = MsMonFileQueryInformation;
        record.text = L"system:send_message";
        record.value0 = request.req;
        record.value1 = msg;
        record.target = destination == tgid || to == request.win_tid ? 0 : destination;
        record.detail = L"ws=send_message;type=" + MessageType(type) + L";to_tid=" + Num(to) + L";win=" + Hex(window) + L";msg=" +
                        Hex(msg) + Message(msg, type, U64(q, 32), U64(q, 40), data, length, request.total) + L";flags=" +
                        Hex(U32(q, 20)) + L";timeout=" + std::to_wstring(static_cast<int64_t>(U64(q, 48))) + tail;
        out.collapse = true;
        out.repeatKey = (static_cast<uint64_t>(destination ? destination : to) << 32) | msg;
        break;
    }
    case GetMessage: {
        /* What the thread received (GetMessage, PeekMessage): window, message, type, parameters; STATUS_PENDING:
         * nothing was waiting. Collapsed per window and message. */
        record.type = MsMonFileQueryInformation;
        record.text = L"system:get_message";
        record.value0 = request.req;
        std::wstring got;
        if (ok && status != kStatusPending) {
            const uint32_t msg = U32(r, 12), type = U32(r, 32);
            record.value1 = msg;
            got = L";win=" + Hex(U32(r, 8)) + L";msg=" + Hex(msg) + L";type=" + MessageType(type) +
                  Message(msg, type, U64(r, 16), U64(r, 24), replyData, replyLength, U32(r, 48)) + L";x=" +
                  std::to_wstring(static_cast<int32_t>(U32(r, 36))) + L";y=" + std::to_wstring(static_cast<int32_t>(U32(r, 40))) +
                  L";time=" + Hex(U32(r, 44));
            out.repeatKey = (static_cast<uint64_t>(U32(r, 8)) << 32) | msg;
        }
        record.detail = L"ws=get_message;flags=" + Hex(U32(q, 12)) + L";get_win=" + Hex(U32(q, 16)) + got + tail;
        out.collapse = true;
        break;
    }
    case GetAsyncResult:
        /* An overlapped I/O's output (a DeviceIoControl or pipe read that finished later): its size, SHA-256 and first
         * bytes. */
        record.type = MsMonFileQueryInformation;
        record.text = L"system:get_async_result";
        record.value0 = request.req;
        record.value1 = reply != nullptr ? reply->total : 0;
        record.detail = L"ws=get_async_result;user_arg=" + Hex(U64(q, 16)) +
                        (ok ? Result(out, replyData, replyLength, reply->total) : L"") + tail;
        out.collapse = true;
        break;
    case SetIrpResult:
        IrpResult(request, U32(q, 12), U32(q, 16), U32(q, 20), data, length, request.total, sink);
        return;
    case CreateWindow:   /* its creator owns it: messages and window requests of other processes name it */
        if (ok) windows_[U32(r, 8) & 0xffff] = {tgid, request.win_tid, U32(r, 8) >> 16};
        return generic(true);
    case DestroyWindow:
        if (ok) windows_.erase(U32(q, 12) & 0xffff);
        return generic(true);
    default:   /* every request no case above names, and request numbers past the table */
        return generic(true);
    }
    Emit(out, sink);
}

/* The message parameters: wparam, lparam and the message data's size and SHA-256 (WM_COPYDATA's bytes, a hook's
 * input); for keyboard messages only with --log-real-input (they carry the user's keys). */
std::wstring WsDecoder::Message(uint32_t msg, uint32_t type, uint64_t wparam, uint64_t lparam, const uint8_t* data,
                                size_t length, uint64_t total)
{
    if (KeyboardMessage(msg, type) && !realInput_) return L";input=withheld";
    std::wstring out = L";wparam=" + Hex(wparam) + L";lparam=" + Hex(lparam);
    if (total != 0)
        out += L";data_bytes=" + Num(total) + L";sha256=" + LinuxWide(Sha256Bytes(data, std::min<uint64_t>(length, total)));
    return out;
}

/* ";out_bytes=<total>;sha256=<of the bytes captured>" (";hashed_bytes=" when fewer were), and with payloads the first
 * kResultBytes (with --log-content all the captured bytes, payloads or not) as Out's ipc_data payload, as an RPC stub's:
 * what a driver, an overlapped I/O or a device answered. */
std::wstring WsDecoder::Result(WsRecord& out, const uint8_t* bytes, size_t captured, uint64_t total)
{
    captured = std::min<uint64_t>(captured, total);
    std::wstring text = L";out_bytes=" + Num(total);
    if (total == 0) return text;
    text += Hashed(bytes, captured, total);
    if ((payloads_ || content_) && captured != 0) {
        out.bytes.assign(bytes, bytes + (content_ ? captured : std::min(captured, kResultBytes)));
        out.payload = true;
        out.payloadKind = MsMonPayloadIpcData;
        out.payloadTotal = out.bytes.size();
    }
    return text;
}

/* A driver's answer to IRP Handle (set_irp_result, or the result get_next_device_request carries for the previous
 * IRP): as the IRP's record (type, device, the client as target) with irp_result, its status and information and the
 * output the client gets (disk serials, adapter tables...). Collapsed per device, request and status. */
void WsDecoder::IrpResult(const mm_ws_event& request, uint32_t handle, uint32_t status, uint64_t information,
                          const uint8_t* data, size_t length, uint64_t total, const WsSink& sink)
{
    Process& process = processes_[request.tgid];
    const auto known = process.irps.find(handle);
    const Irp irp = known != process.irps.end() ? known->second : Irp{};
    if (known != process.irps.end()) process.irps.erase(known);
    WsRecord out;
    out.request = &request;
    out.tsNs = request.ts_ns;
    LinuxRecord& record = out.record;
    record.type = irp.type != 0 ? irp.type : static_cast<ULONG>(MsMonFileDeviceControl);
    record.text = !irp.text.empty() ? irp.text : L"irp:" + Hex(handle);
    record.status = static_cast<int32_t>(status);
    record.target = irp.clientTgid;
    record.component = irp.driver;
    record.value0 = irp.code;
    record.value1 = information;
    record.detail = L"irp_result;irp=" + std::wstring(*irp.what ? irp.what : L"unknown") + (irp.code ? L";code=" + Hex(irp.code) : L"") +
                    L";status=" + Hex(status) + L";information=" + Num(information) + Result(out, data, length, total) +
                    L";client_win_tid=" + Num(irp.clientWinTid) + L";driver=" + irp.driver;
    out.collapse = true;
    out.repeatKey = (static_cast<uint64_t>(irp.code) << 32) | status;
    Emit(out, sink);
}

/* A write on a request pipe that is not one whole request of the writer's thread (MM_WS_F_REJECTED; ws_bpf.h says which
 * kfilter refuses in block mode): file_write of the pipe, value0 the syscall's count, the pipe's owner as target, detail
 * request_pipe_rejected;reason=..;syscall=..;fd=..;count=.. and the request header it carried. Never collapsed. */
void WsDecoder::Rejected(const mm_ws_event& event, const WsSink& sink)
{
    static const wchar_t* const kReasons[] = {L"unknown", L"chunks", L"resumed",      L"size",   L"unreadable",
                                              L"form",    L"total",  L"foreign_pipe", L"splice", L"other_call"};
    mm_ws_reject reject{};
    std::memcpy(&reject, event.data, std::min<size_t>(event.data_len, sizeof(reject)));
    const bool compat = (event.flags & MM_WS_F_COMPAT) != 0;
    const bool vector = reject.nr == (compat ? 146u : 20u);
    const wchar_t* call = reject.nr == (compat ? 4u : 1u) ? L"write"
                          : vector                       ? L"writev"
                          : reject.nr == (compat ? 313u : 275u) ? L"splice"
                          : reject.nr == (compat ? 315u : 276u) ? L"tee"
                          : reject.nr == (compat ? 316u : 278u) ? L"vmsplice"
                          : reject.nr == (compat ? 379u : 328u) ? L"pwritev2"
                          : reject.nr == (compat ? 187u : 40u)  ? L"sendfile"
                                                                 : L"sendfile64";
    /* Its first bytes are a header wineserver would read: a whole one, or a foreign write's. */
    const bool header = reject.reason == MM_WS_REJECT_FORM || reject.reason == MM_WS_REJECT_TOTAL ||
                        (reject.reason == MM_WS_REJECT_FOREIGN && (vector || reject.count >= 8)) ||
                        (reject.reason == MM_WS_REJECT_SIZE && reject.count >= 8);
    WsRecord out;
    out.request = &event;
    out.tsNs = event.ts_ns;
    LinuxRecord& record = out.record;
    record.type = MsMonFileWrite;
    record.text = L"pipe:[" + Num(reject.ino) + L"]";
    record.value0 = reject.count;
    if (reject.owner != event.tgid) record.target = reject.owner;
    record.detail = L"request_pipe_rejected;reason=" +
                    std::wstring(reject.reason < std::size(kReasons) ? kReasons[reject.reason] : L"unknown") + L";syscall=" +
                    call + L";fd=" + std::to_wstring(reject.fd) + L";count=" + Num(reject.count) +
                    (reject.owner != 0 ? L";owner_pid=" + Num(reject.owner) : L"") +
                    (header ? L";req=" + LinuxWide(WsRequestName(event.req) + std::strlen("wineserver:")) +
                                  L";request_size=" + Num(event.total)
                            : L"");
    Emit(out, sink);
}

/* The generic decoder's request side, at request time (so handles name what they named when it was sent): every
 * fixed field ";<name>=<value>", a handle's name or Windows id (";<name>_name=", "_win_pid=", "_win_tid="), the
 * vararg, the bytes no field covers. Target: the first other tracked process a handle, window or Windows id names. */
std::wstring WsDecoder::Fields(const mm_ws_event& request, Process& process, uint32_t& target)
{
    const Proto& proto = ProtoOf(request.req);
    auto other = [&](const std::unordered_map<uint32_t, Unix>& ids, uint32_t id) {
        const auto known = ids.find(id);
        if (target == 0 && known != ids.end() && known->second.tgid != request.tgid) target = known->second.tgid;
    };
    std::wstring out;
    for (const Field& field : proto.request) {
        if (field.type == 'z') continue;
        const std::wstring name = LinuxWide(field.name);
        const uint32_t value = U32(request.fixed, field.offset);
        out += L";" + name + L"=" + FieldText(field, request.fixed);
        if (field.type == 'h' || field.type == 'a') {
            const auto key = process.keys.find(value);
            const auto file = process.files.find(value);
            const auto pid = process.processes.find(value);
            const auto tid = process.threads.find(value);
            if (key != process.keys.end()) {
                out += L";" + name + L"_name=" + key->second;
            } else if (file != process.files.end()) {
                out += L";" + name + L"_name=" + file->second;
            } else if (pid != process.processes.end()) {
                out += L";" + name + L"_win_pid=" + Num(pid->second);
                other(winPids_, pid->second);
            } else if (tid != process.threads.end() && tid->second != 0) {
                out += L";" + name + L"_win_tid=" + Num(tid->second);
                other(winTids_, tid->second);
            }
        } else if (field.type == 'w') {
            const auto window = windows_.find(value & 0xffff);
            if (window != windows_.end() && window->second.tgid != request.tgid && target == 0) target = window->second.tgid;
        } else if (field.type == 't' || field.type == 'p') {
            other(field.type == 't' ? winTids_ : winPids_, value);
        }
    }
    return out + Vararg(proto.varargs, request.data, std::min<uint32_t>(request.data_len, MM_WS_DATA), request.total, L"") +
           Unknown(proto.request, request.fixed, 12, L"");
}

/* The generic decoder's reply side: ";reply_<name>=<value>", its string vararg, the bytes no field covers. Forget: a
 * handle it gives out no longer names what that value named (unknown beats a wrong name). */
std::wstring WsDecoder::ReplyFields(const mm_ws_event& request, const mm_ws_event* reply, Process& process, bool forget)
{
    if (reply == nullptr) return {};
    const Proto& proto = ProtoOf(request.req);
    std::wstring out;
    for (const Field& field : proto.reply) {
        if (field.type == 'z') continue;
        if (field.type == 'h' && forget) process.Handed(U32(reply->fixed, field.offset));
        out += L";reply_" + LinuxWide(field.name) + L"=" + FieldText(field, reply->fixed);
    }
    return out + Vararg(proto.replyVarargs, reply->data, std::min<uint32_t>(reply->data_len, MM_WS_DATA), reply->total, L"reply_") +
           Unknown(proto.reply, reply->fixed, 8, L"reply_");
}

/* A vararg: the only one when a UTF-16 string (";<prefix><name>=", window text only with payloads), object attributes
 * first (";rootdir=;name="), else ";<prefix>data_bytes=" all of them. */
std::wstring WsDecoder::Vararg(const std::vector<std::string>& varargs, const uint8_t* data, size_t length, uint64_t total,
                               const wchar_t* prefix)
{
    if (total == 0 || varargs.empty()) return {};
    const char mark = varargs[0].back();
    const std::wstring first = LinuxWide(varargs[0].substr(0, varargs[0].size() - (mark == '$' || mark == '@')));
    if (varargs.size() == 1 && mark == '$') {
        if (first == L"text" && !payloads_) return L";" + std::wstring(prefix) + L"text_bytes=" + Num(total);   /* content */
        return L";" + std::wstring(prefix) + first + L"=" + Utf16(data, std::min<uint64_t>(length, total)) +
               (length < total ? L";truncated" : L"");
    }
    std::wstring out;
    if (mark == '@') {
        uint32_t rootdir = 0;
        std::wstring name;
        ObjectAttributes(data, length, rootdir, name);
        out = L";rootdir=" + Hex(rootdir) + L";name=" + name;
    }
    return out + L";" + prefix + L"data_bytes=" + Num(total);
}

void WsDecoder::Rpc(const Pending& pending, const uint8_t* data, size_t length, const wchar_t* via, const WsSink& sink)
{
    WsRpcPdu pdu;
    if (!WsParseRpc(data, length, pdu)) return;
    /* Requests, binds and faults: what ETW's RPC client events give (response PDUs mostly complete through
     * get_async_result, which is not captured). */
    if (pdu.ptype != 0 && pdu.ptype != 3 && pdu.ptype != 11 && pdu.ptype != 14) return;
    const mm_ws_event& request = *pending.event;
    const uint32_t handle = U32(request.fixed, 16);
    auto& contexts = processes_[request.tgid].rpc[handle];
    WsRecord out;
    out.request = &request;
    out.tsNs = request.ts_ns;
    LinuxRecord& record = out.record;
    record.type = MsMonEtwRpc;
    std::wstring protocol;
    record.text = pending.name.empty() ? L"handle:" + Hex(handle) : RpcEndpoint(pending.name, protocol);
    record.value0 = pdu.ptype;
    std::wstring detail, uuid, service, method, arguments;
    const wchar_t* ptype = L"fault";
    if (pdu.ptype == 0) {
        ptype = L"request";
        const auto bound = contexts.find(pdu.context);
        if (bound != contexts.end()) uuid = bound->second;
        /* The same fields, in the same order, as the Windows ETW RPC record (etw.cpp OnRecord). */
        detail = L"op=" + Num(pdu.opnum);
        if (!uuid.empty()) {
            detail += L";interface_uuid=" + uuid;
            if (RpcOperationName(uuid, pdu.opnum, service, method)) {
                detail += L";interface=" + service + L";operation=" + method;
            } else {
                detail += L";interface=" + (RpcInterfaceName(uuid, service) ? service : uuid) + L";operation=" + Num(pdu.opnum);
            }
        } else {
            detail += L";operation=" + Num(pdu.opnum);
        }
        detail += L";context=" + Num(pdu.context);
        /* The request's arguments (its stub: after the 24-byte header and an object UUID, before an auth trailer):
         * the first 1 KiB as an ipc_data payload, and svcctl's service name and binary decoded. */
        const size_t start = 24 + ((data[3] & 0x80) ? 16 : 0), auth = data[10] | (data[11] << 8);
        const size_t trailer = auth != 0 ? auth + 8 : 0;
        const size_t fragment = std::min<size_t>(length, data[8] | (data[9] << 8));
        const size_t end = fragment > trailer ? fragment - trailer : 0;
        if (end > start) {
            if (uuid == L"367abb81-9844-35f1-ad32-98f038001003" &&
                (pdu.opnum == kSvcctlOpenService || pdu.opnum == kSvcctlCreateService))
                arguments = SvcctlArguments(pdu.opnum, data + start, end - start);
            if (payloads_) {
                out.bytes.assign(data + start, data + start + std::min(end - start, kRpcStubBytes));
                out.payload = true;
                out.payloadKind = MsMonPayloadIpcData;
                out.payloadTotal = out.bytes.size();
                record.flags |= MsMonFlagPayloadInput;
                arguments += L";stub_bytes=" + Num(end - start);
            }
        }
    } else if (pdu.ptype == 11 || pdu.ptype == 14) {
        ptype = pdu.ptype == 11 ? L"bind" : L"alter_context";
        for (const auto& bind : pdu.binds) contexts[bind.first] = bind.second;
        uuid = pdu.binds.front().second;
        detail = L"interface_uuid=" + uuid + L";interface=" + (RpcInterfaceName(uuid, service) ? service : uuid) +
                 L";version=" + pdu.version + L";contexts=" + Num(pdu.binds.size());
    } else if (length >= 28) {
        record.status = static_cast<int32_t>(U32(data, 24));   /* fault status */
    }
    record.detail = detail + (detail.empty() ? L"" : L";") + L"ptype=" + ptype + L";call_id=" + Num(pdu.callId) +
                    L";protocol=" + (protocol.empty() ? L"unknown" : protocol) + L";via=" + via + L";handle=" + Hex(handle) +
                    arguments;
    out.collapse = true;
    out.repeatKey = std::hash<std::wstring>()(uuid) ^ (static_cast<uint64_t>(pdu.ptype) << 48) ^ pdu.opnum;
    Emit(out, sink);
}

void WsDecoder::DeviceRequest(const Pending& pending, const mm_ws_event& reply, const WsSink& sink)
{
    /* get_next_device_request reply: irp_params +8 (type, then per type), next +40, client_tid +44, in_size +56. */
    const uint8_t* r = reply.fixed;
    const mm_ws_event& request = *pending.event;
    Process& process = processes_[request.tgid];
    const uint32_t type = U32(r, 8);
    static const struct {
        ULONG record;
        const wchar_t* name;
    } kTypes[] = {{0, nullptr},
                  {MsMonFileCreate, L"create"},
                  {MsMonFileClose, L"close"},
                  {MsMonFileRead, L"read"},
                  {MsMonFileWrite, L"write"},
                  {MsMonFileFlush, L"flush"},
                  {MsMonFileDeviceControl, L"ioctl"},
                  {MsMonFileQueryVolumeInformation, L"volume"}};
    if (type == 0 || type >= std::size(kTypes)) return;   /* none, free, cancel */
    uint64_t device = 0, fileObject = 0;
    if (type == 1) {
        device = U64(r, 24);
        process.creates[U32(r, 32)] = device;   /* set_kernel_object_ptr names its FILE_OBJECT next */
    } else {
        fileObject = U64(r, type == 3 || type == 6 || type == 7 ? 24 : 16);
        const auto known = process.fileObjects.find(fileObject);
        if (known != process.fileObjects.end()) device = known->second;
        else if (!process.drivers.empty() && reader_) reader_(request.tgid, fileObject + 8, device);   /* FILE_OBJECT.DeviceObject */
        if (type == 2 && known != process.fileObjects.end()) process.fileObjects.erase(known);
    }
    auto known = process.devices.find(device);
    if (known == process.devices.end() && device != 0 && !process.drivers.empty())
        known = process.devices.emplace(device, Device{L"", DriverOf(request.tgid, process, device)}).first;
    Irp irp;
    irp.driver = known != process.devices.end() ? known->second.driver : process.driver;
    irp.clientWinTid = U32(r, 44);
    const auto client = winTids_.find(irp.clientWinTid);
    if (client != winTids_.end()) irp.clientTgid = client->second.tgid;
    irps_[request.tid] = irp;

    WsRecord out;
    out.request = &request;
    out.tsNs = reply.ts_ns;
    LinuxRecord& record = out.record;
    record.type = kTypes[type].record;
    record.text = known != process.devices.end() && !known->second.name.empty() ? known->second.name
                  : device != 0                  ? L"device:" + Hex(device)
                                                 : L"file_object:" + Hex(fileObject);
    record.target = irp.clientTgid;
    const uint32_t inSize = U32(r, 56);
    std::wstring extra;
    switch (type) {
    case 1:
        record.desiredAccess = U32(r, 12);
        record.value0 = U32(r, 20);   /* options */
        extra = L";sharing=" + Hex(U32(r, 16));
        break;
    case 3:
        record.value0 = U32(r, 16);   /* length asked for */
        record.value1 = U64(r, 32);   /* pos */
        break;
    case 4:
        record.value0 = inSize;
        record.value1 = U64(r, 24);
        break;
    case 6:   /* as the minifilter's device control: IoControlCode, InputBufferLength */
        record.value0 = U32(r, 12);
        record.value1 = inSize;
        extra = L";code=" + Hex(U32(r, 12)) + L";out_size=" + Num(U32(r, 16));
        break;
    case 7:
        record.value0 = U32(r, 12);   /* FS_INFORMATION_CLASS */
        record.value1 = U32(r, 16);
        break;
    default:
        break;
    }
    record.detail = std::wstring(L"irp=") + kTypes[type].name + extra + L";client_win_tid=" + Num(irp.clientWinTid) +
                    L";driver=" + irp.driver;
    out.collapse = type != 1 && type != 2;
    out.repeatKey = fileObject ^ (static_cast<uint64_t>(record.value0) << 32);
    /* Its handle (next +40) names it in its result (IrpResult). */
    irp.type = record.type;
    irp.text = record.text;
    irp.what = kTypes[type].name;
    irp.code = type == 6 ? U32(r, 12) : 0;
    if (U32(r, 40) != 0) process.irps[U32(r, 40)] = irp;
    Emit(out, sink);
}

std::wstring WsDecoder::DriverOf(uint32_t tgid, const Process& process, uint64_t device)
{
    /* A device created before the agent watched: DEVICE_OBJECT.DriverObject (+8), whose DriverStart (+0x18) or
     * DriverInit (+0x58) lies in one of the driver images (x64 wdm.h layout, as Wine's ntoskrnl fills it). */
    uint64_t driverObject = 0, address = 0;
    if (!reader_ || !reader_(tgid, device + 8, driverObject) || driverObject == 0) return {};
    for (const uint64_t offset : {0x18ull, 0x58ull}) {
        if (!reader_(tgid, driverObject + offset, address)) continue;
        for (const WsDriver& driver : process.drivers) {
            if (address >= driver.base && address < driver.end) return BaseName(driver.path);
        }
    }
    return {};
}

void WsDecoder::Joined(const mm_ws_event& identity, const std::vector<WsDriver>& drivers, const WsSink& sink)
{
    Process& process = processes_[identity.tgid];
    if (process.winedevice) return;
    process.winedevice = true;
    process.drivers = drivers;
    /* Several drivers: work outside an IRP names none (the live decoder names the last one loaded). */
    process.driver = drivers.size() == 1 ? BaseName(drivers[0].path) : L"";
    for (const WsDriver& driver : drivers) {
        WsRecord out;
        out.request = &identity;
        out.tsNs = identity.ts_ns;
        out.record.type = MsMonEtwCodeIntegrity;
        out.record.text = driver.path;
        out.record.component = BaseName(driver.path);
        out.record.value0 = driver.base;
        out.record.value1 = driver.end - driver.base;
        out.record.detail = L"decision=not_enforced;driver_load;driver=" + BaseName(driver.path) + L";reconstructed=1;base=" +
                            Hex(driver.base);
        Emit(out, sink);
    }
}
