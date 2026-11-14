#!/usr/bin/env python3
"""kfilter tuning report: what kfilter blocked, would block, allowed, and missed.

Reads one msmon session (a bundle directory, its .zip, or an events.jsonl) that holds
both msmon's own records and the kfilter_decision records msmon-agent ingested, and
sorts every observed action of every program into:

  BLOCKED          kfilter refused it (deny)
  WOULD BLOCK      audit mode: refused once the policy is switched to block (would_deny)
  ALLOWED BY RULE  kfilter allowed it, by the named rule (or by its default)
  NO RULE          msmon saw it in a layer kfilter filters, but kfilter made no decision
                   about it: a gap kfilter could close (failed actions, e.g. ENOENT, never went
                   through and are not listed; refusals are, a block may have lost its decision).
                   In a rule-only layer (Linux: peer, thread-peer, system, dns, thread, /anon
                   files, message) it means no rule names it yet.
  NOT FILTERABLE   activity classes kfilter has no layer for (signals received, capability
                   checks, trapped instructions, Wine's USER requests, ...)

then what neither tool sees (the session's coverage notes and the known residue), and
candidate rules that tighten the policy (deny by default; audit first in the rule-only
layers; exact, image-scoped allows only for what the client needs). Linux and Windows
bundles share the schema; NT and '/' paths are both understood. Writes markdown and JSON.

Example:
  tools/tuning_report.py <session-dir|bundle.zip|events.jsonl> [--policy policy.txt] \\
      --out tuning.md --json tuning.json
"""
import argparse
import functools
import json
import os
import posixpath
import re
import sys
import tempfile
import urllib.parse
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_reachability import expand_parts, leaf, KNOWN_NAMES  # noqa: E402
from kfilter_policy import records  # noqa: E402

CATEGORIES = ('blocked', 'would_block', 'allowed_by_rule', 'no_rule', 'not_filterable')
TITLES = {'blocked': 'BLOCKED', 'would_block': 'WOULD BLOCK', 'allowed_by_rule': 'ALLOWED BY RULE',
          'no_rule': 'WENT THROUGH WITH NO RULE', 'not_filterable': 'NOT FILTERABLE'}
RIGHTS = ((0x1, 'read'), (0x2, 'write'), (0x4, 'execute'), (0x8, 'delete'), (0x10, 'rename'),
          (0x20, 'set-security'), (0x40, 'enumerate'), (0x80, 'query'), (0x100, 'create'),
          (0x200, 'connect'), (0x400, 'listen'), (0x800, 'raw-device'), (0x1000, 'open'),
          (0x2000, 'send'), (0x4000, 'receive'), (0x8000, 'lock'), (0x10000, 'chdir'), (0x20000, 'touch'))
# Layers whose events carry no comparable path: a decision for the same process and layer counts.
PID_LAYERS = ('process', 'handle', 'thread-handle', 'open', 'launch', 'thread-open', 'peer', 'thread-peer',
              'thread')
# Layers whose rights are a Windows access mask, not kfilter rights.
ACCESS_LAYERS = ('handle', 'thread-handle', 'open', 'launch', 'thread-open', 'peer', 'thread-peer')
# msmon names an open by its opener's handle record; kfilter by which side is protected. Same action.
# A metadata query is a file or dir decision (rights query).
GROUPS = {'dir': 'file', 'query': 'file', 'handle': 'open', 'thread-handle': 'thread-open'}
# Wine's brokers act for the client; kfilter charges their work to the client it serves.
BROKERS = ('wineserver', 'wineserver64', 'winedevice.exe')
# Linux: Wine's loaders are every Wine program's ELF image, never the Windows name kfilter matches.
WINE_LOADER = re.compile(r'^wine(64)?(-preloader)?$')
# ... whose exec record's command line names the program: 'start.exe /exec cmd.exe', 'C:\\windows\\system32\\reg.exe'.
WINE_PROGRAM = re.compile(r'(?:^|[\s\\/])([^\s\\/;]+\.exe)(?=[\s;]|$)', re.I)
# The policy switch that turns a layer on, for gaps in a layer the policy leaves off.
LAYER_FLAGS = {'file': 'block-files', 'dir': 'block-files', 'registry': 'block-registry',
               'process': 'block-process-create', 'handle': 'block-process-memory',
               'thread-handle': 'block-process-memory', 'network': 'block-network',
               'volume': 'block-volume-serial', 'device': 'block-raw-disk', 'query': 'block-file-queries'}
IDENTITY_DEVICE = re.compile(r'^/dev/(sd|nvme|vd|hd|xvd|mmcblk|sg|sr|hidraw|bus/usb|disk/|cpu/|mem|kmem|port)|'
                             r'^\\Device\\(Harddisk|PhysicalDrive|Nsi|MountPointManager|Scsi|CdRom|Volume|Hid)', re.I)
ENDPOINT = re.compile(r'(\[[0-9A-Fa-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3}):(\d+)')
SOCKET = re.compile(r'socket:\[\d+\]')
# Seen by neither tool: listed so the report never reads as complete coverage. The session's own
# coverage notes (not_seen=) are added to these.
BLIND_SPOTS = (
    'instructions that never trap: XGETBV, RDPID, LSL/LAR, RDRAND/RDSEED, and RDFSBASE/RDGSBASE and '
    'RDPKRU unless booted with nofsgsbase/nopku (CPUID and RDTSC are seen only with --trap-cpuid/--trap-rdtsc)',
    'cache, TSX and other timing side channels',
    'game-protocol plaintext inside PE code (its own crypto, OpenSSL/BoringSSL DLLs, CEF): only ciphertext '
    'crosses a socket (--tls-keylog helps only a stack that honours SSLKEYLOGFILE)',
    'reads of memory already mapped (shared sections, Wine\'s desktop and queue shared memory, '
    'KUSER_SHARED_DATA): no syscall; msmon --page-faults sees first touches only',
    'vDSO time calls (clock_gettime, gettimeofday, getcpu): no syscall',
    'WMI ExecMethod (method calls; ExecQuery, ExecQueryAsync, GetObject and CreateInstanceEnum are decided, Linux)',
    'work done entirely inside the kernel',
    'window, process-list and handle enumeration through win32k/NtQuerySystemInformation (Windows)',
)
# NOT FILTERABLE labels (shared with tests/report_test.py).
NF_SIGNAL = 'signal received from another process or the kernel (kfilter decides signals the program sends)'
NF_CONTROL = 'process control (prctl, personality, seccomp, LDT, namespaces, credentials, capability checks)'
NF_INSN = 'trapped instruction (CPUID, RDTSC, UMIP): logged, never refused (--cpuid-mask hides leaves)'
NF_NTDLL = 'ntdll call Wine answers in-process (its wineserver requests are /system/wine/<request>)'
NF_PIPE = ('anonymous pipe I/O (the family\'s own pipes are never decided; pipes made outside it are '
           '/anon/pipe/<maker> where a rule names them)')
NF_NAMED_PIPE = ('I/O on a Wine NT object or named pipe (wineserver moves it; its open is decided, the request '
                 'is /system/wine/<request>)')
NF_UNIX = ('AF_UNIX socket I/O and the requests in it (X11, D-Bus, PulseAudio; or a socket made before tracking): '
           'its connect is a pipe decision, a send to a named peer a unix= message rule\'s (a kill switch for the connection)')
NF_SYSCALL = 'system call with no kfilter layer (lsm_*, statmount, ...)'
NF_LOCK = ('fcntl command kfilter does not decide, or a lock on something without a path (kfilter decides locks on '
           'files and directories, right lock, and /system/fcntl/<setown|setown_ex|setsig|setlease|notify|add_seals>)')
NF_UNNAMED = 'I/O on an inode msmon could not name (its open was decided by its path)'
# fcntl commands kfilter's file_fcntl decides (filter/linux/bpf/kfilter.bpf.c kb_file_fcntl).
FCNTL_DECIDED = {8: 'setown', 15: 'setown_ex', 10: 'setsig', 1024: 'setlease', 1026: 'notify', 1033: 'add_seals'}
NF_WATCH = 'a process\'s own loads and stores at a watched address (not refusable, F11)'
NF_WINE_NAME = ('NT name Wine serves itself (timer, job, mailslot, directory watch): kfilter decides the '
                'Linux file, socket or device behind it; an open by NT name (open_file_object) is a file decision')
NAME_FAILURE = '(name kfilter could not resolve: refused in block mode)'
# Every wineserver request (protocol 930, filter/linux/bpf/kfilter_bpf.h KB_WINE_REQUESTS), by number: kfilter decides
# each as /system/wine/<request> where a rule names it (named objects: /system/wine/<request>/<name>).
WINE_REQUESTS = ('new_process', 'get_new_process_info', 'new_thread', 'get_startup_info', 'init_process_done',
                 'init_first_thread', 'init_thread', 'terminate_process', 'terminate_thread', 'get_process_info',
                 'get_process_debug_info', 'get_process_image_name', 'get_process_vm_counters', 'set_process_info',
                 'get_thread_info', 'get_thread_times', 'set_thread_info', 'suspend_thread', 'resume_thread',
                 'queue_apc', 'get_apc_result', 'close_handle', 'set_handle_info', 'dup_handle',
                 'allocate_reserve_object', 'compare_objects', 'set_object_permanence', 'open_process',
                 'open_thread', 'select', 'create_event', 'event_op', 'query_event', 'open_event',
                 'create_keyed_event', 'open_keyed_event', 'create_mutex', 'release_mutex', 'open_mutex',
                 'query_mutex', 'create_semaphore', 'release_semaphore', 'query_semaphore', 'open_semaphore',
                 'create_file', 'open_file_object', 'alloc_file_handle', 'get_handle_unix_name', 'get_handle_fd',
                 'get_directory_cache_entry', 'flush', 'get_file_info', 'get_volume_info', 'lock_file',
                 'unlock_file', 'recv_socket', 'send_socket', 'socket_get_events', 'socket_send_icmp_id',
                 'socket_get_icmp_id', 'get_next_console_request', 'read_directory_changes', 'read_change',
                 'create_mapping', 'open_mapping', 'get_mapping_info', 'get_image_map_address', 'map_view',
                 'map_image_view', 'map_builtin_view', 'get_image_view_info', 'unmap_view',
                 'get_mapping_committed_range', 'add_mapping_committed_range', 'is_same_mapping',
                 'get_mapping_filename', 'list_processes', 'create_debug_obj', 'wait_debug_event',
                 'queue_exception_event', 'get_exception_status', 'continue_debug_event', 'debug_process',
                 'set_debug_obj_info', 'read_process_memory', 'write_process_memory', 'create_key', 'open_key',
                 'delete_key', 'flush_key', 'enum_key', 'set_key_value', 'get_key_value', 'enum_key_value',
                 'delete_key_value', 'load_registry', 'unload_registry', 'save_registry',
                 'set_registry_notification', 'rename_key', 'create_timer', 'open_timer', 'set_timer',
                 'cancel_timer', 'get_timer_info', 'get_thread_context', 'set_thread_context', 'add_atom',
                 'delete_atom', 'find_atom', 'get_atom_information', 'add_user_atom', 'get_user_atom_name',
                 'get_msg_queue_handle', 'get_msg_queue', 'set_queue_fd', 'set_queue_mask', 'get_queue_status',
                 'get_process_idle_event', 'send_message', 'post_quit_message', 'send_hardware_message',
                 'get_message', 'reply_message', 'accept_hardware_message', 'get_message_reply', 'set_win_timer',
                 'kill_win_timer', 'is_window_hung', 'get_serial_info', 'set_serial_info', 'cancel_sync',
                 'register_async', 'cancel_async', 'get_async_result', 'set_async_direct_result', 'read', 'write',
                 'ioctl', 'set_irp_result', 'create_named_pipe', 'set_named_pipe_info', 'create_window',
                 'destroy_window', 'get_desktop_window', 'set_window_owner', 'get_window_info', 'init_window_info',
                 'set_window_info', 'set_parent', 'get_window_parents', 'get_window_list', 'get_class_windows',
                 'get_window_children_from_point', 'get_window_tree', 'set_window_pos', 'get_window_rectangles',
                 'get_window_text', 'set_window_text', 'get_windows_offset', 'get_visible_region',
                 'get_window_region', 'set_window_region', 'get_update_region', 'update_window_zorder',
                 'redraw_window', 'set_window_property', 'remove_window_property', 'get_window_property',
                 'get_window_properties', 'create_winstation', 'open_winstation', 'close_winstation',
                 'set_winstation_monitors', 'get_process_winstation', 'set_process_winstation', 'enum_winstation',
                 'create_desktop', 'open_desktop', 'open_input_desktop', 'set_input_desktop', 'close_desktop',
                 'get_thread_desktop', 'set_thread_desktop', 'set_user_object_info', 'register_hotkey',
                 'unregister_hotkey', 'attach_thread_input', 'get_thread_input', 'get_last_input_time',
                 'get_key_state', 'set_key_state', 'set_foreground_window', 'set_focus_window', 'set_active_window',
                 'set_capture_window', 'set_caret_window', 'set_caret_info', 'set_hook', 'remove_hook',
                 'start_hook_chain', 'finish_hook_chain', 'get_hook_info', 'create_class', 'destroy_class',
                 'set_class_info', 'get_class_info', 'open_clipboard', 'close_clipboard', 'empty_clipboard',
                 'set_clipboard_data', 'get_clipboard_data', 'get_clipboard_formats', 'enum_clipboard_formats',
                 'release_clipboard', 'get_clipboard_info', 'set_clipboard_viewer', 'add_clipboard_listener',
                 'remove_clipboard_listener', 'create_token', 'open_token', 'set_desktop_shell_windows',
                 'adjust_token_privileges', 'get_token_privileges', 'check_token_privileges', 'duplicate_token',
                 'filter_token', 'access_check', 'get_token_sid', 'get_token_groups', 'get_token_default_dacl',
                 'set_token_default_dacl', 'set_security_object', 'get_security_object', 'get_system_handles',
                 'get_tcp_connections', 'get_udp_endpoints', 'create_mailslot', 'set_mailslot_info',
                 'create_directory', 'open_directory', 'get_directory_entries', 'create_symlink', 'open_symlink',
                 'query_symlink', 'get_object_info', 'get_object_name', 'get_object_type', 'get_object_types',
                 'allocate_locally_unique_id', 'create_device_manager', 'create_device', 'delete_device',
                 'get_next_device_request', 'get_kernel_object_ptr', 'set_kernel_object_ptr', 'grab_kernel_object',
                 'release_kernel_object', 'get_kernel_object_handle', 'make_process_system',
                 'grant_process_admin_token', 'get_token_info', 'create_linked_token', 'create_completion',
                 'open_completion', 'add_completion', 'remove_completion', 'get_thread_completion',
                 'query_completion', 'set_completion_info', 'add_fd_completion', 'set_fd_completion_mode',
                 'set_fd_disp_info', 'set_fd_name_info', 'set_fd_eof_info', 'get_window_layered_info',
                 'set_window_layered_info', 'alloc_user_handle', 'free_user_handle', 'set_cursor',
                 'get_cursor_history', 'get_rawinput_buffer', 'update_rawinput_devices', 'create_job', 'open_job',
                 'assign_job', 'process_in_job', 'set_job_limits', 'set_job_completion_port', 'get_job_info',
                 'terminate_job', 'suspend_process', 'resume_process', 'get_next_process', 'get_next_thread',
                 'set_keyboard_repeat', 'get_inproc_sync_fd', 'get_inproc_alert_fd', 'd3dkmt_object_create',
                 'd3dkmt_object_update', 'd3dkmt_object_query', 'd3dkmt_object_open', 'd3dkmt_share_objects',
                 'd3dkmt_object_open_name', 'd3dkmt_mutex_acquire', 'd3dkmt_mutex_release')
# ... these (KB_W_HANDLE) on a real handle to its own process or thread; by pseudo handle as
# /system/wine/self/<request>; another's is a handle or peer.
WINE_HANDLE = ('terminate_process', 'terminate_thread', 'suspend_thread', 'resume_thread', 'queue_apc',
               'debug_process', 'read_process_memory', 'write_process_memory', 'get_thread_context',
               'set_thread_context', 'suspend_process', 'resume_process', 'get_process_info', 'get_process_debug_info',
               'get_process_image_name', 'get_process_vm_counters', 'set_process_info', 'get_mapping_filename')
NAMED_OBJECTS = re.compile(r'^(create|open)_(event|mutex|semaphore|mapping|directory|symlink)$')
# The syscalls msmon records as system:<call> that a kfilter /system name decides.
SYSTEM_CALLS = {'uname': '/system/uname', 'sysinfo': '/system/sysinfo', 'keyctl': '/system/keyring',
                'add_key': '/system/keyring', 'request_key': '/system/keyring',
                'io_uring_enter': '/system/io_uring', 'io_uring_register': '/system/io_uring',
                'sched_setaffinity': '/system/sched', 'sched_setscheduler': '/system/sched',
                'sched_setparam': '/system/sched', 'sched_setattr': '/system/sched', 'setpriority': '/system/sched/nice',
                'ioprio_set': '/system/sched/ioprio', 'mount': '/system/mount', 'umount': '/system/mount',
                'umount2': '/system/mount', 'pivot_root': '/system/mount', 'move_mount': '/system/mount',
                'syslog': '/system/syslog', 'clock_settime': '/system/time', 'settimeofday': '/system/time',
                'adjtimex': '/system/time', 'clock_adjtime': '/system/time'}
SOCKET_FAMILIES = {1: 'unix', 2: 'inet', 10: 'inet6', 16: 'netlink', 17: 'packet'}
SOCKET_TYPES = {1: 'stream', 2: 'dgram', 3: 'raw', 5: 'seqpacket'}
# How much of a /system name is its class (a decision anywhere in the class covers msmon's record,
# which names less): /system/memory/private/rx -> /system/memory/private, /system/wine/create_mutex/x
# -> /system/wine/create_mutex.
# Windows access names kfilterctl takes on handle, open, thread-handle and thread-open rules.
PROCESS_ACCESS = ((0x1, 'terminate'), (0x2, 'create-thread'), (0x8, 'vm-operation'), (0x10, 'vm-read'),
                  (0x20, 'vm-write'), (0x40, 'dup-handle'), (0x80, 'create-process'), (0x100, 'set-quota'),
                  (0x200, 'set-information'), (0x400, 'query-information'), (0x800, 'suspend-resume'),
                  (0x1000, 'query-limited-information'), (0x2000, 'set-limited-information'))
THREAD_ACCESS = ((0x1, 'terminate'), (0x2, 'suspend-resume'), (0x8, 'get-context'), (0x10, 'set-context'),
                 (0x20, 'set-information'), (0x40, 'query-information'), (0x80, 'set-thread-token'),
                 (0x100, 'impersonate'), (0x200, 'direct-impersonation'), (0x400, 'set-limited-information'),
                 (0x800, 'query-limited-information'))
STANDARD_ACCESS = ((0x10000, 'delete'), (0x20000, 'read-control'), (0x40000, 'write-dac'), (0x80000, 'write-owner'),
                   (0x100000, 'synchronize'))
SYSTEM_DEPTH = {'sockopt': 3, 'wine': 4, 'arch_prctl': 4, 'memfd': 3, 'memory': 4, 'keyring': 3, 'ipc': 4}


def detail_fields(detail):
    """key=value pairs of a detail string; rule= is last and may itself hold ';'."""
    detail = detail or ''
    rule = None
    cut = detail.find(';rule=') if not detail.startswith('rule=') else -1
    if detail.startswith('rule='):
        detail, rule = '', detail[5:]
    elif cut >= 0:
        detail, rule = detail[:cut], detail[cut + 6:]
    fields = dict(part.split('=', 1) for part in detail.split(';') if '=' in part)
    if 'image' in fields:  # msmon percent-encodes '%', ';' and '=' in the program name
        fields['image'] = urllib.parse.unquote(fields['image'])
    if rule is not None:
        fields['rule'] = rule
    return fields


def rights_names(fields):
    if (fields.get('layer') or fields.get('target')) == 'dns':
        return 'query'   # kb_dns decides query; its value is the query type (1 A, 28 AAAA), not rights
    if fields.get('rights_names'):
        return fields['rights_names']
    if (fields.get('layer') or fields.get('target')) in ACCESS_LAYERS:
        return fields.get('access') or fields.get('rights', '')
    try:
        value = int(fields.get('rights', '0'), 16)
    except ValueError:
        return ''
    return ','.join(name for bit, name in RIGHTS if value & bit)


def remote_endpoint(path):
    """msmon writes 'local:port -> remote:port', kfilter only the remote: the last endpoint."""
    matches = list(ENDPOINT.finditer(path))
    return matches[-1] if matches else None


@functools.lru_cache(maxsize=65536)
def resolved(path):
    return os.path.realpath(path)


@functools.lru_cache(maxsize=65536)
def sysfs_real(path):
    # shortcut: sysfs symlinks (/sys/bus/usb/devices/1-14 -> /sys/devices/...) are resolved on the machine
    # running the report, as kfilter resolved them; right when monfilter.py writes the report after the run.
    return os.path.realpath(path)   # resolves the existing part of the path, also when the leaf is gone


def key_of(layer, path):
    if layer in ('network', 'message'):
        # A message decision names its connection (socket:[inode]) as msmon's socket I/O does.
        connection = SOCKET.search(path) if layer == 'message' else None
        match = remote_endpoint(path)
        return connection.group(0) if connection else match.group(0).lower() if match else path.lower()
    if layer == 'dns':
        return path.lower().rstrip('.')
    if path.lower().endswith('.sys'):
        return leaf(path).lower()   # a driver: msmon names \??\C:\...\drivers\x.sys, kfilter Wine's own file
    if layer == 'pipe' and path.startswith('unix:'):
        path = '/' + path[5:] if path.startswith('unix:@') else path[5:]   # kfilter: /@name for an abstract socket
    if not path.startswith('/'):
        return path.lower()
    # kfilter names the resolved file: no '//' or '..', and Wine's drive links C: (../drive_c) and Z: (/) followed.
    # shortcut: other drive letters and symlinks are not resolved offline; they stay apart from their decision.
    path = posixpath.normpath(re.sub(r'/+', '/', path))   # posixpath: also on Windows
    path = re.sub(r'/dosdevices/c:(?=/|$)', '/drive_c', path)
    path = re.sub(r'^.*/dosdevices/z:(?=/)', '', path)
    return class_of(sysfs_real(path) if path.startswith('/sys/') else path)


def class_of(path):
    """The part of a kfilter name msmon can also name: /proc/<pid> and /proc/@self alike, a thread's
    id, a pseudo file's class, a /system name's class."""
    path = re.sub(r'^/proc/(@[a-z]+|\d+|self|thread-self)(?=/|$)', '/proc/@', path)
    path = re.sub(r'/task/\d+(?=/|$)', '/task/*', path)
    path = re.sub(r'^/anon/(memfd:|SYSV|pipe/).*', lambda match: '/anon/' + match[1].rstrip(':/'), path)
    path = re.sub(r'^/net/netlink/.*', '/net/netlink', path)
    parts = path.split('/')
    if path.startswith('/system/'):
        own = parts[2] == 'wine' and len(parts) > 3 and parts[3] == 'self'   # /system/wine/self/<request>
        path = '/'.join(parts[:SYSTEM_DEPTH.get(parts[2], len(parts)) + own])
        path = path.lower() if path.startswith('/system/wmi/') else path
    return path


def shown_path(layer, path):
    """A decision's path as listed: one line per connection peer, per thread-less /proc name."""
    if layer == 'message':
        return re.sub(r' socket:\[\d+\].*', '', path)
    return re.sub(r'^(/proc/@[a-z]+/task/)\d+', r'\g<1>*', path)


def failed(record):
    """An action that failed (NT error severity, which a negative errno shares) never went through;
    a refusal (EPERM, EACCES, ACCESS_DENIED) still counts: it may be a block whose decision was lost."""
    status = int(record.get('status') or 0) & 0xFFFFFFFF
    return (status & 0xC0000000) == 0xC0000000 and status not in (0xFFFFFFFF, 0xFFFFFFF3, 0xC0000022)


def group_of(layer):
    return GROUPS.get(layer, layer)


def argument(fields, index):
    """A syscall record's argument (args=0x..,0x..), 0 when it is missing or unreadable."""
    try:
        return int(fields.get('args', '').split(',')[index], 16)
    except (IndexError, ValueError):
        return 0


def system_call_layer(text, fields):
    """(layer, path) of a system:<name> record: a syscall, a trapped instruction, a win32u/ntdll call
    Wine answers in-process, or a wineserver request."""
    name = text[len('system:'):]
    if fields.get('source') in ('sigsegv', 'umip_emulated') or 'insn' in fields:
        return '', NF_INSN
    if 'library' in fields:
        return ('system', f'/system/win32k/{name}') if fields['library'].endswith('win32u.so') else ('', NF_NTDLL)
    if 'ws' in fields:
        return 'system', f'/system/wine/{name}'
    if name in SYSTEM_CALLS:
        return 'system', SYSTEM_CALLS[name]
    if name in ('bpf', 'perf_event_open'):
        return 'process', ''   # refused for every protected program, as a process decision with no path
    return '', NF_SYSCALL


def observed_layer(record, fields, families=None):
    """(layer, path) for an msmon record kfilter could decide, path in kfilter's terms where msmon
    can name it; ('', reason) if no kfilter layer can; None for bookkeeping records that are not
    actions or whose decision is another record's (a view of a mapping, a served device request)."""
    kind = record['type']
    text = record.get('text') or ''
    detail = record.get('detail') or ''
    first = detail.split(';', 1)[0]
    call = fields.get('syscall', '').replace('wineserver:', '')
    op = call if first == 'repeats_tail' or first.startswith('syscall=') else first
    linux = text.startswith('/') or 'syscall=' in detail
    # Linux (a Wine loader's record): an NT name is one wineserver serves; kfilter never decides it by that name.
    wine_name = text.startswith('\\') and (record.get('process_path') or '').startswith('/')
    if kind in ('process_exit', 'thread_exit', 'file_close', 'file_cleanup', 'file_flush', 'network_flow_close',
                'coverage', 'coverage_usage', 'kfilter_decision') or kind.startswith('observer'):
        return None
    if op in ('map_view', 'map_image_view', 'unmap_view', 'new_process', 'apc_result', 'create_device') or \
            'irp' in fields or (kind.startswith('file_') and fields.get('ws', '').startswith('set_fd')):
        return None   # decided at the mapping, the child's exec, the driver's own syscalls, wineserver's rename
    if op == 'image_unload':
        return None   # the /proc maps poll found a library gone (a dlclose): an observation, not an action
    if first == 'repeats_tail' and ';aggregate=kernel;ino=' in detail and 'attribution=native_helper' in detail:
        return None   # a native helper's I/O counted per inode: its sampled record (native_io=sampled) is decided
    if kind == 'process_start':
        return ('process', text) if text else None   # a fork: its exec, if any, is the decided creation
    if kind == 'thread_start':
        return 'thread', ''
    if kind == 'image_load':   # anon_pe: names a region whose own record is the action (/system/memory/image)
        if text.startswith('/') and 'source' not in fields:
            # The kernel sensors write every mapping as it is made (source=mmap/mprotect); the /proc maps
            # poll adds only those already there when msmon looked (a process running before it).
            return '', 'mapping already present when msmon looked (the process ran before it)'
        return None if text.startswith('anon_pe:') else ('file', text)
    if kind == 'process_handle' and (text.startswith('watch:') or op.startswith('watch_')):
        return '', NF_WATCH   # msmon's hardware watchpoints (watch_*) on the process itself: no rule decides them
    if kind in ('process_handle', 'thread_handle'):
        return ('handle' if kind == 'process_handle' else 'thread-handle'), text   # analyze() sorts these
    if kind.startswith('registry_'):
        return 'registry', text
    if kind == 'etw_wmi':
        if text.startswith('query:'):   # Linux: wbemprox's ExecQuery in the program, by WQL class
            name = text[len('query:'):]
            return 'system', '/system/wmi/' + ('@other' if name == 'unknown' else name.lower())
        return ('', 'WMI COM activation or provider load (its query is /system/wmi/<class>)') if linux or \
            text.startswith(('com:', 'module:')) else ('', 'WMI query (served by the WMI service)')
    if kind == 'etw_rpc':   # a desktop service's summary (unix_service) names socket:[ino] when its connect went unseen
        return ('', NF_UNIX) if text.startswith('unix:') or call == 'unix_service' else ('', 'RPC/ALPC call to a service')
    if kind == 'etw_dns':
        return 'dns', text
    if kind == 'etw_code_integrity':
        return ('file', text) if text.lower().endswith('.sys') and not wine_name else ('', 'code integrity check')
    if kind == 'etw_tcp':
        if fields.get('to') == 'LISTEN':   # kfilter names a listen by its local address, the first endpoint
            return 'network', text.split(' -> ')[0]
        return None if fields.get('to') == 'CLOSE' else ('network', text)   # a socket's teardown: no action
    if kind.startswith('network_') or (op == 'socket' and 'family' in fields):
        family = fields.get('family', '')
        if family == '16':
            return 'device', '/net/netlink'   # netlink: adapter and route queries (block-network-adapter)
        if op == 'socket':
            number = int(family or 0)
            kind_number = int(fields.get('type', '0') or 0)
            return 'system', (f"/system/socket/{SOCKET_FAMILIES.get(number, number)}/"
                              f"{SOCKET_TYPES.get(kind_number, kind_number)}/{fields.get('protocol', '0')}")
        if family == '1' or text.startswith(('@', '/', 'unix:')):
            # AF_UNIX: kfilter's pipe rules decide the connect; the socket I/O after it is not decided.
            if op in ('sendto', 'recvfrom', 'sendmsg', 'recvmsg'):
                return '', NF_UNIX
            path = text[len('unix:'):] if text.startswith('unix:') else text
            return 'pipe', '/' + path if path.startswith('@') else path
        # Not connections kfilter could decide here: a bind is decided at its listen or connect, and
        # Wine's Winsock requests by the socket call wineserver then makes.
        if op == 'listen' and text.startswith('socket:'):
            # shortcut: assumes msmon's tcp state records are on; their LISTEN record names the address.
            return None
        if op == 'bind' and text.endswith(':0'):
            return '', 'bind to an ephemeral port (decided at listen and connect)'
        if op == 'connect' and family == '0':
            return '', 'connect to AF_UNSPEC (ends a datagram association)'
        if 'ws' in fields:
            return '', 'Winsock request to wineserver (the socket call it makes is decided)'
        return ('message' if op in ('sendto', 'recvfrom', 'sendmsg', 'recvmsg') else 'network'), text
    if not kind.startswith('file_'):
        return '', f'other: {kind}'
    if kind == 'file_device_control' and op in ('fcntl', 'flock'):
        # Locks (F_SETLK/F_SETLKW/OFD, flock other than LOCK_UN) are file_lock's file or dir decision on the path.
        locks = op == 'flock' and not argument(fields, 1) & 8 or op == 'fcntl' and argument(fields, 1) in (6, 7, 37, 38)
        if locks:
            return ('file', text) if text.startswith('/') else ('', NF_LOCK)
        name = FCNTL_DECIDED.get(argument(fields, 1)) if op == 'fcntl' else None
        return ('system', f'/system/fcntl/{name}') if name else ('', NF_LOCK)
    pipe_name =text.lower().startswith(('\\??\\pipe\\', '\\pipe\\', '\\device\\namedpipe\\'))
    if pipe_name or op == 'create_named_pipe':
        # Wine's create_named_pipe / open_file_object: kfilter decides it as a pipe, by its NT name.
        if pipe_name and kind == 'file_create':
            return 'pipe', text
        return ('system', f"/system/wine/{fields['ws']}") if fields.get('ws') in WINE_REQUESTS else ('', NF_NAMED_PIPE)
    if NAMED_OBJECTS.match(op):
        if not text or text.endswith('\\'):
            return None   # unnamed objects are not decided
        # A named section is decided as a file by its NT name (shared memory); the other objects only
        # where a rule names /system/wine/<op>/<name>.
        return ('file', text) if op.endswith('_mapping') else ('system', f'/system/wine/{op}')
    if op in ('open_desktop', 'open_winstation'):
        return 'system', f'/system/wine/{op}'
    if op in ('create_winstation', 'create_desktop'):
        return 'system', f'/system/wine/{op}'
    if wine_name:   # an open by NT name (\??\PhysicalDrive0, \Device\Afd) is decided as a file by that name
        if op == 'open_file_object':
            return 'file', text
        return ('system', f'/system/wine/{op}') if op in WINE_REQUESTS else ('', NF_WINE_NAME)
    if text.startswith('handle:') and 'ws' in fields:
        return 'system', f"/system/wine/{fields['ws']}"   # read, write or ioctl on a handle msmon could not name
    if text.startswith('system:'):
        return system_call_layer(text, fields)
    if text.startswith(('sysv_shm:', 'sysv_msg:', 'sysv_sem:')):
        if ':addr=' in text:
            return None   # shmdt: the attach was decided
        what, _, value = text.partition(':')
        key = f'/{int(value.split("=", 1)[1], 16) & 0xFFFFFFFF:08x}' if value.startswith('key=') else ''
        return 'system', f'/system/ipc/{what[len("sysv_"):]}{key}'
    if text.startswith('mq:'):
        return 'file', '/anon/mqueue' + text[len('mq:'):]
    if text.startswith('memfd:'):
        name = text[len('memfd:'):]
        return ('system', f'/system/memfd/{name}') if op == 'memfd_create' else ('file', '/anon/memfd:' + name)
    for prefix, name in (('userfaultfd:', 'userfaultfd'), ('memfd_secret:', 'secretmem'),
                         ('io_uring_setup:', 'io_uring')):
        if text.startswith(prefix):
            return 'system', f'/system/{name}'
    if text.startswith('fanotify_init:'):
        return '', 'fanotify group (needs CAP_SYS_ADMIN; its marks are decided as watches)'
    if text.startswith('tls:session='):
        return '', 'TLS plaintext through Wine\'s schannel (the socket sends are message rules on ciphertext)'
    if text in ('anonymous', '') and kind == 'file_section' or text.startswith('mprotect:'):
        if 'anon_pe' not in fields and 'first_page_sha256' not in fields:
            return None   # a file mapping made executable: decided as its file's execute (its image_load)
        rwx = argument(fields, 2) & 2   # PROT_WRITE besides PROT_EXEC
        return 'system', f"/system/memory/{'image' if 'anon_pe' in fields else 'private'}/{'rwx' if rwx else 'rx'}"
    if op in ('inotify_add_watch', 'fanotify_mark'):
        return 'query', text   # path_notify: enumerate on a dir, read on a file (block-file-queries)
    if text.startswith('pipe:'):
        return '', NF_PIPE
    if re.match(r'(file|dir|char|anon_inode):\[\d+\]$', text) and kind != 'file_device_control':
        return '', NF_UNNAMED
    if text.startswith('socket:'):
        if op in ('getsockopt', 'setsockopt'):
            return 'system', '/system/sockopt'   # kfilter: /system/sockopt/<level>/<optname>
        if op in ('getsockname', 'getpeername'):
            return 'system', f'/system/{op[3:]}'
        if op == 'ioctl':
            return 'device', '/net/ioctl'   # SIOCGIF*: adapter queries
        # Message rules decide INET sockets only; the family comes from the socket's creation or join.
        return ('message', text) if (families or {}).get(text) in ('2', '10') else ('', NF_UNIX)
    if kind == 'file_device_control':
        if text.startswith('anon_inode:'):
            return 'device', '/anon'
        return ('device', text) if IDENTITY_DEVICE.match(text) or linux else \
            ('', 'device ioctl on a non-identity device (its open is decided as a file)')
    if kind in ('file_query_information', 'file_query_ea', 'file_query_volume_information') and linux:
        if op in ('statfs', 'fstatfs') or kind == 'file_query_volume_information':
            return 'volume', text   # logged as an audit volume decision, never refused
        flags = {'newfstatat': 3, 'statx': 2}.get(op)
        if op.startswith(('fstat', 'fget', 'flist')) and op != 'fstatat' or \
                (flags is not None and argument(fields, flags) & 0x1000):
            return None   # on an fd (AT_EMPTY_PATH): decided at its open
        return ('query', text) if text else ('', 'file operation without a path')
    if kind == 'file_query_information':
        return None   # Windows: decided at the open
    if kind == 'file_query_volume_information':
        return 'volume', text
    if kind == 'file_directory_control':
        return 'dir', text
    if not text:
        return '', 'file operation without a path'
    return 'file', text


def load_policy_rules(path):
    """Rule ID -> rule line, numbered as kfilterctl numbers them: path rules 1.., network and
    message rules 10001.. (see ParsePolicy in tool/kfilterctl.cpp)."""
    rules, flags = {}, set()
    if not path or not os.path.exists(path):
        return rules, None
    numbered = network = 0
    with open(path, encoding='utf-8-sig') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            fields = line.split('|') if '|' in line else line.split()
            if fields[0] in ('allow', 'deny', 'audit') and len(fields) > 1:
                if fields[1] in ('network', 'message'):
                    network += 1
                    rules[10000 + network] = line
                else:
                    numbered += 1
                    rules[numbered] = line
            elif fields[0].startswith(('block-', 'default-deny')) and (len(fields) < 2 or fields[1] != 'off'):
                flags.add(fields[0])
            elif fields[0] == 'message-default':
                flags.add('message-default')
    return rules, flags


def event_paths(bundle, scratch):
    """(event parts, policy file, directory holding client/) of a bundle directory, .zip or events.jsonl."""
    if os.path.isdir(bundle):
        parts = expand_parts(os.path.join(bundle, 'events.jsonl'))
        return parts, os.path.join(bundle, 'kfilter-policy.txt'), bundle
    if zipfile.is_zipfile(bundle):
        with zipfile.ZipFile(bundle) as archive:
            names = [name for name in archive.namelist()
                     if re.fullmatch(r'events\.jsonl(\.\d+)?|kfilter-policy\.txt|client/cpu-trap\.log', name)]
            archive.extractall(scratch, names)
        return (expand_parts(os.path.join(scratch, 'events.jsonl')), os.path.join(scratch, 'kfilter-policy.txt'),
                scratch)
    return expand_parts(bundle), '', os.path.dirname(bundle)


def cpu_trap(directory):
    """client/cpu-trap.log (monfilter run --trap-cpuid/--trap-rdtsc), or the log file Directory names, as the client
    itself reported it: {instruction: {'count', 'processes', 'leaves', 'masked'}}; {} without the log."""
    summary = {}
    path = directory if os.path.isfile(directory) else os.path.join(directory, 'client', 'cpu-trap.log')
    try:
        with open(path, encoding='utf-8', errors='replace') as log:
            for line in log:
                fields = dict(part.split('=', 1) for part in line.split() if '=' in part)
                if 'insn' not in fields:
                    continue
                entry = summary.setdefault(fields['insn'], {'count': 0, 'processes': set(), 'leaves': set(),
                                                            'masked': set()})
                entry['processes'].add(fields.get('exe', '?'))
                entry['count'] += int(fields.get('count', '0') or 0)
                if 'leaf' in fields:
                    (entry['masked'] if fields.get('masked') == '1' else entry['leaves']).add(fields['leaf'])
    except OSError:
        return {}
    return {insn: {key: sorted(value) if isinstance(value, set) else value for key, value in entry.items()}
            for insn, entry in summary.items()}


def not_seen(coverage):
    """BLIND_SPOTS plus what the session's coverage notes say they did not see (not_seen=a(why),b)."""
    items = list(BLIND_SPOTS)
    for state, detail in sorted(coverage.items()):
        value = detail_fields(detail).get('not_seen', '')
        for item in re.findall(r'[^,(]+(?:\([^)]*\))?', value):
            item = item.strip().replace('_', ' ')
            if item and item not in items:
                items.append(f'{item} ({state})')
    return items


def program_name(path):
    return leaf(path) if path else ''


# Calls that change how the process itself runs; capability checks and credential changes too.
CONTROL_OPS = ('prctl', 'personality', 'seccomp', 'modify_ldt', 'set_thread_area', 'unshare', 'setns', 'clone',
               'clone3', 'setuid', 'setgid', 'setreuid', 'setregid', 'setresuid', 'setresgid', 'setfsuid',
               'setfsgid', 'setgroups', 'capset', 'capability', 'cred_change')
MESSAGE_NO_RULES = 'socket send/receive (the policy has no message rule: decided only at connect)'


def handle_layer(layer, path, record, fields, pid, protected, image_of, owner):
    """(layer, path, shown) of a process or thread record: a handle crossing the family, one between
    protected programs (peer), a Wine request decided as /system/wine/<request>, or ('', reason, example)."""
    target = int(record.get('target_process_id') or 0)
    first = (record.get('detail') or '').split(';', 1)[0]
    operation = fields.get('syscall', first).replace('wineserver:', '') if first == 'repeats_tail' else first
    pseudo = fields.get('handle') in ('0xffffffff', '0xfffffffe')
    own = target == pid or (target and owner.get(target) == pid) or pseudo or \
        (not target and 'win_pid' not in fields and 'handle' not in fields)
    if 'served_request' in fields:
        return '', '', ''   # wineserver signalling a client for a request: the request is the decided action
    shown = path or f"{operation} -> {image_of(target) if target else 'unknown'}"
    if operation == 'new_thread' and not target:
        return '', 'first thread of a new process (decided as the process creation)', shown
    if layer == 'handle' and operation == 'dup_handle' and fields.get('object') == 'unknown' and \
            int((re.search(r';options=(0x[0-9a-f]+)', record.get('detail') or '') or [0, '0x0'])[1], 16) & 2:
        return '', 'copy of a handle that is no process or thread, with the same access (no new right)', shown
    # Its own thread's context, its own memory (a repeats_tail record names no handle: left as its own request).
    if operation in WINE_HANDLE and own and 'handle' in fields:
        name = f"/system/wine/{'self/' if pseudo else ''}{operation}"
        return 'system', name, name
    if operation in WINE_REQUESTS and operation not in WINE_HANDLE and own:   # its token, hiding from a debugger, its jobs
        return 'system', f'/system/wine/{operation}', f'/system/wine/{operation}'
    if operation == 'arch_prctl':
        name = f"/system/arch_prctl/{int(fields.get('option', '0') or '0', 0):#x}"
        return 'system', name, name
    if operation in SYSTEM_CALLS:   # scheduling another task (wineserver: a client's thread)
        return 'system', SYSTEM_CALLS[operation], SYSTEM_CALLS[operation]
    if operation == 'signal_received':
        return '', NF_SIGNAL, shown
    if operation == 'module_request':
        return '', 'kernel module autoload request (decide the socket family that asks: /system/socket/...)', path
    if operation in CONTROL_OPS or operation.startswith('capability'):
        return '', NF_CONTROL, shown
    if own:
        return '', 'request on its own process (process info, jobs, tokens, limits, scheduling)', shown
    if pid in protected and target in protected:
        return ('peer' if layer == 'handle' else 'thread-peer'), path, shown
    return layer, path, shown


def analyze(parts, policy_path):
    rules, policy_flags = load_policy_rules(policy_path)
    decisions, observed, images, coverage = [], [], {}, {}
    named, weak_images = {}, {}
    owner, families = {}, {}   # thread id -> process; socket:[inode] -> address family

    def windows_name(path):
        name = program_name(path)
        return '' if WINE_LOADER.match(name) else name

    for part in parts:
        for record in records(part):
            pid = int(record['process_id'])
            fields = detail_fields(record.get('detail'))
            kind = record['type']
            if kind == 'coverage':
                coverage[record.get('text') or ''] = record.get('detail') or ''
            elif kind == 'kfilter_decision':
                decisions.append((pid, record.get('text') or '', fields))
                if windows_name(fields.get('image')):
                    named[pid] = fields['image']   # the name kfilter matches image= against; latest wins
                elif fields.get('target') in ('handle', 'thread-handle') and (record.get('text') or '').startswith('/'):
                    weak_images.setdefault(pid, program_name(record['text']))   # an outside opener: its own program
                continue
            if kind == 'process_start' and windows_name(record.get('text')):
                images.setdefault(pid, windows_name(record['text']))
            elif kind == 'process_start':
                # Linux: a Wine process kfilter never named (unprotected); the latest exec names it.
                found = WINE_PROGRAM.search(record.get('detail') or '')
                if found:
                    images[pid] = found.group(1)
            if windows_name(record.get('process_path')):
                weak_images.setdefault(pid, windows_name(record['process_path']))
            elif kind == 'image_load' and (record.get('text') or '').lower().endswith('.exe'):
                # A Wine program msmon joined running (services.exe, plugplay.exe): its .exe image names it.
                weak_images.setdefault(pid, program_name(record['text']))
            owner[int(record.get('thread_id') or 0)] = pid
            if 'family' in fields:   # a socket's creation, or its join (value0 the inode)
                text = record.get('text') or ''
                families[text if text.startswith('socket:') else f"socket:[{record.get('value0')}]"] = fields['family']
            observed.append((pid, record, fields))

    def image_of(pid):
        return named.get(pid) or images.get(pid) or weak_images.get(pid) or f'pid {pid}'

    programs = {}

    def add(image, category, layer, path, count=1, **extra):
        bucket = programs.setdefault(image, {}).setdefault(category, {})
        entry = bucket.setdefault((layer, path, extra.get('rule_id', 0)),
                                  dict(layer=layer, path=path, count=0, **extra))
        entry['count'] += count
        if extra.get('rights'):
            names = set(filter(None, entry['rights'].split(','))) | set(extra['rights'].split(','))
            entry['rights'] = ','.join(sorted(names))
        return entry

    decided_path, decided_pid, decided_any = set(), set(), set()
    protected = set(named)   # pids kfilter decided for under a Windows name: the protected family
    # kfilter never refuses in audit mode: a refusal (EACCES, EPERM, ACCESS_DENIED) there is the system's own.
    audit_run = 'mode=audit;' in coverage.get('kfilter_status', '')
    # unix= rules decide AF_UNIX sends alone: the kernel counts no INET message rule for them (kb_cfg.msg_count).
    no_message_rules = policy_flags is not None and 'message-default' not in policy_flags and not any(
        (line.split('|') if '|' in line else line.split())[1:2] == ['message'] and '|unix=' not in line
        for line in rules.values())
    for pid, path, fields in decisions:
        decision = fields.get('decision') or fields.get('action', '')
        layer = fields.get('layer') or fields.get('target', 'unknown')
        layer = 'process' if layer == 'process_create' else layer
        image = fields.get('image') or image_of(pid)
        rule_id = int(fields.get('rule_id', '0') or 0)
        count = int(fields.get('repeat', '1') or 1)
        rule = fields.get('rule') or rules.get(rule_id, '') or ('(default: no rule matched)' if rule_id == 0 else
                                                                f'rule {rule_id}')
        if not path and 'name_failure' in fields.get('flags_names', ''):
            path = NAME_FAILURE
        category = {'deny': 'blocked', 'would_deny': 'would_block'}.get(decision, 'allowed_by_rule')
        add(image, category, layer, shown_path(layer, path), count, rule_id=rule_id, rule=rule,
            rights=rights_names(fields), decision=decision)
        # By pid only: a same-named copy kfilter never protected must still show as a gap. A message
        # decision covers its connection and its peer (a sendto record names only the peer).
        endpoint = remote_endpoint(path) if layer == 'message' else None
        for key in {key_of(layer, path)} | ({endpoint.group(0).lower()} if endpoint else set()):
            decided_path.add((group_of(layer), key, pid))
            decided_any.add((group_of(layer), key))
        decided_pid.add((group_of(layer), pid))

    # Allowed metadata queries leave no event (only refusals, audits and would-denies do).
    status_flags = int(detail_fields(coverage.get('kfilter_status', '')).get('flags', '0') or '0', 16)
    queries_decided = (policy_flags is not None and 'block-file-queries' in policy_flags) or \
        bool(status_flags & 0x1000)
    quiet_queries = 0
    for pid, record, fields in observed:
        result = observed_layer(record, fields, families)
        if result is None:
            continue
        layer, path = result
        image = image_of(pid)
        if layer in ('handle', 'thread-handle'):
            layer, path, shown = handle_layer(layer, path, record, fields, pid, protected, image_of, owner)
            if not layer and not path:
                continue
        else:
            shown = path   # matched on the path msmon wrote (or its kfilter name); listed under it
        if not layer:
            # One entry per class and program; the first action seen is its example.
            add(image, 'not_filterable', path, '').setdefault('example', shown or record.get('text') or '')
            continue
        if layer == 'message' and no_message_rules:
            add(image, 'no_rule', 'message', MESSAGE_NO_RULES, rights='')
            continue
        group, key = group_of(layer), key_of(layer, path)
        # msmon could not name the key or file (a handle opened before tracking): kfilter names it, so any
        # decision of that program in the layer counts, as for the PID layers.
        pid_layer = layer in PID_LAYERS or path.startswith(('hkey:', 'handle:'))
        if layer == 'process' and record['type'] == 'process_start':
            if record.get('status') or (record.get('detail') or '').startswith(('exec_failed', 'clone_failed')):
                continue   # refused (by kfilter or anything else): it never went through
            # Windows decides a creation in the creator's context (its pid and image); Linux at the
            # exec, in the process's own. Either way the requester is named like its parent.
            creator = int(record.get('parent_process_id') or 0)
            if (group, key, creator) in decided_path:
                continue
            image, pid_layer = image_of(creator), path.startswith('/')
        if ((group, key, pid) in decided_path or (pid_layer and (group, pid) in decided_pid) or
                (image.lower() in BROKERS and (group, key) in decided_any) or failed(record) or
                (audit_run and int(record.get('status') or 0) != 0)):
            continue
        if key.startswith('/') and not pid_layer:
            # kfilter names the file a symlink leads to (fonts -> /usr/share/javascript/...): resolved on the
            # machine running the report, only for what would otherwise be a gap.
            real = class_of(resolved(key))
            if real != key and ((group, real, pid) in decided_path or
                                (image.lower() in BROKERS and (group, real) in decided_any)):
                continue
        if layer == 'query' and queries_decided:
            quiet_queries += 1
            continue
        add(image, 'no_rule', layer, shown, rights='')

    for image in programs:
        for category in CATEGORIES:
            entries = programs[image].get(category, {}).values()
            programs[image][category] = sorted(entries, key=lambda entry: -entry['count'])
    if quiet_queries:
        coverage['report_quiet_queries'] = str(quiet_queries)
    return programs, coverage, rules, policy_flags, len(decisions), len(observed)


def gap_rule(layer, path, image, scope):
    """The candidate rule for a gap: a deny where the layer refuses by default, an audit first where
    kfilter decides only what a rule names (Linux rule-only layers and namespaces), else a review line."""
    review = f'# review {layer} {path or "(no path)"} by {image}: no kfilter decision'
    if layer in ('network', 'message'):
        if path == MESSAGE_NO_RULES:
            return 'audit|message|rights=send|index=1'
        match = remote_endpoint(path)
        return f'deny|{layer}|ip={match.group(1).strip("[]")}|port={match.group(2)}{scope}' if match else review
    if layer in ('peer', 'thread-peer'):
        target = path.rsplit('-> ', 1)[-1]
        return review if target.startswith(('pid ', 'unknown')) else f'audit|{layer}|\\{target}{scope}'
    if layer == 'thread':
        return review if image.startswith('pid ') else f'audit|thread|\\{image}'
    if layer == 'dns':
        return f"{'deny' if path.startswith('wpad') else 'audit'}|dns|{path}{scope}"
    if layer == 'system':
        return f'audit|system|{path}{scope}'
    if path.startswith('/anon/'):
        name = class_of(path)
        return f"audit|{layer}|{name + (':*' if name == '/anon/memfd' else '*' if name == '/anon/SYSV' else '')}{scope}"
    if layer == 'device' and path.startswith(('/net/', '/anon')):
        return review   # adapter queries are block-network-adapter's; anonymous inodes have no name msmon knows
    if layer == 'device' and not IDENTITY_DEVICE.match(path) and path.startswith('/'):
        # any ioctl on it, logged (rule-only); a file's or directory's ioctls are left to review
        return f'audit|device|{path}{scope}' if path.startswith('/dev/') else review
    if layer == 'query' or (layer == 'volume' and path.startswith('/')):
        return ''   # block-file-queries decides them all; Linux statfs is only logged (block-volume-serial)
    if layer in ('file', 'dir') and path.startswith(('/', '\\')):
        parent = re.split(r'[\\/][^\\/]*$', path)[0] or path
        return review if parent in ('/', '\\') else f'deny|file|{parent}{scope}'   # no rule names the root
    if (layer in PID_LAYERS and layer != 'process') or not path.startswith(('/', '\\')) or \
            WINE_LOADER.match(program_name(path)):   # denying a loader stops all of Wine
        return review
    return f'deny|{layer}|{path}{scope}'


def candidates(programs, policy_flags, limit, existing=()):
    """Rules that tighten the policy. Gaps get denies (or the switch for their layer; an audit rule
    first in a rule-only layer); broad allows get exact, image-scoped replacements; would-blocks get
    exact allows only as a reminder of what to add back if the client needs it. Lines the policy
    already has are not repeated."""
    tighten, needed = [], []
    seen = set(existing)

    def emit(target, rule, reason):
        if rule and rule not in seen:
            seen.add(rule)
            target.append({'rule': rule, 'reason': reason})

    # An exact allow needs rights and a name (not the root); network, message and device allows also a uses=
    # budget: review those.
    def exact(entry):
        path = entry['path']
        return entry['layer'] not in ('network', 'message', 'device', *PID_LAYERS) and entry['rights'] and \
            path and path != NAME_FAILURE and not path.endswith(('/', '\\'))

    gap_layers = {entry['layer'] for categories in programs.values() for entry in categories['no_rule']}
    for flag in sorted({'default-deny'} | {LAYER_FLAGS[layer] for layer in gap_layers if layer in LAYER_FLAGS}):
        if policy_flags is not None and flag not in policy_flags:
            emit(tighten, f'{flag} on', 'the policy leaves this layer undecided')
    for image, categories in sorted(programs.items()):
        scope = '' if image.startswith('pid ') else f'|image={image}'
        groups = {}
        for entry in categories['blocked'] + categories['would_block']:   # all of them: each may be needed
            verb = 'blocked' if entry.get('decision') == 'deny' else 'would be blocked'
            emit(needed, needed_rule(entry, scope),
                 f'{image}: {verb} {entry["count"]}x; add only if the client needs it')
        for entry in categories['no_rule']:
            rule = gap_rule(entry['layer'], entry['path'], image, scope)
            groups[rule] = groups.get(rule, 0) + entry['count']
        for rule, count in sorted(groups.items(), key=lambda item: -item[1]):
            first = rule.split('|', 2)[:2]
            reason = (' (rule-only: only a rule makes kfilter decide it; audit, then deny once reviewed)'
                      if first[0] == 'audit' else '')
            emit(tighten, rule, f'{image}: {count} action(s) went through with no kfilter decision{reason}')
        broad = {}
        for entry in categories['allowed_by_rule']:
            rule = entry.get('rule', '')
            if entry['rule_id'] and 'exact' not in rule.split('|') and ' exact' not in rule and exact(entry):
                broad.setdefault(entry['rule_id'], []).append(entry)
        for rule_id, entries in broad.items():
            for entry in entries[:limit]:
                emit(tighten, f"allow|{entry['layer']}|{entry['path']}|rights={entry['rights']}|exact{scope}",
                     f"{image}: narrows rule {rule_id} ({entry['rule']}) to what was used")
    return tighten, needed


def needed_rule(entry, scope):
    """The exact allow that lets a refused action through, in the form kfilterctl takes for its layer (network
    and device allows with a uses= budget of what the run used), or '' when the action names nothing a rule can
    (a name failure, an unknown program, the root)."""
    layer, path, count = entry['layer'], entry['path'], entry['count']
    if not path or path == NAME_FAILURE or path.endswith(('/', '\\')):
        return ''
    if layer == 'network':
        match = re.match(r'(tcp|udp) \[?([0-9A-Fa-f:.]+?)\]?:(\d+)$', path)
        if not match:
            return ''
        proto, ip, port = match.groups()
        if port == '0':
            return ''   # a send with no port (a broadcast probe): no connect to allow
        return (f"allow|network|ip={ip}/{128 if ':' in ip else 32}|port={port}|proto={proto}|rights=connect|"
                f"uses={count}|risk=needed{scope}")
    if layer == 'device':
        return f'allow|device|{path}|rights=raw-device|uses={count}|risk=needed{scope}' if path.startswith('/') else ''
    if layer in ('handle', 'open', 'thread-handle', 'thread-open'):
        mask = 0
        for value in (entry.get('rights') or '').split(','):
            try:
                mask |= int(value, 16)
            except ValueError:
                pass
        names = [name for bit, name in (THREAD_ACCESS if layer.startswith('thread') else PROCESS_ACCESS) + STANDARD_ACCESS
                 if mask & bit]
        return f"allow|{layer}|{path}|rights={','.join(names)}|risk=needed{scope}" if names else ''
    if layer in PID_LAYERS or layer == 'message' or not entry['rights'] or (layer == 'registry' and path[0] != '\\'):
        return ''   # a registry name without its root, as wineserver refuses it anyway
    return f"allow|{layer}|{path}|rights={entry['rights']}|exact{scope}"


def render(bundle, policy_label, programs, coverage, total_decisions, total_observed, tighten, needed, top,
           trap=None):
    totals = {category: sum(entry['count'] for categories in programs.values() for entry in categories[category])
              for category in CATEGORIES}
    notes = []
    kfilter_state = [state for state in coverage if state.startswith('kfilter')]
    if total_decisions == 0:
        notes.append('No kfilter_decision records: kfilter was not running or msmon could not read it '
                     f'({", ".join(kfilter_state) or "no kfilter coverage record"}). Every filterable action '
                     'shows as WENT THROUGH WITH NO RULE.')
    for state in kfilter_state:
        if 'degraded' in coverage[state] and 'degraded=0x00000000' not in coverage[state]:
            notes.append(f'kfilter reported a degraded layer: {state} {coverage[state]}')
    # The last kfilter_status is cumulative for the session (dropped_delta counts from its start).
    status = detail_fields(coverage.get('kfilter_status', ''))
    lost = [f'{name}={status[name]}' for name in ('dropped_delta', 'session_changed')
            if status.get(name, '0') != '0']
    if status.get('name_failures', '0') != '0':
        notes.append(f"kfilter decided {status['name_failures']} actions it could not name (listed as '(name kfilter "
                     "could not resolve...)'): audit mode let them through; block mode refuses them.")
    if 'kfilter_unavailable' in coverage and ('kfilter_status' in coverage or 'kfilter_available' in coverage):
        lost.append('the decision reader was lost mid-session (kfilter_unavailable)')
    if lost:
        notes.append('kfilter decisions were lost (' + '; '.join(lost) + '): actions whose decision is missing, '
                     'blocked ones included, show as WENT THROUGH WITH NO RULE.')
    if not policy_label:
        notes.append('No policy file: rule text comes from the decisions only.')
    if coverage.get('report_quiet_queries'):
        notes.append(f"{coverage['report_quiet_queries']} metadata queries (stat, access, readlink, xattrs) were "
                     'allowed without an event: kfilter logs only refused, audited and would-deny queries.')
    unseen = not_seen(coverage)
    report = {'schema': 'monfilter-tuning-report-v1', 'bundle': bundle, 'policy': policy_label,
              'kfilter_decisions': total_decisions, 'observed_records': total_observed, 'totals': totals,
              'kfilter_coverage': {state: coverage[state] for state in kfilter_state},
              'programs': programs, 'candidates_tighten': tighten, 'candidates_if_needed': needed,
              'not_seen': unseen, 'cpu_trap': trap or {}, 'notes': notes}

    lines = ['# kfilter tuning report', '', f'Bundle: `{bundle}`', f'Policy: `{policy_label or "(none)"}`',
             f'kfilter decisions: {total_decisions}; msmon records: {total_observed}', '']
    lines += [f'> {note}' for note in notes] + ([''] if notes else [])
    lines += ['| category | actions |', '|---|---|'] + [f'| {TITLES[c]} | {totals[c]} |' for c in CATEGORIES]
    lines += ['', 'BLOCKED: kfilter refused it. WOULD BLOCK: audit mode let it through; block mode refuses it. '
              'ALLOWED BY RULE: kfilter let it through by the rule shown (or the policy default). '
              'WENT THROUGH WITH NO RULE: msmon saw it succeed in a layer kfilter filters, with no kfilter '
              'decision (a gap). NOT FILTERABLE: kfilter has no layer for it.']
    lines += ['', '## Per program', '',
              '| program | ' + ' | '.join(TITLES[c] for c in CATEGORIES) + ' |', '|---' * (len(CATEGORIES) + 1) + '|']
    family = [name.lower() for name in KNOWN_NAMES]
    order = sorted(programs, key=lambda image: (image.lower() not in family, image.lower()))
    for image in order:
        lines.append(f'| {image} | ' + ' | '.join(str(sum(e['count'] for e in programs[image][c]))
                                                 for c in CATEGORIES) + ' |')
    for image in order:
        lines += ['', f'### {image}']
        for category in CATEGORIES:
            entries = programs[image][category]
            if not entries:
                continue
            lines += ['', f'**{TITLES[category]}** ({sum(e["count"] for e in entries)})', '']
            for entry in entries[:top]:
                if category == 'not_filterable':
                    lines.append(f"- {entry['layer']} x{entry['count']}, e.g. `{entry.get('example', '')}`")
                    continue
                rule = ''
                if category != 'no_rule':
                    rule = (f" -- rule {entry['rule_id']}: `{entry['rule']}`" if entry['rule_id']
                            else ' -- policy default (no rule matched)')
                rights = f" [{entry['rights']}]" if entry.get('rights') else ''
                lines.append(f"- {entry['layer']} `{entry['path']}`{rights} x{entry['count']}{rule}")
            if len(entries) > top:
                lines.append(f'- ... {len(entries) - top} more in the JSON report')
    lines += ['', '## Candidate rules to tighten', '',
              'Review each line before adding it. First match wins: put denies above the allows they narrow.', '',
              '```']
    lines += [f"{item['rule']}    # {item['reason']}" for item in tighten] or ['# (none)']
    lines += ['```', '', '## Exact allows, only if the client needs them (from WOULD BLOCK)', '', '```']
    lines += [f"{item['rule']}    # {item['reason']}" for item in needed] or ['# (none)']
    lines += ['```', '', '## NOT SEEN BY EITHER TOOL', ''] + [f'- {item}' for item in unseen]
    if trap:
        lines += ['', '## CPU instructions the client trapped (client/cpu-trap.log, reported by the client itself)', '']
        for insn, entry in sorted(trap.items()):
            leaves = f"; leaves {', '.join(entry['leaves'])}" if entry['leaves'] else ''
            masked = f"; masked {', '.join(entry['masked'])}" if entry['masked'] else ''
            lines.append(f"- {insn} x{entry['count']} in {', '.join(entry['processes'])}{leaves}{masked}")
    return '\n'.join(lines) + '\n', report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('bundle', help='session directory, bundle .zip, or events.jsonl')
    parser.add_argument('--policy', default='', help='default: kfilter-policy.txt in the bundle')
    parser.add_argument('--out', default='', help='markdown report (default: stdout)')
    parser.add_argument('--json', default='', help='JSON report')
    parser.add_argument('--top', type=int, default=25, help='entries per category and program in markdown')
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix='monfilter-report-') as scratch:
        parts, bundled_policy, side = event_paths(args.bundle, scratch)
        if not parts:
            sys.exit(f'no events found in {args.bundle}')
        policy_path = args.policy or (bundled_policy if bundled_policy and os.path.exists(bundled_policy) else '')
        programs, coverage, rules, policy_flags, total_decisions, total_observed = analyze(parts, policy_path)
        tighten, needed = candidates(programs, policy_flags, args.top, rules.values())
        trap = cpu_trap(side)
        label = args.policy or (policy_path if os.path.isdir(args.bundle) else
                                'kfilter-policy.txt in the bundle' if policy_path else '')
        markdown, report = render(args.bundle, label,
                                  programs, coverage, total_decisions, total_observed, tighten, needed, args.top,
                                  trap)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as handle:
            handle.write(markdown)
        print(f'Wrote {args.out}')
    else:
        sys.stdout.write(markdown)
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=1)
        print(f'Wrote {args.json}')
    return report


if __name__ == '__main__':
    main()
