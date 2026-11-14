# Design

## Components

```
kfilterctl.exe ──IOCTL──► \Device\KFilter (admin-only)
                         │
                         ├─ policy.c       ordered rules and protected identities
                         ├─ events.c       fixed ring of deny/audit decisions
                         ├─ process.c      process family and AppContainer identity
                         ├─ file_filter.c  files, directories, pipes and volumes
                         ├─ registry.c     CmRegisterCallbackEx
                         ├─ object.c       ObRegisterCallbacks
                         ├─ disk.c         dynamic disk/volume upper filters
                         ├─ device.c       identity-bearing device filters
                         └─ network.c      WFP connect/listen/receive-accept callouts
```

The control tool parses text into a fixed `KFILTER_CONFIG`. The driver validates
the complete configuration, including required registration bits in block mode,
then publishes an immutable generation. Readers hold a reference while matching.

## Decision path

The minifilter, registry callback, storage filter and process-create callback
use the shared matcher. Rules are evaluated top to bottom; the first eligible
rule wins. Allow rules must cover every requested right, while deny and audit
rules match when any requested right overlaps. Allows require explicit,
nonzero rights. Root approval for process creation is only a fallback when no
process rule matches.

A missing or unnormalizable name denies before rule evaluation for a protected
process in block mode. In audit mode it is recorded and allowed. A deny is
recorded as `WOULD_DENY` in audit mode; audit rules always allow and record.

## Enforcement mechanisms

- **Files and directories.** Pre-create is the authorization point. The rights,
  generation, rule ID and directory flag are saved in a stream-handle context
  for later read/write, directory, set-info, set-security and section
  operations. Missing contexts fail closed in block mode. `IRP_MJ_SET_SECURITY`
  is authorized with the independent `set-security` right against that context,
  using the recorded file/directory class, so a handle that was not opened with
  `WRITE_DAC`/`WRITE_OWNER` (or that predates the current policy generation)
  cannot change a security descriptor. Rename and hard-link set-information
  operations bypass the create-time rights check and authorize the source again
  under the current policy with the rename right, resolving the source name with
  a full name query rather than the name cache. They then resolve the supplied
  destination name (relative to `RootDirectory` when present) and authorize it
  separately. Both decisions use file or directory rules according to the saved
  flag; an unresolvable name fails closed in block mode.
  `IRP_MJ_CREATE_NAMED_PIPE` and `IRP_MJ_CREATE_MAILSLOT` are registered as well
  as ordinary creates on NPFS/MSFS.
- **Volumes.** Volume-information and object-ID queries call `KfDecide` with the
  volume path and raw-device right. A matching volume rule takes precedence;
  otherwise the volume-serial flag denies these identity classes.
- **Registry.** Open/create, query, multi-value query, enumerate, set, delete,
  rename, load/save/restore and security classes are covered. Value names are
  matched exactly without file ADS or trailing-dot/space normalization; an
  unrepresentable value name fails closed in block mode. Enumeration is its own
  right: `KEY_ENUMERATE_SUB_KEYS` and the key/value enumerate callbacks request
  `enumerate`, so a read-only allow does not permit enumeration (and an
  enumerate-only allow does not permit a read). `KEY_READ` and the generic
  `GENERIC_READ`/`GENERIC_EXECUTE` forms request both rights, so a generic
  execute open cannot slip past the subset check with zero requested rights.
  Multi-value queries check every requested value and fail closed above 64
  entries. Rename uses the rename right on both source and destination;
  relative destinations replace the source basename.
- **Process handles.** Object callbacks remove terminate, create-thread, VM,
  duplication, set-information, query-information (and, for threads, the
  limited-information forms), suspend, context and impersonation rights from
  handles to processes and threads outside the protected family. They cannot
  revoke handles that already exist. Only protected-source creates and
  cross-family duplicates are filtered: an unprotected outside service may
  still open a protected process. The handle object, the duplicating process
  and the receiving process are checked separately, so a handle never crosses
  the boundary from any protected endpoint unfiltered.
- **Process creation.** Both the actual creator and declared parent must be
  protected for family inheritance. This prevents a spoofed
  `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` from escaping containment. Image rules
  use the create right in normal first-match order. In block mode a protected
  image started by an unprotected parent is refused unless the creator is the
  launcher registered over `KFILTER_IOCTL_REGISTER_LAUNCHER`; that process is
  created suspended and then admitted by PID, so it never runs uncontained.
  A protected-name image whose AppContainer SID does not match the configured
  package is also refused in block mode before that launcher path.
- **Raw disks and volumes.** Device-interface arrival notifications attach
  upper filters to existing and later-arriving disk and volume interfaces. The
  filter name is resolved with `ObQueryNameString`, so device rules see the
  canonical `\Device\...` name rather than the `\??\Volume{...}` interface
  link. Requests whose file object carries a non-empty remaining name are
  ordinary file I/O and belong to the minifilter; only a handle opened directly
  on the disk or volume (empty remaining name) is a raw-device request. Every
  protected-process raw open, read, write, device-control,
  internal-device-control and filesystem-control request is decided against
  device rules with the raw-device right; an explicit allow rule matches
  first, otherwise the request is denied whenever the layer is active, even
  when default-deny is off. The layer reports itself
  unavailable for block-mode activation when no filter attached or when any
  required attach failed, including table exhaustion. A later failure marks the
  layer degraded and fails protected decisions closed until a policy re-arm
  re-enumerates interfaces successfully. A global rundown
  reference keeps the filter list alive across unload, and teardown holds the
  per-device `IO_REMOVE_LOCK` across `IoCallDriver` and takes it before
  draining on `IRP_MN_REMOVE_DEVICE`.
- **Identity devices.** Upper filters cover NSI, MountPointManager, every SCSI
  adapter, NDIS miniports, and HID/USB interfaces, including later PnP arrivals.
  Protected user-mode creates and device/internal-device controls are deny-by-default
  and logged with the device name and IOCTL. Only an exact, counted, risk-bearing
  device allow can relax one device, optionally restricted to one IOCTL. Other
  processes pass through. Rundown and remove locks protect removal/unload, and any
  missing required attachment refuses block activation.
- **Network.** Six WFP callouts cover IPv4/IPv6 connect, listen and
  receive-accept. Listen uses the local address/port, TCP protocol and listen
  right. Static rules match IP prefix, protocol, port and connect/listen right;
  the parser requires a complete numeric port in the range 0–65535. WFP reports
  an IPv4 address as a host-order number, so it is converted to wire-order bytes
  before prefix and loopback matching against the `InetPtonW` layout rules use.
  Login allows are exact host/port, counted and risk-labelled. Dynamic FQDN mediation is not implemented.

Risk-bearing file, handle and network allows carry a bounded reason. Each consumed
allow emits a separate RISK event with its rule ID and object path; network RISK events
also carry the granted right. The normal ALLOW and counted-use events remain unchanged.

## Process identity

Every tracked entry holds a referenced `PEPROCESS`, PID, creation time, full
image path, AppContainer SID and policy generation. Lookups match PID plus
creation time, so a reused PID does not inherit protection. An optional
`appcontainer <profile>` setting pins admitted and child processes to the
derived package SID; absence of that SID is a mismatch when the setting is
present. In block mode, a protected image created outside the family is denied
on that mismatch even when its creator is the registered launcher. Repeating
admission for the same PID/start-time succeeds after image and SID validation,
which supports the suspended launcher in audit mode.

The table is bounded at 128 processes. Admission failure in block mode refuses
process creation rather than silently leaving an approved child unprotected.

## IRQL and lifetime

Name acquisition is attempted only at `APC_LEVEL` or below. Matching uses
bounded, nonpaged state and the configuration spin lock is released before
event logging. Process and registry callbacks run at `PASSIVE_LEVEL`; storage
PnP/remove-lock teardown follows the usual device-filter model.

Unload unregisters interface notifications and callbacks, drains notification,
I/O and control-operation rundown references, detaches filters, then frees
policy and event state. Standalone minifilter detach and service stop both use
this teardown path.

## Not implemented

- ALPC/COM and named-pipe payload inspection.
- Blocking `WriteProcessMemory` or thread injection; object callbacks reduce
  handle rights only.
- General WMI/RPC, SMBIOS/firmware-table, CPUID/MSR, GPU adapter and process-list
  interception.
- Driver-side DNS/FQDN resolution. The network policy is static only.
- Tamper resistance against kernel-mode code that removes or bypasses callbacks.

## Validation status

The code is built and offline policy/matcher tests are available. `build.cmd`,
`kfilterctl self-test` and `kfilterctl check` validate compilation, parsing and
the shared matcher only. They do not validate runtime containment, AppContainer
or real-client compatibility, signing, VM behavior, Driver Verifier, or
anti-cheat compatibility. The driver has not been signed, installed, loaded or
run on a VM.
