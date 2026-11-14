# The sysall upgrade (every syscall recorded: kernel aggregates and the once count-only calls) needs no shell steps:
# its actions are in tests/fixtures/probe_sysall.h and the ia32 probe, its checks in check_sysall.py.
sysall_session() { :; }
sysall_end() { :; }
