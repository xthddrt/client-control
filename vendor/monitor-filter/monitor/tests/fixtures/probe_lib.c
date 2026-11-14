/* A library tests/ebpf_checks/gaps.sh has the probe load and unload (linux_ebpf_probe --unload): its image comes and
 * goes from /proc/<pid>/maps (image_unload;source=maps_poll). */
int msmon_probe_lib(void) { return 42; }
