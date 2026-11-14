# Windows-parity checks of the kernel sensors (check_parity.py holds the expectations): the ia32 probe
# (tests/fixtures/ia32_probe.c, a 32-bit Wine-like process) runs from the session's extra root, so it is
# also the check that every scope root reaches the kernel (it is admitted by its exec mapping there).
parity_session() {
    [ "$name" = fallback ] && return 0
    if [ ! -x build/linux/ia32_probe ]; then
        echo "parity: build/linux/ia32_probe not built (gcc -m32); the ia32 checks are skipped"
        return 0
    fi
    mkdir -p "$extra/files"
    cp build/linux/ia32_probe "$extra/ia32_probe"
    (cd "$extra/files" && "$extra/ia32_probe") || { echo "FAIL $name: ia32_probe exited $?"; fail=1; }
}
parity_end() { :; }
