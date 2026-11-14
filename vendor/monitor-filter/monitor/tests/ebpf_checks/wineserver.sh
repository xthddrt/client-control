# Wineserver upgrade (sourced by tests/linux_ebpf_test.sh): two fake Wine clients (64-bit and ia32,
# tests/fixtures/ws_fake_client.c) run under the scope, each from a <arch>-unix directory holding a fake
# ntdll.so with the wine-11.0 build string, while the agent runs. They run in the ebpf and nopayloads
# sessions (check_wineserver.py expects their records in both); under --no-ebpf they are not run.
wineserver_session() {
    [ "$name" = fallback ] && return 0
    for arch in x86_64 i386; do
        client=ws_fake_client
        [ "$arch" = i386 ] && client=ws_fake_client32
        if [ ! -x "build/linux/$client" ]; then
            echo "wineserver: build/linux/$client not built; skipped"
            continue
        fi
        dir="$scope/$arch-unix"
        mkdir -p "$dir"
        printf 'FAKE\0wine-11.0\0' >"$dir/ntdll.so"
        cp "build/linux/$client" "$dir/$client"
        (cd "$dir" && "./$client") || { echo "FAIL $name: $client exited $?"; fail=1; }
    done
}
wineserver_end() { :; }
