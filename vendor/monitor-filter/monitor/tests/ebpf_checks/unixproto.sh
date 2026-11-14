# The unixproto upgrade (sourced by tests/linux_ebpf_test.sh; checks in check_unixproto.py): desktop services over
# AF_UNIX against a private Xvfb on a free display :90-:99 (never the user's, the game's :5 or the scraper's :6). The probe
# as an X11 client (--x11: a QueryExtension split over iovecs, an 8 KiB ChangeProperty with a GetInputFocus past the
# 4 KiB walk, then a QueryPointer), and copies in the scope of xdpyinfo -queryExtensions (extension requests named
# through the agent's table), xdotool (XTEST FakeInput, QueryPointer), dbus-send on the system bus (a call and its
# method_return) and pactl as the invoking user when a PulseAudio server runs for them. unixproto_end runs one more
# agent session with --log-content: the probe's X11 bytes as payloads (the 8 KiB write capped) and its socket ioctl's
# argument struct. Skipped without Xvfb and xdpyinfo; not under --no-ebpf.
unixproto_display() {   # starts Xvfb on a free display: xdisplay, xvfb
    command -v Xvfb >/dev/null && command -v xdpyinfo >/dev/null || { echo "SKIP unixproto: Xvfb or xdpyinfo missing"; return 1; }
    xdisplay=
    for n in 90 91 92 93 94 95 96 97 98 99; do
        [ -e "/tmp/.X11-unix/X$n" ] || [ -e "/tmp/.X$n-lock" ] || { xdisplay=$n; break; }
    done
    [ -n "$xdisplay" ] || { echo "SKIP unixproto: no free display in :90-:99"; return 1; }
    Xvfb ":$xdisplay" -nolisten tcp -noreset -screen 0 640x480x24 >/dev/null 2>&1 &
    xvfb=$!
    for _ in $(seq 1 50); do [ -S "/tmp/.X11-unix/X$xdisplay" ] && return 0; sleep 0.1; done
    echo "SKIP unixproto: Xvfb :$xdisplay did not start"
    kill "$xvfb" 2>/dev/null
    return 1
}
unixproto_stop() { kill "$xvfb" 2>/dev/null; wait "$xvfb" 2>/dev/null; }

unixproto_session() {
    [ "$name" = fallback ] && return 0
    unixproto_display || return 0
    echo "$xdisplay" >"$work/$name/unixproto.display"
    cp build/linux/linux_ebpf_probe "$scope/x11-probe"
    "$scope/x11-probe" --x11 "/tmp/.X11-unix/X$xdisplay" || { echo "FAIL $name: the X11 probe exited $?"; fail=1; }
    for tool in xdpyinfo xdotool dbus-send pactl; do
        command -v "$tool" >/dev/null && cp "$(command -v "$tool")" "$scope/$tool"
    done
    DISPLAY=":$xdisplay" "$scope/xdpyinfo" -queryExtensions >"$work/$name/xdpyinfo.txt" 2>&1 ||
        { echo "FAIL $name: xdpyinfo exited $?"; fail=1; }
    if [ -x "$scope/xdotool" ]; then
        DISPLAY=":$xdisplay" "$scope/xdotool" mousemove 10 10 key --clearmodifiers a getmouselocation >"$work/$name/xdotool.txt" 2>&1 ||
            { echo "FAIL $name: xdotool exited $?"; fail=1; }
    fi
    [ -x "$scope/dbus-send" ] && "$scope/dbus-send" --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.ListNames >"$work/$name/dbus.txt" 2>&1
    uid=${SUDO_UID:-}
    if [ -x "$scope/pactl" ] && [ -n "$uid" ] && [ -S "/run/user/$uid/pulse/native" ]; then
        runuser -u "$SUDO_USER" -- env XDG_RUNTIME_DIR="/run/user/$uid" "$scope/pactl" info >"$work/$name/pactl.txt" 2>&1 &&
            touch "$work/$name/unixproto.pulse"
    fi
    unixproto_stop
    return 0
}

unixproto_end() {
    unixproto_display || return 0
    content="$work/content"
    mkdir -p "$content/scope"
    cp build/linux/linux_ebpf_probe "$content/scope/x11-probe"
    build/linux/msmon-agent --scope-root "$content/scope" --output "$content/events.jsonl" --max-file-mb 0 \
        --stop-file "$content/stop" --wait-ms 100 --no-etw --log-content >"$content/agent.log" 2>&1 &
    agent=$!
    for _ in $(seq 1 60); do grep -q Registered "$content/agent.log" && break; sleep 0.5; done
    "$content/scope/x11-probe" --x11 "/tmp/.X11-unix/X$xdisplay" || { echo "FAIL content: the X11 probe exited $?"; fail=1; }
    sleep 2
    touch "$content/stop"
    wait "$agent" || { echo "FAIL content: agent exited $?"; tail -n 40 "$content/agent.log"; fail=1; }
    unixproto_stop
    python3 tests/ebpf_checks/check_unixproto.py "$content/events.jsonl" || fail=1
}
