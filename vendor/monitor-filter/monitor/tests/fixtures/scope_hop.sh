#!/bin/sh
# scope_hop.sh DEPTH DIR PORT (tests/ebpf_checks/scope.sh): each hop execs the next, one native depth deeper; DEPTH is
# this hop's. The 6th is python3: it connects to 127.0.0.1:PORT, sends and receives, writes DIR/hop.txt in 10 calls,
# renames it to hop.txt.done and execs the 7th; the 8th execs /bin/true, the 9th.
depth=$1 dir=$2 port=$3
case $depth in
5) exec python3 - "$0" "$dir" "$port" <<'PY'
import os, socket, sys
hop, folder, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with socket.create_connection(("127.0.0.1", port)) as peer:
    peer.sendall(b"hop" * 100)
    peer.recv(64)
path = os.path.join(folder, "hop.txt")
with open(path, "wb", buffering=0) as out:
    for _ in range(10):
        out.write(b"depth 6\n")
os.rename(path, path + ".done")
os.execv("/bin/sh", ["/bin/sh", hop, "7", folder, str(port)])
PY
;;
8) exec /bin/true ;;
*) exec /bin/sh "$0" $((depth + 1)) "$dir" "$port" ;;
esac
