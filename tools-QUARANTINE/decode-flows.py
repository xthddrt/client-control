#!/usr/bin/env python3
"""
decode-flows.py -- decrypt every NGS-X control-plane response in a mitmproxy
flow dump and dump the cleartext control plane.

    python3 decode-flows.py ../data/nexon-flows-2026-10-29.mitm            # summary
    python3 decode-flows.py ../data/nexon-flows-2026-10-29.mitm --json out.json
    python3 decode-flows.py ../data/nexon-flows-2026-10-29.mitm --raw      # dump every body

Requires: mitmproxy (pip install --user mitmproxy) and ngs_cipher.py alongside.
Only RESPONSE bodies decode (see ngs_cipher.py scope note); requests are shown
as <request-cipher-not-broken>.
"""
import argparse
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ngs_cipher import decrypt_response  # noqa: E402

from mitmproxy import io as mio  # noqa: E402
from mitmproxy import http       # noqa: E402


def b64_or_raw(content):
    try:
        return base64.b64decode(content.strip(), validate=True)
    except Exception:
        return content


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--json", metavar="OUT", help="write decoded control plane to JSON")
    ap.add_argument("--raw", action="store_true", help="print every decoded body in full")
    args = ap.parse_args()

    out = {}
    with open(args.dump, "rb") as f:
        for fl in mio.FlowReader(f).stream():
            if not isinstance(fl, http.HTTPFlow):
                continue
            if "ngs.nexon.com" not in fl.request.pretty_host:
                continue
            tag = fl.request.host.split(".")[0] + fl.request.path
            print(f"\n===== {fl.request.method} {fl.request.pretty_host}{fl.request.path} =====")
            # request (cipher not broken)
            if fl.request.content:
                print("  [REQ ] <request-cipher-not-broken, position-dependent keystream>")
            # response
            if fl.response and fl.response.content:
                try:
                    plain = decrypt_response(fl.response.content)
                    try:
                        j = json.loads(plain)
                        out[tag] = j
                        txt = json.dumps(j)
                    except Exception:
                        txt = plain.decode("utf-8", "replace")
                    print(f"  [RESP] {txt if args.raw else txt[:400]}")
                except Exception as e:
                    print(f"  [RESP] <decode failed: {e}>")
            else:
                print("  [RESP] <empty>")

    if args.json and out:
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json} ({len(out)} endpoints)")


if __name__ == "__main__":
    main()
