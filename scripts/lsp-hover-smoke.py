#!/usr/bin/env python3
"""Smoke test for syscall hover / inlay hints through the real LSP server.

Run from the repo root:  python3 scripts/lsp-hover-smoke.py
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("YANA_LSP", os.path.join(ROOT, "target/debug/yana-lsp"))
FILE = os.path.join(ROOT, "examples", "hello.yana")
URI = "file://" + FILE


class Lsp:
    def __init__(self):
        self.p = subprocess.Popen(
            [BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.seq = 1
        self.pending = []

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if not notify:
            msg["id"] = self.seq
            self.seq += 1
        if params is not None:
            msg["params"] = params
        body = json.dumps(msg).encode()
        self.p.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.p.stdin.flush()
        return msg.get("id")

    def recv(self):
        headers = {}
        while True:
            line = self.p.stdout.readline()
            if not line:
                return None
            line = line.decode().rstrip("\r\n")
            if not line:
                break
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        return json.loads(self.p.stdout.read(int(headers["content-length"])))

    def response(self, req_id, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.recv()
            if msg is None:
                raise RuntimeError("server closed the stream")
            if msg.get("id") == req_id:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg["result"]
            self.pending.append(msg)
        raise TimeoutError(f"no response for {req_id}")


def check(cond, msg):
    print(("ok: " if cond else "FAIL: ") + msg, flush=True)
    if not cond:
        sys.exit(1)


def main():
    if not os.path.exists(BIN):
        sys.exit(f"binary not found: {BIN}\nbuild it with: cargo build -p yana-lsp")

    source = open(FILE).read()
    lines = source.split("\n")
    lsp = Lsp()

    lsp.send(
        "initialize",
        {
            "processId": os.getpid(),
            "rootUri": "file://" + ROOT,
            "capabilities": {
                "textDocument": {
                    "hover": {"contentFormat": ["markdown"]},
                    "inlayHint": {"dynamicRegistration": False},
                }
            },
        },
    )
    lsp.response(1)
    lsp.send("initialized", {}, notify=True)
    lsp.send(
        "textDocument/didOpen",
        {
            "textDocument": {
                "uri": URI,
                "languageId": "yana",
                "version": 1,
                "text": source,
            }
        },
        notify=True,
    )

    def hover(line, char):
        req = lsp.send(
            "textDocument/hover",
            {"textDocument": {"uri": URI}, "position": {"line": line, "character": char}},
        )
        return lsp.response(req)

    # --- hover over the number in #[syscall(1)] --------------------------
    attr_line = next(i for i, l in enumerate(lines) if "#[syscall(1)]" in l)
    attr_char = lines[attr_line].index("(1)") + 1
    h = hover(attr_line, attr_char)
    check(h is not None, "hover on syscall number returns something")
    md = h["contents"]["value"]
    check("**`write`**" in md, "hover names the syscall (write)")
    check("syscall 1" in md, "hover shows the number")
    check("ssize_t write(int fd" in md, "hover shows the C signature")
    check("`rdi`" in md and "`rsi`" in md and "`rdx`" in md, "hover lists argument registers")
    check("man 2 write" in md, "hover points at the man page")
    check("§5.5" in md, "hover cites SPEC §5.5")
    check("rcx" in md and "r11" in md, "hover mentions clobbers")
    check(h.get("range") is not None, "hover gives a range for the number")

    # --- hover over the extern fn name -----------------------------------
    fn_line = next(i for i, l in enumerate(lines) if "extern fn write" in l)
    h = hover(fn_line, lines[fn_line].index("write") + 1)
    check(h is not None, "hover on extern fn name returns something")
    md = h["contents"]["value"]
    check("syscall 1" in md and "ssize_t write" in md, "extern fn hover shows the syscall docs")

    # --- hover over the call site ----------------------------------------
    call_line = next(i for i, l in enumerate(lines) if "call write" in l)
    h = hover(call_line, lines[call_line].index("write") + 1)
    check("syscall 1" in h["contents"]["value"], "call-site hover also explains the syscall")

    # --- hover over #[syscall(60)] → exit --------------------------------
    exit_line = next(i for i, l in enumerate(lines) if "#[syscall(60)]" in l)
    h = hover(exit_line, lines[exit_line].index("(60)") + 1)
    md = h["contents"]["value"]
    check("**`exit`**" in md and "не возвращается" in md, "number 60 resolves to exit")

    # --- hover over the raw `syscall` keyword ----------------------------
    raw = "// probe\n#[entry]\nfn main() -> ! {\n    syscall;\n}\n"
    probe = "file://" + os.path.join(ROOT, "examples", "probe.yana")
    lsp.send(
        "textDocument/didOpen",
        {
            "textDocument": {
                "uri": probe,
                "languageId": "yana",
                "version": 1,
                "text": raw,
            }
        },
        notify=True,
    )
    req = lsp.send(
        "textDocument/hover",
        {"textDocument": {"uri": probe}, "position": {"line": 3, "character": 6}},
    )
    h = lsp.response(req)
    check(
        h is not None and "rdi" in h["contents"]["value"],
        "raw `syscall` hover explains the ABI",
    )

    # --- inlay hints ------------------------------------------------------
    req = lsp.send(
        "textDocument/inlayHint",
        {
            "textDocument": {"uri": URI},
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": len(lines), "character": 0}},
        },
    )
    hints = lsp.response(req) or []
    labels = [x["label"] for x in hints if isinstance(x["label"], str)]
    check(" write" in labels, f"inlay hint names syscall 1 (hints={labels})")
    check(" exit" in labels, f"inlay hint names syscall 60 (hints={labels})")

    lsp.send("shutdown", None)
    lsp.response(lsp.seq - 1)
    lsp.send("exit", {}, notify=True)
    print("\nALL SYSCALL HOVER CHECKS PASSED")


if __name__ == "__main__":
    main()
