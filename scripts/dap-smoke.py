#!/usr/bin/env python3
"""End-to-end smoke test for `yana-lsp --dap`.

Run from the repo root:  python3 scripts/dap-smoke.py
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("YANA_LSP", os.path.join(ROOT, "target/debug/yana-lsp"))
EXAMPLES = os.path.join(ROOT, "examples")


class Dap:
    def __init__(self, timeout=5):
        self.p = subprocess.Popen(
            [BIN, "--dap"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.seq = 1
        self.pending = []
        self.timeout = timeout

    def send(self, command, arguments=None):
        msg = {"seq": self.seq, "type": "request", "command": command}
        if arguments is not None:
            msg["arguments"] = arguments
        self.seq += 1
        body = json.dumps(msg).encode()
        self.p.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.p.stdin.flush()
        return msg["seq"]

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

    def response(self, request_seq):
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            msg = self.recv()
            if msg is None:
                raise RuntimeError("adapter closed the stream")
            if msg.get("type") == "response" and msg.get("request_seq") == request_seq:
                return msg
            self.pending.append(msg)
        raise TimeoutError(f"no response for request {request_seq}")

    def event(self, name):
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            for i, m in enumerate(self.pending):
                if m.get("type") == "event" and m.get("event") == name:
                    return self.pending.pop(i)
            msg = self.recv()
            if msg is None:
                raise RuntimeError("adapter closed the stream")
            if msg.get("type") == "event" and msg.get("event") == name:
                return msg
            self.pending.append(msg)
        raise TimeoutError(f"no event {name}")

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        self.p.terminate()
        self.p.wait(timeout=5)


def check(cond, msg):
    print(("ok: " if cond else "FAIL: ") + msg, flush=True)
    if not cond:
        sys.exit(1)


def factorial(d):
    program = os.path.join(EXAMPLES, "factorial.yana")

    seq = d.send("initialize", {"clientID": "smoke", "adapterID": "yana"})
    caps = d.response(seq)["body"]["capabilities"]
    check(caps.get("supportsConfigurationDoneRequest") is True, "configurationDone supported")
    check(caps.get("supportsSetVariable") is True, "setVariable supported")

    seq = d.send("launch", {"program": program})
    check(d.response(seq)["success"], "launch accepted")
    d.event("initialized")

    seq = d.send(
        "setBreakpoints",
        {"source": {"path": program}, "breakpoints": [{"line": 12}, {"line": 13}]},
    )
    bps = d.response(seq)["body"]["breakpoints"]
    check(len(bps) == 2 and all(b["verified"] for b in bps), "breakpoints verified")

    seq = d.send("configurationDone")
    d.response(seq)
    check(d.event("stopped")["body"]["reason"] == "entry", "stopped at entry")

    seq = d.send("threads")
    check(d.response(seq)["body"]["threads"][0]["name"] == "main", "thread is main")

    seq = d.send("stackTrace", {"threadId": 1})
    top = d.response(seq)["body"]["stackFrames"][0]
    check(top["name"] == "main", "top frame is the entry function")
    check(top["line"] == 8, f"entry line is 8 (got {top['line']})")

    seq = d.send("scopes", {"frameId": top["id"]})
    reg_ref = d.response(seq)["body"]["scopes"][0]["variablesReference"]

    seq = d.send("variables", {"variablesReference": reg_ref})
    regs = {v["name"]: v["value"] for v in d.response(seq)["body"]["variables"]}
    check("rax" in regs and "rsp" in regs, "register view has rax/rsp")

    seq = d.send("continue", {"threadId": 1})
    check(d.response(seq)["body"]["allThreadsContinued"] is True, "continue acknowledged")
    check(d.event("stopped")["body"]["reason"] == "breakpoint", "hit breakpoint")

    seq = d.send("stackTrace", {"threadId": 1})
    check(d.response(seq)["body"]["stackFrames"][0]["line"] == 12, "stopped on line 12")

    seq = d.send("next", {"threadId": 1})
    d.response(seq)
    check(d.event("stopped")["body"]["reason"] == "step", "step completed")
    seq = d.send("stackTrace", {"threadId": 1})
    check(d.response(seq)["body"]["stackFrames"][0]["line"] == 13, "stepped to line 13")

    seq = d.send("evaluate", {"expression": "rbx", "frameId": 1, "context": "hover"})
    check(d.response(seq)["body"]["result"].startswith("5"), "rbx == 5")

    seq = d.send("setVariable", {"variablesReference": reg_ref, "name": "rbx", "value": "3"})
    check(d.response(seq)["success"], "setVariable(rbx=3)")

    exit_code = None
    while exit_code is None:
        seq = d.send("continue", {"threadId": 1})
        d.response(seq)
        while True:
            msg = d.recv()
            if msg is None:
                raise RuntimeError("stream closed before exit")
            if msg.get("type") == "event" and msg["event"] == "exited":
                exit_code = msg["body"]["exitCode"]
                break
            if msg.get("type") == "event" and msg["event"] == "stopped":
                break
    check(exit_code == 10, f"exit code 10 after forcing rbx=3 (got {exit_code})")


def hello(d):
    program = os.path.join(EXAMPLES, "hello.yana")

    seq = d.send("initialize", {"adapterID": "yana"})
    d.response(seq)
    seq = d.send("launch", {"program": program})
    d.response(seq)
    d.event("initialized")
    seq = d.send(
        "setBreakpoints",
        {"source": {"path": program}, "breakpoints": [{"line": 13}]},
    )
    check(d.response(seq)["body"]["breakpoints"][0]["verified"], "hello breakpoint verified")
    seq = d.send("configurationDone")
    d.response(seq)
    d.event("stopped")

    seq = d.send("continue", {"threadId": 1})
    d.response(seq)
    check(d.event("stopped")["body"]["reason"] == "breakpoint", "hello: stopped at exit")

    seq = d.send("continue", {"threadId": 1})
    d.response(seq)

    stdout = ""
    exit_code = None
    while exit_code is None:
        msg = d.pending.pop(0) if d.pending else d.recv()
        if msg is None:
            break
        if msg.get("type") == "event" and msg["event"] == "output":
            if msg["body"].get("category") == "stdout":
                stdout += msg["body"]["output"]
        elif msg.get("type") == "event" and msg["event"] == "exited":
            exit_code = msg["body"]["exitCode"]

    check(stdout == "Hello, YANA!\n", f"stdout captured: {stdout!r}")
    check(exit_code == 0, f"hello exits 0 (got {exit_code})")


def main():
    if not os.path.exists(BIN):
        sys.exit(f"binary not found: {BIN}\nbuild it with: cargo build -p yana-lsp")

    d = Dap()
    factorial(d)
    d.close()

    d = Dap()
    hello(d)
    d.close()

    print("\nALL DAP CHECKS PASSED")


if __name__ == "__main__":
    main()
