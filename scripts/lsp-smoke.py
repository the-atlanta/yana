#!/usr/bin/env python3
"""Live smoke test of yana-lsp over stdio JSON-RPC (binary framing)."""
import json, subprocess, sys, threading, time

BINARY = "./target/debug/yana-lsp"

proc = subprocess.Popen(
    [BINARY], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
)

def send(obj):
    body = json.dumps(obj).encode("utf-8")
    # Content-Length is a BYTE count — hello.yana contains UTF-8 comments
    proc.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    proc.stdin.flush()

responses = {}
notifications = []

def reader():
    while True:
        header = proc.stdout.readline()
        if not header:
            break
        if header.startswith(b"Content-Length:"):
            n = int(header.split(b":")[1].strip())
            proc.stdout.readline()  # blank line
            body = proc.stdout.read(n).decode("utf-8")
            obj = json.loads(body)
            if "id" in obj:
                responses[obj["id"]] = obj
            else:
                notifications.append(obj)

threading.Thread(target=reader, daemon=True).start()

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}, "processId": None, "rootUri": None}})
time.sleep(0.3)
send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
time.sleep(0.3)

src_bad = "bind x @ rax: u64 = 1;\nalt x += 1;\nfn f( {"
send({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {"uri": "file:///tmp/t1.yana", "languageId": "yana", "version": 1, "text": src_bad}}})

src_good = open("examples/hello.yana").read()
send({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {"uri": "file:///tmp/hello.yana", "languageId": "yana", "version": 1, "text": src_good}}})

# completion in place context: a doc whose line ends with "bind n @ "
src_ctx = "fn f() {\n    bind n @ \n}\n"
send({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {"uri": "file:///tmp/ctx.yana", "languageId": "yana", "version": 1, "text": src_ctx}}})
time.sleep(0.5)
send({"jsonrpc": "2.0", "id": 2, "method": "textDocument/completion", "params": {"textDocument": {"uri": "file:///tmp/ctx.yana"}, "position": {"line": 1, "character": 13}}})

# hover on rdi in hello.yana (0-based line 4: `extern fn write(fd @ rdi: u64...`)
line = 4
col = src_good.split("\n")[4].index("rdi") + 1
send({"jsonrpc": "2.0", "id": 3, "method": "textDocument/hover", "params": {"textDocument": {"uri": "file:///tmp/hello.yana"}, "position": {"line": line, "character": col}}})

deadline = time.time() + 15
while time.time() < deadline and (2 not in responses or 3 not in responses):
    time.sleep(0.1)
time.sleep(1.5)  # let diagnostics arrive

# ---- checks ----
ok = True
init = responses.get(1, {})
caps = init.get("result", {}).get("capabilities", {})
print("initialize:", "OK" if caps.get("completionProvider") and caps.get("hoverProvider") else "FAIL")
ok &= bool(caps.get("completionProvider"))

diags_by_uri = {}
for n in notifications:
    if n.get("method") == "textDocument/publishDiagnostics":
        diags_by_uri[n["params"]["uri"]] = n["params"]["diagnostics"]

t1 = diags_by_uri.get("file:///tmp/t1.yana", None)
print("bad-file diagnostics:", len(t1) if t1 is not None else "NONE")
if t1 is not None:
    print("  codes:", [d.get("code") for d in t1])
    ok &= len(t1) >= 1
hello = diags_by_uri.get("file:///tmp/hello.yana", [])
print("hello diagnostics:", len(hello), [d.get("code") for d in hello])
ok &= len(hello) == 0

comp = responses.get(2, {}).get("result") or []
if isinstance(comp, dict):
    comp = comp.get("items", [])
labels = [c["label"] for c in comp]
print("completion(place ctx):", len(labels), "items; has rax:", "rax" in labels, "; has .rodata:", ".rodata" in labels)
ok &= "rax" in labels

hov = responses.get(3, {}).get("result")
val = (hov or {}).get("contents", {}).get("value", "") if hov else ""
print("hover(rdi):", val[:90] if val else "NONE")
ok &= bool(hov) and "rdi" in val

proc.terminate()
try:
    _, err = proc.communicate(timeout=3)
    if err:
        print("--- server stderr ---")
        print(err.decode("utf-8", "replace")[-2000:])
except Exception as e:
    print("stderr capture failed:", e)
print("responses seen:", sorted(responses.keys()))
print("notifications seen:", [n.get("method") for n in notifications])
print("SMOKE:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
