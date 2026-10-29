#!/usr/bin/env python3
"""Minimal: didOpen only, dump stderr + any notifications."""
import json, subprocess, threading, time

proc = subprocess.Popen(["./target/debug/yana-lsp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def msg(obj):
    body = json.dumps(obj)
    return f"Content-Length: {len(body)}\r\n\r\n{body}"

def send(obj):
    proc.stdin.write(msg(obj)); proc.stdin.flush()

lines = []
def errreader():
    for line in proc.stderr:
        lines.append(line)
threading.Thread(target=errreader, daemon=True).start()

notifs = []
def reader():
    while True:
        header = proc.stdout.readline()
        if not header:
            break
        if header.startswith("Content-Length:"):
            n = int(header.split(":")[1].strip())
            proc.stdout.readline()
            obj = json.loads(proc.stdout.read(n))
            notifs.append(obj)
threading.Thread(target=reader, daemon=True).start()

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"processId":None,"rootUri":None}})
time.sleep(0.3)
send({"jsonrpc":"2.0","method":"initialized","params":{}})
time.sleep(0.3)
send({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///tmp/bad.yana","languageId":"yana","version":1,"text":"bind x @ rax: u64 = 1;\nalt x += 1;\nfn f( {"}}})
time.sleep(2.0)
proc.terminate()
time.sleep(0.3)
print("NOTIFS:")
for n in notifs:
    print(json.dumps(n)[:400])
print("STDERR:")
print("".join(lines)[-3000:])
