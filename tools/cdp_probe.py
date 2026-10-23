#!/usr/bin/env python3
"""Minimal CDP client: navigate, wait, evaluate JS, print result. Stdlib only.

Usage: cdp.py [url] [js-expression] [wait-seconds]
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request

CHROME = os.environ.get("CHROME") or "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PORT = 9333


def http_json(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=5) as r:
        return json.load(r)


def find_target():
    for _ in range(30):
        try:
            for t in http_json("/json"):
                if t.get("type") == "page":
                    return t
        except Exception:
            pass
        time.sleep(0.3)
    return None


def ws_connect(ws_url):
    path = ws_url.split(f"127.0.0.1:{PORT}", 1)[1]
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    assert b"101" in buf.split(b"\r\n")[0], buf[:200]
    return s


def ws_send(s, obj):
    data = json.dumps(obj).encode()
    header = bytearray([0x81])
    n = len(data)
    mask = os.urandom(4)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", n)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    s.sendall(bytes(header) + masked)


def ws_recv(s, timeout=15):
    s.settimeout(timeout)
    def rd(n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError
            buf += chunk
        return buf
    b0, b1 = rd(2)
    ln = b1 & 0x7F
    masked = bool(b1 & 0x80)
    if ln == 126:
        ln = struct.unpack(">H", rd(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", rd(8))[0]
    mk = rd(4) if masked else b""
    data = rd(ln)
    if masked:
        data = bytes(b ^ mk[i % 4] for i, b in enumerate(data))
    return json.loads(data)


def run(url, expr, wait=4.0, mobile=None):
    proc = subprocess.Popen([
        CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
        f"--remote-debugging-port={PORT}", "--user-data-dir=/tmp/cdp-prof",
        "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        target = find_target()
        if not target:
            print("no target")
            return None, []
        s = ws_connect(target["webSocketDebuggerUrl"])
        ws_send(s, {"id": 0, "method": "Runtime.enable"})
        ws_send(s, {"id": 1, "method": "Page.navigate", "params": {"url": url}})
        if mobile:
            ws_send(s, {"id": 4, "method": "Emulation.setDeviceMetricsOverride",
                        "params": {"width": 390, "height": 844, "deviceScaleFactor": 2, "mobile": True}})
        exc = []
        t_end = time.time() + wait
        s.settimeout(2)
        while time.time() < t_end:
            try:
                m = ws_recv(s, timeout=2)
            except Exception:
                continue
            if m.get("method") == "Runtime.exceptionThrown":
                exc.append(m["params"]["exceptionDetails"]["exception"].get("description", "?"))
        ws_send(s, {"id": 2, "method": "Runtime.evaluate",
                    "params": {"expression": expr, "returnByValue": True}})
        value = None
        for _ in range(40):
            m = ws_recv(s)
            if m.get("id") == 2:
                res = m.get("result", {}).get("result", {})
                value = res.get("value")
                break
        s.close()
        return value, exc
    finally:
        proc.terminate()


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8912/"
    expr = sys.argv[2] if len(sys.argv) > 2 else "document.title"
    wait = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0
    if expr.startswith("@"):
        expr = open(expr[1:]).read()
    value, exc = run(url, expr, wait)
    print(value if value is not None else "(no value)")
    if exc:
        print("EXCEPTIONS:")
        for e in exc[:5]:
            print(e[:400])
