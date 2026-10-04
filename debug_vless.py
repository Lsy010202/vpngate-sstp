"""临时诊断: 分步验证 Worker 的 VLESS 接入.
1. /version?uuid= 确认 Worker 存活且 UUID 正确
2. 普通 VLESS (无链式) 拉 example.com
3. SSTP 链式 VLESS 拉 api.ipify.org
"""
import base64 as b64mod
import os as osmod
import socket
import ssl
import struct
import urllib.request

UUID = osmod.environ.get("EDT_UUID", "")
DOMAIN = osmod.environ.get("EDT_DOMAIN", "")
NODE = "219.100.37.217"  # 已验证 SSTP ACK 的主机


def ws_conn(path):
    s = socket.create_connection((DOMAIN, 443), timeout=15)
    ctx = ssl.create_default_context()
    t = ctx.wrap_socket(s, server_hostname=DOMAIN)
    t.settimeout(25)
    key = b64mod.b64encode(osmod.urandom(16)).decode()
    t.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {DOMAIN}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\nUser-Agent: v2rayN/7.0\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        c = t.recv(4096)
        if not c:
            return None, "no-handshake-response"
        resp += c
    status = resp.split(b"\r\n")[0]
    if b"101" not in status:
        return None, f"upgrade-failed: {status[:80]!r}"
    return t, "101"


def ws_send(t, data):
    hdr = bytes([0x82])
    n = len(data)
    mask = osmod.urandom(4)
    if n < 126:
        hdr += bytes([0x80 | n])
    elif n < 65536:
        hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
    t.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def ws_recv_all(t, limit=32768):
    out = b""
    try:
        while len(out) < limit:
            h = t.recv(2)
            if len(h) < 2:
                break
            op, ln = h[0] & 0x0F, h[1] & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", t.recv(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", t.recv(8))[0]
            data = b""
            while len(data) < ln:
                c = t.recv(ln - len(data))
                if not c:
                    break
                data += c
            if op == 0x8:
                break
            if op in (0x1, 0x2):
                out += data
            if b"</html>" in out or b"</HTML>" in out:
                break
    except socket.timeout:
        pass
    return out


def vless_fetch(path, target_host, label):
    t, msg = ws_conn(path)
    if t is None:
        print(f"[{label}] {msg}", flush=True)
        return
    print(f"[{label}] WS {msg}", flush=True)
    uuid_b = bytes.fromhex(UUID.replace("-", ""))
    tb = target_host.encode()
    vless = (b"\x00" + uuid_b + b"\x00" + b"\x01" + struct.pack(">H", 80)
             + b"\x02" + bytes([len(tb)]) + tb)
    ws_send(t, vless)
    ws_send(t, f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode())
    out = ws_recv_all(t)
    t.close()
    print(f"[{label}] 收到 {len(out)} 字节", flush=True)
    if out:
        print(f"[{label}] 前120字节: {out[:120]!r}", flush=True)


# 1. version 接口
try:
    r = urllib.request.urlopen(
        f"https://{DOMAIN}/version?uuid={UUID}", timeout=20).read()
    print(f"[version] {r[:80]}", flush=True)
except Exception as e:
    print(f"[version] FAIL {e}", flush=True)

# 2. 普通 VLESS
vless_fetch(f"/{UUID}", "example.com", "plain-vless")

# 3. SSTP 链式
vless_fetch(f"/{UUID}/gsstp=vpn:vpn@{NODE}:443", "api.ipify.org", "sstp-chain")
print("DONE")
