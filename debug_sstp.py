"""临时诊断: 对已知 443 开放的 VPN Gate 主机做详细 SSTP 握手, 打印每一步."""
import socket
import ssl
import struct

HOSTS = ["219.100.37.217", "219.100.37.214", "60.124.87.220",
         "219.100.37.193", "219.100.37.4"]

CALL_CONNECT_REQUEST = bytes([
    0x10, 0x01, 0x00, 0x10,   # ver=0x10, C=1, len=16
    0x00, 0x01,               # CALL_CONNECT_REQUEST
    0x00, 0x01,               # 1 attribute
    0x00, 0x01, 0x00, 0x08,   # attr ENCAPSULATED_PROTOCOL_ID, len=8
    0x00, 0x00, 0x00, 0x01,   # value = PPP
])

for host in HOSTS:
    print(f"=== {host} ===", flush=True)
    try:
        s = socket.create_connection((host, 443), timeout=10)
        print("  TCP OK", flush=True)
    except Exception as e:
        print(f"  TCP FAIL: {e}", flush=True)
        continue
    for label, use_sni in [("SNI=host", True), ("no-SNI", False)]:
        try:
            s2 = socket.create_connection((host, 443), timeout=10)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            t = ctx.wrap_socket(s2, server_hostname=host if use_sni else None)
            t.settimeout(10)
            print(f"  [{label}] TLS OK cipher={t.cipher()[0]}", flush=True)
            t.sendall(CALL_CONNECT_REQUEST)
            print(f"  [{label}] sent CALL_CONNECT_REQUEST", flush=True)
            resp = t.recv(128)
            print(f"  [{label}] resp {len(resp)} bytes: {resp.hex()}", flush=True)
            t.close()
        except Exception as e:
            print(f"  [{label}] FAIL: {type(e).__name__} {str(e)[:100]}", flush=True)
    try:
        s.close()
    except Exception:
        pass
print("DONE")
