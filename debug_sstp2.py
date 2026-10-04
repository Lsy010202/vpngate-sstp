"""临时诊断: 用 edgetunnel 同款 SSTP-over-HTTPS 握手测试已知开放主机的 SSTP."""
import os
import socket
import ssl
import struct
import uuid as uuidmod

HOSTS = ["219.100.37.217", "219.100.37.214", "60.124.87.220",
         "219.100.37.193", "219.100.37.4"]


def sstp_https_handshake(host, timeout=15):
    try:
        s = socket.create_connection((host, 443), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        t.settimeout(timeout)
        corr = str(uuidmod.uuid4())
        http_req = (
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 18446744073709551615\r\n"
            f"SSTPCORRELATIONID: {{{corr}}}\r\n\r\n"
        )
        t.sendall(http_req.encode())
        # CALL_CONNECT_REQUEST, edgetunnel 同款编码: [0x10,0x01] + u16be(len|0x8000)
        pkt = (bytes([0x10, 0x01]) + struct.pack(">H", 16 | 0x8000) + bytes([
            0x00, 0x01,  # CALL_CONNECT_REQUEST
            0x00, 0x01,  # 1 attribute
            0x00, 0x01, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x01]))
        t.sendall(pkt)
        # 读 HTTP 状态行
        status = b""
        while b"\r\n" not in status:
            c = t.recv(1)
            if not c:
                return f"no-status"
            status += c
        status_s = status.decode("latin1").strip()
        # 读完 headers
        while True:
            line = b""
            while not line.endswith(b"\r\n"):
                c = t.recv(1)
                if not c:
                    break
                line += c
            if line in (b"\r\n", b""):
                break
        # 读 SSTP 回包
        hdr = t.recv(4)
        if len(hdr) < 4:
            t.close()
            return f"HTTP:{status_s} + 无SSTP回包"
        length = struct.unpack(">H", hdr[2:4])[0] & 0x7FFF
        body = b""
        while len(body) < length - 4:
            c = t.recv(length - 4 - len(body))
            if not c:
                break
            body += c
        t.close()
        msg = struct.unpack(">H", body[0:2])[0] if len(body) >= 2 else -1
        name = {0x0002: "CALL_CONNECT_ACK", 0x0003: "CALL_CONNECT_NAK"}.get(msg, hex(msg))
        return f"HTTP:{status_s} SSTP回包 msg={name}"
    except Exception as e:
        return f"FAIL {type(e).__name__} {str(e)[:80]}"


for h in HOSTS:
    print(f"{h}: {sstp_https_handshake(h)}", flush=True)
print("DONE")
