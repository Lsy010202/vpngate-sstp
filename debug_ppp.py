"""临时诊断: 完整 SSTP+PPP 握手 (LCP -> PAP(vpn/vpn) -> IPCP),
验证 VPN Gate 节点是否真的能建立隧道."""
import socket
import ssl
import struct
import uuid as uuidmod

HOST = "217.138.212.62"
TIMEOUT = 20


class SSTP:
    def __init__(self, host):
        s = socket.create_connection((host, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.t = ctx.wrap_socket(s, server_hostname=host)
        self.t.settimeout(TIMEOUT)
        self.buf = b""
        self.ident = 1

    def _recv(self, n):
        while len(self.buf) < n:
            c = self.t.recv(n - len(self.buf))
            if not c:
                raise RuntimeError("连接关闭")
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def build_lcp(self, ident=1):
        frame = struct.pack(">H", 0xC021) + bytes([1, ident]) \
            + struct.pack(">H", 8) + bytes([1, 4]) + struct.pack(">H", 1500)
        pkt_len = 6 + 2 + len(frame)
        hdr = bytes([0x10, 0x00, ((pkt_len >> 8) & 0x0F) | 0x80,
                     pkt_len & 0xFF, 0xFF, 0x03])
        return hdr + frame

    def handshake(self):
        corr = str(uuidmod.uuid4())
        http_req = (
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
            f"Host: {HOST}\r\nContent-Length: 18446744073709551615\r\n"
            f"SSTPCORRELATIONID: {{{corr}}}\r\n\r\n").encode()
        pkt = bytes([0x10, 0x01]) + struct.pack(">H", 14 | 0x8000) + bytes([
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01])
        # worker 同款: HTTP请求 + CALL_CONNECT_REQUEST + LCP 一次性发出
        self.t.sendall(http_req + pkt + self.build_lcp(1))
        print("已一次性发出 HTTP+握手+LCP", flush=True)
        status = b""
        while b"\r\n" not in status:
            status += self._recv(1)
        print("HTTP:", status.decode("latin1").strip(), flush=True)
        while True:
            line = b""
            while not line.endswith(b"\r\n"):
                line += self._recv(1)
            if line in (b"\r\n", b""):
                break
        hdr = self._recv(4)
        ln = struct.unpack(">H", hdr[2:4])[0] & 0x7FFF
        body = self._recv(ln - 4)
        msg = struct.unpack(">H", body[0:2])[0]
        print("SSTP msg:", hex(msg), "(2=ACK)", flush=True)
        return msg == 0x0002

    def send_ppp(self, proto, code, ident, payload=b""):
        # SSTP data 包: [0x10,0x00,len|0x80..] + FF 03 + proto + code/id/len + payload
        frame = struct.pack(">H", proto) + bytes([code, ident]) \
            + struct.pack(">H", 4 + len(payload)) + payload
        pkt_len = 6 + 2 + len(frame)
        hdr = bytes([0x10, 0x00, ((pkt_len >> 8) & 0x0F) | 0x80,
                     pkt_len & 0xFF, 0xFF, 0x03])
        self.t.sendall(hdr + frame)

    def recv_ppp(self):
        hdr = self._recv(4)
        ln = struct.unpack(">H", hdr[2:4])[0] & 0x0FFF
        body = self._recv(ln - 4)
        # body: FF 03 | proto(2) | code | id | len(2) | payload
        off = 2 if body[:2] == b"\xff\x03" else 0
        proto = struct.unpack(">H", body[off:off + 2])[0]
        code, ident = body[off + 2], body[off + 3]
        plen = struct.unpack(">H", body[off + 4:off + 6])[0]
        payload = body[off + 6:off + plen]
        return proto, code, ident, payload


def main():
    s = SSTP(HOST)
    if not s.handshake():
        print("握手失败")
        return
    print("等待 LCP 回应...", flush=True)
    for _ in range(8):
        proto, code, ident, payload = s.recv_ppp()
        names = {1: "Req", 2: "Ack", 3: "Nak", 4: "Rej", 5: "TermReq", 6: "TermAck"}
        print(f"<- proto={hex(proto)} {names.get(code, code)} id={ident} "
              f"payload={payload.hex()[:40]}", flush=True)
        if proto == 0xC021 and code == 2:
            print("LCP Acked!", flush=True)
            break
        if proto == 0xC021 and code == 1:
            # 对端发来的 Request, 回 Ack
            s.send_ppp(0xC021, 2, ident, payload)
            print("-> LCP Ack (回应对方)", flush=True)
    # PAP Authenticate-Request: vpn/vpn
    user, pwd = b"vpn", b"vpn"
    s.send_ppp(0xC023, 1, 2, bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
    print("-> PAP Auth(vpn/vpn)", flush=True)
    for _ in range(6):
        proto, code, ident, payload = s.recv_ppp()
        print(f"<- proto={hex(proto)} code={code} id={ident} "
              f"payload={payload.hex()[:40]}", flush=True)
        if proto == 0xC023 and code == 2:
            print("PAP 成功!", flush=True)
            break
        if proto == 0xC023 and code == 3:
            print("PAP 失败, 凭证被拒")
            return
    # IPCP Configure-Request: 请求 IP 0.0.0.0
    s.send_ppp(0x8021, 1, 3, bytes([3, 6, 0, 0, 0, 0]))
    print("-> IPCP Configure-Request", flush=True)
    for _ in range(10):
        proto, code, ident, payload = s.recv_ppp()
        names = {1: "Req", 2: "Ack", 3: "Nak", 4: "Rej"}
        print(f"<- proto={hex(proto)} {names.get(code, code)} id={ident} "
              f"payload={payload.hex()[:40]}", flush=True)
        if proto == 0x8021 and code == 1:
            s.send_ppp(0x8021, 2, ident, payload)
            print("-> IPCP Ack (回应对方)", flush=True)
        if proto == 0x8021 and code == 2:
            print("IPCP Acked! 隧道可建立", flush=True)
            break
        if proto == 0x8021 and code == 3:
            print("IPCP Nak, payload:", payload.hex())
    print("DONE")


main()
