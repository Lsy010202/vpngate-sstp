"""临时诊断: 完整正确的 SSTP+PPP 客户端, 验证隧道能否建立."""
import socket
import ssl
import struct
import time
import uuid as uuidmod

HOST = "219.100.37.217"
TIMEOUT = 15


class PPP:
    def __init__(self, host):
        s = socket.create_connection((host, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.t = ctx.wrap_socket(s, server_hostname=host)
        self.t.settimeout(TIMEOUT)
        self.buf = b""
        self.idseq = 10

    def _recv(self, n):
        while len(self.buf) < n:
            c = self.t.recv(n - len(self.buf))
            if not c:
                raise RuntimeError("closed")
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _sstp_data(self, ppp_frame):
        # ppp_frame: 不含 FF 03, 以 proto 开头
        plen = 6 + len(ppp_frame)
        hdr = bytes([0x10, 0x00, ((plen >> 8) & 0x0F) | 0x80, plen & 0xFF])
        return hdr + b"\xff\x03" + ppp_frame

    def _lcp(self, code, ident, options=b""):
        return struct.pack(">H", 0xC021) + bytes([code, ident]) \
            + struct.pack(">H", 4 + len(options)) + options

    def send(self, ppp_frame):
        self.t.sendall(self._sstp_data(ppp_frame))

    def start(self):
        corr = str(uuidmod.uuid4())
        http_req = (
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
            f"Host: {HOST}\r\nContent-Length: 18446744073709551615\r\n"
            f"SSTPCORRELATIONID: {{{corr}}}\r\n\r\n").encode()
        hs = bytes([0x10, 0x01]) + struct.pack(">H", 14 | 0x8000) + bytes(
            [0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01])
        lcp_req = self._lcp(1, 1, bytes([1, 4]) + struct.pack(">H", 1500))
        self.t.sendall(http_req + hs + self._sstp_data(lcp_req))
        print("发出握手+LCP", flush=True)

    def read_packet(self):
        hdr = self._recv(4)
        ln = struct.unpack(">H", hdr[2:4])[0] & 0x0FFF
        body = self._recv(ln - 4) if ln > 4 else b""
        is_ctrl = (hdr[1] & 1) != 0
        return is_ctrl, body

    def parse_ppp(self, body):
        off = 2 if body[:2] == b"\xff\x03" else 0
        proto = struct.unpack(">H", body[off:off + 2])[0]
        code, ident = body[off + 2], body[off + 3]
        plen = struct.unpack(">H", body[off + 4:off + 6])[0]
        payload = body[off + 6:off + 6 + plen - 4]
        return proto, code, ident, payload


def main():
    p = PPP(HOST)
    p.start()
    # 读 HTTP 200
    status = b""
    while b"\r\n" not in status:
        status += p._recv(1)
    print("HTTP:", status.decode("latin1").strip(), flush=True)
    while True:
        line = b""
        while not line.endswith(b"\r\n"):
            line += p._recv(1)
        if line in (b"\r\n", b""):
            break

    local_acked = False
    peer_acked = False
    pap_done = False
    ipcp_done = False
    my_ip = None
    pap_sent = False

    t0 = time.time()
    while time.time() - t0 < 40 and not ipcp_done:
        try:
            is_ctrl, body = p.read_packet()
        except Exception as e:
            print("读包异常:", e, flush=True)
            break
        if is_ctrl:
            msg = struct.unpack(">H", body[0:2])[0] if len(body) >= 2 else -1
            print(f"控制包 msg={hex(msg)}", flush=True)
            if msg == 0x0005:
                print("服务器发来 CALL_DISCONNECT", flush=True)
                break
            continue
        proto, code, ident, payload = p.parse_ppp(body)
        if proto == 0xC021:  # LCP
            if code == 1:  # Request -> Ack
                print(f"LCP Request id={ident} opts={payload.hex()}", flush=True)
                p.send(p._lcp(2, ident, payload))
                print(f"  -> LCP Ack id={ident}", flush=True)
                peer_acked = True
            elif code == 2:  # Ack
                print(f"LCP Ack id={ident}", flush=True)
                local_acked = True
            elif code == 5:
                print("LCP Terminate-Request, 回 Terminate-Ack", flush=True)
                p.send(p._lcp(6, ident))
        elif proto == 0xC023:  # PAP
            if code == 2:
                print("PAP 成功!", flush=True)
                pap_done = True
            elif code == 3:
                print("PAP 失败!", flush=True)
                break
        elif proto == 0x8021:  # IPCP
            if code == 1:  # Request -> Ack
                print(f"IPCP Request id={ident} opts={payload.hex()}", flush=True)
                p.send(struct.pack(">H", 0x8021) + bytes([2, ident])
                       + struct.pack(">H", 4 + len(payload)) + payload)
            elif code == 2:
                print(f"IPCP Ack id={ident} opts={payload.hex()}", flush=True)
                # 解析分配的 IP (option type 3)
                i = 0
                while i + 2 <= len(payload):
                    t_, l_ = payload[i], payload[i + 1]
                    if t_ == 3 and l_ == 6:
                        my_ip = ".".join(str(b) for b in payload[i+2:i+6])
                    i += l_ if l_ >= 2 else 2
                ipcp_done = True
            elif code == 3:  # Nak -> 按建议重发
                print(f"IPCP Nak opts={payload.hex()}, 按建议重发", flush=True)
                p.idseq += 1
                p.send(struct.pack(">H", 0x8021) + bytes([1, p.idseq])
                       + struct.pack(">H", 4 + len(payload)) + payload)
        # 状态推进
        if local_acked and peer_acked and not pap_sent:
            user, pwd = b"vpn", b"vpn"
            pap = bytes([len(user)]) + user + bytes([len(pwd)]) + pwd
            p.idseq += 1
            p.send(struct.pack(">H", 0xC023) + bytes([1, p.idseq])
                   + struct.pack(">H", 4 + len(pap)) + pap)
            pap_sent = True
            print("-> PAP Auth(vpn/vpn)", flush=True)
        if pap_done and not ipcp_done and not hasattr(main, "_ipcp"):
            main._ipcp = True
            p.idseq += 1
            ipcp_req = bytes([3, 6, 0, 0, 0, 0])
            p.send(struct.pack(">H", 0x8021) + bytes([1, p.idseq])
                   + struct.pack(">H", 4 + len(ipcp_req)) + ipcp_req)
            print("-> IPCP Request", flush=True)

    print(f"结果: local_acked={local_acked} peer_acked={peer_acked} "
          f"pap_done={pap_done} ipcp_done={ipcp_done} my_ip={my_ip}", flush=True)
    print("DONE")


main()
