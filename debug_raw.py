"""临时诊断: SSTP 握手后原始字节全量 dump, 手动解码服务器行为."""
import socket
import ssl
import struct
import uuid as uuidmod

HOST = "219.100.37.217"
TIMEOUT = 15


def main():
    s = socket.create_connection((HOST, 443), timeout=TIMEOUT)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname=HOST)
    t.settimeout(TIMEOUT)
    corr = str(uuidmod.uuid4())
    http_req = (
        "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
        f"Host: {HOST}\r\nContent-Length: 18446744073709551615\r\n"
        f"SSTPCORRELATIONID: {{{corr}}}\r\n\r\n").encode()
    hs = bytes([0x10, 0x01]) + struct.pack(">H", 14 | 0x8000) + bytes(
        [0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01])
    # LCP Configure-Request (id=1, MRU=1500)
    frame = struct.pack(">H", 0xC021) + bytes([1, 1]) + struct.pack(">H", 8) \
        + bytes([1, 4]) + struct.pack(">H", 1500)
    plen = 6 + len(frame)
    lcp = bytes([0x10, 0x00, ((plen >> 8) & 0x0F) | 0x80, plen & 0xFF,
                 0xFF, 0x03]) + frame
    t.sendall(http_req + hs + lcp)
    print(f"发出 {len(http_req+hs+lcp)} 字节", flush=True)

    buf = b""
    t0 = __import__("time").time()
    try:
        while __import__("time").time() - t0 < 25:
            c = t.recv(4096)
            if not c:
                print("服务器关闭连接", flush=True)
                break
            buf += c
            print(f"收到 {len(c)} 字节: {c.hex()}", flush=True)
    except socket.timeout:
        print("接收超时", flush=True)
    print(f"总计收到 {len(buf)} 字节", flush=True)
    # 尝试解码 HTTP 状态行
    if b"HTTP" in buf:
        print("HTTP部分:", buf.split(b"\r\n")[0], flush=True)


main()
