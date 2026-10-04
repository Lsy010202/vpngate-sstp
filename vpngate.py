"""VPN Gate SSTP 节点检测 + 订阅生成（跑在 GitHub Actions 上）.

流程:
  1. 抓取 https://www.vpngate.net/api/iphone/ 公开节点列表
  2. 按 ping/speed 初筛, 对候选逐个做 SSTP 握手验证
     (TCP+TLS 到 :443, 发送 CALL_CONNECT_REQUEST, 等待 CALL_CONNECT_ACK)
  3. 对通过握手的节点做全链路验证:
     VLESS --wss--> Cloudflare Worker --SSTP--> VPN Gate 节点 --HTTP--> 外网,
     通过 api.ipify.org 确认出口 IP 确实是该节点 IP (排除 Worker 兜底直连)
  4. 生成 public/sub.txt (base64 订阅), public/index.html (节点页),
     public/hosts.txt, public/meta.json, 发布到 GitHub Pages

环境变量:
  EDT_DOMAIN  - edgetunnel Worker 域名 (如 edt-sstp.kikinytbttv.workers.dev)
  EDT_UUID    - Worker 的 UUID
  MAX_NODES   - 订阅保留节点数 (默认 12)
"""
import concurrent.futures
import datetime
import html
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request
from urllib.parse import quote

EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "").strip()
EDT_UUID = os.environ.get("EDT_UUID", "").strip()
MAX_NODES = int(os.environ.get("MAX_NODES", "12"))
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")

if not EDT_DOMAIN or not EDT_UUID:
    print("ERROR: EDT_DOMAIN / EDT_UUID 环境变量未设置", flush=True)
    sys.exit(1)


def fetch_csv():
    for url in ("https://www.vpngate.net/api/iphone/",
                "http://www.vpngate.net/api/iphone/"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            raw = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
            if "#HostName" in raw:
                print(f"节点列表获取成功: {url}", flush=True)
                return raw
        except Exception as e:
            print(f"获取失败 {url}: {e}", flush=True)
    raise RuntimeError("无法获取 VPN Gate 节点列表")


def parse_csv(raw):
    header, rows = None, []
    for line in raw.splitlines():
        if not line:
            continue
        if line.startswith("#HostName"):
            header = line[1:].split(",")
        elif not line.startswith(("*", "#")):
            rows.append(line)
    nodes = []
    for line in rows:
        cols = line.split(",")
        if len(cols) < 15:
            continue
        d = dict(zip(header, cols))
        try:
            speed = int(d.get("Speed") or 0)
            ping = int(d.get("Ping") or 99999)
            sessions = int(d.get("NumVpnSessions") or 0)
        except ValueError:
            continue
        if speed < 8_000_000:  # 广告带宽 < 8Mbps 的跳过
            continue
        nodes.append({
            "host": d.get("HostName"), "ip": d.get("IP"),
            "cc": d.get("CountryShort"), "country": d.get("CountryLong"),
            "speed": speed, "ping": ping, "sessions": sessions,
        })
    # ping 优先, 速度其次
    nodes.sort(key=lambda n: (n["ping"], -n["speed"]))
    print(f"初筛候选: {len(nodes)} 个", flush=True)
    return nodes


def sstp_handshake(host, timeout=12):
    """返回 (ok, 握手耗时ms)."""
    t0 = time.time()
    try:
        s = socket.create_connection((host, 443), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=host)
        t.settimeout(timeout)
        pkt = bytes([0x10, 0x01, 0x00, 0x10,
                     0x00, 0x01, 0x00, 0x01,
                     0x00, 0x01, 0x00, 0x08,
                     0x00, 0x00, 0x00, 0x01])
        t.sendall(pkt)
        resp = t.recv(64)
        t.close()
        if len(resp) >= 8 and resp[0] == 0x10 and resp[1] == 0x01:
            if struct.unpack(">H", resp[4:6])[0] == 0x0002:  # CALL_CONNECT_ACK
                return True, int((time.time() - t0) * 1000)
        return False, 0
    except Exception:
        return False, 0


def ws_vless_e2e(node_host, node_ip, timeout=30):
    """完整链路验证, 返回出口 IP (成功) 或 None."""
    import base64 as b64mod, os as osmod
    ws_path = f"/{EDT_UUID}/gsstp=vpn:vpn@{node_host}:443"
    try:
        s = socket.create_connection((EDT_DOMAIN, 443), timeout=15)
        ctx = ssl.create_default_context()
        t = ctx.wrap_socket(s, server_hostname=EDT_DOMAIN)
        t.settimeout(timeout)
        key = b64mod.b64encode(osmod.urandom(16)).decode()
        t.sendall(
            f"GET {ws_path} HTTP/1.1\r\nHost: {EDT_DOMAIN}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"User-Agent: v2rayN/7.0\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = t.recv(4096)
            if not chunk:
                return None
            resp += chunk
        if b"101" not in resp.split(b"\r\n")[0]:
            return None

        def ws_send(data):
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

        def ws_recv():
            h = t.recv(2)
            if len(h) < 2:
                return None
            ln = h[1] & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", t.recv(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", t.recv(8))[0]
            data = b""
            while len(data) < ln:
                data += t.recv(ln - len(data))
            return h[0] & 0x0F, data

        uuid_b = bytes.fromhex(EDT_UUID.replace("-", ""))
        tgt = b"api.ipify.org"
        vless = (b"\x00" + uuid_b + b"\x00" + b"\x01" + struct.pack(">H", 80)
                 + b"\x03" + bytes([len(tgt)]) + tgt)
        ws_send(vless)
        ws_send(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        out = b""
        try:
            while True:
                r = ws_recv()
                if r is None:
                    break
                op, data = r
                if op == 0x8:
                    break
                out += data
                if len(out) > 8192:
                    break
        except socket.timeout:
            pass
        t.close()
        # 提取 HTTP body 里的 IP
        if b"\r\n\r\n" in out:
            body = out.split(b"\r\n\r\n", 1)[1].decode("utf-8", "replace").strip()
            ip = body.split()[0] if body else ""
            if ip and all(p.isdigit() and 0 <= int(p) <= 255 for p in ip.split(".") if p):
                return ip if len(ip.split(".")) == 4 else None
        return None
    except Exception:
        return None


def build_link(node):
    path = f"/{EDT_UUID}/gsstp=vpn:vpn@{node['host']}:443"
    name = f"VG-{node['cc']}-{node['ip']}"
    return (f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
            f"&host={EDT_DOMAIN}&path={quote(path, safe='')}"
            f"&fp=chrome&sni={EDT_DOMAIN}&encryption=none#{quote(name, safe='')}")


def main():
    t_start = time.time()
    raw = fetch_csv()
    cands = parse_csv(raw)[:60]

    print("== SSTP 握手检测 ==", flush=True)
    hs_ok = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(sstp_handshake, n["host"]): n for n in cands}
        for f in concurrent.futures.as_completed(futs):
            n = futs[f]
            ok, ms = f.result()
            if ok:
                n["hs_ms"] = ms
                hs_ok.append(n)
                print(f"  握手通过: {n['host']} ({n['ip']}) {n['cc']} {ms}ms", flush=True)
    print(f"握手通过: {len(hs_ok)} 个", flush=True)
    if not hs_ok:
        print("ERROR: 没有可用的 SSTP 节点", flush=True)
        sys.exit(1)

    print("== 全链路验证 (VLESS->Worker->SSTP->外网) ==", flush=True)
    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(ws_vless_e2e, n["host"], n["ip"]): n for n in hs_ok[:24]}
        for f in concurrent.futures.as_completed(futs):
            n = futs[f]
            exit_ip = f.result()
            n["exit_ip"] = exit_ip
            # 出口 IP 必须等于节点 IP, 否则可能是 Worker 兜底直连
            n["residential_ok"] = (exit_ip == n["ip"])
            flag = "住宅出口✓" if n["residential_ok"] else ("出口漂移✗" if exit_ip else "不通✗")
            print(f"  {n['host']}: 出口 {exit_ip} {flag}", flush=True)
            if exit_ip:
                verified.append(n)
    # 优先保留出口 IP 吻合的节点
    verified.sort(key=lambda n: (not n["residential_ok"], n["ping"]))
    nodes = verified[:MAX_NODES]
    print(f"最终可用: {len(nodes)} 个 (出口吻合 {sum(1 for n in nodes if n['residential_ok'])})",
          flush=True)
    if not nodes:
        print("ERROR: 全链路验证全部失败", flush=True)
        sys.exit(1)

    os.makedirs(OUT_DIR, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

    links = [build_link(n) for n in nodes]
    import base64 as b64mod
    with open(os.path.join(OUT_DIR, "sub.txt"), "w") as f:
        f.write(b64mod.b64encode("\n".join(links).encode()).decode())
    with open(os.path.join(OUT_DIR, "hosts.txt"), "w") as f:
        f.write("\n".join(f"vpn:vpn@{n['host']}:443  # {n['cc']} {n['ip']}"
                          for n in nodes) + "\n")
    with open(os.path.join(OUT_DIR, "meta.json"), "w") as f:
        json.dump({"updated": now, "count": len(nodes), "domain": EDT_DOMAIN,
                   "nodes": [{k: n[k] for k in ("host", "ip", "cc", "country", "ping",
                             "speed", "hs_ms", "exit_ip", "residential_ok")} for n in nodes]},
                  f, ensure_ascii=False, indent=2)
    rows = "\n".join(
        f"<tr><td>{html.escape(n['cc'])}</td><td>{html.escape(n['host'])}</td>"
        f"<td>{html.escape(n['ip'])}</td><td>{n['ping']}ms</td>"
        f"<td>{n['speed']//1000000}Mbps</td>"
        f"<td>{'✓' if n['residential_ok'] else '漂移'}</td></tr>" for n in nodes)
    with open(os.path.join(OUT_DIR, "index.html"), "w") as f:
        f.write(f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Gate SSTP 备用节点</title>
<style>body{{font-family:system-ui;max-width:900px;margin:2em auto;padding:0 1em}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px 10px;font-size:14px}}
code{{background:#f4f4f4;padding:2px 6px;word-break:break-all}}</style></head>
<body><h2>VPN Gate SSTP 备用节点</h2>
<p>更新时间: {html.escape(now)} | 共 {len(nodes)} 个节点 | 每小时自动检测</p>
<p>订阅链接: <code>{html.escape('https://<user>.github.io/<repo>/sub.txt')}</code>
（复制到 v2rayN / Clash 的订阅栏）</p>
<table><tr><th>国家</th><th>主机</th><th>IP</th><th>Ping</th><th>带宽</th><th>出口</th></tr>
{rows}</table>
<p style="color:#888;font-size:13px">节点来自 VPN Gate 志愿者网络, 流量经志愿者电脑出境,
请勿传输敏感信息; 单个节点随时可能失效, 以订阅自动更新为准。</p>
</body></html>""")
    print(f"完成, 用时 {int(time.time()-t_start)}s, 输出到 {OUT_DIR}", flush=True)


if __name__ == "__main__":
    main()
