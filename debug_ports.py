"""临时诊断: 对 VPN Gate 候选 IP 扫常用端口, 看看到底哪些端口通."""
import socket
import urllib.request

PORTS = [443, 992, 1194, 5555, 500, 4500, 1701, 1723, 80, 8080]

raw = urllib.request.urlopen(
    urllib.request.Request("https://www.vpngate.net/api/iphone/",
                           headers={"User-Agent": "Mozilla/5.0"}),
    timeout=30).read().decode("utf-8", "replace")
hosts = []
for line in raw.splitlines():
    if line.startswith("#HostName"):
        header = line[1:].split(",")
    elif line and not line.startswith(("*", "#")):
        cols = line.split(",")
        d = dict(zip(header, cols))
        try:
            if int(d.get("Speed") or 0) > 8_000_000:
                hosts.append((d["IP"], d["CountryShort"]))
        except ValueError:
            pass
        if len(hosts) >= 8:
            break

for ip, cc in hosts:
    open_ports = []
    for p in PORTS:
        try:
            s = socket.create_connection((ip, p), timeout=6)
            # 抓一点 banner
            s.settimeout(4)
            try:
                banner = s.recv(64)
            except Exception:
                banner = b""
            s.close()
            open_ports.append(f"{p}({banner[:18]!r})")
        except Exception:
            pass
    print(f"{ip} [{cc}]: open={open_ports or 'none'}", flush=True)
print("DONE")
