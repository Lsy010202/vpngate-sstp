# VPN Gate SSTP 备用节点

每小时自动检测一次 VPN Gate 公开节点:
1. 抓取公开节点列表, 按 ping/带宽初筛
2. 逐个做 SSTP 握手验证 (TCP+TLS 到 443, CALL_CONNECT_REQUEST → CALL_CONNECT_ACK)
3. 对通过的节点做**全链路验证**: VLESS → Cloudflare Worker → SSTP → 节点 → 外网,
   并确认出口 IP 与节点 IP 一致 (排除 Worker 兜底直连)
4. 生成订阅发布到 GitHub Pages

## 所需 Secrets

| Secret       | 说明                          |
| ------------ | ----------------------------- |
| `EDT_DOMAIN` | edgetunnel Worker 域名        |
| `EDT_UUID`   | Worker 的 UUID                |

## 输出 (GitHub Pages)

- `sub.txt` — base64 订阅, 直接填入 v2rayN/Clash 订阅栏
- `index.html` — 节点列表页
- `hosts.txt` / `meta.json` — 原始数据
