#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 xgonce/Cloudflare_IP 的 result.csv 筛选优质 Cloudflare IP。

筛选条件（可用命令行覆盖）:
  - TLS 延迟(ms) < 100
  - 速度(Mbps)  > 10

输出格式:
  8.35.211.177:443#SG

用法:
  python filter.py --url <csv_url> --out ips.txt
"""

import argparse
import csv
import io
import os
import sys
import urllib.request

DEFAULT_URL = (
    "https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv"
)

# 国内/受限网络下 raw.githubusercontent.com 可能不通，按顺序尝试镜像
MIRRORS = [
    "https://gh-proxy.org/",
    "https://ghfast.top/",
    "https://raw.gitmirror.com/",
    "https://cdn.jsdelivr.net/gh/xgonce/Cloudflare_IP@main/result.csv",
]


def fetch(url: str, timeout: int = 60) -> bytes:
    """抓取 CSV 内容，主源失败时自动回退镜像。"""
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 cf-ip-pick"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as err:  # noqa: BLE001
        print(f"[warn] 主源失败: {err}", file=sys.stderr)

    for prefix in MIRRORS:
        if prefix.endswith("result.csv"):
            mirror = prefix
        else:
            mirror = prefix + url
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    mirror, headers={"User-Agent": "Mozilla/5.0 cf-ip-pick"}
                ),
                timeout=timeout,
            ) as resp:
                data = resp.read()
                print(f"[info] 使用镜像: {mirror}", file=sys.stderr)
                return data
        except Exception as err:  # noqa: BLE001
            print(f"[warn] 镜像失败 {mirror}: {err}", file=sys.stderr)

    raise SystemExit("[error] 所有数据源均无法访问")


def to_float(value, default=float("inf")) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--out", default="ips.txt", help="输出结果文件")
    ap.add_argument("--csv-out", default="", help="可选：附带明细的 CSV")
    ap.add_argument("--max-tls", type=float, default=100.0, help="TLS 延迟上限(ms)，小于该值")
    ap.add_argument("--min-speed", type=float, default=10.0, help="速度下限(Mbps)，大于该值")
    ap.add_argument("--limit", type=int, default=0, help="最多输出多少条，0=不限")
    ap.add_argument("--sort", default="tls", choices=["tls", "speed", "none"])
    args = ap.parse_args()

    raw = fetch(args.url).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))

    rows = []
    for r in reader:
        ip = (r.get("IP") or "").strip()
        if not ip:
            continue
        tls = to_float(r.get("TLS延迟(ms)"))
        speed = to_float(r.get("速度(Mbps)"), default=0.0)
        if tls >= args.max_tls or speed <= args.min_speed:
            continue
        rows.append(
            {
                "ip": ip,
                "port": (r.get("端口") or "443").strip() or "443",
                "cc": (r.get("CF归属国") or "").strip(),
                "colo": (r.get("机房") or "").strip(),
                "tcp": to_float(r.get("TCP延迟(ms)")),
                "tls": tls,
                "speed": speed,
            }
        )

    if args.sort == "tls":
        rows.sort(key=lambda x: (x["tls"], -x["speed"]))
    elif args.sort == "speed":
        rows.sort(key=lambda x: (-x["speed"], x["tls"]))

    if args.limit > 0:
        rows = rows[: args.limit]

    lines = [f"{r['ip']}:{r['port']}#{r['cc']}" for r in rows]

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

    if args.csv_out:
        with open(args.csv_out, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP:端口#国家", "IP", "端口", "国家", "机房", "TCP延迟(ms)", "TLS延迟(ms)", "速度(Mbps)"])
            for r in rows:
                w.writerow(
                    [
                        f"{r['ip']}:{r['port']}#{r['cc']}",
                        r["ip"],
                        r["port"],
                        r["cc"],
                        r["colo"],
                        r["tcp"],
                        r["tls"],
                        r["speed"],
                    ]
                )

    print(f"[ok] 命中 {len(lines)} 条 -> {args.out}")
    for line in lines[:10]:
        print("   ", line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
