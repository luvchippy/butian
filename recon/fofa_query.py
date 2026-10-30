#!/usr/bin/env python3
"""FOFA 查询工具 — 配合补天授权资产使用

用法:
    export FOFA_EMAIL=xxx@qq.com
    export FOFA_KEY=xxxxxxxx
    python recon/fofa_query.py 'domain="example.com"' --out targets/example.com/subs/fofa.txt
"""
import argparse
import base64
import json
import os
import sys
import urllib.request

API = "https://fofa.info/api/v1/search/all"


def query(qbase64: str, size: int, fields: str) -> dict:
    email = os.environ.get("FOFA_EMAIL")
    key = os.environ.get("FOFA_KEY")
    if not email or not key:
        sys.exit("请先设置环境变量 FOFA_EMAIL / FOFA_KEY")

    url = (
        f"{API}?email={email}&key={key}"
        f"&qbase64={qbase64}&size={size}&fields={fields}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("query", help='FOFA 语法，如 domain="example.com"')
    p.add_argument("--size", type=int, default=1000, help="返回条数（免费账户上限较小）")
    p.add_argument("--fields", default="host,ip,port,title,domain,server")
    p.add_argument("--out", help="输出文件")
    args = p.parse_args()

    qb64 = base64.b64encode(args.query.encode()).decode()
    resp = query(qb64, args.size, args.fields)

    if resp.get("error"):
        sys.exit(f"FOFA 返回错误: {resp.get('errmsg')}")

    results = resp.get("results", [])
    lines = []
    for row in results:
        if isinstance(row, list):
            lines.append("\t".join(str(x) for x in row))
        else:
            lines.append(str(row))

    out = "\n".join(lines)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print(f"[+] {len(lines)} 条 -> {args.out}")
    else:
        print(out)
    print(f"[i] 总数: {resp.get('size', '?')}")


if __name__ == "__main__":
    main()
