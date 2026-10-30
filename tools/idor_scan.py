#!/usr/bin/env python3
"""越权 / IDOR 批量检测

思路：拿两条不同身份的凭据，交叉访问同一批接口，对比响应差异。

用法:
    python tools/idor_scan.py \
        --urls urls.txt \
        --token-a "Bearer eyJ..." \
        --token-b "Bearer eyJ..." \
        --cookie-a "SESSION=aaa" \
        --cookie-b "SESSION=bbb"

判定：A 的凭据请求返回 200 且响应体与 B 的凭据请求高度相似
      => 该接口可能未做用户隔离（水平越权嫌疑）
"""
import argparse
import difflib

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"


def fetch(url: str, headers: dict, timeout: int = 15):
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        return r
    except Exception as e:
        return None


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--urls", required=True, help="待测 URL 列表，一行一个")
    ap.add_argument("--token-a")
    ap.add_argument("--token-b")
    ap.add_argument("--cookie-a")
    ap.add_argument("--cookie-b")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()

    ha = {"User-Agent": UA}
    hb = {"User-Agent": UA}
    if args.token_a:
        ha["Authorization"] = args.token_a
    if args.token_b:
        hb["Authorization"] = args.token_b
    if args.cookie_a:
        ha["Cookie"] = args.cookie_a
    if args.cookie_b:
        hb["Cookie"] = args.cookie_b

    with open(args.urls, encoding="utf-8", errors="ignore") as f:
        urls = [u.strip() for u in f if u.strip() and not u.startswith("#")]

    print(f"[*] 待测 {len(urls)} 条")
    findings = []

    for i, url in enumerate(urls, 1):
        ra = fetch(url, ha)
        rb = fetch(url, hb)
        if not ra or not rb:
            continue
        if ra.status_code != 200:
            continue
        sim = similarity(ra.text, rb.text)
        # 两个不同身份的凭据拿到几乎一样的响应 = 没做隔离
        flag = sim > 0.90 and len(ra.text) > 200
        mark = "!!!" if flag else "   "
        print(f"{mark} [{i}/{len(urls)}] sim={sim:.2f} {ra.status_code}/{rb.status_code}  {url[:100]}")
        if flag:
            findings.append((url, sim, len(ra.text)))

    print()
    if findings:
        print(f"[+] 疑似越权接口 {len(findings)} 个：")
        for u, s, n in findings:
            print(f"    sim={s:.2f} size={n}  {u}")
        print("[!] 需人工确认：换掉 URL 里的 ID 参数，看是否返回对方数据")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                for u, s, n in findings:
                    f.write(f"{s:.2f}\t{n}\t{u}\n")
    else:
        print("[-] 未发现明显越权嫌疑")


if __name__ == "__main__":
    main()
