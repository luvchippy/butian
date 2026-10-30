#!/usr/bin/env python3
"""多线程目录 / 接口爆破

用法:
    python tools/dirbrute.py -u https://target.com -w wordlist.txt -t 30
    python tools/dirbrute.py -u https://target.com -w api_paths.txt --ext .php,.bak
"""
import argparse
import queue
import sys
import threading
from dataclasses import dataclass

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"


@dataclass
class Hit:
    url: str
    code: int
    size: int
    title: str


class Bruteforcer:
    def __init__(self, base: str, threads: int, timeout: int, exts: list[str]):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.exts = exts
        self.q: queue.Queue = queue.Queue()
        self.hits: list[Hit] = []
        self.lock = threading.Lock()
        self.seen: set[str] = set()
        self.count = 0
        self.threads = threads

    def load(self, path: str) -> None:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                p = line.strip()
                if not p or p.startswith("#"):
                    continue
                self.q.put(p)
                for e in self.exts:
                    self.q.put(f"{p}{e}")

    def worker(self) -> None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        while True:
            try:
                p = self.q.get_nowait()
            except queue.Empty:
                return
            url = f"{self.base}/{p.lstrip('/')}"
            if url in self.seen:
                self.q.task_done()
                continue
            with self.lock:
                self.seen.add(url)
                self.count += 1
            try:
                r = s.get(url, timeout=self.timeout, allow_redirects=False, verify=False)
                code = r.status_code
                size = len(r.content)
                if code in (200, 201, 204, 301, 302, 307, 401, 403, 500):
                    title = ""
                    if b"<title" in r.content[:2000]:
                        import re
                        m = re.search(rb"<title[^>]*>(.*?)</title>", r.content[:2000], re.I | re.S)
                        if m:
                            title = m.group(1).decode("utf-8", "ignore").strip()[:60]
                    with self.lock:
                        self.hits.append(Hit(url, code, size, title))
                    color = "\033[92m" if code == 200 else "\033[93m"
                    print(f"{color}[{code}] {size:>7}B  {title:<40} {url}\033[0m")
            except Exception:
                pass
            finally:
                self.q.task_done()

    def run(self) -> None:
        threads = [threading.Thread(target=self.worker, daemon=True) for _ in range(self.threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-w", "--wordlist", required=True)
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--ext", default="", help="逗号分隔，如 .php,.bak,.zip")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()
    exts = [e.strip() for e in args.ext.split(",") if e.strip()]

    bf = Bruteforcer(args.url, args.threads, args.timeout, exts)
    bf.load(args.wordlist)
    total = bf.q.qsize()
    print(f"[*] 目标: {args.url}")
    print(f"[*] 载荷数: {total}  线程: {args.threads}")
    print("-" * 80)
    bf.run()
    print("-" * 80)
    print(f"[+] 完成，请求 {bf.count} 次，命中 {len(bf.hits)} 个")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for h in sorted(bf.hits, key=lambda x: x.code):
                f.write(f"{h.code}\t{h.size}\t{h.url}\t{h.title}\n")
        print(f"[+] 结果 -> {args.out}")


if __name__ == "__main__":
    main()
