#!/usr/bin/env python3
"""轻量多线程端口扫描（替代 nmap 的快速版）

用法:
    python tools/portscan.py -H target.com -p 1-1000 -t 200
    python tools/portscan.py -H target.com --top
"""
import argparse
import socket
import threading
import queue

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    873, 993, 995, 1025, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2222,
    2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900, 5984,
    6379, 6443, 7001, 7002, 8000, 8001, 8008, 8009, 8010, 8043, 8069, 8080,
    8081, 8082, 8088, 8090, 8161, 8180, 8443, 8500, 8529, 8880, 8888, 9000,
    9001, 9042, 9090, 9200, 9300, 9418, 9443, 9600, 9999, 10000, 10250, 11211,
    15672, 27017, 27018, 28017, 50000, 50070,
]

SERVICE_HINT = {
    6379: "Redis(未授权?)", 27017: "MongoDB(未授权?)", 9200: "Elasticsearch(未授权?)",
    2375: "Docker API(未授权?)", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 1433: "MSSQL", 7001: "WebLogic", 8080: "HTTP-Alt",
    8161: "ActiveMQ", 11211: "Memcached(未授权?)", 50070: "HDFS(未授权?)",
    9000: "PHP-FPM/FastCGI", 22: "SSH", 3389: "RDP", 21: "FTP",
}


class Scanner:
    def __init__(self, host: str, ports: list[int], threads: int, timeout: float):
        self.host = host
        self.ports = ports
        self.timeout = timeout
        self.q: queue.Queue = queue.Queue()
        for p in ports:
            self.q.put(p)
        self.open: list[int] = []
        self.lock = threading.Lock()
        self.threads = threads

    def worker(self) -> None:
        while True:
            try:
                p = self.q.get_nowait()
            except queue.Empty:
                return
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((self.host, p)) == 0:
                        with self.lock:
                            self.open.append(p)
                        hint = SERVICE_HINT.get(p, "")
                        print(f"\033[92m[OPEN]\033[0m {p:<6} {hint}")
            except Exception:
                pass
            finally:
                self.q.task_done()

    def run(self) -> None:
        ts = [threading.Thread(target=self.worker, daemon=True) for _ in range(self.threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()


def parse_ports(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return sorted(set(out))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-H", "--host", required=True)
    ap.add_argument("-p", "--ports", default="1-1000")
    ap.add_argument("--top", action="store_true", help="用内置常见端口表")
    ap.add_argument("-t", "--threads", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=1.0)
    args = ap.parse_args()

    ports = TOP_PORTS if args.top else parse_ports(args.ports)
    print(f"[*] 目标 {args.host}  端口 {len(ports)} 个  线程 {args.threads}")
    sc = Scanner(args.host, ports, args.threads, args.timeout)
    sc.run()
    print(f"\n[+] 开放 {len(sc.open)} 个: {sc.open}")


if __name__ == "__main__":
    main()
