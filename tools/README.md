# 工具说明

全部零依赖（除 requests），Python 3.9+ 直接跑。

## 安装

```bash
pip install -r tools/requirements.txt
```

## 各工具用途

| 工具 | 用途 | 典型命令 |
|---|---|---|
| `sqliscan.py` | SQL 注入检测（布尔/报错/时间） | `python tools/sqliscan.py -u "https://t/x?id=1"` |
| `dirbrute.py` | 多线程目录/接口爆破 | `python tools/dirbrute.py -u https://t -w wl.txt` |
| `idor_scan.py` | 越权批量检测（双 token 对比） | 见下文 |
| `portscan.py` | 轻量端口扫描 | `python tools/portscan.py -H t.com --top` |

## 越权检测的正确用法

1. 目标站注册**两个账号** A 和 B
2. 各自登录，从 Burp 里拿到 token 或 cookie
3. 用浏览器的历史记录 / katana 抓一批带 ID 的接口 URL
4. 跑：

```bash
python tools/idor_scan.py --urls urls.txt \
  --token-a "Bearer AAA" --token-b "Bearer BBB" \
  --cookie-a "SESSION=xxx" --cookie-b "SESSION=yyy" \
  -o idor_candidates.txt
```

5. 输出 sim > 0.90 的是嫌疑接口，再手工换 ID 确认

## 注意

- 所有脚本默认 `verify=False`，跳过证书校验（测自签证书站点用）
- 默认 UA 是 Chrome，避免被简单 UA 规则拦
- 请求频率靠 `-t` 控制。**打生产环境建议 t<=20，别打挂**
