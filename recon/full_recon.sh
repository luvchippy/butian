#!/usr/bin/env bash
# 一键资产收集：子域 -> 存活 -> 端口 -> URL -> 接口
# 用法: bash recon/full_recon.sh target.com
# 前置: subfinder httpx naabu gau waybackurls katana anew jq curl

set -uo pipefail

TARGET="$1"
[ -z "$TARGET" ] && { echo "用法: bash recon/full_recon.sh <domain>"; exit 1; }

BASE="targets/$TARGET"
mkdir -p "$BASE"/{subs,ports,urls,screens,report,js}
START=$(date +%s)

say() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$1"; }

# ---------- 1. 子域 ----------
say "1/6 子域枚举"
subfinder -d "$TARGET" -all -silent 2>/dev/null | anew "$BASE/subs/subfinder.txt" >/dev/null

curl -s -m 30 "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' | tr '\n' '\n' | sort -u \
  | anew "$BASE/subs/crtsh.txt" >/dev/null

cat "$BASE"/subs/*.txt 2>/dev/null | sort -u > "$BASE/subs/all.txt"
echo "子域总数: $(wc -l < "$BASE/subs/all.txt")"

# ---------- 2. 存活 ----------
say "2/6 存活探测与指纹"
httpx -l "$BASE/subs/all.txt" \
  -sc -title -tech-detect -web-server -cdn \
  -rate-limit 80 -silent -o "$BASE/subs/alive.txt" 2>/dev/null

grep -E "\[200\]|\[401\]|\[403\]" "$BASE/subs/alive.txt" 2>/dev/null \
  > "$BASE/subs/interesting.txt"
echo "存活: $(wc -l < "$BASE/subs/alive.txt") / 关注: $(wc -l < "$BASE/subs/interesting.txt")"

# ---------- 3. 端口 ----------
say "3/6 端口扫描"
if command -v naabu >/dev/null 2>&1; then
  naabu -list "$BASE/subs/all.txt" -top-ports 1000 -rate 1500 -silent \
    -o "$BASE/ports/ports.txt" 2>/dev/null
  echo "开放端口记录: $(wc -l < "$BASE/ports/ports.txt" 2>/dev/null || echo 0)"
else
  echo "跳过（naabu 未安装）"
fi

# ---------- 4. URL ----------
say "4/6 历史 URL 收集"
gau --subs "$TARGET" 2>/dev/null | anew "$BASE/urls/gau.txt" >/dev/null
waybackurls "$TARGET" 2>/dev/null | anew "$BASE/urls/wayback.txt" >/dev/null

if command -v katana >/dev/null 2>&1; then
  katana -list "$BASE/subs/interesting.txt" -d 2 -jc -silent 2>/dev/null \
    | anew "$BASE/urls/katana.txt" >/dev/null
fi

cat "$BASE"/urls/*.txt 2>/dev/null | sort -u > "$BASE/urls/all.txt"
echo "URL 总数: $(wc -l < "$BASE/urls/all.txt")"

# ---------- 5. 参数分类 ----------
say "5/6 参数分类"
if command -v gf >/dev/null 2>&1; then
  for p in ssrf redirect sqli lfi idor rce; do
    cat "$BASE/urls/all.txt" | gf "$p" > "$BASE/urls/$p.txt" 2>/dev/null || true
    echo "  $p: $(wc -l < "$BASE/urls/$p.txt" 2>/dev/null || echo 0)"
  done
fi

# ---------- 6. JS 接口 ----------
say "6/6 JS 接口提取"
cat "$BASE/urls/all.txt" 2>/dev/null \
  | grep -Ei '\.js(\?|$)' | sort -u > "$BASE/urls/js.txt"

if [ -s "$BASE/urls/js.txt" ]; then
  head -200 "$BASE/urls/js.txt" | while read -r u; do
    f=$(echo "$u" | md5sum | cut -c1-12)
    curl -s -m 8 -k "$u" -o "$BASE/js/$f.js" 2>/dev/null
  done
  cat "$BASE"/js/*.js 2>/dev/null \
    | grep -oE '"(/[a-zA-Z0-9_-]+){2,6}"' \
    | tr -d '"' | sort -u > "$BASE/urls/api_paths.txt"
  echo "JS 文件: $(wc -l < "$BASE/urls/js.txt") / 接口: $(wc -l < "$BASE/urls/api_paths.txt")"
fi

# ---------- 汇总 ----------
END=$(date +%s)
say "完成，耗时 $((END-START)) 秒"
cat <<EOF

产出目录: $BASE/
  subs/all.txt          全量子域
  subs/interesting.txt  有响应的目标（带指纹）
  ports/ports.txt       开放端口
  urls/all.txt          全量 URL
  urls/{ssrf,sqli,lfi,...}.txt  分类候选
  urls/api_paths.txt    从 JS 提取的接口

下一步: 打开 docs/04-漏洞挖掘SOP.md 开始挖
EOF
