# 信息收集 SOP

挖洞 90% 时间在这里。资产收得越偏，出货率越高。

## 前提：目标从补天来

**不要自己随便找域名打。** 流程是：

1. 登录 https://www.butian.net
2. 进「公益SRC」或「企业SRC」，选一个范围明确的目标
3. **把资产范围那一页截图存档**（`loot/` 目录），这是你的合法凭证
4. 从范围里提取域名，才开始收资产

## 第一步：子域枚举

```bash
TARGET=example.com

# 多引擎合并
subfinder -d $TARGET -all -silent | anew targets/$TARGET/subs/subfinder.txt

# 证书透明日志（能挖到很久以前的子域）
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u \
  | anew targets/$TARGET/subs/crtsh.txt

# 合并去重
cat targets/$TARGET/subs/*.txt | sort -u > targets/$TARGET/subs/all.txt
wc -l targets/$TARGET/subs/all.txt
```

**如果装了 FOFA API**（推荐，国内资产最全）：

```bash
# FOFA 查询（domain 精确匹配）
FOFA_EMAIL="你的邮箱"; FOFA_KEY="你的key"
QUERY="domain=\"$TARGET\""
B64=$(echo -n "$QUERY" | base64 -w0)
curl -s "https://fofa.info/api/v1/search/all?email=$FOFA_EMAIL&key=$FOFA_KEY&qbase64=$B64&size=10000&fields=host,ip,port,title,domain" \
  | jq -r '.results[] | @tsv' > targets/$TARGET/subs/fofa.tsv

# 只看域名字段
cut -f1 targets/$TARGET/subs/fofa.tsv | sed 's#https\?://##;s#:[0-9]*$##' \
  | sort -u | anew targets/$TARGET/subs/all.txt
```

FOFA 常用语法（直接抄）：

```
domain="example.com"                    # 该域名所有资产
domain="example.com" && port!="80"      # 非标准端口
domain="example.com" && title="后台"    # 找后台
domain="example.com" && body="spring"   # 找框架
cert="example.com"                      # 证书包含（能挖到子公司）
domain="example.com" && protocol="http" # 只看http（无https=老系统）
```

## 第二步：存活探测 + 指纹

```bash
httpx -l targets/$TARGET/subs/all.txt \
  -sc -title -tech-detect -web-server -cdn \
  -rate-limit 100 -o targets/$TARGET/subs/alive.txt

# 只看 200/403（403 最值得注意，说明有东西但被挡）
grep -E "\[200\]|\[403\]|\[401\]" targets/$TARGET/subs/alive.txt \
  > targets/$TARGET/subs/interesting.txt
```

**403 是宝藏**：说明目录存在但被拦。绕过手法见 `payloads/bypass_403.md`。

## 第三步：端口（别只扫 80/443）

```bash
# 快速扫常见端口
naabu -list targets/$TARGET/subs/all.txt -top-ports 1000 -rate 2000 \
  -o targets/$TARGET/ports/ports.txt

# 重点盯这些端口
# 6379 redis / 27017 mongo / 3306 mysql / 9200 es / 2375 docker
# 8080 8081 8088 9000 7001 weblogic 8888 8443 后台
```

## 第四步：URL 与接口收集（最关键）

老接口、废弃接口是未授权访问的重灾区。

```bash
# 历史 URL（Wayback / CommonCrawl）
gau --subs $TARGET | anew targets/$TARGET/urls/gau.txt
waybackurls $TARGET | anew targets/$TARGET/urls/wayback.txt

# 从存活站点爬
katana -list targets/$TARGET/subs/alive.txt -d 3 -jc -silent \
  | anew targets/$TARGET/urls/katana.txt

# 合并
cat targets/$TARGET/urls/*.txt | sort -u > targets/$TARGET/urls/all.txt

# 按漏洞类型分类（gf 模式）
cat targets/$TARGET/urls/all.txt | gf ssrf     > targets/$TARGET/urls/ssrf.txt
cat targets/$TARGET/urls/all.txt | gf redirect > targets/$TARGET/urls/redirect.txt
cat targets/$TARGET/urls/all.txt | gf sqli     > targets/$TARGET/urls/sqli.txt
cat targets/$TARGET/urls/all.txt | gf lfi      > targets/$TARGET/urls/lfi.txt
cat targets/$TARGET/urls/all.txt | gf idor     > targets/$TARGET/urls/idor.txt
```

## 第五步：JS 里挖接口（新手最容易出洞的地方）

现代站的接口一半藏在 JS 里。

```bash
# 收集所有 JS
cat targets/$TARGET/urls/all.txt | grep -Ei '\.js(\?|$)' | sort -u \
  > targets/$TARGET/urls/js.txt

# 下载并提取接口路径
mkdir -p targets/$TARGET/js
while read u; do
  f=$(echo "$u" | md5sum | cut -c1-12).js
  curl -s -m 10 "$u" -o targets/$TARGET/js/$f
done < targets/$TARGET/urls/js.txt

# 提取 API 路径
cat targets/$TARGET/js/*.js \
  | grep -oE '"(/[a-zA-Z0-9_\-]+){2,6}"' \
  | tr -d '"' | sort -u > targets/$TARGET/urls/api_paths.txt

# 提取被注释掉的、测试用的路径
cat targets/$TARGET/js/*.js | grep -oE '(api|v[0-9]|admin|internal|test)/[a-zA-Z0-9_/\-]+' \
  | sort -u | anew targets/$TARGET/urls/api_paths.txt
```

## 第六步：敏感文件一把梭

```bash
# 常见泄露文件
for p in .git/config .svn/entries .env backup.zip www.zip db.sql \
         config.php.bak web.config application.yml actuator/env \
         swagger-ui.html v2/api-docs druid/index.html; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "https://$TARGET/$p")
  [ "$code" = "200" ] && echo "[HIT] https://$TARGET/$p"
done
```

## 产出清单

跑完这几步，你应该有：

- `subs/all.txt` —— 全量子域
- `subs/interesting.txt` —— 有响应的（带指纹）
- `ports/ports.txt` —— 开放端口
- `urls/api_paths.txt` —— 接口清单
- `urls/ssrf.txt` 等 —— 分类好的候选点

**没跑完这些就去打漏洞，等于闭眼开枪。**
