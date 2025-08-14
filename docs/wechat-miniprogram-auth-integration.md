### 微信小程序接入 WeSpring Auth Server（短信登录 + HttpOnly Cookie 刷新）实战指南

本文档面向微信小程序前端开发，指导如何对接本认证服务器的“短信验证码登录”与“基于 HttpOnly Cookie 的 refresh_token 自动刷新”能力，涵盖端到端测试方法、常见问题排查以及生产注意事项。

---

#### 能力概览
- 短信验证码登录（/sms/auth 与 /sms/login）
- access_token 短时有效；refresh_token 安全地写入 HttpOnly Cookie
- 刷新接口（/sms/refresh-token）从 Cookie 读取 refresh_token 并自动更新 Cookie
- 可选：应用商店审核“测试手机号 + 固定验证码”直登（仅测试环境）

---

## 1. 服务端准备

确保生产环境启用 Cookie 模式，并正确配置 Cookie 属性与 HTTPS：

```bash
OAUTH2_COOKIE_MODE_ENABLED=true
OAUTH2_COOKIE_DOMAIN=.ruichuangqi.com
OAUTH2_COOKIE_SECURE=true
OAUTH2_COOKIE_SAME_SITE=None
```

要点：
- 使用 HTTPS；`Secure=true` 生效且必须
- `Domain` 覆盖实际请求域，例如 `iam.ruichuangqi.com` → 建议 `.ruichuangqi.com`
- `SameSite=None` 以兼容小程序/嵌入式场景；必须与 `Secure` 搭配
- 反向代理/网关需透传 `Set-Cookie`，不要篡改属性（见第 6 节）

### 1.1 Token 有效期配置（DB 中）
access_token/refresh_token 的 TTL 存于数据库表 `oauth2_registered_client.token_settings`（由 `RegisteredClientRepository` 读取），不是 `application.yml`。

查询当前配置：
```sql
SELECT token_settings
FROM oauth2_registered_client
WHERE client_id = 'ffv-client';
```

示例：将 access_token 改为 4 小时（14400 秒），refresh_token 为 90 天（7776000 秒）：
```sql
UPDATE oauth2_registered_client
SET token_settings = '{"@class":"java.util.Collections$UnmodifiableMap",
"settings.token.reuse-refresh-tokens":true,
"settings.token.access-token-time-to-live":["java.time.Duration",14400.000000000],
"settings.token.refresh-token-time-to-live":["java.time.Duration",7776000.000000000],
"settings.token.authorization-code-time-to-live":["java.time.Duration",600.000000000]}'
WHERE client_id = 'ffv-client';
```

> 建议策略：短 access_token + 长 refresh_token；前端在 401 时或定时触发刷新，用户无感续期。

### 1.2 应用商店审核“测试手机号 + 固定验证码”（仅测试环境启用）

```bash
SMS_TEST_LOGIN_ENABLED=true
SMS_TEST_LOGIN_PHONE_NUMBER=13800138000
SMS_TEST_LOGIN_CODE=246810
```

启用后，特定手机号使用固定验证码即可登录，无需发送短信。切勿在生产环境长期开启。

---

## 2. 端点说明

- 发送验证码
  - POST `/sms/send-code`（表单或 JSON）
- 登录并颁发令牌
  - GET `/sms/auth`（推荐，响应 JSON：access_token；refresh_token 写入 HttpOnly Cookie）
  - GET `/sms/login`（等价别名）
- 刷新令牌
  - POST `/sms/refresh-token`（只需带 Cookie；服务端从 Cookie 读取 refresh_token 并在成功时通过 `Set-Cookie` 轮换）

---

## 3. 微信小程序对接示例

> 小程序无法读取 HttpOnly Cookie（更安全），但会自动随同同域请求发送。只需拿住 access_token 调用需要 Bearer 的 API；当遇到 401 时调用刷新端点。

### 3.1 发送验证码
```javascript
const BASE_URL = 'https://iam.ruichuangqi.com';
const phone = '13800138000';

wx.request({
  url: `${BASE_URL}/sms/send-code`,
  method: 'POST',
  header: { 'Content-Type': 'application/x-www-form-urlencoded' },
  data: `mobileNumber=${encodeURIComponent(phone)}`,
  success(res) { console.log('send-code ok', res.data); },
  fail(err) { console.error('send-code fail', err); }
});
```

（或 JSON）
```javascript
wx.request({
  url: `${BASE_URL}/sms/send-code`,
  method: 'POST',
  header: { 'Content-Type': 'application/json' },
  data: { mobileNumber: phone },
  success(res) { /* ... */ },
  fail(err) { /* ... */ }
});
```

### 3.2 登录（颁发 access_token，Cookie 内含 refresh_token）
```javascript
const BASE_URL = 'https://iam.ruichuangqi.com';
const phone = '13800138000';
const code  = '123456'; // 或审核模式下的固定验证码

wx.request({
  url: `${BASE_URL}/sms/auth`,
  method: 'GET',
  data: {
    clientId: 'ffv-client',
    mobileNumber: phone,
    verificationCode: code
  },
  success(res) {
    const { access_token } = res.data || {};
    if (access_token) wx.setStorageSync('ACCESS_TOKEN', access_token);
  },
  fail(err) { console.error('auth fail', err); }
});
```

### 3.3 刷新令牌（依赖 Cookie，前端无需读取 refresh_token）
```javascript
const BASE_URL = 'https://iam.ruichuangqi.com';

wx.request({
  url: `${BASE_URL}/sms/refresh-token`,
  method: 'POST',
  header: { 'Content-Type': 'application/x-www-form-urlencoded' },
  data: 'grant_type=refresh_token&client_id=ffv-client',
  success(res) {
    const { access_token } = res.data || {};
    if (access_token) wx.setStorageSync('ACCESS_TOKEN', access_token);
  },
  fail(err) { console.error('refresh fail', err); }
});
```

### 3.4 携带 Bearer 访问受保护 API
```javascript
const BASE_URL = 'https://iam.ruichuangqi.com';
const token = wx.getStorageSync('ACCESS_TOKEN');

wx.request({
  url: `${BASE_URL}/auth-srv/some-protected-api`,
  method: 'GET',
  header: { Authorization: `Bearer ${token}` },
  success(res) { console.log('api ok', res.data); },
  fail(err) { console.error('api fail', err); }
});
```

> 推荐策略：API 返回 401 后先调用 `/sms/refresh-token`，刷新成功则重试原请求；若刷新仍失败则引导重新登录。

---

## 4. curl 自测速查

```bash
BASE_URL="https://iam.ruichuangqi.com"
PHONE="13800138000"
CODE="123456"

# 发送验证码（表单）
curl -sS -X POST "$BASE_URL/sms/send-code" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "mobileNumber=$PHONE"

# 登录并保存 Cookie（refresh_token 在 Cookie 中）
curl -sS -G "$BASE_URL/sms/auth" \
  --data-urlencode "clientId=ffv-client" \
  --data-urlencode "mobileNumber=$PHONE" \
  --data-urlencode "verificationCode=$CODE" \
  -c cookies.txt

# 刷新令牌（基于 Cookie）
curl -sS -X POST "$BASE_URL/sms/refresh-token" \
  -b cookies.txt -c cookies.txt \
  -d "grant_type=refresh_token" \
  -d "client_id=ffv-client"
```

---

## 5. 一键端到端测试脚本

仓库已包含脚本 `scripts/test-sms-login.sh`，集成如下能力：
- 发送验证码 → 数据库查询验证码（可选） → 登录（保存 Cookie） → 刷新 → 调用受保护 API
- 自动解析并展示 JWT Header/Payload 以便调试
- 使用 Cookie jar 验证 `refresh_token` 已在 HttpOnly Cookie 中

使用步骤（示例）：
```bash
# 配置服务地址
export BASE_URL=https://iam.ruichuangqi.com

# 运行（可传入手机号，也可在提示时输入）
bash scripts/test-sms-login.sh 13800138000
```

脚本片段（登录时携带 Cookie）：
```bash
curl -s -w "\n%{http_code}" -X GET \
  "$BASE_URL/sms/login?mobileNumber=$PHONE_NUMBER&verificationCode=$VERIFICATION_CODE" \
  --cookie-jar "$COOKIE_JAR" \
  --cookie "$COOKIE_JAR"
```

---

## 6. 网关/反向代理配置要点（以 Nginx 为例）

```nginx
# 透传 Set-Cookie
proxy_pass_header Set-Cookie;

# 避免错误改写 Cookie 属性（若无必要不要使用以下指令）
# proxy_cookie_domain off;
# proxy_cookie_path   off;

# 保持主机头一致，利于后端生成正确的 Cookie Domain / 链接
proxy_set_header Host $host;
```

注意：若存在 302 重定向至不同域名的流程，Cookie 往往不会按预期携带。移动端/小程序建议使用纯 JSON API，不走跨域跳转链路。

---

## 7. 常见问题排查

- 未携带 Cookie：检查 Domain 与请求域一致、`Secure=true`、`SameSite=None`、代理是否透传
- 频繁要求重新登录：多为未实现自动刷新；实现 `/sms/refresh-token` 调用并在成功后重试原请求
- 跨域跳转导致会话丢失：改为直接使用无状态 JSON 登录/刷新端点
- 设置了“测试手机号 + 固定验证码”后仍失败：确认已启用 `SMS_TEST_LOGIN_ENABLED=true` 且手机号/验证码匹配

---

## 8. 安全与合规注意事项

- refresh_token 仅在 HttpOnly Cookie；不要在响应体或日志中暴露
- 生产环境强制使用 HTTPS 与 `Secure` Cookie
- 审核“测试手机号 + 固定验证码”仅用于短期测试，务必在生产关闭
- 管理端接口与页面必须有 `ROLE_ADMIN` 保护（参考项目安全开发规范）

---

## 9. 验收清单（Check List）

- [ ] 域名、HTTPS、Cookie 属性（Domain/SameSite=None/Secure）均正确
- [ ] 登录成功返回 access_token，Cookie 中写入 refresh_token
- [ ] 刷新成功返回新 access_token，且 Cookie 中 refresh_token 已更新
- [ ] 401 → 刷新 → 重试逻辑在小程序端可用
- [ ] 反向代理透传 `Set-Cookie`，无错误改写

---

如需将本指南中的示例整理为最小可运行 Demo（含微信开发者工具配置与 Mock API），请联系平台维护者，我们可提供模板工程与进一步支持。


