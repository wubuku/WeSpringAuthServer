### 微信小程序接入 WeSpring Auth Server（微信登录 + 短信登录 + 安全Token管理）实战指南

本文档面向微信小程序前端开发，指导如何对接本认证服务器的"微信登录"、"短信验证码登录"与"安全Token管理"能力，涵盖端到端测试方法、常见问题排查以及生产注意事项。

## 🚩 关键信息（重要变更）

- 默认安全策略：服务端使用 HttpOnly Cookie 管理 `refresh_token`，响应体仅返回 `access_token`（适用于 Web）。
- 为兼容微信小程序，现支持可选参数 `legacyMode=true`，当设置后，服务端会在响应体中一并返回 `refresh_token`，以便小程序本地安全存储；默认仍为 `false`。
- 支持 `legacyMode` 的端点（仅列出与登录/刷新相关）：
  - `GET /wechat/login`、`POST /wechat/refresh-token`
  - `GET /sms/auth`、`GET /sms/login`、`POST /sms/refresh-token`
- 微信小程序接入要点（强烈推荐遵循）：
  - 登录与刷新时都携带 `legacyMode=true`
  - 登录成功后从响应体获取并安全存储 `access_token` 与 `refresh_token`
  - 刷新时显式传入 `refresh_token`

## ⚠️ 重要说明：微信小程序Cookie限制

**微信小程序不支持传统浏览器的Cookie机制**，包括HttpOnly Cookie。因此在小程序场景下，请使用 `legacyMode=true` 获取并在本地安全存储 `refresh_token`（例如 `wx.setStorageSync()`）。

---

#### 能力概览
- **微信登录**（/wechat/login）- 使用微信授权码直接登录
- **短信验证码登录**（/sms/auth 与 /sms/login）- 传统手机号验证码登录
- **统一Token机制**：`access_token` 短时有效；`refresh_token` 按场景存储
- **统一刷新接口**：
  - `/wechat/refresh-token` - 微信登录专用刷新端点
  - `/sms/refresh-token` - SMS登录专用刷新端点
- **按场景切换**：
  - Web：默认使用 HttpOnly Cookie 管理 `refresh_token`
  - 小程序：请求时加 `legacyMode=true`，在响应体获取 `refresh_token` 并本地安全存储
- 可选：应用商店审核"测试手机号 + 固定验证码"直登（仅测试环境）

---

## 1. 微信登录集成指南

### 1.1 微信登录流程概述

微信登录提供了一种更便捷的用户认证方式，用户无需输入手机号和验证码，直接使用微信授权即可完成登录。

**微信登录流程：**
1. 小程序调用 `wx.login()` 获取临时授权码（code）
2. 将授权码发送到认证服务器的 `/wechat/login` 端点
3. 服务器使用授权码向微信服务器验证用户身份
4. 验证成功后返回 `access_token` 和（当 `legacyMode=true`）`refresh_token`
5. 小程序使用 `wx.setStorageSync()` 安全存储两个 token
6. 后续 API 调用使用 `access_token`，token 过期时使用 `refresh_token` 刷新

### 1.2 微信登录端点

```javascript
// 微信小程序端代码示例
wx.login({
  success: function(res) {
    if (res.code) {
      // 发送 res.code 到后台换取 tokens
      wx.request({
        url: 'https://your-auth-server.com/wechat/login',
        method: 'GET',
        data: {
          loginCode: res.code,
          clientId: 'ffv-client',  // 可选，默认为 ffv-client
          mobileCode: '',          // 可选，如需绑定手机号
          referrerId: '',          // 可选，推荐人ID
          legacyMode: true         // 关键：小程序需置为 true 才会在响应体返回 refresh_token
        },
        success: function(loginRes) {
          if (loginRes.statusCode === 200) {
            // 登录成功，获取tokens
            const { access_token, refresh_token } = loginRes.data;
            
            // 安全存储tokens到小程序本地存储
            wx.setStorageSync('access_token', access_token);
            wx.setStorageSync('refresh_token', refresh_token);
            
            console.log('微信登录成功');
          }
        }
      });
    }
  }
});
```

### 1.3 微信Token刷新

当 `access_token` 过期时，使用专用的微信刷新端点：

```javascript
// 刷新 access_token
function refreshWeChatToken() {
  return new Promise((resolve, reject) => {
    const refreshToken = wx.getStorageSync('refresh_token');
    if (!refreshToken) {
      reject(new Error('没有可用的refresh_token'));
      return;
    }
    
    wx.request({
      url: 'https://your-auth-server.com/wechat/refresh-token',
      method: 'POST',
      data: {
        grant_type: 'refresh_token',
        client_id: 'ffv-client',
        refresh_token: refreshToken, // 从本地存储获取
        legacyMode: true             // 关键：小程序需置为 true 才会在响应体返回 refresh_token（如有轮换）
      },
      success: function(res) {
        if (res.statusCode === 200) {
          // 刷新成功，更新本地存储的tokens
          const { access_token, refresh_token } = res.data;
          wx.setStorageSync('access_token', access_token);
          if (refresh_token) {
            wx.setStorageSync('refresh_token', refresh_token);
          }
          resolve(access_token);
        } else {
          reject(new Error('Token刷新失败'));
        }
      },
      fail: reject
    });
  });
}

// 自动重试的API调用封装
function apiRequest(options) {
  const accessToken = wx.getStorageSync('access_token');
  
  return new Promise((resolve, reject) => {
    wx.request({
      ...options,
      header: {
        ...options.header,
        'Authorization': `Bearer ${accessToken}`
      },
      success: function(res) {
        if (res.statusCode === 401) {
          // Token过期，尝试刷新
          refreshWeChatToken().then(newToken => {
            // 使用新token重试请求
            wx.request({
              ...options,
              header: {
                ...options.header,
                'Authorization': `Bearer ${newToken}`
              },
              success: resolve,
              fail: reject
            });
          }).catch(reject);
        } else {
          resolve(res);
        }
      },
      fail: reject
    });
  });
}
```

---

## 2. 短信登录集成指南

短信登录适用于需要验证用户手机号的场景，或作为微信登录的补充认证方式。

### 2.1 服务端准备

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

测试手机号使用固定验证码是否生效（返回 Access Token）：

```bash
export BASE_URL=https://al.u2511175.nyat.app:50518
export SMS_TEST_LOGIN_PHONE_NUMBER=xxxxxxxxxxx
export SMS_TEST_LOGIN_CODE=xxx
curl -sS -G "$BASE_URL/sms/auth" \
--data-urlencode "legacyMode=true" \
--data-urlencode "mobileNumber=$SMS_TEST_LOGIN_PHONE_NUMBER" \
--data-urlencode "verificationCode=$SMS_TEST_LOGIN_CODE"
```

---

## 2. 端点说明

- 发送验证码
  - POST `/sms/send-code`（表单或 JSON）
- 登录并颁发令牌
  - GET `/sms/auth`（Web 默认：响应 JSON 仅含 `access_token`，`refresh_token` 写入 HttpOnly Cookie）
  - GET `/sms/login`（等价别名）
  - 小程序：上述登录请求需加 `legacyMode=true`，服务端会在响应体包含 `refresh_token`
- 刷新令牌
  - Web 默认：POST `/sms/refresh-token`（仅需 Cookie；服务端从 Cookie 读取 `refresh_token` 并通过 `Set-Cookie` 轮换）
  - 小程序：POST `/sms/refresh-token` 时带上 `refresh_token` 与 `legacyMode=true`

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

### 3.2 登录（小程序：响应体返回 refresh_token）
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
    verificationCode: code,
    legacyMode: true
  },
  success(res) {
    const { access_token, refresh_token } = res.data || {};
    if (access_token) wx.setStorageSync('ACCESS_TOKEN', access_token);
    if (refresh_token) wx.setStorageSync('refresh_token', refresh_token);
  },
  fail(err) { console.error('auth fail', err); }
});
```

### 3.3 刷新令牌（小程序需显式传参）
```javascript
const BASE_URL = 'https://iam.ruichuangqi.com';

wx.request({
  url: `${BASE_URL}/sms/refresh-token`,
  method: 'POST',
  header: { 'Content-Type': 'application/x-www-form-urlencoded' },
  // Web 默认：只需 Cookie；
  // 小程序：需要传入 refresh_token 与 legacyMode=true
  data: `grant_type=refresh_token&client_id=ffv-client&refresh_token=${encodeURIComponent(wx.getStorageSync('refresh_token'))}&legacyMode=true`,
  success(res) {
    const { access_token } = res.data || {};
    if (access_token) wx.setStorageSync('ACCESS_TOKEN', access_token);
  },
  fail(err) { console.error('refresh fail', err); }
});
```

---

## 3. 微信登录 vs SMS登录 对比与选择指南

### 3.1 功能对比

| 特性                  | 微信登录 (`/wechat/login`) | SMS登录 (`/sms/auth` + `/sms/login`) |
| --------------------- | -------------------------- | ------------------------------------ |
| **用户体验**          | 一键登录，无需输入         | 需要输入手机号和验证码               |
| **安全性**            | 依赖微信平台认证           | 手机号短信验证                       |
| **refresh_token支持** | ✅ 完全支持                 | ✅ 完全支持                           |
| **存储方式**          | 小程序本地存储（`legacyMode=true` 时响应体返回） | Web: HttpOnly Cookie<br/>小程序: 本地存储 |
| **刷新端点**          | `/wechat/refresh-token`    | `/sms/refresh-token`                 |
| **适用场景**          | 微信生态内应用             | 通用手机号验证                       |
| **离线使用**          | 需要微信授权               | 独立于第三方平台                     |

### 3.2 Token机制统一性

**两种登录方式的Token机制基本一致：**

1. **Token生成**：都使用相同的OAuth2 Token生成器
2. **存储方式**：
   - **Web应用**：`refresh_token` 存储在 HttpOnly Cookie 中
   - **微信小程序**：将 `legacyMode=true`，在响应体获取 `refresh_token` 后本地安全存储（`wx.setStorageSync()`）
3. **安全策略**：
   - **Web应用**：默认不在响应中暴露 `refresh_token`（Cookie 模式）
   - **微信小程序**：通过 `legacyMode=true` 在响应中返回 `refresh_token`（仅限小程序场景）
4. **刷新机制**：
   - **Web应用**：从 Cookie 自动读取 `refresh_token`
   - **微信小程序**：从本地存储读取 `refresh_token` 并在请求中传递，同时设置 `legacyMode=true`
5. **过期时间**：access_token (1小时)，refresh_token (24小时)

### 3.3 最佳实践建议

#### 推荐的登录策略

```javascript
// 推荐：优先微信登录，SMS登录作为备选
async function smartLogin() {
  try {
    // 1. 尝试微信登录
    const wechatResult = await attemptWeChatLogin();
    if (wechatResult.success) {
      return { method: 'wechat', token: wechatResult.access_token };
    }
  } catch (error) {
    console.log('微信登录失败，降级到SMS登录');
  }
  
  // 2. 降级到SMS登录
  try {
    const smsResult = await attemptSMSLogin();
    return { method: 'sms', token: smsResult.access_token };
  } catch (error) {
    throw new Error('所有登录方式都失败');
  }
}

// 统一的Token刷新处理（微信小程序版本）
async function refreshToken(loginMethod) {
  const endpoint = loginMethod === 'wechat' 
    ? '/wechat/refresh-token' 
    : '/sms/refresh-token';
  
  const refreshToken = wx.getStorageSync('refresh_token');
  if (!refreshToken) {
    throw new Error('没有可用的refresh_token');
  }
    
  return wx.request({
    url: `https://your-auth-server.com${endpoint}`,
    method: 'POST',
    data: {
      grant_type: 'refresh_token',
      client_id: 'ffv-client',
      refresh_token: refreshToken  // 微信小程序需要显式传递
    }
  });
}
```

#### 生产环境配置要点

```bash
# 微信登录需要的额外配置
WECHAT_APP_ID=your_wechat_app_id
WECHAT_APP_SECRET=your_wechat_app_secret

# 通用Cookie安全配置（两种登录方式共用）
OAUTH2_COOKIE_MODE_ENABLED=true
OAUTH2_COOKIE_DOMAIN=.your-domain.com
OAUTH2_COOKIE_SECURE=true
OAUTH2_COOKIE_SAME_SITE=None
```

### 3.4 错误处理统一化

```javascript
// 统一的错误处理函数
function handleAuthError(error, loginMethod) {
  const methodName = loginMethod === 'wechat' ? '微信登录' : 'SMS登录';
  
  if (error.statusCode === 401) {
    console.log(`${methodName}: Token已过期，尝试刷新`);
    return refreshToken(loginMethod);
  } else if (error.statusCode === 400) {
    console.log(`${methodName}: 请求参数错误`);
    // 重新引导用户登录
  } else {
    console.log(`${methodName}: 服务器错误`);
  }
}
```

---

## 4. API调用与Token管理

### 4.1 携带 Bearer 访问受保护 API
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

- **Web**：`refresh_token` 存储于 HttpOnly Cookie；不要在响应体或日志中暴露。
- **微信小程序**：仅当请求携带 `legacyMode=true` 时，响应体才会返回 `refresh_token`；务必本地安全存储（例如 `wx.setStorageSync()`），并严格避免在日志中暴露。
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


