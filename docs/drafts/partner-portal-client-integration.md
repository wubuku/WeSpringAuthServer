# Partner Portal Client 集成指南

## 问题描述

```
Internal server error: Registered client not found, clientId: partner-portal
```

此错误表示 OAuth2 客户端 `partner-portal` 未在授权服务器中注册。

---

## 根本原因

该授权服务器使用 **数据库存储** 来管理 OAuth2 客户端（通过 `JdbcRegisteredClientRepository`）。客户端配置存储在 `oauth2_registered_client` 表中，**不是** 在代码中硬编码。

---

## 解决方案

在生产环境中，有 **两种方式** 注册新客户端：

### 方式一：通过 SQL 脚本注册（推荐）

#### 步骤 1：生成客户端密钥的 BCrypt 哈希

在服务启动前，需要为客户端密码生成 BCrypt 哈希值：

```bash
# 使用 Spring Security 的 BCrypt 编码器生成哈希
# 你可以使用在线工具或通过代码生成

# 示例：通过 Docker/本地运行服务时使用
# 在 Spring Boot 应用中可以通过 Bean 或命令行生成
```

推荐使用以下 BCrypt 哈希生成方法之一：

**方法 A：使用 htpasswd 工具**
```bash
htpasswd -bnBC 10 "" "your-client-secret" | tr -d ':\n' | sed 's/$2y/$2a/'
```

**方法 B：使用在线工具**
访问 https://www.bcrypt.fr/ 或 https://bcrypt-generator.com/

**方法 C：通过 Spring Boot Actuator 或代码**
启动应用后通过代码生成（参见下方"动态注册"部分）

#### 步骤 2：在 `data-prod.sql` 中添加客户端配置

编辑 `src/main/resources/data-prod.sql`，取消注释模板并修改：

```sql
-- 生产环境OAuth2客户端配置
-- Partner Portal Client
INSERT INTO public.oauth2_registered_client (
    id,client_id,client_id_issued_at,client_secret,client_secret_expires_at,client_name,
    client_authentication_methods,authorization_grant_types,
    redirect_uris,post_logout_redirect_uris,scopes,client_settings,token_settings
) VALUES (
    'partner-portal-static-id',                              -- id: 唯一标识符
    'partner-portal',                                        -- client_id: 客户端ID（用于登录）
    CURRENT_TIMESTAMP,                                       -- client_id_issued_at: 发行时间
    '{bcrypt}$2a$10$YOUR_BCRYPT_HASH_HERE',                -- client_secret: BCrypt加密后的密钥
    NULL,                                                    -- client_secret_expires_at: 密钥永不过期
    'Partner Portal',                                        -- client_name: 客户端显示名称
    'client_secret_basic',                                   -- client_authentication_methods: 认证方式
    'authorization_code,refresh_token',                      -- authorization_grant_types: 授权类型
    'https://partner.yourdomain.com/auth/callback',         -- redirect_uris: 回调URI（替换为实际地址）
    'https://partner.yourdomain.com/login,https://partner.yourdomain.com/logout', -- post_logout_redirect_uris
    'openid,profile',                                        -- scopes: 权限范围
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":false}',
    '{"@class":"java.util.Collections$UnmodifiableMap",
    "settings.token.reuse-refresh-tokens":true,
    "settings.token.access-token-time-to-live":["java.time.Duration",7200.000000000],
    "settings.token.refresh-token-time-to-live":["java.time.Duration",7776000.000000000],
    "settings.token.authorization-code-time-to-live":["java.time.Duration",600.000000000]}'
) ON CONFLICT (id) DO NOTHING;
```

#### 步骤 3：重新构建并部署

```bash
./mvnw clean package -DskipTests
# 然后重新部署
```

---

### 方式二：直接插入数据库（无需重新部署）

如果不想修改代码，可以通过 SQL 直接在数据库中添加客户端：

```sql
-- 直接在生产数据库执行此 SQL
INSERT INTO public.oauth2_registered_client (
    id,client_id,client_id_issued_at,client_secret,client_secret_expires_at,client_name,
    client_authentication_methods,authorization_grant_types,
    redirect_uris,post_logout_redirect_uris,scopes,client_settings,token_settings
) VALUES (
    'partner-portal-static-id',
    'partner-portal',
    CURRENT_TIMESTAMP,
    '{bcrypt}$2a$10$YOUR_BCRYPT_HASH_HERE',
    NULL,
    'Partner Portal',
    'client_secret_basic',
    'authorization_code,refresh_token',
    'https://partner.yourdomain.com/auth/callback',
    'https://partner.yourdomain.com/login,https://partner.yourdomain.com/logout',
    'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":false}',
    '{"@class":"java.util.Collections$UnmodifiableMap",
    "settings.token.reuse-refresh-tokens":true,
    "settings.token.access-token-time-to-live":["java.time.Duration",7200.000000000],
    "settings.token.refresh-token-time-to-live":["java.time.Duration",7776000.000000000],
    "settings.token.authorization-code-time-to-live":["java.time.Duration",600.000000000]}'
) ON CONFLICT (id) DO NOTHING;
```

---

## 关键配置说明

### 字段详解

| 字段 | 说明 | 示例值 |
|------|------|--------|
| `id` | 数据库主键，唯一标识此客户端配置 | `partner-portal-static-id` |
| `client_id` | OAuth2 客户端标识符，登录时使用 | `partner-portal` |
| `client_secret` | 客户端密钥（BCrypt 加密） | `{bcrypt}$2a$10$...` |
| `client_authentication_methods` | 客户端认证方式 | `client_secret_basic` |
| `authorization_grant_types` | 支持的授权类型 | `authorization_code,refresh_token` |
| `redirect_uris` | 授权成功后的回调 URI（多个用逗号分隔） | `https://partner.yourdomain.com/auth/callback` |
| `post_logout_redirect_uris` | 登出后的回调 URI | `https://partner.yourdomain.com/login,...` |
| `scopes` | 授权范围 | `openid,profile` |

### Client Settings 配置

```json
{
  "settings.client.require-proof-key": true,           // 启用 PKCE
  "settings.client.require-authorization-consent": false  // 不需要用户手动同意（简化流程）
}
```

- `require-proof-key: true` - 启用 PKCE (Proof Key for Code Exchange)，提高安全性
- `require-authorization-consent: false` - 跳过授权确认页面（如果为 true，用户每次登录都会看到授权确认页面）

### Token Settings 配置

```json
{
  "settings.token.reuse-refresh-tokens": true,                            // 复用 refresh token
  "settings.token.access-token-time-to-live": ["java.time.Duration", 7200],        // Access Token 有效期 2 小时
  "settings.token.refresh-token-time-to-live": ["java.time.Duration", 7776000],     // Refresh Token 有效期 90 天
  "settings.token.authorization-code-time-to-live": ["java.time.Duration", 600]    // Authorization Code 有效期 10 分钟
}
```

---

## Partner Portal 端配置

确保 Partner Portal 配置以下内容与 Auth Server 匹配：

### 环境变量或配置文件

```yaml
# Partner Portal 的 OAuth2 配置
oauth2:
  issuer-uri: https://auth.yourdomain.com
  client-id: partner-portal
  client-secret: your-client-secret
  redirect-uri: https://partner.yourdomain.com/auth/callback
  scopes: openid,profile
```

### 常见错误排查

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `Registered client not found` | 客户端未在数据库注册 | 执行上述 SQL 注册客户端 |
| `invalid redirect_uri` | 回调 URI 不匹配 | 检查 `redirect_uris` 配置，确保完全匹配 |
| `invalid client` | client_id 或 secret 错误 | 核对 `client_id` 和 `client_secret` |
| `unauthorized` | 认证方式或授权类型不支持 | 检查 `client_authentication_methods` 和 `authorization_grant_types` |

---

## 数据库表结构参考

`oauth2_registered_client` 表结构：

```sql
CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at TIMESTAMPTZ DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);
```

---

## 验证配置

部署完成后，可通过以下方式验证：

1. **检查数据库记录**：
```sql
SELECT client_id, client_name, client_authentication_methods
FROM oauth2_registered_client
WHERE client_id = 'partner-portal';
```

2. **OAuth2 发现端点**：
```
GET https://auth.yourdomain.com/.well-known/openid-configuration
```

3. **尝试授权码流程**：
```
GET https://auth.yourdomain.com/oauth2/authorize?
    response_type=code&
    client_id=partner-portal&
    redirect_uri=https://partner.yourdomain.com/auth/callback&
    scope=openid%20profile&
    state=random-state
```

---

## 参考资料

- Spring Authorization Server 文档：https://docs.spring.io/spring-authorization-server/reference/html/
- OAuth 2.0 规范：https://datatracker.ietf.org/doc/html/rfc6749
- PKCE 规范：https://datatracker.ietf.org/doc/html/rfc7636
