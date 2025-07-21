-- 生产环境数据文件
-- 仅包含生产环境必需的最小数据集

-- 生产环境提示：请在部署前修改以下默认配置
-- 1. 修改 admin 用户密码
-- 2. 修改 OAuth2 客户端密钥
-- 3. 根据实际需求调整权限配置

-- 生产环境不包含测试用户和测试数据
-- 所有数据都在 data-base.sql 中定义

-- 可以在这里添加生产环境特定的配置
-- 例如：生产环境特定的OAuth2客户端、特殊权限等

-- 生产环境OAuth2客户端示例（如果需要不同的配置）
/*
INSERT INTO oauth2_registered_client (
    id,
    client_id,
    client_id_issued_at,
    client_secret,
    client_name,
    client_authentication_methods,
    authorization_grant_types,
    redirect_uris,
    post_logout_redirect_uris,
    scopes,
    client_settings,
    token_settings
) VALUES (
    'prod-client-id',
    'production-client',
    CURRENT_TIMESTAMP,
    '{bcrypt}$2a$10$PRODUCTION_SECRET_HASH_HERE',
    'Production Client',
    'client_secret_basic',
    'authorization_code,refresh_token',
    'https://yourdomain.com/callback',
    'https://yourdomain.com/logout',
    'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
    '{"@class":"java.util.Collections$UnmodifiableMap",
    "settings.token.reuse-refresh-tokens":false,
    "settings.token.access-token-time-to-live":["java.time.Duration",3600.000000000],
    "settings.token.refresh-token-time-to-live":["java.time.Duration",86400.000000000],
    "settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}'
) ON CONFLICT (id) DO NOTHING;
*/