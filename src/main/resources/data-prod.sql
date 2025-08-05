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
-- 把下面的 SQL 作为模板。特别注意修改包含了 `xxx` 和 `XXX` 的部分。
/*
INSERT INTO public.oauth2_registered_client (
    id,client_id,client_id_issued_at,client_secret,client_secret_expires_at,client_name,
    client_authentication_methods,authorization_grant_types,
    redirect_uris,post_logout_redirect_uris,scopes,client_settings,token_settings
    ) VALUES (
	 'xxx-client-static-id',
	 'xxx-client',
	 '2025-06-15 21:44:30.947',
	 '{bcrypt}$2a$10$xxx',
	 NULL,
	 'XXX Client',
	 'client_secret_basic','authorization_code,refresh_token',
	 'https://admin.xxx.com/auth/callback',
	 'https://admin.xxx.com/login,https://admin.xxx.com/logout',
	 'openid,profile','{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":false}',
	 '{"@class":"java.util.Collections$UnmodifiableMap",
    "settings.token.reuse-refresh-tokens":true,
    "settings.token.access-token-time-to-live":["java.time.Duration",7200.000000000],
    "settings.token.refresh-token-time-to-live":["java.time.Duration",7776000.000000000],
    "settings.token.authorization-code-time-to-live":["java.time.Duration",600.000000000]}'
    ) ON CONFLICT (id) DO NOTHING;
*/


-- 创建项目特定的用户组
INSERT INTO groups (group_name, enabled) VALUES
    ('HQ_ADMIN_GROUP', true),
    ('DISTRIBUTOR_ADMIN_GROUP', true),
    ('STORE_ADMIN_GROUP', true),
    ('CONSULTANT_GROUP', true),
    ('DISTRIBUTOR_EMPLOYEE_GROUP', true)
ON CONFLICT (group_name) DO NOTHING;


-- 添加项目特定的权限定义
INSERT INTO authority_definitions (authority_id, description, enabled) VALUES
    ('ROLE_HQ_ADMIN', 'Headquarters Administrator', true),
    ('ROLE_DISTRIBUTOR_ADMIN', 'Distributor Administrator', true),
    ('ROLE_STORE_ADMIN', 'Store Administrator', true),
    ('ROLE_CONSULTANT', 'Consultant Role', true),
    ('ROLE_DISTRIBUTOR_EMPLOYEE', 'Distributor Employee', true)
ON CONFLICT (authority_id) DO NOTHING;

-- 移除 authorities 表的 fk_authorities_users 约束。
-- 因为我们需要预先给使用手机号登录的用户添加权限。
-- 按照目前的应用逻辑，使用手机号登录的用户，只有在第一次登录时才会创建用户。
ALTER TABLE public.authorities DROP CONSTRAINT fk_authorities_users;

-- 总部管理员 - 拥有所有权限
/*
INSERT INTO users (username, password, enabled, password_change_required, first_login, password_last_changed) VALUES
    ('hq_admin', '{bcrypt}$2a$10$xxx', true, false, false, CURRENT_TIMESTAMP)
ON CONFLICT (username) DO NOTHING;

INSERT INTO authorities (username, authority) VALUES
    ('hq_admin', 'ROLE_HQ_ADMIN'),
    ('hq_admin', 'ROLE_ADMIN')
ON CONFLICT (username, authority) DO NOTHING;

INSERT INTO authorities (username, authority) VALUES
    ('MV_15201936881', 'ROLE_STORE_ADMIN')
ON CONFLICT (username, authority) DO NOTHING;

INSERT INTO authorities (username, authority) VALUES
    ('MV_15837656031', 'ROLE_STORE_ADMIN')
ON CONFLICT (username, authority) DO NOTHING;

INSERT INTO authorities (username, authority) VALUES
    ('MV_19122156038', 'ROLE_HQ_ADMIN'),
    ('MV_19122156038', 'ROLE_DISTRIBUTOR_ADMIN')
ON CONFLICT (username, authority) DO NOTHING;

*/
