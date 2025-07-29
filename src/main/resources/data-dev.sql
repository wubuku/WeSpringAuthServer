-- 开发环境测试数据文件
-- 包含开发和测试阶段需要的测试用户和权限数据

-- 创建系统管理员用户（开发环境默认密码）
INSERT INTO users (username, password, enabled, password_change_required, first_login, password_last_changed) VALUES
    ('admin', '{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky', true, false, false, CURRENT_TIMESTAMP)  -- password=admin
ON CONFLICT (username) DO NOTHING;

-- 给 admin 用户添加 ROLE_ADMIN 权限（auth server 核心权限）
INSERT INTO authorities (username, authority) VALUES 
    ('admin', 'ROLE_ADMIN'),
    ('admin', 'Users_Read'),
    ('admin', 'Roles_Read')
ON CONFLICT (username, authority) DO NOTHING;

-- 创建项目特定的用户组
INSERT INTO groups (group_name, enabled) VALUES 
    ('HQ_ADMIN_GROUP', true),
    ('DISTRIBUTOR_ADMIN_GROUP', true),
    ('STORE_ADMIN_GROUP', true),
    ('CONSULTANT_GROUP', true),
    ('DISTRIBUTOR_EMPLOYEE_GROUP', true)
ON CONFLICT (group_name) DO NOTHING;

-- 创建测试用户
INSERT INTO users (username, password, enabled, password_change_required, first_login, password_last_changed) VALUES
    ('user', '{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky', true, true, true, null),   -- password=admin
    -- 项目特定测试用户
    ('hq_admin', '{bcrypt}$2a$10$WX8ouiJg.KT4RCFxCdfATudErurseawM2dHtlE2SXYAU0IEF9zKI.', true, false, false, CURRENT_TIMESTAMP),  -- password=hq123
    ('distributor_admin', '{bcrypt}$2a$10$fMEcFK6P5EATp4CD5P1P6.c86Haw9p7kolTtvhFzkfMhGdIH8JbHO', true, false, false, CURRENT_TIMESTAMP),  -- password=dist123
    ('store_admin', '{bcrypt}$2a$10$HoULU5oixEHgHVZAIqX1lueng0ls0LcfD4TbL8Be5oc7CpGSatv0y', true, false, false, CURRENT_TIMESTAMP),  -- password=store123
    ('consultant', '{bcrypt}$2a$10$q4ZW6VAWdxHEY8iL/lwfhecLwh3WaDvhywDVgki2JwPBXK2ZfvT8.', true, false, false, CURRENT_TIMESTAMP),  -- password=cons123
    ('distributor_employee', '{bcrypt}$2a$10$nk4.os29D8FnllyyXOsu3uy1ExfH45rH3sVeksDdnZD7K6K7i2FN.', true, false, false, CURRENT_TIMESTAMP)  -- password=emp123
ON CONFLICT (username) DO NOTHING;

-- 添加项目特定的权限定义
INSERT INTO authority_definitions (authority_id, description, enabled) VALUES
    ('ROLE_HQ_ADMIN', 'Headquarters Administrator', true),
    ('ROLE_DISTRIBUTOR_ADMIN', 'Distributor Administrator', true),
    ('ROLE_STORE_ADMIN', 'Store Administrator', true),
    ('ROLE_CONSULTANT', 'Consultant Role', true),
    ('ROLE_DISTRIBUTOR_EMPLOYEE', 'Distributor Employee', true),
    -- 业务权限
    ('Vendors_Read', 'Read vendor information', true),
    ('Vendors_Create', 'Create new vendors', true),
    ('Vendors_Update', 'Update vendor information', true),
    ('Vendors_Disable', 'Disable/Enable vendors', true),
    ('Items_Read', 'Read item information', true),
    ('Items_Create', 'Create new items', true),
    ('Items_Update', 'Update item information', true),
    ('Items_Disable', 'Disable/Enable items', true),
    ('Warehouses_Read', 'Read warehouse information', true),
    ('Warehouses_Create', 'Create new warehouses', true),
    ('Warehouses_Update', 'Update warehouse information', true),
    ('Warehouses_Disable', 'Disable/Enable warehouses', true),
    ('Procurement_Read', 'Read procurement information', true),
    ('Procurement_Create', 'Create procurement orders', true),
    ('Procurement_Update', 'Update procurement orders', true),
    ('Procurement_ApproveUpdates', 'Approve procurement updates', true),
    ('Procurement_RequestUpdates', 'Request procurement updates', true),
    ('Receiving_Read', 'Read receiving information', true),
    ('Receiving_Create', 'Create receiving records', true),
    ('Receiving_Update', 'Update receiving records', true),
    ('Receiving_ApproveUpdates', 'Approve receiving updates', true),
    ('Receiving_RequestUpdates', 'Request receiving updates', true),
    ('QA_Read', 'Read QA information', true),
    ('QA_Create', 'Create QA records', true),
    ('Locations_Read', 'Read location information', true),
    ('Locations_Create', 'Create new locations', true),
    ('Locations_Update', 'Update location information', true)
ON CONFLICT (authority_id) DO NOTHING;

-- 为测试用户分配权限
-- 总部管理员 - 拥有所有权限
INSERT INTO authorities (username, authority) VALUES 
    ('hq_admin', 'ROLE_HQ_ADMIN'),
    ('hq_admin', 'ROLE_ADMIN'),
    ('hq_admin', 'Users_Read'),
    ('hq_admin', 'Users_Create'),
    ('hq_admin', 'Users_Update'),
    ('hq_admin', 'Users_Disable'),
    ('hq_admin', 'Roles_Read'),
    ('hq_admin', 'Roles_Create'),
    ('hq_admin', 'Roles_Update'),
    ('hq_admin', 'Roles_Disable'),
    ('hq_admin', 'Vendors_Read'),
    ('hq_admin', 'Vendors_Create'),
    ('hq_admin', 'Vendors_Update'),
    ('hq_admin', 'Vendors_Disable'),
    ('hq_admin', 'Items_Read'),
    ('hq_admin', 'Items_Create'),
    ('hq_admin', 'Items_Update'),
    ('hq_admin', 'Items_Disable'),
    ('hq_admin', 'Warehouses_Read'),
    ('hq_admin', 'Warehouses_Create'),
    ('hq_admin', 'Warehouses_Update'),
    ('hq_admin', 'Warehouses_Disable'),
    ('hq_admin', 'Procurement_Read'),
    ('hq_admin', 'Procurement_Create'),
    ('hq_admin', 'Procurement_Update'),
    ('hq_admin', 'Procurement_ApproveUpdates'),
    ('hq_admin', 'Receiving_Read'),
    ('hq_admin', 'Receiving_Create'),
    ('hq_admin', 'Receiving_Update'),
    ('hq_admin', 'Receiving_ApproveUpdates'),
    ('hq_admin', 'QA_Read'),
    ('hq_admin', 'QA_Create')
ON CONFLICT (username, authority) DO NOTHING;

-- 经销商管理员 - 经销商相关管理权限
INSERT INTO authorities (username, authority) VALUES 
    ('distributor_admin', 'ROLE_DISTRIBUTOR_ADMIN'),
    ('distributor_admin', 'Vendors_Read'),
    ('distributor_admin', 'Items_Read'),
    ('distributor_admin', 'Warehouses_Read'),
    ('distributor_admin', 'Warehouses_Create'),
    ('distributor_admin', 'Warehouses_Update'),
    ('distributor_admin', 'Procurement_Read'),
    ('distributor_admin', 'Procurement_Create'),
    ('distributor_admin', 'Procurement_Update'),
    ('distributor_admin', 'Procurement_RequestUpdates'),
    ('distributor_admin', 'Receiving_Read'),
    ('distributor_admin', 'Receiving_Create'),
    ('distributor_admin', 'Receiving_Update'),
    ('distributor_admin', 'Receiving_RequestUpdates'),
    ('distributor_admin', 'Users_Read'),
    ('distributor_admin', 'Users_Create'),
    ('distributor_admin', 'Users_Update')
ON CONFLICT (username, authority) DO NOTHING;

-- 门店管理员 - 门店相关管理权限
INSERT INTO authorities (username, authority) VALUES 
    ('store_admin', 'ROLE_STORE_ADMIN'),
    ('store_admin', 'Items_Read'),
    ('store_admin', 'Locations_Read'),
    ('store_admin', 'Locations_Create'),
    ('store_admin', 'Locations_Update'),
    ('store_admin', 'Receiving_Read'),
    ('store_admin', 'Receiving_Create'),
    ('store_admin', 'QA_Read'),
    ('store_admin', 'QA_Create'),
    ('store_admin', 'Users_Read')
ON CONFLICT (username, authority) DO NOTHING;

-- 咨询师 - 基础角色
INSERT INTO authorities (username, authority) VALUES 
    ('consultant', 'ROLE_CONSULTANT'),
    ('consultant', 'Items_Read'),
    ('consultant', 'Vendors_Read'),
    ('consultant', 'QA_Read')
ON CONFLICT (username, authority) DO NOTHING;

-- 经销商员工 - 基础角色
INSERT INTO authorities (username, authority) VALUES 
    ('distributor_employee', 'ROLE_DISTRIBUTOR_EMPLOYEE'),
    ('distributor_employee', 'Items_Read'),
    ('distributor_employee', 'Receiving_Read'),
    ('distributor_employee', 'Procurement_Read')
ON CONFLICT (username, authority) DO NOTHING;

-- 添加开发环境OAuth2客户端
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
    'ffv-client-static-id',
    'ffv-client',
    CURRENT_TIMESTAMP,
    '{bcrypt}$2a$10$RxycSRXenJ6CeGMP0.LGIOzesA2VwJXBOlmq33t9dn.yU8nX1fqsK',
    'FFV Client',
    'client_secret_basic',
    'authorization_code,refresh_token',
    'http://127.0.0.1:3000/auth/callback,http://localhost:3000/auth/callback,http://localhost:9000/callback',
    'http://127.0.0.1:3000/login,http://127.0.0.1:3000/logout,http://localhost:3000/login,http://localhost:3000/logout',
    'openid,profile',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":false}',
    '{"@class":"java.util.Collections$UnmodifiableMap",
    "settings.token.reuse-refresh-tokens":true,
    "settings.token.access-token-time-to-live":["java.time.Duration",7200.000000000],
    "settings.token.refresh-token-time-to-live":["java.time.Duration",7776000.000000000],
    "settings.token.authorization-code-time-to-live":["java.time.Duration",600.000000000]}'
) ON CONFLICT (id) DO UPDATE SET
    client_secret = EXCLUDED.client_secret,
    client_name = EXCLUDED.client_name,
    client_authentication_methods = EXCLUDED.client_authentication_methods,
    authorization_grant_types = EXCLUDED.authorization_grant_types,
    redirect_uris = EXCLUDED.redirect_uris,
    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
    scopes = EXCLUDED.scopes,
    client_settings = EXCLUDED.client_settings,
    token_settings = EXCLUDED.token_settings;

-- 添加用户标识测试数据
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
    ('MOBILE_NUMBER', 'admin', '13800138000', true, CURRENT_TIMESTAMP),
    ('WECHAT_OPENID', 'admin', 'oABC123def456ghi789jkl', true, CURRENT_TIMESTAMP),
    ('EMAIL', 'admin', 'admin@example.com', false, NULL),
    ('ID_CARD', 'admin', '11010119800101001X', NULL, NULL)
ON CONFLICT (user_identification_type_id, username) DO UPDATE SET
    identifier = EXCLUDED.identifier,
    verified = EXCLUDED.verified,
    verified_at = EXCLUDED.verified_at,
    updated_at = CURRENT_TIMESTAMP;