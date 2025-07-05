-- 清理现有数据 (注释掉删除操作以确保可重复运行)
-- DELETE FROM group_members;
-- DELETE FROM group_authorities;
-- DELETE FROM groups;
-- DELETE FROM authorities;
-- DELETE FROM users;

-- 重置组 ID 序列 (注释掉以避免重复运行时的错误)
-- ALTER SEQUENCE groups_id_seq RESTART WITH 1;

-- 创建用户组（不再手动指定 ID，使用DO NOTHING避免重复插入）
INSERT INTO groups (group_name, enabled) VALUES 
    ('ADMIN_GROUP', true),
    ('USER_GROUP', true),
    ('HQ_ADMIN_GROUP', true),
    ('DISTRIBUTOR_ADMIN_GROUP', true),
    ('STORE_ADMIN_GROUP', true),
    ('CONSULTANT_GROUP', true),
    ('DISTRIBUTOR_EMPLOYEE_GROUP', true)
ON CONFLICT (group_name) DO NOTHING;

-- 我们使用了 JDBC 来存储 session，在测试阶段，我们自动清理 session 表中的数据！
-- (注释掉删除操作以确保可重复运行)
-- DELETE FROM SPRING_SESSION_ATTRIBUTES;
-- DELETE FROM SPRING_SESSION;

-- 创建特殊的基础权限用户 (注释掉避免重复插入)
-- INSERT INTO users (username, password, enabled, password_change_required, first_login, password_last_changed,temp_password_last_generated) VALUES
--     ('*', '{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky', true, false, false, CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);

-- 创建测试用户 (使用ON CONFLICT避免重复插入)
INSERT INTO users (username, password, enabled, password_change_required, first_login, password_last_changed) VALUES
    ('admin', '{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky', true, false, false, CURRENT_TIMESTAMP),  -- password=admin
    ('user', '{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky', true, true, true, null),   -- password=admin
    -- 新增的测试用户
    ('hq_admin', '{bcrypt}$2a$10$WX8ouiJg.KT4RCFxCdfATudErurseawM2dHtlE2SXYAU0IEF9zKI.', true, false, false, CURRENT_TIMESTAMP),  -- password=hq123
    ('distributor_admin', '{bcrypt}$2a$10$fMEcFK6P5EATp4CD5P1P6.c86Haw9p7kolTtvhFzkfMhGdIH8JbHO', true, false, false, CURRENT_TIMESTAMP),  -- password=dist123
    ('store_admin', '{bcrypt}$2a$10$HoULU5oixEHgHVZAIqX1lueng0ls0LcfD4TbL8Be5oc7CpGSatv0y', true, false, false, CURRENT_TIMESTAMP),  -- password=store123
    ('consultant', '{bcrypt}$2a$10$q4ZW6VAWdxHEY8iL/lwfhecLwh3WaDvhywDVgki2JwPBXK2ZfvT8.', true, false, false, CURRENT_TIMESTAMP),  -- password=cons123
    ('distributor_employee', '{bcrypt}$2a$10$nk4.os29D8FnllyyXOsu3uy1ExfH45rH3sVeksDdnZD7K6K7i2FN.', true, false, false, CURRENT_TIMESTAMP)  -- password=emp123
ON CONFLICT (username) DO NOTHING;

-- 给 admin 用户添加 ROLE_ADMIN 权限（auth server 使用这个权限对特权操作进行保护）
INSERT INTO authorities (username, authority) VALUES ('admin', 'ROLE_ADMIN')
ON CONFLICT (username, authority) DO NOTHING;

-- 给 admin 用户添加访问管理页面所需的权限
INSERT INTO authorities (username, authority) VALUES 
    ('admin', 'Users_Read'),
    ('admin', 'Roles_Read')
ON CONFLICT (username, authority) DO NOTHING;

-- 为新测试用户添加角色权限
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

-- 设置组权限 (注释掉以避免重复插入错误)
-- INSERT INTO group_authorities (group_id, authority) VALUES 
--     (1, 'ROLE_ADMIN'),
--     (1, 'ROLE_USER'),
--     (2, 'ROLE_USER');

-- 将用户分配到组 (注释掉以避免重复插入错误)
-- INSERT INTO group_members (username, group_id) VALUES 
--     ('admin', 1),
--     ('user', 2);

-- 设置直接权限（可选） (注释掉以避免重复插入错误)
-- INSERT INTO authorities (username, authority) VALUES 
--     ('admin', 'DIRECT_ADMIN_AUTH');

-- 删除原来的特殊基础权限用户相关的数据 (注释掉删除操作以确保可重复运行)
-- DELETE FROM authorities WHERE username = '*';
-- DELETE FROM users WHERE username = '*';

-- 添加基础权限 (使用ON CONFLICT避免重复插入)
INSERT INTO authority_definitions (authority_id, description, enabled) VALUES 
('Vendors_Read', 'Authority to read vendors', true),
('Vendors_Create', 'Authority to create vendors', true),
('Vendors_Update', 'Authority to update vendors', true),
('Vendors_Disable', 'Authority to disable vendors', true),
('Items_Read', 'Authority to read items', true),
('Items_Create', 'Authority to create items', true),
('Items_Update', 'Authority to update items', true),
('Items_Disable', 'Authority to disable items', true),
('Warehouses_Read', 'Authority to read warehouses', true),
('Warehouses_Create', 'Authority to create warehouses', true),
('Warehouses_Update', 'Authority to update warehouses', true),
('Warehouses_Disable', 'Authority to disable warehouses', true),
('Locations_Read', 'Authority to read locations', true),
('Locations_Create', 'Authority to create locations', true),
('Locations_Update', 'Authority to update locations', true),
('Locations_Disable', 'Authority to disable locations', true),
('Procurement_Read', 'Authority to read procurement', true),
('Procurement_Create', 'Authority to create procurement', true),
('Procurement_Update', 'Authority to update procurement', true),
('Procurement_RequestUpdates', 'Authority to request updates for procurement', true),
('Procurement_Cancel', 'Authority to cancel procurement', true),
('Procurement_ApproveUpdates', 'Authority to approve procurement updates', true),
('Receiving_Read', 'Authority to read receiving', true),
('Receiving_Create', 'Authority to create receiving', true),
('Receiving_Update', 'Authority to update receiving', true),
('Receiving_RequestUpdates', 'Authority to request updates for receiving', true),
('Receiving_ApproveUpdates', 'Authority to approve receiving updates', true),
('QA_Read', 'Authority to read quality assurance', true),
('QA_Create', 'Authority to create quality assurance', true),
('Users_Read', 'Authority to read users', true),
('Users_Create', 'Authority to create users', true),
('Users_Update', 'Authority to update users', true),
('Users_Disable', 'Authority to disable users', true),
('Roles_Read', 'Authority to read roles', true),
('Roles_Create', 'Authority to create roles', true),
('Roles_Update', 'Authority to update roles', true),
('Roles_Disable', 'Authority to disable roles', true),
('Basedata', 'Authority to access base data', true),
('Vendors', 'Authority to access vendors module', true),
('Items', 'Authority to access items module', true),
('Warehouses', 'Authority to access warehouses module', true),
('Locations', 'Authority to access locations module', true),
('Procurement', 'Authority to access procurement module', true),
('Receiving', 'Authority to access receiving module', true),
('QA', 'Authority to access quality assurance module', true),
('Users', 'Authority to access users module', true),
('Roles', 'Authority to access roles module', true)
ON CONFLICT (authority_id) DO UPDATE SET 
    description = EXCLUDED.description,
    enabled = EXCLUDED.enabled;

-- 为测试用户添加一些初始权限 (注释掉以避免重复插入错误)
-- INSERT INTO authorities (username, authority) VALUES 
--     ('user', 'Vendors_Read'),
--     ('user', 'Vendors_Create'),
--     ('user', 'Warehouses_Create');

-- 添加默认的OAuth2客户端
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
    'http://127.0.0.1:3000/callback,http://localhost:3000/callback,http://localhost:9000/callback',
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

