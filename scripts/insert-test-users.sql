-- 插入测试用户数据的SQL脚本
-- 这个脚本可以在应用运行时执行，添加新的测试用户

-- 创建新的用户组
INSERT INTO groups (group_name, enabled) VALUES 
    ('HQ_ADMIN_GROUP', true),
    ('DISTRIBUTOR_ADMIN_GROUP', true),
    ('STORE_ADMIN_GROUP', true),
    ('CONSULTANT_GROUP', true),
    ('DISTRIBUTOR_EMPLOYEE_GROUP', true)
ON CONFLICT (group_name) DO NOTHING;

-- 创建新的测试用户
INSERT INTO users (username, password, enabled, password_change_required, first_login, password_last_changed) VALUES
    ('hq_admin', '{bcrypt}$2a$10$WX8ouiJg.KT4RCFxCdfATudErurseawM2dHtlE2SXYAU0IEF9zKI.', true, false, false, CURRENT_TIMESTAMP),  -- password=hq123
    ('distributor_admin', '{bcrypt}$2a$10$fMEcFK6P5EATp4CD5P1P6.c86Haw9p7kolTtvhFzkfMhGdIH8JbHO', true, false, false, CURRENT_TIMESTAMP),  -- password=dist123
    ('store_admin', '{bcrypt}$2a$10$HoULU5oixEHgHVZAIqX1lueng0ls0LcfD4TbL8Be5oc7CpGSatv0y', true, false, false, CURRENT_TIMESTAMP),  -- password=store123
    ('consultant', '{bcrypt}$2a$10$q4ZW6VAWdxHEY8iL/lwfhecLwh3WaDvhywDVgki2JwPBXK2ZfvT8.', true, false, false, CURRENT_TIMESTAMP),  -- password=cons123
    ('distributor_employee', '{bcrypt}$2a$10$nk4.os29D8FnllyyXOsu3uy1ExfH45rH3sVeksDdnZD7K6K7i2FN.', true, false, false, CURRENT_TIMESTAMP)  -- password=emp123
ON CONFLICT (username) DO NOTHING;

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

-- 查询验证结果
SELECT 'Users created:' as info;
SELECT username, enabled, password_change_required FROM users WHERE username IN ('hq_admin', 'distributor_admin', 'store_admin', 'consultant', 'distributor_employee');

SELECT 'User authorities:' as info;
SELECT username, authority FROM authorities WHERE username IN ('hq_admin', 'distributor_admin', 'store_admin', 'consultant', 'distributor_employee') ORDER BY username, authority;