-- 基础数据文件 - 生产环境和开发环境都需要的核心数据
-- 这个文件包含系统运行的必要基础数据

-- 创建基础用户组
INSERT INTO groups (group_name, enabled) VALUES 
    ('ADMIN_GROUP', true),
    ('USER_GROUP', true)
ON CONFLICT (group_name) DO NOTHING;

-- 注意：系统管理员用户和OAuth2客户端配置已移至开发环境配置
-- 生产环境应该通过安全的方式创建管理员用户和客户端配置

-- 添加基础权限定义
INSERT INTO authority_definitions (authority, description, category, enabled) VALUES
    ('ROLE_ADMIN', 'System Administrator Role', 'SYSTEM', true),
    ('ROLE_USER', 'Basic User Role', 'SYSTEM', true),
    ('Users_Read', 'Read user information', 'USER_MANAGEMENT', true),
    ('Users_Create', 'Create new users', 'USER_MANAGEMENT', true),
    ('Users_Update', 'Update user information', 'USER_MANAGEMENT', true),
    ('Users_Disable', 'Disable/Enable users', 'USER_MANAGEMENT', true),
    ('Roles_Read', 'Read role information', 'ROLE_MANAGEMENT', true),
    ('Roles_Create', 'Create new roles', 'ROLE_MANAGEMENT', true),
    ('Roles_Update', 'Update role information', 'ROLE_MANAGEMENT', true),
    ('Roles_Disable', 'Disable/Enable roles', 'ROLE_MANAGEMENT', true)
ON CONFLICT (authority) DO NOTHING;

