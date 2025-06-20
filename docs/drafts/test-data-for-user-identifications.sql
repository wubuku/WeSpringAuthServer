-- 用户标识功能测试数据
-- 请在测试时手动执行这些SQL语句

-- 为现有用户添加各种类型的标识
-- 注意：请根据实际的用户名修改下面的用户名

-- 示例1：为用户添加手机号标识（已验证）
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
('MOBILE_NUMBER', 'admin', '13800138000', true, CURRENT_TIMESTAMP)
ON CONFLICT (user_identification_type_id, username) DO UPDATE SET
    identifier = EXCLUDED.identifier,
    verified = EXCLUDED.verified,
    verified_at = EXCLUDED.verified_at,
    updated_at = CURRENT_TIMESTAMP;

-- 示例2：为用户添加微信OpenID（已验证）
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
('WECHAT_OPENID', 'admin', 'oABC123def456ghi789jkl', true, CURRENT_TIMESTAMP)
ON CONFLICT (user_identification_type_id, username) DO UPDATE SET
    identifier = EXCLUDED.identifier,
    verified = EXCLUDED.verified,
    verified_at = EXCLUDED.verified_at,
    updated_at = CURRENT_TIMESTAMP;

-- 示例3：为用户添加邮箱（未验证）
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
('EMAIL', 'admin', 'admin@example.com', false, NULL)
ON CONFLICT (user_identification_type_id, username) DO UPDATE SET
    identifier = EXCLUDED.identifier,
    verified = EXCLUDED.verified,
    verified_at = EXCLUDED.verified_at,
    updated_at = CURRENT_TIMESTAMP;

-- 示例4：为用户添加身份证号（验证状态为null）
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
('ID_CARD', 'admin', '11010119800101001X', NULL, NULL)
ON CONFLICT (user_identification_type_id, username) DO UPDATE SET
    identifier = EXCLUDED.identifier,
    verified = EXCLUDED.verified,
    verified_at = EXCLUDED.verified_at,
    updated_at = CURRENT_TIMESTAMP;

-- 示例5：为另一个用户添加多种标识
-- 请将 'testuser' 替换为您系统中实际存在的用户名
/*
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
('MOBILE_NUMBER', 'testuser', '13900139000', true, CURRENT_TIMESTAMP),
('WECHAT_OPENID', 'testuser', 'oXYZ789abc012def345ghi', true, CURRENT_TIMESTAMP),
('WECHAT_UNIONID', 'testuser', 'uUNI567opq890rst123uvw', true, CURRENT_TIMESTAMP),
('EMAIL', 'testuser', 'testuser@company.com', false, NULL),
('WECHAT_MOBILE_NUMBER', 'testuser', '13700137000', true, CURRENT_TIMESTAMP)
ON CONFLICT (user_identification_type_id, username) DO UPDATE SET
    identifier = EXCLUDED.identifier,
    verified = EXCLUDED.verified,
    verified_at = EXCLUDED.verified_at,
    updated_at = CURRENT_TIMESTAMP;
*/

-- 查询用户标识数据（用于验证）
SELECT 
    username,
    user_identification_type_id,
    identifier,
    verified,
    verified_at,
    created_at
FROM user_identifications 
ORDER BY username, user_identification_type_id;

-- 测试最终的用户列表查询（与实际API相同的SQL）
SELECT u.username, u.enabled, u.password_change_required,
       STRING_AGG(DISTINCT g.group_name, ', ') as groups,
       STRING_AGG(DISTINCT a.authority, ', ') as authorities,
       STRING_AGG(DISTINCT 
           CASE WHEN ui.user_identification_type_id IS NOT NULL THEN
               ui.user_identification_type_id || ':' || ui.identifier || '|' || COALESCE(ui.verified::text, 'null')
           END, ', ') as identifications
FROM users u
LEFT JOIN group_members gm ON u.username = gm.username
LEFT JOIN groups g ON gm.group_id = g.id
LEFT JOIN authorities a ON u.username = a.username
LEFT JOIN user_identifications ui ON u.username = ui.username
WHERE u.username != '*'
GROUP BY u.username, u.enabled, u.password_change_required
ORDER BY u.username; 