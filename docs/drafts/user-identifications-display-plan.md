# 用户标识显示功能实现规划

## 📋 需求分析

### 业务需求
在用户管理页面 `http://localhost:9000/user-management` 中，为用户列表增加一个"用户标识"列，显示每个用户拥有的多个标识信息。

### 数据表分析
根据 `schema.sql` 中的 `user_identifications` 表结构：
```sql
CREATE TABLE IF NOT EXISTS user_identifications (
    user_identification_type_id VARCHAR(50) NOT NULL,  -- 标识类型（如：mobile, wechat_openid, wechat_unionid, id_card等）
    username VARCHAR(50) NOT NULL,                     -- 用户名
    identifier VARCHAR(100) NOT NULL,                  -- 标识值
    verified BOOLEAN DEFAULT FALSE,                    -- 是否已验证
    verified_at TIMESTAMPTZ DEFAULT NULL,              -- 验证时间
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,  -- 创建时间
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,  -- 更新时间
    PRIMARY KEY (user_identification_type_id, username),
    CONSTRAINT fk_user_identifications_users FOREIGN KEY(username) REFERENCES users(username)
);
```

### 显示需求
- 格式：`标识类型：标识值`
- 多个标识在同一单元格中显示，用逗号分隔
- 需要显示验证状态（已验证/未验证）

## 🎯 实现方案

### 1. 后端API修改

#### 1.1 修改UserManagementApiController.getUsers()
**文件**: `src/main/java/org/dddml/ffvtraceability/auth/controller/UserManagementApiController.java`

**当前SQL**:
```sql
SELECT u.username, u.enabled, u.password_change_required,
       STRING_AGG(DISTINCT g.group_name, ', ') as groups,
       STRING_AGG(DISTINCT a.authority, ', ') as authorities
FROM users u
LEFT JOIN group_members gm ON u.username = gm.username
LEFT JOIN groups g ON gm.group_id = g.id
LEFT JOIN authorities a ON u.username = a.username
WHERE u.username != '*'
GROUP BY u.username, u.enabled, u.password_change_required
ORDER BY u.username
```

**修改后SQL**:
```sql
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
ORDER BY u.username
```

**Java代码处理逻辑**:
```java
// 在getUsers()方法返回前添加处理
@GetMapping("/list")
@Transactional(readOnly = true)
public List<Map<String, Object>> getUsers() {
    String sql = """
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
            ORDER BY u.username
            """;

    List<Map<String, Object>> users = jdbcTemplate.queryForList(sql);
    
    // 处理标识数据
    users.forEach(user -> {
        String rawIdentifications = (String) user.get("identifications");
        if (rawIdentifications != null) {
            user.put("identifications", formatIdentifications(rawIdentifications));
        }
    });
    
    return users;
}

private String formatIdentifications(String rawIdentifications) {
    if (rawIdentifications == null || rawIdentifications.trim().isEmpty()) {
        return null;
    }
    
    return Arrays.stream(rawIdentifications.split(", "))
            .map(this::formatSingleIdentification)
            .collect(Collectors.joining(", "));
}

private String formatSingleIdentification(String identification) {
    String[] parts = identification.split("\\|");
    if (parts.length != 2) {
        return identification; // fallback
    }
    
    String typeAndValue = parts[0];
    String verifiedStatus = parts[1];
    
    // 脱敏处理
    String maskedIdentification = maskSensitiveIdentification(typeAndValue);
    
    // 验证状态处理：只有明确为false才显示警告，null不显示符号
    if ("true".equals(verifiedStatus)) {
        return maskedIdentification + "✓";
    } else if ("false".equals(verifiedStatus)) {
        return maskedIdentification + "⚠";
    } else {
        // verified为null的情况，不显示符号
        return maskedIdentification;
    }
}

private String maskSensitiveIdentification(String typeAndValue) {
    String[] parts = typeAndValue.split(":", 2);
    if (parts.length != 2) {
        return typeAndValue;
    }
    
    String type = parts[0];
    String value = parts[1];
    String maskedValue = maskSensitiveValue(type, value);
    
    return type + ":" + maskedValue;
}
```

#### 1.2 数据处理逻辑
1. **SQL查询**: 使用管道符`|`分隔标识值和验证状态，避免在SQL中使用特殊字符
2. **Java处理**: 在Controller中格式化数据，添加验证状态符号
3. **验证状态规则**:
   - `verified = true`: 显示 ✓
   - `verified = false`: 显示 ⚠  
   - `verified = null`: 不显示符号

#### 1.3 安全考虑
- ✅ **路径权限**: 已由SecurityConfig保护，需要ROLE_ADMIN权限
- ✅ **数据敏感性**: 标识信息对管理员可见是合理的
- ✅ **SQL注入**: 使用参数化查询，无风险
- ⚠️ **数据脱敏**: 考虑对手机号等敏感信息进行脱敏显示

### 2. 前端页面修改

#### 2.1 修改user-management.html模板
**文件**: `src/main/resources/templates/user-management.html`

**需要修改的部分**:

1. **表头增加列**:
```html
<thead>
    <tr>
        <th>Username</th>
        <th>Status</th>
        <th>Password Status</th>
        <th>Groups</th>
        <th>Direct Authorities</th>
        <th>User Identifications</th>  <!-- 新增列 -->
        <th>Actions</th>
    </tr>
</thead>
```

2. **表格行数据显示** (借鉴Direct Authorities列的实现):
```javascript
// 在loadUsers()函数中增加标识列的显示，仿照authorities列的做法
<td class="identifications-cell">
    ${user.identifications ? user.identifications.split(', ').map(identification => {
        let badgeClass = 'identification-badge';
        
        if (identification.endsWith('✓')) {
            badgeClass += ' verified';
        } else if (identification.endsWith('⚠')) {
            badgeClass += ' unverified';
        } else {
            badgeClass += ' normal';
        }
        
        return `<span class="${badgeClass}">${identification}</span>`;
    }).join('') : '-'}
</td>
```

3. **CSS样式增加**:
```css
.identification-badge {
    display: inline-block;
    padding: 2px 8px;
    margin: 2px;
    border-radius: 12px;
    font-size: 12px;
}

.identification-badge.verified {
    background: #d1e7dd;
    color: #0f5132;
}

.identification-badge.unverified {
    background: #fff3cd;
    color: #856404;
}

.identification-badge.normal {
    background: #e9ecef;
    color: #495057;
}

.identifications-cell {
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.identifications-cell:hover {
    overflow: visible;
    white-space: normal;
    background: white;
    position: relative;
    z-index: 1;
}
```

### 3. 数据脱敏考虑

#### 3.1 敏感信息处理
对于可能包含敏感信息的标识类型，实施脱敏处理：

```java
// 在SQL查询中或Java代码中实现脱敏
private String maskSensitiveValue(String identificationType, String identifier) {
    switch (identificationType.toLowerCase()) {
        case "mobile":
        case "phone":
            // 手机号脱敏：139****8888
            if (identifier.length() >= 7) {
                return identifier.substring(0, 3) + "****" + identifier.substring(identifier.length() - 4);
            }
            break;
        case "id_card":
            // 身份证脱敏：110***********1234
            if (identifier.length() >= 8) {
                return identifier.substring(0, 3) + "***********" + identifier.substring(identifier.length() - 4);
            }
            break;
        case "email":
            // 邮箱脱敏：abc***@example.com
            int atIndex = identifier.indexOf('@');
            if (atIndex > 3) {
                return identifier.substring(0, 3) + "***" + identifier.substring(atIndex);
            }
            break;
        default:
            // 微信OpenID、UnionID等保持原样显示
            return identifier;
    }
    return identifier;
}
```

## 🔒 安全性评估

### 权限控制
- ✅ **API端点保护**: `/api/users/list` 已被SecurityConfig保护，需要ROLE_ADMIN权限
- ✅ **页面访问控制**: user-management页面需要ROLE_ADMIN权限
- ✅ **数据访问合理性**: 管理员查看用户标识信息是合理的管理需求

### 数据安全
- ⚠️ **敏感信息脱敏**: 建议对手机号、身份证号等进行脱敏处理
- ✅ **SQL注入防护**: 使用JdbcTemplate参数化查询
- ✅ **XSS防护**: Thymeleaf模板引擎自动转义

### 性能考虑
- ✅ **查询优化**: 使用LEFT JOIN和STRING_AGG聚合，避免N+1查询
- ✅ **索引支持**: user_identifications表已有适当索引
- ⚠️ **数据量**: 如果用户数量很大，考虑分页显示

## 📝 实施步骤

### Phase 1: 后端API修改
1. 修改UserManagementApiController.getUsers()方法
2. 添加数据脱敏处理逻辑
3. 测试API返回数据格式

### Phase 2: 前端页面修改
1. 修改HTML模板，增加表头和数据列
2. 添加CSS样式，美化标识显示
3. 更新JavaScript代码，处理新数据字段

### Phase 3: 测试验证
1. 创建测试用户和标识数据
2. 验证页面显示效果
3. 验证权限控制
4. 验证脱敏效果

### Phase 4: 文档更新
1. 更新安全审计文档
2. 记录新增功能说明

## 🧪 测试数据准备

为了测试功能，需要在user_identifications表中插入一些测试数据：

```sql
-- 示例测试数据
INSERT INTO user_identifications (user_identification_type_id, username, identifier, verified, verified_at) VALUES
('mobile', 'testuser1', '13800138000', true, CURRENT_TIMESTAMP),
('wechat_openid', 'testuser1', 'wx_openid_123456', true, CURRENT_TIMESTAMP),
('email', 'testuser1', 'testuser1@example.com', false, NULL),
('mobile', 'testuser2', '13900139000', true, CURRENT_TIMESTAMP),
('id_card', 'testuser2', '11010119800101001X', false, NULL);
```

## ⚠️ 风险评估

### 低风险
- ✅ 不影响现有功能
- ✅ 纯显示功能，无状态变更
- ✅ 权限控制完善

### 需要注意的点
- 📋 敏感信息显示策略需要仔细考虑
- 📋 页面布局可能需要调整以适应新列
- 📋 确保不同标识类型的显示一致性

## 🎯 验收标准

1. ✅ 用户管理页面正确显示用户标识列
2. ✅ 标识格式为"类型：值"，多个标识用逗号分隔
3. ✅ 验证状态用图标正确显示（✓已验证，⚠未验证）
4. ✅ 敏感信息正确脱敏
5. ✅ 页面布局美观，不影响其他功能
6. ✅ 权限控制正常，只有ADMIN可访问
7. ✅ 性能表现良好，加载时间可接受

## 📊 实施影响评估

**影响范围**: 低
- 只涉及用户管理页面显示
- 不影响认证登录流程
- 不影响权限控制逻辑

**部署复杂度**: 低
- 只需要重启应用
- 无数据库结构变更
- 无配置文件修改

**向后兼容性**: 完全兼容
- 不影响现有API
- 不影响现有页面功能 