# API安全审计进度表

## 审计目标
🎯 确保所有会"改变状态"的API都有适当的权限保护
🔒 对于不确定的API，采用保守策略：设置为需要ROLE_ADMIN权限
📋 重点检查管理页面使用的API端点

## 审计范围
- [ ] 所有*Controller.java文件中的API端点
- [ ] SecurityConfig中的权限配置
- [ ] 特别关注POST/PUT/DELETE等会改变状态的方法

## 审计进度

### Phase 1: 控制器发现 🔍
- [x] 列出所有控制器文件
- [x] 识别所有API端点
- [x] 分类：认证类 vs 业务类 vs 管理类

### Phase 2: 端点权限分析 🔐
- [ ] 检查每个端点的当前权限配置
- [ ] 识别缺少权限保护的端点
- [ ] 分析业务逻辑确定合适的权限级别

### Phase 3: 权限修复 🛠️
- [ ] 修复SecurityConfig配置
- [ ] 为高危端点添加ROLE_ADMIN保护
- [ ] 验证修复效果

### Phase 4: 验证测试 ✅
- [ ] 测试认证类API正常工作
- [ ] 测试管理类API需要正确权限
- [ ] 确认安全配置生效

## 发现的控制器列表

### 🔒 管理类API（高危，需要ROLE_ADMIN权限）
1. **AuthorityManagementApiController** - 权限管理
   - POST /update, /batch-update, /group/update, /group/batch-update
   - POST /create, /{authorityId}/toggle-enabled, /{authorityId}/update
   - POST /import-csv

2. **GroupManagementApiController** - 组管理
   - POST /create, /{groupId}/members, /{groupId}/toggle-enabled
   - DELETE /{groupId}/members/{username}

3. **UserManagementApiController** - 用户管理
   - POST /{username}/toggle-enabled, /{username}/toggle-password-change

4. **UserPreRegistrationController** - 用户预注册
   - POST /pre-register
   - PUT /{username}/regenerate-password

5. **GroupController** - 组操作
   - POST /, PUT /{groupId}, PUT /{groupId}/users

6. **UserController** - 用户操作
   - PUT /{username} 

### 🔐 认证类API（部分不需要认证）
1. **SmsLoginController** - SMS登录
   - POST /send-code (两种格式)

2. **WebSmsController** - Web SMS
   - POST /send-code, /verify

3. **SocialLoginController** - 微信登录
   - POST /wechat/refresh-token

4. **WebTokenController** - Token管理
   - POST /token

5. **PasswordController** - 密码管理
   - POST /change

6. **PasswordTokenController** - 密码令牌
   - PUT /resend-register-email, /create-password
   - POST /forgot-password

## 权限配置分析

### 🚨 发现的严重安全问题

1. **GroupController** (`/auth-srv/groups`) - ❌ 完全无保护！
   - POST / (创建组)
   - PUT /{groupId} (更新组)
   - PUT /{groupId}/users (组用户管理)
   - **路径未被SecurityConfig覆盖**

2. **UserController** (`/auth-srv/users`) - ❌ 完全无保护！
   - PUT /{username} (更新用户)
   - **路径未被SecurityConfig覆盖**

3. **密码相关端点** - ⚠️ 需要检查
   - PasswordController (/password/change)
   - PasswordTokenController 各种密码重置端点

### ✅ 已保护的端点
- `/api/users/**` → Users_Read权限
- `/api/groups/**` → Roles_Read权限  
- `/api/authorities/**` → ROLE_ADMIN权限
- `/pre-register**` → ROLE_ADMIN权限

### 🔍 当前SecurityConfig覆盖范围
- **Order 1**: `/sms/**`, `/wechat/**`, `/api/sms/**` (STATELESS, permitAll)
- **Order 2**: `/api/**`, `/web-sms/**` (有权限控制)
- **Order 3**: 其他路径 (页面访问控制，但`/auth-srv/**`API**缺少保护**！)

## 修复清单

### ✅ 已修复的安全漏洞
1. **扩展webApiSecurityFilterChain范围**
   - 添加`/auth-srv/**`到securityMatcher
   - 所有`/auth-srv/**`端点现在需要ROLE_ADMIN权限

2. **具体保护的端点**
   - `/auth-srv/users/**` → ROLE_ADMIN
   - `/auth-srv/groups/**` → ROLE_ADMIN  
   - `/auth-srv/authorities/**` → ROLE_ADMIN
   - `/auth-srv/password/**` → ROLE_ADMIN
   - `/auth-srv/password-tokens/**` → ROLE_ADMIN
   - `/auth-srv/emails/**` → ROLE_ADMIN

### 🧪 验证结果
- ✅ `/auth-srv/groups` GET请求: 302重定向 (需要认证)
- ✅ `/auth-srv/users` GET请求: 302重定向 (需要认证)  
- ✅ `/auth-srv/groups` POST请求: 403 Forbidden (权限不足)

### 📋 安全态势改善
**修复前**: 高危管理API完全无保护 🚨
**修复后**: 所有管理API需要ROLE_ADMIN权限 🔒

---
**审计原则**: 宁可保守，不可冒险！ 