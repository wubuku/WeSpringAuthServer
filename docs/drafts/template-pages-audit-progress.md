# 模板页面审计进度跟踪

## 审计目标
检查重构后哪些修改可能对管理页面功能造成破坏，特别是API端点路径变更。

## 页面清单及审计状态

### 🔍 需要审计的页面 (11个)
- [x] 1. **login.html** (12KB, 349行) - 登录页面 ❌ **发现问题**
- [x] 2. **error.html** (1.6KB, 55行) - 错误页面 *(跳过，静态页面)*
- [x] 3. **authority-management.html** (28KB, 786行) - 权限管理页面 ❌ **发现问题**
- [x] 4. **group-management.html** (23KB, 706行) - 组管理页面 ❌ **发现问题**
- [x] 5. **user-management.html** (16KB, 495行) - 用户管理页面 ❌ **发现问题**
- [x] 6. **authority-settings.html** (24KB, 721行) - 权限设置页面 ❌ **发现问题**
- [x] 7. **home.html** (5.8KB, 185行) - 首页 ✅ **正常**
- [x] 8. **change-password.html** (8.1KB, 239行) - 修改密码页面 ❌ **发现问题**
- [x] 9. **oauth2-test-callback.html** (4.2KB, 119行) - OAuth2测试回调页面 ✅ **正常**
- [x] 10. **oauth2-test.html** (8.9KB, 238行) - OAuth2测试页面 ✅ **正常**
- [x] 11. **pre-register.html** (9.3KB, 290行) - 预注册页面 ❌ **发现问题**

## 当前浏览器状态
- **错误**: 登录后出现404错误
- **控制台错误**: Chrome扩展相关错误 (非应用相关)
- **网络错误**: 无

## 审计方法
1. 检查每个页面的JavaScript中的API调用
2. 验证API端点路径是否与当前后端控制器匹配
3. 检查表单提交的action URL
4. 验证AJAX请求的URL
5. 检查页面导航链接

## 发现的问题

### 🚨 **系统性问题：API路径前缀不匹配**

所有管理页面都使用 `/api/` 前缀调用API，但后端控制器使用 `/auth-srv/` 前缀！

#### 受影响的页面和端点：
1. **login.html**:
   - `/api/sms/send-code` → 应为 `/sms/send-code`
   - `/api/sms/verify` → 端点不存在，需要创建

2. **authority-management.html**:
   - `/api/authorities/*` → 应为 `/auth-srv/authorities/*`

3. **user-management.html**:
   - `/api/users/*` → 应为 `/auth-srv/users/*`

4. **group-management.html**:
   - `/api/groups/*` → 应为 `/auth-srv/groups/*`

5. **authority-settings.html**:
   - `/api/authorities/*` → 应为 `/auth-srv/authorities/*`

6. **pre-register.html**:
   - `/api/users/pre-register` → 应为 `/auth-srv/users/pre-register`

7. **change-password.html**:
   - `/password/change` → 需要确认正确的端点路径

## 修复计划

### 🎯 **推荐方案：统一API路径前缀**

有两种修复方案：

#### 方案A：修改所有页面 (不推荐)
- 将所有页面中的 `/api/` 改为 `/auth-srv/`
- 工作量大，容易遗漏

#### 方案B：添加API路径映射 (推荐) ⭐
- 在Spring配置中添加 `/api/*` 到 `/auth-srv/*` 的路径重写
- 或者为所有API控制器添加 `/api` 前缀的映射
- 一次修复，影响最小

### 🔧 **具体修复步骤**：
1. ✅ 为SMS创建Web登录验证端点
2. ✅ 修复change-password的表单action路径  
3. ✅ 实现API路径统一方案

## 🎯 **修复结果**

### 已修复的控制器路径映射：
1. **AuthorityManagementApiController**: 添加 `/api/authorities` 映射
2. **UserManagementApiController**: 添加 `/api/users` 映射
3. **GroupManagementApiController**: 添加 `/api/groups` 映射
4. **UserPreRegistrationController**: 添加 `/api/users` 映射
5. **SmsLoginController**: 添加 `/api/sms` 映射
6. **PasswordController**: 添加 `/password` 映射

### 新增功能：
7. **SmsLoginController**: 新增 `/sms/verify` 端点用于Web页面SMS验证

### ✅ **现在所有页面的API调用应该正常工作**：
- `/api/authorities/*` → ✅ 可用
- `/api/users/*` → ✅ 可用 
- `/api/groups/*` → ✅ 可用
- `/api/sms/*` → ✅ 可用
- `/password/change` → ✅ 可用

---
**开始时间**: 2025-06-19 21:55  
**当前状态**: ✅ 审计完成 + 修复完成  
**最后更新**: 2025-06-19 22:15

## 审计总结 📊
- ✅ **已检查**: 11/11 页面
- ❌ **有问题**: 7个页面
- ✅ **正常**: 4个页面
- 🚨 **核心问题**: API路径前缀不匹配 (`/api/` vs `/auth-srv/`) 