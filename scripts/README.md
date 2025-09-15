# WeSpringAuthServer 测试脚本集合

本目录包含WeSpringAuthServer项目的各种测试和工具脚本。

## 🚀 启动和演示脚本

### `start-cookie-demo.sh` 
**同域Cookie安全模式演示启动脚本**
- 启动后端服务（如未运行）
- 通过Spring Boot的`/demo`端点提供同域演示页面
- 自动打开浏览器到Cookie安全模式演示
- 提供完整的Cookie安全特性说明和测试指导

```bash
bash scripts/start-cookie-demo.sh
```

## 🧪 核心功能测试脚本

### `test-sms-login.sh`
**SMS登录端到端测试脚本（包含Cookie支持）**
- 测试SMS验证码发送和登录流程
- 支持Cookie刷新token测试
- 自动从数据库获取验证码
- JWT token解析和验证

```bash
bash scripts/test-sms-login.sh [手机号]
# 示例: bash scripts/test-sms-login.sh 13800138000
```

### `test-wechat-login.sh` 
**微信登录端到端测试脚本**
- 微信授权码登录测试
- 微信刷新token功能验证
- 完整的微信OAuth2流程测试

```bash
bash scripts/test-wechat-login.sh [授权码]
```

### `test-cookie-security.sh`
**Cookie安全功能专项测试**
- HttpOnly Cookie安全特性验证
- OAuth2客户端凭据后端管理测试
- 安全评分和详细报告
- Cookie属性全面检测

```bash
bash scripts/test-cookie-security.sh
```

### `verify-oauth2-security.sh`
**OAuth2安全配置验证**
- OAuth2端点安全配置检查
- 权限控制验证
- 安全漏洞检测

```bash
bash scripts/verify-oauth2-security.sh
```

## 🔐 权限和用户管理测试

### `test-permissions.sh`
**权限系统测试脚本**
- 用户权限验证
- 角色权限检查
- 权限控制功能测试

```bash
bash scripts/test-permissions.sh
```

### `test-all-pages-and-apis.sh`
**页面和API全面测试**
- 所有管理页面访问测试
- API端点权限验证
- 完整功能覆盖测试

```bash
bash scripts/test-all-pages-and-apis.sh
```

### `debug-permissions-issue.sh`
**权限问题调试脚本**
- 权限相关问题排查
- 详细的权限配置检查
- 调试信息收集

```bash
bash scripts/debug-permissions-issue.sh
```

### `test-method-security.sh`
**方法级安全测试**
- Spring Security方法级权限验证
- @PreAuthorize和@Secured注解测试

```bash
bash scripts/test-method-security.sh
```

### `test-api-security.sh`
**API安全测试**
- API端点安全配置验证
- 认证和授权测试

```bash
bash scripts/test-api-security.sh
```

## 🛠️ 工具脚本

### `get-test-user-tokens.sh`
**测试用户token获取工具**
- 自动获取测试用户的access_token
- 用于其他脚本的token准备

```bash
bash scripts/get-test-user-tokens.sh
```

### `generate-jwt-keystore.sh`
**JWT密钥库生成工具**
- 生成JWT签名所需的密钥库
- 配置JWT安全设置

```bash
bash scripts/generate-jwt-keystore.sh
```

## 🐳 Docker 构建

### `docker-build-push.sh`
**本地Docker构建脚本** - 替代GitHub Actions的本地构建方案

```bash
# 设置环境变量
export DOCKERHUB_USERNAME="your_username"
export DOCKERHUB_TOKEN="your_token"

# 构建并推送到DockerHub
bash scripts/docker-build-push.sh
```

## 📊 测试数据和配置

### 环境变量文件
- `auth.env` - 认证相关环境变量
- `tokens.env` - Token测试数据
- `sms_tokens.env` - SMS登录token数据
- `wechat_tokens.env` - 微信登录token数据
- `all-test-tokens.env` - 所有测试token集合
- `test-user-tokens.env` - 测试用户token
- `session.env` - 会话相关配置
- `wechat-test.env` - 微信测试配置

### 数据库脚本
- `insert-test-users.sql` - 测试用户数据插入脚本

### 其他工具文件
- `cookies.txt` - Cookie测试数据
- `README-wechat-test.md` - 微信测试详细说明

## 🎯 推荐使用流程

### 1. Cookie安全模式开发测试
```bash
# 启动Cookie安全演示
bash scripts/start-cookie-demo.sh

# 运行SMS登录测试
bash scripts/test-sms-login.sh 13800138000

# 验证Cookie安全特性
bash scripts/test-cookie-security.sh
```

### 2. 完整功能验证
```bash
# OAuth2安全验证
bash scripts/verify-oauth2-security.sh

# 权限系统测试
bash scripts/test-permissions.sh

# 页面和API全面测试
bash scripts/test-all-pages-and-apis.sh
```

### 3. 问题调试
```bash
# 权限问题调试
bash scripts/debug-permissions-issue.sh

# 方法级安全检查
bash scripts/test-method-security.sh
```

## 📝 脚本说明

- **所有脚本都支持彩色输出**，便于识别测试结果
- **大多数脚本会自动检测服务状态**，确保测试环境就绪
- **测试脚本提供详细的错误信息**，便于问题诊断
- **Cookie相关脚本专门针对OAuth2安全升级**进行了优化

## 🔒 安全注意事项

1. **生产环境使用**: 这些脚本主要用于开发和测试，生产环境使用需要谨慎
2. **敏感信息**: 测试脚本可能包含测试用的敏感信息，请妥善保管
3. **Cookie安全**: Cookie相关测试验证了HttpOnly、Secure、SameSite等安全特性
4. **权限验证**: 所有权限相关测试都遵循最小权限原则

---

**💡 提示**: 如需了解特定脚本的详细用法，请查看脚本文件头部的注释说明。 