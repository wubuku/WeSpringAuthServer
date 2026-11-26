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

### `test.sh`
**OAuth2 授权码流程端到端测试（加固版）**
- `set -euo pipefail`，启动前检查 `curl`/`jq`/`openssl`/`base64` 依赖
- cookies 与响应头放在 `mktemp` 临时目录，`EXIT` trap 自动清理，**不再在当前目录留下 `cookies.txt`**
- `TEST_OUTPUT_DIR` 控制 `tokens.env` / `auth.env` / `session.env` 的输出目录（默认当前目录以保持兼容）
- 本地回环绕过代理并设超时；响应头与 JSESSIONID 提取兼容大小写及 HTTP/1.1、HTTP/2
- 令牌文件原子写入并 `chmod 600`；运行前清理旧 `tokens.env`，失败不会被误读旧值

```bash
bash scripts/test.sh
TEST_USERNAME=admin TEST_PASSWORD=admin bash scripts/test.sh
```

可用环境变量：`TEST_USERNAME`、`TEST_PASSWORD`、`TEST_BASE_URL`、`TEST_OUTPUT_DIR`、`TEST_REFRESH_TOKEN`。

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
**批量获取测试用户 Token**
- 通过 `test.sh` 驱动多用户流程，临时产物隔离到 `mktemp` 目录并自动清理
- 汇总文件默认 `scripts/all-test-tokens.env`，原子写入并 `chmod 600`；全部失败时不覆盖已有文件
- 任一用户失败即返回非零退出码，便于 `dev.sh` / CI 感知
- 依赖 `jq`；`--help` 可独立查看，不依赖 `test.sh` 是否存在

```bash
bash scripts/get-test-user-tokens.sh --help
bash scripts/get-test-user-tokens.sh                          # 默认输出 scripts/all-test-tokens.env
bash scripts/get-test-user-tokens.sh -o /tmp/my-tokens.env    # 指定输出文件
bash scripts/get-test-user-tokens.sh -r -d                    # 刷新一次并打印解码结果
```

选项：`-r/--refresh`、`-d/--decode`、`-o/--output PATH`、`-h/--help`。环境变量：`BASE_URL`、`OUTPUT_FILE`、`TEST_OUTPUT_DIR`。

### `generate-jwt-keystore.sh`
**JWT密钥库生成工具**
- 生成JWT签名所需的密钥库
- 配置JWT安全设置

```bash
bash scripts/generate-jwt-keystore.sh
```

### 其他工具脚本

| 脚本 | 说明 |
|------|------|
| `generate-production-config.sh` | 交互式生成 `.env.prod` 与 JWT 密钥（生产配置生成工具，见根 README） |
| `get-user-token.sh` | 获取单个用户的 Token |
| `password-encoder-help.sh` | 生成 BCrypt 编码密码的辅助脚本 |
| `test-cross-platform-compatibility.sh` | 跨平台兼容性检查 |

## 🐳 Docker 构建

### `docker-build-local.sh`
**本地 Docker 镜像构建（不推送仓库）**

```bash
bash scripts/docker-build-local.sh
```

### `docker-build-push.sh`
**本地Docker构建脚本** - 替代GitHub Actions的本地构建方案

```bash
# 设置环境变量
export DOCKERHUB_USERNAME="your_username"
export DOCKERHUB_TOKEN="your_token"

# 构建并推送到DockerHub
bash scripts/docker-build-push.sh

# 构建完成后，从DockerHub拉取镜像
docker pull --platform linux/amd64 your_username/wespring-auth-server:latest
```

**注意**: 在macOS上构建推送后，需要重新pull镜像才能在本地使用。使用 `--platform linux/amd64` 确保拉取正确的架构版本。

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
- `cookies.txt` — 历史遗留 Cookie 测试数据；当前 `scripts/test.sh` 改用 `mktemp` 临时目录并在退出时清理，**不再生成工作目录中的 `cookies.txt`**
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
5. **令牌产物权限**: `tokens.env` / `all-test-tokens.env` 等由脚本原子写入并设为 `600`，不要提交或改成宽松权限

---

**💡 提示**: 如需了解特定脚本的详细用法，请查看脚本文件头部的注释说明。 