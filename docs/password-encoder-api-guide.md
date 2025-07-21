# 密码编码API使用指南

## 🎯 功能概述

为了方便系统初始化和配置，我们提供了一个开发工具API来编码密码，避免只能通过运行测试来获取编码密码的不便。

## 🔒 安全特性

- ✅ **仅开发环境启用**：使用 `@Profile("dev")` 注解，生产环境自动禁用
- ✅ **配置控制**：可通过 `auth-server.dev-tools.enabled=false` 禁用
- ✅ **安全日志**：不在日志中记录明文密码
- ✅ **权限控制**：端点路径 `/dev-tools/**` 在SecurityConfig中配置为permitAll

## 📡 API端点

### 基础URL
```
http://localhost:9000/dev-tools/password-encoder
```

### 1. 编码单个密码
```bash
POST /dev-tools/password-encoder/encode

# 请求体
{
  "password": "mypassword123"
}

# 响应
{
  "success": true,
  "rawPassword": "mypassword123",
  "encodedPassword": "{bcrypt}$2a$10$...",
  "algorithm": "bcrypt",
  "note": "This encoded password can be used in data.sql or database directly"
}
```

### 2. 批量编码用户密码
```bash
POST /dev-tools/password-encoder/encode-batch

# 请求体
{
  "users": [
    {"username": "admin", "password": "admin123"},
    {"username": "user1", "password": "user123"}
  ]
}

# 响应
{
  "success": true,
  "count": 2,
  "users": {
    "admin": {
      "username": "admin",
      "rawPassword": "admin123",
      "encodedPassword": "{bcrypt}$2a$10$..."
    },
    "user1": {
      "username": "user1", 
      "rawPassword": "user123",
      "encodedPassword": "{bcrypt}$2a$10$..."
    }
  },
  "sqlTemplate": "INSERT INTO users (username, password, enabled) VALUES ('{username}', '{encodedPassword}', true);"
}
```

### 3. 验证密码匹配
```bash
POST /dev-tools/password-encoder/verify

# 请求体
{
  "rawPassword": "admin",
  "encodedPassword": "{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky"
}

# 响应
{
  "success": true,
  "matches": true,
  "rawPassword": "admin",
  "encodedPassword": "{bcrypt}$2a$10$..."
}
```

### 4. 编码OAuth2客户端密钥
```bash
POST /dev-tools/password-encoder/encode-client-secret

# 请求体
{
  "clientId": "my-client",
  "clientSecret": "my-secret"
}

# 响应
{
  "success": true,
  "clientId": "my-client",
  "rawSecret": "my-secret",
  "encodedSecret": "{bcrypt}$2a$10$...",
  "basicAuthHeader": "Basic bXktY2xpZW50Om15LXNlY3JldA==",
  "curlExample": "curl -H \"Authorization: Basic bXktY2xpZW50Om15LXNlY3JldA==\" http://localhost:9000/oauth2/token"
}
```

### 5. 获取常用密码编码
```bash
GET /dev-tools/password-encoder/common-passwords

# 响应
{
  "success": true,
  "passwords": {
    "admin": "{bcrypt}$2a$10$...",
    "password": "{bcrypt}$2a$10$...",
    "123456": "{bcrypt}$2a$10$...",
    "test": "{bcrypt}$2a$10$...",
    "dev": "{bcrypt}$2a$10$..."
  },
  "note": "These are common passwords for development/testing only",
  "warning": "⚠️ Never use these passwords in production!"
}
```

## 🚀 快速使用

### 启动开发环境
```bash
export SPRING_PROFILES_ACTIVE=dev
./start.sh
```

### 使用示例脚本
```bash
# 运行完整的使用示例
./scripts/password-encoder-examples.sh
```

### 手动调用示例
```bash
# 编码密码
curl -X POST http://localhost:9000/dev-tools/password-encoder/encode \
  -H "Content-Type: application/json" \
  -d '{"password": "newpassword123"}'

# 编码客户端密钥
curl -X POST http://localhost:9000/dev-tools/password-encoder/encode-client-secret \
  -H "Content-Type: application/json" \
  -d '{"clientId": "prod-client", "clientSecret": "super-secret-key"}'
```

## 📝 实际使用场景

### 1. 创建新用户
```bash
# 1. 获取编码密码
curl -X POST http://localhost:9000/dev-tools/password-encoder/encode \
  -H "Content-Type: application/json" \
  -d '{"password": "newuser123"}' | jq -r '.encodedPassword'

# 2. 在data.sql中使用
INSERT INTO users (username, password, enabled) VALUES 
  ('newuser', '{bcrypt}$2a$10$...', true);
```

### 2. 配置OAuth2客户端
```bash
# 1. 获取编码客户端密钥
curl -X POST http://localhost:9000/dev-tools/password-encoder/encode-client-secret \
  -H "Content-Type: application/json" \
  -d '{"clientId": "prod-client", "clientSecret": "prod-secret"}' | jq -r '.encodedSecret'

# 2. 在OAuth2客户端配置中使用
INSERT INTO oauth2_registered_client (client_secret, ...) VALUES 
  ('{bcrypt}$2a$10$...', ...);
```

### 3. 生产环境密码生成
```bash
# 为生产环境管理员生成强密码
curl -X POST http://localhost:9000/dev-tools/password-encoder/encode \
  -H "Content-Type: application/json" \
  -d '{"password": "Prod@Admin#2024!Strong"}' | jq -r '.encodedPassword'
```

## ⚠️ 注意事项

1. **仅开发环境**：此API仅在 `dev` profile 下可用
2. **生产环境禁用**：生产环境自动禁用，无法访问
3. **密码安全**：生成的编码密码应安全存储
4. **日志安全**：API不会在日志中记录明文密码
5. **网络安全**：建议仅在本地网络使用

## 🔧 配置选项

在 `application-dev.yml` 中可以控制此功能：

```yaml
auth-server:
  dev-tools:
    enabled: true  # 设为false可禁用开发工具
```

## 🆚 对比原有方式

### 原有方式（运行测试）
```bash
./mvnw test -Dtest=PasswordEncoderTest#testPasswordEncoding
# 需要查看控制台输出获取编码密码
```

### 新方式（API调用）
```bash
curl -X POST http://localhost:9000/dev-tools/password-encoder/encode \
  -H "Content-Type: application/json" \
  -d '{"password": "admin"}' | jq -r '.encodedPassword'
# 直接获取编码密码，可用于脚本自动化
```

新方式更加便利，支持自动化脚本，且提供了更多功能如批量编码、客户端密钥编码等。