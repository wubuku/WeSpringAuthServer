# 微信登录测试套件

全面的端到端微信OAuth2登录功能测试，具备自动授权码过期处理功能。

## 概述

此测试套件验证以下功能：
- ✅ 微信配置验证
- ✅ JWK端点可访问性和结构
- ✅ 使用新鲜授权码的微信登录流程
- ✅ JWT令牌对JWK集合的验证
- ✅ 刷新令牌功能
- ✅ 使用微信颁发令牌的API访问
- ✅ 过期授权码的自动处理

## 功能特性

### 🔑 核心测试功能

1. **JWK端点测试**
   - 测试 `/oauth2/jwks` 端点可访问性
   - 验证JWK JSON结构
   - 显示密钥信息和元数据

2. **微信登录流程**
   - 使用授权码测试 `/wechat/login` 端点
   - 验证令牌响应格式
   - 提取访问令牌和刷新令牌

3. **JWT令牌验证**
   - 解码JWT头部和负载
   - 将令牌密钥ID与JWK集合匹配
   - 验证令牌过期时间
   - 支持macOS和Linux的base64解码

4. **刷新令牌测试**
   - 使用自定义 `/wechat/refresh-token` 端点测试令牌刷新
   - 验证新令牌生成
   - 更新令牌变量以继续测试

5. **API访问测试**
   - 使用微信生成的令牌测试受保护的API访问
   - 验证令牌授权能力

6. **综合报告**
   - 彩色编码的测试结果
   - 详细的错误消息和调试信息
   - 通过/失败计数的测试摘要

### 🛠 配置说明

**基础配置：**
```bash
BASE_URL="http://localhost:9000"
```

**OAuth2客户端配置：**
- 客户端ID: `ffv-client`
- 客户端密钥: `secret`（bcrypt编码）
- 作用域: `openid profile`

## 使用方法

### 启动服务

在运行测试之前，需要启动服务：

```bash
# 假设环境变量保存在 .env 文件中
export $(cat .env | grep -v '^#' | xargs) && echo "Environment loaded: WECHAT_APP_ID=$WECHAT_APP_ID" && ./mvnw spring-boot:run -Dspring-boot.run.jvmArguments="-Xmx512m -Xms256m" -Dspring-boot.run.profiles=dev
```

### 命令行选项

```bash
# 交互模式（推荐）
./test-wechat-login.sh

# 明确指定交互模式
./test-wechat-login.sh -i

# 提供授权码作为参数
./test-wechat-login.sh --code "0c1eiYFa1i5jLJ0HWxIa1ixTGq1eiYFj"

# 显示帮助
./test-wechat-login.sh --help
```

### 参数说明

- `-c, --code CODE` - 微信授权码
- `-i, --interactive` - 强制交互模式
- `-h, --help` - 显示帮助信息

### 授权码管理

**重要提示**：微信授权码在生成后几分钟内就会过期。此脚本提供以下功能来处理这个问题：

1. **交互式代码输入**：如果未提供代码，脚本会提示输入
2. **代码过期检测**：自动检测过期的代码（错误40029）
3. **重试机制**：当检测到过期时提供获取新代码的选项
4. **验证**：对微信授权码进行基本格式验证

## 获取新鲜授权码

微信授权码必须从您的微信小程序开发环境获取：

1. **微信开发者工具**：
   - 打开您的小程序项目
   - 使用开发环境模拟器
   - 触发OAuth登录流程
   - 从回调URL或调试日志中复制授权码

2. **微信小程序测试**：
   - 部署到开发环境
   - 使用微信应用测试登录流程
   - 从后端日志中捕获授权码

3. **模拟微信服务**（如果可用）：
   - 使用生成有效测试代码的模拟微信服务
   - 确保模拟服务正确配置了您的App ID

## 测试流程

脚本按以下顺序执行测试：

### 1. 配置验证
- 验证服务器是否运行
- 检查微信配置
- 验证App ID未使用默认占位符值

### 2. JWK端点测试
- 测试 `/oauth2/jwks` 端点可访问性
- 验证JSON结构和密钥存在
- 显示可用密钥及其属性

### 3. 微信登录流程
- 使用提供/输入的授权码
- 处理代码过期并提供重试机制
- 提取访问令牌和刷新令牌
- 将令牌保存到 `wechat_tokens.env`

### 4. JWT令牌验证
- 解码JWT头部和负载
- 对JWK集合验证令牌
- 检查密钥ID (kid) 匹配
- 验证令牌过期时间

### 5. 刷新令牌测试
- 使用刷新令牌获取新的访问令牌
- 验证新令牌结构
- 更新保存的令牌

### 6. 刷新后令牌验证
- 对JWK验证新的访问令牌
- 确保令牌轮换正确工作

### 7. API访问测试
- 使用微信令牌测试受保护端点访问
- 验证端到端授权流程

## 交互式功能

### 代码过期处理

当微信授权码过期（错误40029）时，脚本会：

1. **检测过期**：识别特定的微信错误代码
2. **通知用户**：解释代码在几分钟内过期
3. **提供重试**：提示输入新鲜的授权码
4. **验证格式**：确保新代码符合基本格式要求
5. **自动重试**：使用新鲜代码自动尝试登录

### 用户友好提示

```
⚠️  授权码已过期！
微信授权码在生成后只有几分钟的有效期。

您想输入一个新鲜的授权码吗？(y/n):
```

### 代码格式验证

脚本验证授权码：
- 最少20个字符
- 仅限字母数字字符
- 为无效输入提供格式示例

## 输出功能

### 彩色编码结果
- 🟢 **绿色**：成功的操作
- 🔴 **红色**：错误和失败
- 🟡 **黄色**：警告和过期通知
- 🔵 **蓝色**：信息和数据显示

### 详细信息
- JWT头部和负载解码
- JWK集合结构显示
- 令牌过期时间
- HTTP状态码和错误消息

### 进度跟踪
- 每个测试阶段的清晰章节标题
- 重试尝试计数
- 整体测试成功/失败摘要

## 技术实现细节

### 令牌端点
- **微信登录**: `/wechat/login` - 使用授权码获取令牌
- **刷新令牌**: `/wechat/refresh-token` - 使用刷新令牌获取新的访问令牌
- **JWK端点**: `/oauth2/jwks` - 获取公钥用于令牌验证

### 客户端认证
刷新令牌端点支持以下认证方式：
- HTTP Basic认证（Authorization头部）
- 表单参数（client_id和client_secret）

### 令牌存储
测试完成后，令牌会保存到 `wechat_tokens.env` 文件中以供手动测试使用。

## 故障排除

### 常见问题

1. **服务器未运行**：确保使用正确的环境变量启动Spring Boot应用
2. **授权码过期**：从微信开发者工具获取新的授权码
3. **客户端认证失败**：确保使用正确的客户端凭据
4. **JWK端点不可访问**：检查OAuth2配置和端点映射

### 日志记录
测试脚本提供详细的日志记录，包括：
- HTTP状态码
- 响应内容
- 错误消息
- 令牌解码信息

## 测试覆盖范围

此测试套件验证：
- ✅ 微信OAuth2登录完整流程
- ✅ JWT令牌生成和验证
- ✅ 刷新令牌机制
- ✅ 客户端认证
- ✅ 令牌过期处理
- ✅ API授权访问

## 注意事项

- 微信授权码只能使用一次
- 授权码有短暂的生命周期（通常几分钟）
- 生产环境应使用真实的微信API端点
- 确保正确配置微信App ID和Secret 

## 问题修复历史

### Refresh Token 修复 (2025-06-14)

#### 问题描述
在之前的版本中，refresh token功能存在以下问题：
- HTTP 500 "Internal server error" 
- NullPointerException: `Cannot invoke "OAuth2Authorization$Token.getToken()" because the return value of "OAuth2Authorization.getAccessToken()" is null`
- 数据库中OAuth2Authorization记录缺少access_token字段

#### 根本原因
1. **Token类型转换问题**：`OAuth2Token`未正确转换为`OAuth2AccessToken`类型
2. **Builder方法使用错误**：使用了通用的`token()`方法而非专用的`accessToken()`和`refreshToken()`方法
3. **ObjectMapper配置冲突**：CustomJacksonModule与OAuth2序列化模块存在冲突

#### 修复方案

**1. SocialLoginController.java**
- 添加了完整的refresh token端点实现
- 修复了token类型转换逻辑
- 使用正确的Builder方法保存tokens
- 添加了优雅的错误处理机制

**2. WebMvcConfig.java**
- 移除了@Primary注解避免ObjectMapper冲突
- 移除了CustomJacksonModule，只保留OAuth2相关模块
- 确保正确的JSON序列化/反序列化

**3. AuthorizationServerConfig.java**
- 配置了正确的ObjectMapper实例
- 设置了OAuth2AuthorizationRowMapper和ParametersMapper

#### 修复结果
✅ **WeChat登录成功** (HTTP 200)
✅ **Refresh token成功** (HTTP 200) 
✅ **JWT token验证通过**
✅ **数据库正确保存access_token和refresh_token**
✅ **完整的OAuth2流程正常工作**

#### 测试覆盖
- 7/7 测试全部通过
- JWK端点验证
- WeChat登录流程
- JWT token解码和验证  
- Refresh token功能
- 新token的JWK验证
- API访问测试

### 技术细节

**核心修复代码：**
```java
// 正确的token类型转换
OAuth2AccessToken accessToken;
if (generatedAccessToken instanceof OAuth2AccessToken) {
    accessToken = (OAuth2AccessToken) generatedAccessToken;
} else {
    accessToken = new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        generatedAccessToken.getTokenValue(),
        generatedAccessToken.getIssuedAt(),
        generatedAccessToken.getExpiresAt(),
        Set.of("openid", "profile")
    );
}

// 使用正确的Builder方法
authorizationBuilder.accessToken(accessToken);
authorizationBuilder.refreshToken(refreshToken);
```

**ObjectMapper配置优化：**
```java
@Bean
public ObjectMapper oauth2ObjectMapper() {
    ObjectMapper objectMapper = new ObjectMapper();
    // 只注册Spring Security和OAuth2相关的模块
    objectMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
    objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    // 不包含CustomJacksonModule，避免JsonTypeInfo干扰
    return objectMapper;
}
```

**验证方法：**
- 使用真实WeChat授权码进行端到端测试
- 验证数据库记录完整性
- 确认JWT token结构和签名
- 测试token轮换机制 