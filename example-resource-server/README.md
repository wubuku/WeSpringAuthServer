# WeSpring 示例资源服务器

这是一个示例资源服务器项目，展示了如何配置OAuth2资源服务器与WeSpringAuthServer配合使用。

## 📋 目录

- [概述](#概述)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [API端点](#api端点)
- [权限控制](#权限控制)
- [缓存机制](#缓存机制)
- [测试](#测试)
- [故障排除](#故障排除)

## 概述

这个示例资源服务器演示了以下核心概念：

1. **OAuth2资源服务器配置** - 如何配置Spring Security来验证JWT令牌
2. **权限系统集成** - 如何从JWT中提取权限信息并进行权限控制
3. **组权限缓存** - 如何实现高效的权限查询缓存机制
4. **多数据源配置** - 如何配置业务数据源和权限数据源
5. **端到端测试** - 如何测试完整的OAuth2授权流程

## 功能特性

### 🔐 安全特性
- JWT令牌验证
- 方法级权限控制（@PreAuthorize）
- URL级权限控制
- CORS配置
- 自定义JWT认证转换器

### 📊 权限系统
- 直接权限支持
- 组权限支持
- 权限缓存机制
- 与WeSpringAuthServer权限系统集成

### 🧪 测试支持
- 完整的E2E测试
- 缓存测试客户端
- 权限验证测试

## 快速开始

### 前置条件

1. Java 17+
2. Maven 3.6+
3. PostgreSQL数据库
4. WeSpringAuthServer已启动并运行在localhost:9000

### 1. 配置数据库

更新`src/main/resources/application.yml`中的数据库配置：

```yaml
spring:
  # 业务数据源（可选）
  datasource:
    url: jdbc:postgresql://localhost:5432/your_business_db
    username: your_username
    password: your_password
    
  # 权限数据源（连接到WeSpringAuthServer的数据库）
  security:
    datasource:
      url: jdbc:postgresql://localhost:5432/wespring_auth_db
      username: your_username
      password: your_password
```

### 2. 配置OAuth2

确保WeSpringAuthServer的JWK Set URI配置正确：

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:9000/oauth2/jwks
```

### 3. 启动应用

```bash
# 编译项目
mvn clean compile

# 启动应用
mvn spring-boot:run
```

应用将在 http://localhost:8081 启动。

### 4. 验证安装

访问公开API端点验证应用正常运行：

```bash
curl http://localhost:8081/api/public/hello
```

应该返回：
```json
{
  "message": "Hello from public endpoint!",
  "timestamp": 1234567890,
  "authentication": "not required"
}
```

## 配置说明

### OAuth2资源服务器配置

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # 方式1: 直接指定JWK Set URI
          jwk-set-uri: http://localhost:9000/oauth2/jwks
          
          # 方式2: 使用issuer-uri自动发现（二选一）
          # issuer-uri: http://localhost:9000
```

### 缓存配置

```yaml
spring:
  cache:
    caffeine:
      spec: maximumSize=100,expireAfterWrite=3600s
```

### 日志配置

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.cache: DEBUG
    org.dddml.wespring.resource.example: DEBUG
```

## API端点

### 公开端点（无需认证）

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/public/hello` | GET | 公开的问候端点 |

### 受保护端点（需要认证）

| 端点 | 方法 | 权限要求 | 描述 |
|------|------|----------|------|
| `/api/protected/user-info` | GET | 已认证 | 获取当前用户信息 |
| `/api/protected/users` | GET | `Users_Read` | 获取用户列表 |
| `/api/protected/roles` | GET | `Roles_Read` | 获取角色列表 |
| `/api/protected/user-management` | GET | `Users_Read` AND `Users_Write` | 用户管理功能 |

### 管理员端点

| 端点 | 方法 | 权限要求 | 描述 |
|------|------|----------|------|
| `/api/admin/system-info` | GET | `ROLE_ADMIN` | 系统信息（方法级权限） |
| `/api/admin/cache-stats` | GET | `ROLE_ADMIN` | 缓存统计（URL级权限） |

## 权限控制

### 两种权限控制方式

1. **URL级权限控制**（在SecurityConfig中配置）
```java
.requestMatchers("/api/admin/**").hasAnyAuthority("DIRECT_ADMIN_AUTH", "ROLE_ADMIN")
```

2. **方法级权限控制**（使用注解）
```java
@PreAuthorize("hasAuthority('Users_Read')")
public Map<String, Object> getUsers() { ... }
```

### 权限类型

1. **直接权限** - 用户直接拥有的权限（存储在JWT的`authorities`声明中）
2. **组权限** - 通过用户所属组获得的权限（存储在JWT的`groups`声明中）

### 权限验证流程

1. 客户端发送带有JWT令牌的请求
2. `CustomJwtAuthenticationConverter`提取JWT中的权限信息
3. 对于组权限，`GroupAuthorityService`查询数据库获取组对应的权限
4. Spring Security根据权限信息进行访问控制

## 缓存机制

### 缓存策略

- **缓存对象**: 组权限映射
- **缓存时间**: 1小时（可配置）
- **缓存大小**: 最多100个条目
- **缓存键**: 组名

### 缓存观察

运行缓存测试客户端观察缓存行为：

```bash
# 首先获取访问令牌（通过E2E测试或其他方式）
export ACCESS_TOKEN=your_access_token_here

# 运行缓存测试客户端
mvn exec:java -Dexec.mainClass="org.dddml.wespring.resource.example.CacheTestClient"
```

在资源服务器日志中观察：
- 第一次请求: `Cache MISS - Loading authorities from database for group: GROUP_XXX`
- 后续请求: 不会出现cache miss日志（使用缓存）

### 手动缓存管理

```java
@Autowired
private CacheConfig cacheConfig;

// 清除特定组的缓存
cacheConfig.evictGroupAuthorities("ADMIN_GROUP");

// 清除所有缓存
cacheConfig.evictAllGroupAuthorities();
```

## 测试

### E2E测试

运行完整的OAuth2授权流程测试：

```bash
# 确保WeSpringAuthServer和资源服务器都在运行
mvn test -Dtest=E2EAuthFlowTests
```

测试包括：
1. 生成PKCE参数
2. 用户登录
3. 获取授权码
4. 交换访问令牌
5. 测试资源访问

### 单元测试

```bash
mvn test
```

### 手动测试

1. 获取访问令牌：
```bash
# 运行WeSpringAuthServer的测试脚本
cd /path/to/WeSpringAuthServer/scripts
./test.sh
cat tokens.env
```

2. 测试API访问：
```bash
export ACCESS_TOKEN=your_access_token

# 测试公开API
curl http://localhost:8081/api/public/hello

# 测试受保护API
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8081/api/protected/user-info

# 测试权限控制
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8081/api/protected/users
```

## 故障排除

### 常见问题

#### 1. JWT验证失败

**错误**: `Invalid JWT signature` 或 `JWT validation failed`

**解决方案**:
- 检查`jwk-set-uri`配置是否正确
- 确保WeSpringAuthServer正在运行
- 验证访问令牌是否有效且未过期

#### 2. 权限不足

**错误**: `403 Forbidden`

**解决方案**:
- 检查用户是否有相应权限
- 验证JWT中的`authorities`和`groups`声明
- 检查数据库中的权限配置

#### 3. 数据库连接失败

**错误**: `Connection refused` 或 `Database connection failed`

**解决方案**:
- 检查数据库配置
- 确保数据库服务正在运行
- 验证用户名和密码

#### 4. 缓存问题

**问题**: 权限更新后仍然使用旧权限

**解决方案**:
- 等待缓存过期（默认1小时）
- 或手动清除缓存
- 或重启应用

### 调试技巧

1. **启用详细日志**:
```yaml
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.cache: DEBUG
    org.dddml.wespring.resource.example: DEBUG
```

2. **检查JWT内容**:
```bash
# 解码JWT令牌查看内容
echo "your_jwt_token" | cut -d'.' -f2 | base64 -d | jq
```

3. **监控缓存统计**:
访问 http://localhost:8081/actuator/caches 查看缓存状态

## 扩展开发

### 添加新的API端点

1. 在`ExampleController`中添加新方法
2. 使用`@PreAuthorize`注解设置权限要求
3. 更新测试用例

### 自定义权限验证

1. 扩展`CustomJwtAuthenticationConverter`
2. 实现自定义权限逻辑
3. 更新相关配置

### 集成其他数据源

1. 在`DataSourceConfig`中添加新数据源
2. 创建相应的`JdbcTemplate` Bean
3. 在服务类中使用新数据源

## 参考文档

- [Spring Security OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html)
- [WeSpringAuthServer文档](../README.md)
- [Spring Boot Caching](https://docs.spring.io/spring-boot/docs/current/reference/html/io.html#io.caching)

## 许可证

本项目基于MIT许可证开源。 