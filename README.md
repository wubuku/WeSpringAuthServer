# FFV Traceability Auth Server

基于Spring Authorization Server的独立认证授权服务

## 项目说明

本项目已从原父项目中独立出来，现在是一个完全独立的Spring Boot应用程序。

### 主要特性

- 🔐 **多种认证方式**: 用户名/密码、短信验证码、微信登录
- 🌐 **跨域支持**: 支持前后端分离架构
- 🔄 **双模式认证**: 支持传统Session和JWT Token两种认证模式
- 📱 **移动端适配**: 支持微信小程序登录
- 🛡️ **安全加固**: CORS配置、CSRF防护、JWT安全管理

### 技术栈

- **Java**: 17
- **Spring Boot**: 3.2.0
- **Spring Security**: 6.2.0
- **Spring Authorization Server**: 最新版本
- **Database**: PostgreSQL

## 快速开始

### 环境要求

- JDK 17+
- Maven 3.6+
- PostgreSQL 12+

## 生产环境部署

### 🚀 一键生成生产配置

本项目提供了智能的生产环境配置生成工具，可以引导您完成所有必要的配置：

```bash
# 运行配置生成工具
./scripts/generate-production-config.sh
```

该工具将：
- ✅ 引导您输入所有必需的配置项
- ✅ 自动生成强密码和加密密钥
- ✅ 创建JWT签名密钥库
- ✅ 生成完整的 `.env.prod` 环境变量文件
- ✅ 提供Docker部署命令示例

### 📋 生产部署步骤

1. **生成配置文件**
   ```bash
   ./scripts/generate-production-config.sh
   ```

2. **构建应用**
   ```bash
   ./mvnw clean package -DskipTests
   ```

3. **准备部署文件**
   ```bash
   # 将以下文件上传到生产服务器：
   # - .env.prod (环境变量配置)
   # - production-keys/ (JWT密钥目录)
   # - target/ffvtraceability-auth-server-*.jar (应用JAR包)
   ```

4. **Docker部署**
   ```bash
   # 使用生成的配置文件部署
   docker run -d \
     --name auth-server \
     --env-file .env.prod \
     -v $(pwd)/production-keys:/app/keys:ro \
     -p 9000:9000 \
     your-registry/auth-server:latest
   ```

### 🔧 配置说明

#### 必需配置项
- **数据库配置**: PostgreSQL连接信息
- **OAuth2配置**: 授权服务器URL、Cookie域名
- **JWT密钥**: 自动生成的签名密钥
- **邮件服务**: 用于密码重置功能
- **CORS配置**: 前端应用的访问权限

#### 可选配置项
- **微信登录**: 微信小程序集成
- **短信服务**: 阿里云或火山引擎短信
- **日志配置**: 自定义日志级别和路径

#### 安全注意事项
- 🔒 所有敏感信息通过环境变量配置
- 🔒 JWT密钥使用独立的密钥库文件
- 🔒 生产环境强制HTTPS Cookie
- 🔒 严格的CORS域名限制
- 🔒 不暴露任何错误详情

### 🐳 Docker Compose 部署

创建 `docker-compose.yml`:

```yaml
version: '3.8'
services:
  auth-server:
    image: your-registry/auth-server:latest
    container_name: auth-server
    env_file:
      - .env.prod
    volumes:
      - ./production-keys:/app/keys:ro
      - ./logs:/var/log/auth-server
    ports:
      - "9000:9000"
    restart: unless-stopped
    depends_on:
      - postgres
    
  postgres:
    image: postgres:15
    container_name: auth-postgres
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USERNAME}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

### 🔍 部署验证

部署完成后，验证服务状态：

```bash
# 检查服务健康状态
curl http://localhost:9000/actuator/health

# 检查OAuth2配置
curl http://localhost:9000/.well-known/oauth-authorization-server

# 检查OIDC配置
curl http://localhost:9000/.well-known/openid_configuration
```

### ⚠️ 重要提醒

1. **检查占位符**: 部署前确保所有 `xxx` 占位符都已替换为实际值
2. **数据库初始化**: 首次部署时确保数据库已创建
3. **HTTPS配置**: 生产环境建议使用负载均衡器处理HTTPS
4. **备份密钥**: 妥善保管 `production-keys/` 目录中的密钥文件
5. **监控日志**: 关注应用启动日志，确保所有配置正确加载

### 启动服务器

```bash
# 方式1: 使用启动脚本（推荐）
./start.sh

# 方式2: 使用Maven Wrapper
./mvnw clean spring-boot:run

# 方式3: 使用本地Maven
mvn clean spring-boot:run

# 方式4: 构建后运行
./mvnw clean package
java -jar target/ffvtraceability-auth-server-1.0.0-SNAPSHOT.jar
```

服务器将在 9000 端口启动。

### 认证模式配置

项目支持两种认证模式：

#### Session模式（默认）
```bash
# 使用启动脚本
./start.sh

# 或直接使用Maven
./mvnw spring-boot:run
# 或显式指定
AUTH_MODE=session ./start.sh
```

#### JWT模式（跨域认证）
```bash
# 使用启动脚本
AUTH_MODE=jwt ./start.sh

# 或直接使用Maven
AUTH_MODE=jwt ./mvnw spring-boot:run
```


## 在 Auth Server 测试页面上测试 OAuth 2.0 授权码流程

### 浏览器访问测试页面

访问 http://localhost:9000/oauth2-test 开始测试流程。

### 详细流程说明

1. **初始化 PKCE 参数**
```javascript
// 生成随机的 code_verifier (43字节)
const array = new Uint8Array(32);
window.crypto.getRandomValues(array);
const codeVerifier = base64URLEncode(array);

// 生成 code_challenge (SHA-256 哈希后的 base64url 编码)
const encoder = new TextEncoder();
const data = encoder.encode(codeVerifier);
const hash = await window.crypto.subtle.digest('SHA-256', data);
const codeChallenge = base64URLEncode(new Uint8Array(hash));
```

2. **发起授权请求**
```javascript
const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'ffv-client',
    redirect_uri: 'http://localhost:9000/oauth2-test-callback',
    scope: 'openid read write',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
});

window.location.href = '/oauth2/authorize?' + params.toString();
```

3. **用户登录认证**
- 系统跳转到登录页面
- 用户输入用户名和密码 (admin/admin)
- Spring Security 验证凭据
- 登录成功后继续授权流程

4. **授权确认**
- 如果需要用户同意，显示授权确认页面
- 用户确认授权范围 (scopes)
- 系统生成授权码

5. **获取授权码**
- 系统重定向到回调地址，附带授权码
- 回调页面获取授权码并保存
```javascript
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
```

6. **交换访问令牌**
```javascript
const tokenResponse = await fetch('/oauth2/token', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa('ffv-client:secret')
    },
    body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'http://localhost:9000/oauth2-test-callback',
        code_verifier: codeVerifier,
        scope: 'openid read write'
    })
});
```

7. **解析令牌信息**
```javascript
const tokenData = await tokenResponse.json();
// 访问令牌
console.log('Access Token:', tokenData.access_token);
// 刷新令牌
console.log('Refresh Token:', tokenData.refresh_token);
// ID 令牌 (OpenID Connect)
console.log('ID Token:', tokenData.id_token);

// 解码 JWT 令牌
function decodeJWT(token) {
    const parts = token.split('.');
    const payload = base64URLDecode(parts[1]);
    return JSON.parse(payload);
}
```

### 令牌内容示例

**Access Token Claims:**
```json
{
  "sub": "admin",
  "aud": "ffv-client",
  "nbf": 1731915436,
  "scope": [
    "read",
    "openid",
    "write"
  ],
  "iss": "http://localhost:9000",
  "exp": 1731919036,
  "iat": 1731915436,
  "jti": "c5f3eac0-61e6-4a94-9bf8-dd5bc684d177",
  "authorities": [
    "ROLE_USER",
    "ROLE_ADMIN",
    "DIRECT_ADMIN_AUTH"
  ]
}
```

**ID Token Claims:**
```json
{
  "sub": "admin",
  "aud": "ffv-client",
  "azp": "ffv-client",
  "auth_time": 1731915436,
  "iss": "http://localhost:9000",
  "exp": 1731917236,
  "iat": 1731915436,
  "jti": "ba9509c9-3b7b-4635-abac-beb2c178c912",
  "sid": "D4a00T_VVb_xRj4fQQygxI77NWP-LEzMN8F9KuqYifE"
}
```

### 安全考虑

1. **PKCE (Proof Key for Code Exchange)**
   - 防止授权码拦截攻击
   - 客户端生成随机 code_verifier
   - 使用 SHA-256 哈希生成 code_challenge
   - 令牌请求时验证 code_verifier

2. **状态管理**
   - 使用 sessionStorage 存储 code_verifier
   - 令牌信息安全存储
   - 适当的页面跳转和状态维护

3. **令牌安全**
   - 访问令牌有限时效
   - 刷新令牌用于获取新的访问令牌
   - ID 令牌用于身份验证

### 调试信息

测试页面 (/oauth2-test) 显示：
- 授权码
- 访问令牌
- 刷新令牌
- ID 令牌
- 解码后的令牌载荷 (Claims)
- 完整的请求/响应信息


## 使用 Shell 脚本测试授权码流程

见：[scripts/test.sh](scripts/test.sh)（脚本索引见 [scripts/README.md](scripts/README.md)）

## "测试资源服务器"的端到端测试（授权码流程测试）

我们创建了一个供测试用的资源服务器项目，包含了授权码流程的测试。
相关描述见：[example-resource-server/README.md](example-resource-server/README.md)


## 测试 Web 前端 OAuth2 授权码流程


独立后的认证服务器自带测试页面 `/oauth2-test`，可直接验证授权码 + PKCE 流程。
见本页「在 Auth Server 测试页面上测试 OAuth 2.0 授权码流程」一节，以及 [API 测试索引](docs/api-testing/README.md)。



## 对 Spring Security OAuth2 Authorization Server 的扩展

下面讨论的是我们对 Spring Security OAuth2 Authorization Server 所做的扩展。

### 支持有层级的权限

Spring Security 默认使用的 Schema 对于权限的"粒度"基本没有什么原生的支持。

```sql
CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY(username) REFERENCES users(username)
);
```

可见，默认只是支持扁平化的权限。

我们在不修改 Spring Security 默认的 Schema 的情况下支持有层级的权限（呈现为树形结构）。

我们新增了一个表 ~~`permissions`~~ `authority_definitions`，用于存储所有的基础权限。这些基础权限是系统中可在"权限管理界面"进行设置的权限的集合。

表 ~~`permissions`~~ `authority_definitions` 包含两列：
* ~~`permission_id`~~ `authority_id` - 权限的唯一标识符
* `description` - 权限的描述信息（可以为 null）

基础权限的示例：

```sql
INSERT INTO ~~permissions~~ authority_definitions (~~permission_id~~ authority_id, description) VALUES 
    ('ITEM_CREATE', '创建物料的权限'),
    ('ITEM_READ', '读取物料的权限'),
    ('ITEM_UPDATE', '更新物料的权限'),
    ('ITEM_DELETE', '删除物料的权限'),
    ('ORDER_PO_CREATE', '创建采购订单的权限'),
    -- 更多权限...
```

在上面的示例中，权限的分隔符是 `_`，表示层级关系。这些基础权限在数据库初始化时插入，一般不需要进行手动管理。


### ✅ 用户权限管理 UI 的实现（已完成）

✅ **权限管理界面已经实现并完全重构完成！**

我们将上面所举例的扁平化的权限在界面上呈现为类似这样的树形结构
（读取 ~~`permissions`~~ `authority_definitions` 表中的记录，整理为树形结构）：

```
./
├── ITEM
│   ├── CREATE
│   ├── READ
│   ├── UPDATE
│   └── DELETE
├── ORDER
│   ├── PO
│   │   ├── CREATE
│   │   ├── READ
│   │   ├── UPDATE
│   │   └── DEACTIVATE
│   └── SO
│       ├── CREATE
│       ├── READ
│       ├── UPDATE
│       └── DEACTIVATE
```

✅ **以上所有功能都已完全实现：**
- ✅ 用户权限管理界面 (`/authority-management`)
- ✅ 权限树形结构显示和交互
- ✅ 叶子节点权限的单个设置和批量操作
- ✅ 父节点的自动选中/取消功能
- ✅ 批量权限更新API (`/api/authorities/user/batch`)
- ✅ 完整的错误处理和并发冲突容忍机制
- ✅ 所有操作都基于重构后的 `authority_definitions` 表和 Spring Security 的 `authorities` 表


## 授权码流程测试脚本解析

脚本见 [scripts/test.sh](scripts/test.sh)。

> 说明：以下为流程示意。当前脚本已启用 `set -euo pipefail`，cookies 与响应头放在 `mktemp` 临时目录并在退出时清理，不再在当前目录留下 `cookies.txt`；令牌文件原子写入并 `chmod 600`。详见 [scripts/README.md](scripts/README.md)。

### 1. PKCE 参数生成
```bash
# 生成 code_verifier (随机字符串)
code_verifier=$(openssl rand -base64 32 | tr -d /=+ | cut -c -43)
echo "🔑 Code Verifier: $code_verifier"

# 生成 code_challenge (base64url-encode(sha256(code_verifier)))
code_challenge=$(printf "%s" "$code_verifier" | openssl sha256 -binary | base64url_encode)
echo "🔒 Code Challenge: $code_challenge"
```

### 2. 用户登录流程
```bash
# 获取登录页面和 CSRF token
csrf_token=$(curl -c cookies.txt -b cookies.txt -s http://localhost:9000/login | 
    sed -n 's/.*name="_csrf" type="hidden" value="\([^"]*\).*/\1/p')

# 执行登录请求
curl -X POST http://localhost:9000/login \
    -c cookies.txt -b cookies.txt \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin" \
    -d "password=admin" \
    -d "_csrf=$encoded_csrf_token"
```

### 3. 授权请求
```bash
auth_page=$(curl -s \
    -c cookies.txt -b cookies.txt \
    "http://localhost:9000/oauth2/authorize?\
client_id=ffv-client&\
response_type=code&\
scope=openid%20read%20write&\
redirect_uri=${encoded_redirect_uri}&\
code_challenge=${code_challenge}&\
code_challenge_method=S256")
```

### 4. 用户授权确认
```bash
if echo "$auth_page" | grep -q "Consent required"; then
    curl -s \
        -c cookies.txt -b cookies.txt \
        "http://localhost:9000/oauth2/authorize" \
        -d "client_id=ffv-client" \
        -d "state=$state" \
        -d "scope=read" \
        -d "scope=write" \
        -d "scope=openid"
fi
```

### 5. 交换访问令牌
```bash
curl -X POST "http://localhost:9000/oauth2/token" \
    -H "Authorization: Basic $(echo -n 'ffv-client:secret' | base64)" \
    -d "grant_type=authorization_code" \
    -d "code=$encoded_auth_code" \
    -d "redirect_uri=$encoded_redirect_uri" \
    -d "code_verifier=$encoded_code_verifier"
```


## 更多参考信息

见 [OAuth2 客户端集成指南](docs/oauth2-client-integration-guide.md)、[Session vs JWT 深度分析](docs/drafts/oauth2-session-vs-jwt-comprehensive-analysis.md) 与 [资源服务器集成指南](docs/resource-server-integration-guide.md)。



## ~~TODO~~ ✅ 更多改进

### ~~命名问题讨论：permissions 表与 authority 概念~~ ✅ 重构完成

#### ~~当前的命名挑战~~ → 已解决的设计演进

~~在实现权限管理功能时，我们遇到了一个命名上的挑战。~~ Spring Security 框架中并没有定义一个明确的"authority"实体，而是直接使用字符串来表示用户的权限。这种设计在我们需要为用户进行权限配置管理时带来了一些困扰：

1. 系统中有哪些可用的权限？
2. 这些权限的基本信息（如描述、分类等）应该存储在哪里？

显然，我们需要一个实体（表）来存储这些"可用权限"的定义。~~但在Spring Security中，"authority"出现的地方通常都是作为字符串类型，这就产生了概念上的不一致。~~

~~目前我们使用 `permissions` 表来存储权限定义，但这个命名可能不够精确地反映其与Spring Security权限模型的关系。~~ 
**✅ 现在我们使用 `authority_definitions` 表来存储权限定义，完美地反映了与Spring Security权限模型的关系。**

#### ~~命名选项分析~~ → 最终采用方案

经过讨论，我们考虑了以下几个命名选项：

1. ~~**`permissions`** (当前选择) - 简洁但可能和Spring Security的已有概念放在一起显得有些混乱~~
2. **`authority_definitions`** ✅ **已采用** - 明确表示这是对authority的定义表
3. ~~**`permission_catalog`** - 强调这是一个权限目录~~
4. ~~**`available_authorities`** - 表示系统中可用的权限列表~~
5. ~~**`authority_registry`** - 表示权限的注册表~~

#### ~~结论与重构计划~~ → ✅ 重构完成总结

~~经过分析，我们认为~~ **`authority_definitions`** ~~是最准确的命名~~，已被成功采用，因为：

1. ✅ 直接使用"authority"术语，与Spring Security概念保持一致
2. ✅ "definitions"后缀明确表示这是定义表，不是实际的授权表
3. ✅ 清晰地区分于Spring Security的`authorities`表（存储用户-权限关系）
4. ✅ 准确反映表的用途 - 存储系统中可用权限的基本定义

~~在下一个版本的重构中，我们也许应该将`permissions`表重命名为`authority_definitions`，以更好地反映其在系统中的角色。这个重命名会涉及到相关的实体类、数据库表和参考代码的修改，但将使系统的概念模型更加清晰。~~

**✅ 重构已全面完成！** 我们已经：
- ✅ 将 ~~`permissions`~~ 表重命名为 `authority_definitions`
- ✅ 更新了所有相关的实体类、数据库表和参考代码  
- ✅ 统一了整个系统的概念模型，使其更加清晰
- ✅ 实现了与Spring Security框架的完整概念统一
- ✅ 清理了所有注释掉的旧代码和遗留问题

~~在重构完成前，我们将继续使用`permissions`表，但请注意在注释和文档中会明确说明其用途和与Spring Security权限模型的关系。~~


### 增加更多认证方式

#### 微信登录支持

见[相关讨论](docs/wechat-miniprogram-auth-integration.md)

#### 短信登录支持

见[相关讨论](docs/drafts/阿里云短信服务_Spring_Boot_集成指南.md)

### 数据模型改进

为了支持更多类型的"用户 ID"，以及支持更多的用户登录（认证）方式，考虑增加实体 `UserIdentification`。

用 DDDML 描述，大致如下：

```yaml
aggregates:
  User:
    id:
      name: Username
      type: id
    properties:
      #Password:
      #  type: ...
      UserIdentifications:
        itemType: UserIdentification

    entities:
      UserIdentification:
        id:
          name: UserIdentificationTypeId
          type: id-ne
        globalId:
          name: UserIdentificationId
          type: UserIdentificationId
          columnNames:
            - USERNAME
            - USER_IDENTIFICATION_TYPE_ID
        properties:
          IdValue:
            columnName: ID_VALUE
            type: id-long
```

### ✅ 权限系统重构成果总结

通过这次全面重构，我们取得了以下成果：

1. **概念统一**: 全面使用 `authority_definitions` 表替代 `permissions` 表，与 Spring Security 框架概念完全对齐
2. **代码清理**: 移除了所有注释掉的遗留代码，提高了代码整洁度  
3. **数据库优化**: 实现了幂等的数据库初始化脚本，支持重复执行而不出错
4. **API 统一**: 将所有权限相关的 API 端点从 `/permissions` 更新为 `/authorities`
5. **文档更新**: 使用删除线语法保留了设计演进历史，反映了重构完成状态

这次重构确保了系统的长期可维护性和概念一致性，为未来的扩展奠定了坚实基础。

## 🛠️ 开发指南与最佳实践

### 测试数据准备

见：`docs/drafts/测试数据准备.md`

#### JWT令牌获取
```bash
# 获取所有测试用户的JWT令牌
cd scripts
./get-test-user-tokens.sh

# 加载令牌到环境变量
source all-test-tokens.env

# 使用令牌测试API
curl -H "Authorization: Bearer $HQ_ADMIN_ACCESS_TOKEN" http://localhost:9000/api/users
```

汇总文件默认 `scripts/all-test-tokens.env`，原子写入并 `chmod 600`；可用 `-o/--output` 改路径、`-r/--refresh` 刷新、`-d/--decode` 打印解码结果。任一用户失败即返回非零退出码。详见 [scripts/README.md](scripts/README.md)。

### 脚本开发规范

#### 1. 避免硬编码URL
❌ **错误做法**：
```bash
curl http://localhost:9000/login
curl http://localhost:9000/oauth2/token
```

✅ **正确做法**：
```bash
BASE_URL="http://localhost:9000"
curl ${BASE_URL}/login
curl ${BASE_URL}/oauth2/token
```

#### 2. 脚本命名规范
- 使用描述性名称，避免无意义的后缀（如`final`、`new`等）
- 保持一致的命名风格：`get-test-user-tokens.sh`
- 及时清理不再使用的脚本文件

#### 3. 数据库操作最佳实践
- 使用`ON CONFLICT DO NOTHING`确保脚本可重复运行
- 在运行中的应用上操作数据库时，优先使用SQL脚本而非重启应用
- 验证数据插入结果：
```sql
-- 验证用户创建
SELECT username, enabled FROM users WHERE username IN ('hq_admin', 'distributor_admin');

-- 验证权限分配
SELECT username, authority FROM authorities WHERE username = 'hq_admin';
```

### 密码管理

#### 生成测试密码
使用`PasswordEncoderTest`生成BCrypt编码密码：
```java
@Test
public void generateTestUserPasswords() {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    String encodedPassword = encoder.encode("hq123");
    System.out.println("编码密码: " + encodedPassword);
}
```

#### 密码设计原则
- 测试环境使用容易记忆的密码（如`hq123`、`dist123`）
- 生产环境必须使用强密码
- 所有密码都必须经过BCrypt编码存储

### OAuth2测试流程

#### 完整的授权码流程测试
1. **获取授权码**：访问`/oauth2/authorize`端点
2. **用户登录**：提交用户名密码到`/login`
3. **获取令牌**：使用授权码换取访问令牌
4. **验证令牌**：解码JWT查看权限信息

#### 脚本化测试
- 使用`test.sh`进行单用户测试
- 使用`get-test-user-tokens.sh`批量获取多用户令牌
- 令牌自动保存到`all-test-tokens.env`文件

### 权限系统设计

#### 角色层次结构
```
ROLE_HQ_ADMIN (总部管理员)
├── 所有业务权限
├── 用户管理权限
└── 系统管理权限

ROLE_DISTRIBUTOR_ADMIN (经销商管理员)
├── 经销商业务权限
├── 仓库管理权限
└── 部分用户管理权限

ROLE_STORE_ADMIN (门店管理员)
├── 门店业务权限
├── 位置管理权限
└── 基础查看权限

ROLE_CONSULTANT (咨询师)
└── 基础只读权限

ROLE_DISTRIBUTOR_EMPLOYEE (经销商员工)
└── 基础只读权限
```

#### 权限命名规范
- 使用`模块_操作`格式：`Users_Read`、`Vendors_Create`
- 角色使用`ROLE_`前缀：`ROLE_ADMIN`、`ROLE_HQ_ADMIN`
- 保持权限粒度适中，既不过于细化也不过于粗糙

### 文档维护

#### 实时更新原则
- 代码变更后立即更新相关文档
- 脚本重命名后更新所有引用
- 保持文档与实际代码状态一致


### 常见陷阱与解决方案

#### 1. Shell脚本兼容性
❌ **问题**：使用关联数组导致某些shell不兼容
```bash
declare -A TEST_USERS=(["user1"]="pass1")  # 不兼容
```

✅ **解决**：使用简单数组和字符串分割
```bash
TEST_USERS="user1:pass1 user2:pass2"
for user_pair in $TEST_USERS; do
    username=$(echo "$user_pair" | cut -d':' -f1)
    password=$(echo "$user_pair" | cut -d':' -f2)
done
```

#### 2. OAuth2流程调试
- 使用`curl -v`查看详细HTTP交互
- 检查CSRF令牌是否正确获取和传递
- 验证授权码是否成功提取
- 确认客户端认证信息正确

#### 3. 数据库状态管理
- 在运行中的应用上操作数据库时，避免删除现有数据
- 使用`INSERT ... ON CONFLICT`确保幂等性
- 操作前后都要验证数据状态

### 工具依赖
开发和测试需要以下工具：
- `jq` - JSON处理
- `curl` - HTTP客户端
- `openssl` - 加密工具
- `psql` - PostgreSQL客户端

```bash
# macOS安装
brew install jq curl openssl postgresql

# Ubuntu安装
apt-get install jq curl openssl-tool postgresql-client
```

## 📚 文档导航

本项目采用 Hub → Guides → Reference 三层文档体系。已有文档保持原位，通过索引导航：

| 入口 | 说明 |
|------|------|
| [AGENTS.md](AGENTS.md) | AI Agent 导航入口与约束 |
| [CLAUDE.md](CLAUDE.md) | 日常开发速查手册 |
| [.agent.md](.agent.md) / [.cursorrules](.cursorrules) | 项目须知与安全开发规则 |
| [docs/README.md](docs/README.md) | 全项目文档导航中心（按主题索引） |
| [.agents/skills/project-docs/](.agents/skills/project-docs/) | 文档体系建设与维护规范 |

> 版本说明：本文及 `.agent.md` 中的 Spring Boot 3.2.0 / Spring Authorization Server 1.5.0 为历史记录；实际版本以 [pom.xml](pom.xml) 为准（3.4.6 / 1.3.6）。