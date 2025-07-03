# OAuth2 安全修复短期方案 - HttpOnly Cookie 实施计划

## 📋 项目概述

### 问题背景
当前 WeSpringAuthServer 的 OAuth2 实现存在关键安全漏洞：
1. **client_secret 暴露给前端** - 违反 OAuth2 安全规范的绝对规则
2. **refresh_token 前端存储** - 存在 XSS 攻击风险
3. **直接调用 OAuth2 端点** - 缺乏后端安全控制层

### 修复目标
- 消除 client_secret 前端暴露风险
- 实现 refresh_token 的安全存储
- 保持现有功能的完整性
- 为长期后端代理方案奠定基础

## 🎯 **全面端点分析** (新增)

### 📍 **发现的OAuth2安全漏洞端点**

通过分析 `scripts/` 目录下的测试脚本，发现以下端点存在安全问题：

#### 1. **微信相关端点**
```bash
# 脚本：test-wechat-login.sh
# 端点：POST /wechat/refresh-token
# 问题：client_secret暴露
curl -H "Authorization: Basic $(echo -n 'ffv-client:secret' | base64)" \
     -d "refresh_token=$WECHAT_REFRESH_TOKEN"
```

#### 2. **短信相关端点**
```bash
# 脚本：test-sms-login.sh  
# 端点：GET /sms/login (登录时返回refresh_token)
# 问题：refresh_token前端存储
```

#### 3. **标准OAuth2端点**
```bash
# 脚本：test.sh
# 端点：POST /oauth2/token
# 问题：client_secret暴露
curl -H "Authorization: Basic $(echo -n 'ffv-client:secret' | base64)" \
     -d "grant_type=authorization_code"
```

#### 4. **Web客户端代理端点**
```bash
# 控制器：WebTokenController
# 端点：POST /web-clients/oauth2/token
# 问题：潜在的client_secret处理问题
```

### 📊 **端点优先级分类**

| 优先级 | 端点路径 | Controller | 安全风险等级 | 修改复杂度 |
|--------|----------|------------|-------------|------------|
| 🔴 **极高** | `/wechat/refresh-token` | `SocialLoginController` | 极高 | 中等 |
| 🔴 **极高** | `/sms/refresh-token` | `SmsLoginController` | 极高 | 中等 |
| 🟡 **高** | `/oauth2/token` | Spring Security内置 | 高 | 高 |
| 🟡 **高** | `/web-clients/oauth2/token` | `WebTokenController` | 中等 | 低 |
| 🟢 **中** | `/wechat/login` | `SocialLoginController` | 中等 | 低 |
| 🟢 **中** | `/sms/login` | `SmsLoginController` | 中等 | 低 |

## 🎯 解决方案设计

### 方案概述
**短期修复策略**：HttpOnly Cookie + 后端 client_secret 管理
- 将 `client_secret` 完全移至后端配置
- 使用 HttpOnly Cookie 存储 `refresh_token`
- 保持现有 API 端点，仅修改安全实现

### ✅ **实施进度：Phase 1 已完成**

**已完成的组件**：
1. **CookieSecurityConfig.java** - HttpOnly Cookie管理器 ✅
2. **OAuth2ClientSecurityConfig.java** - client_secret后端化管理 ✅
3. **application.yml** - 方案A子域名共享Cookie配置 ✅
4. **test-cookie-security.sh** - 完整的Cookie安全测试套件 ✅

**配置亮点**：
- 支持 `.localhost` 开发环境和 `.yourcompany.com` 生产环境
- 完整的multi-client配置 (ffv-client, wechat-client, sms-client)
- 环境变量支持和安全性最佳实践
- 全面的安全测试脚本

## 🚀 **快速开始 - Phase 1 测试**

### 步骤1: 验证配置
```bash
# 1. 检查新创建的配置文件
ls -la src/main/java/org/dddml/ffvtraceability/auth/config/
# 应该看到：
# - CookieSecurityConfig.java
# - OAuth2ClientSecurityConfig.java

# 2. 检查application.yml中的OAuth2配置
grep -A 20 "oauth2:" src/main/resources/application.yml

# 3. 检测试脚本
ls -la scripts/test-cookie-security.sh
```

### 步骤2: 运行安全测试
```bash
# 1. 确保应用正在运行
# ./gradlew bootRun 或启动IDE中的应用

# 2. 运行Cookie安全测试套件
./scripts/test-cookie-security.sh

# 期望结果：
# ✅ Application is running and healthy
# ✅ OAuth2 JWK endpoint accessible
# ✅ Login page accessible
# ✅ Cookie Security Score: 4/5 or higher
```

### 步骤3: 验证核心安全改进
```bash
# 测试client_secret不再从前端传递
curl -X POST "http://localhost:9000/wechat/refresh-token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: refresh_token=test_token" \
  -d "grant_type=refresh_token"
  
# 预期：不需要Authorization header，说明client_secret已后端化
```

### 故障排查
**如果测试失败**：
1. 检查应用是否正常启动
2. 检查数据库连接
3. 查看日志中的OAuth2配置加载情况
4. 确认端口9000未被占用

**常见问题**：
- Cookie domain配置：开发环境使用 `.localhost`
- HTTPS in production：生产环境需要 `OAUTH2_COOKIE_SECURE=true`
- 子域名测试：需要配置本地DNS或hosts文件

### 技术架构
```
前端 (Web/移动端)
├── 登录请求 (无 client_secret)
├── access_token 使用
└── refresh 请求 (通过 Cookie)

后端 (Spring Boot)
├── client_secret 配置存储
├── HttpOnly Cookie 管理
├── refresh_token 验证
└── 安全响应处理
```

## 🔧 **详细实施方案** (更新)

### Phase 1: 后端安全配置 (2-3天)

#### 1.1 client_secret 后端化
**文件修改**: `src/main/resources/application.yml`
```yaml
# 新增专用配置段
oauth2:
  clients:
    ffv-client:
      client-secret: ${FFV_CLIENT_SECRET:secret}
      client-id: ffv-client
  cookie:
    secure: ${OAUTH2_COOKIE_SECURE:true}
    max-age: ${OAUTH2_COOKIE_MAX_AGE:7776000} # 90天
    same-site: ${OAUTH2_COOKIE_SAME_SITE:Strict}
    http-only: true
    path: "/"
```

**文件修改**: 所有相关Controller
- `SocialLoginController.java` - 微信refresh端点
- `SmsLoginController.java` - 短信refresh端点  
- `WebTokenController.java` - Web客户端代理
- `OAuth2AuthenticationHelper.java` - 统一helper类

#### 1.2 HttpOnly Cookie 机制
**新增配置类**: `CookieSecurityConfig.java`
```java
@Configuration
public class CookieSecurityConfig {
    
    @Value("${oauth2.cookie.secure:true}")
    private boolean secure;
    
    @Value("${oauth2.cookie.max-age:7776000}") // 90天
    private int maxAge;
    
    @Value("${oauth2.cookie.same-site:Strict}")
    private String sameSite;
    
    public ResponseCookie createSecureRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .maxAge(maxAge)
                .path("/")
                .build();
    }
    
    public String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
```

### Phase 2: **六大端点安全实现** (3-4天)

#### 2.1 微信端点重构 (`SocialLoginController`)
```java
// 修改前：暴露client_secret
@PostMapping("/wechat/refresh-token")
public ResponseEntity<Map<String, Object>> refreshToken(
    @RequestParam("client_secret") String clientSecret, // ❌ 暴露
    @RequestParam("refresh_token") String refreshToken,  // ❌ 前端传递
    ...) { ... }

// 修改后：安全实现
@PostMapping("/wechat/refresh-token")
public ResponseEntity<Map<String, Object>> refreshToken(
    HttpServletRequest request,
    HttpServletResponse response) {
    
    // 从Cookie读取refresh_token
    String refreshToken = cookieSecurityConfig.extractRefreshTokenFromCookie(request);
    
    // 从配置读取client_secret (后端注入)
    String clientSecret = clientConfig.getClientSecret();
    
    // 处理刷新逻辑
    OAuth2AuthenticationHelper.TokenPair tokenPair = processRefreshToken(...);
    
    // 设置新的HttpOnly Cookie
    ResponseCookie newRefreshCookie = cookieSecurityConfig
        .createSecureRefreshTokenCookie(tokenPair.getRefreshToken().getTokenValue());
    response.addHeader(HttpHeaders.SET_COOKIE, newRefreshCookie.toString());
    
    // 返回access_token (不包含refresh_token)
    return ResponseEntity.ok(Map.of(
        "access_token", tokenPair.getAccessToken().getTokenValue(),
        "token_type", "Bearer",
        "expires_in", tokenPair.getAccessToken().getExpiresAt()
    ));
}
```

#### 2.2 短信端点重构 (`SmsLoginController`)
- 类似微信端点的处理方式
- 登录成功后设置HttpOnly Cookie
- refresh端点从Cookie读取token

#### 2.3 标准OAuth2端点 (内置Spring Security)
```java
// 通过自定义AuthenticationSuccessHandler处理
@Component
public class CustomTokenResponseHandler implements AuthenticationSuccessHandler {
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                      HttpServletResponse response,
                                      Authentication authentication) {
        if (authentication instanceof OAuth2AccessTokenAuthenticationToken) {
            OAuth2AccessTokenAuthenticationToken tokenAuth = 
                (OAuth2AccessTokenAuthenticationToken) authentication;
            
            // 检查是否为Web客户端请求
            if (isWebClientRequest(request)) {
                // 设置HttpOnly Cookie for refresh_token
                setRefreshTokenCookie(response, tokenAuth.getRefreshToken());
                
                // 修改响应，移除refresh_token字段
                modifyTokenResponse(response, tokenAuth.getAccessToken());
            }
        }
    }
}
```

#### 2.4 Web代理端点 (`WebTokenController`)
- 实现完整的后端代理模式
- 隐藏client_secret
- 统一的Cookie处理

#### 2.5 登录端点增强
- 微信登录和短信登录成功后设置HttpOnly Cookie
- 前端只接收access_token

### Phase 3: **测试脚本全面适配** (2-3天)

#### 3.1 **微信测试脚本修改** (`test-wechat-login.sh`)
```bash
# 修改前：暴露client_secret
curl -H "Authorization: Basic $(echo -n 'ffv-client:secret' | base64)" \
     -d "refresh_token=$WECHAT_REFRESH_TOKEN"

# 修改后：使用Cookie
test_refresh_token() {
    print_section "Testing Refresh Token Functionality (HttpOnly Cookie)"
    
    # 检查Cookie文件中是否有refresh_token
    if ! grep -q "refresh_token" cookies.txt; then
        print_result "error" "No refresh token cookie available"
        return 1
    fi
    
    # 使用Cookie进行刷新请求 (不需要Authorization header)
    local refresh_response=$(curl -s -X POST "${BASE_URL}/wechat/refresh-token" \
        -b cookies.txt -c cookies.txt \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Accept: application/json" \
        -d "grant_type=refresh_token" \
        -w "\n%{http_code}")
    
    # 处理响应...
}

# 新增Cookie验证函数
verify_refresh_token_cookie() {
    print_section "Verifying Refresh Token Cookie Security"
    
    # 检查Cookie属性
    local cookie_line=$(grep "refresh_token" cookies.txt)
    if echo "$cookie_line" | grep -q "HttpOnly"; then
        print_result "success" "Refresh token cookie is HttpOnly ✅"
    else
        print_result "error" "Refresh token cookie is NOT HttpOnly ❌"
    fi
    
    if echo "$cookie_line" | grep -q "Secure"; then
        print_result "success" "Refresh token cookie is Secure ✅"
    else
        print_result "warning" "Refresh token cookie is not Secure (expected in development)"
    fi
}
```

#### 3.2 **短信测试脚本修改** (`test-sms-login.sh`)
```bash
# 新增Cookie处理
sms_login() {
    log_info "使用SMS登录 (HttpOnly Cookie模式)..."
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
        -b cookies.txt -c cookies.txt \
        "$BASE_URL/sms/login?mobileNumber=$PHONE_NUMBER&verificationCode=$VERIFICATION_CODE")
    
    # 验证Cookie设置
    if grep -q "refresh_token" cookies.txt; then
        log_info "✅ Refresh token cookie 已设置"
    else
        log_error "❌ Refresh token cookie 未设置"
    fi
}

# 新增刷新测试
test_sms_refresh_token() {
    log_info "测试SMS刷新令牌 (Cookie模式)..."
    
    curl -s -X POST "$BASE_URL/sms/refresh-token" \
        -b cookies.txt -c cookies.txt \
        -H "Content-Type: application/x-www-form-urlencoded"
}
```

#### 3.3 **主测试脚本修改** (`test.sh`)
```bash
# OAuth2标准流程适配
echo -e "\n🔄 Requesting access token (HttpOnly Cookie mode)..."
token_response=$(curl -v -X POST "${BASE_URL}/oauth2/token" \
    ${session_headers:+-H "X-Auth-Token: $header_session_id"} \
    -b cookies.txt -c cookies.txt \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Accept: application/json" \
    -d "grant_type=authorization_code" \
    -d "code=$encoded_auth_code" \
    -d "redirect_uri=$encoded_redirect_uri" \
    -d "code_verifier=$encoded_code_verifier" \
    -d "scope=openid%20profile" \
    2>&1)

# 注意：移除了 Authorization header with client_secret
# 检查refresh_token Cookie设置
if grep -q "refresh_token" cookies.txt; then
    echo "✅ Refresh token cookie set securely"
else
    echo "❌ Refresh token cookie not set"
fi
```

#### 3.4 **新增Cookie安全验证脚本**
```bash
# 新文件：scripts/test-cookie-security.sh
#!/bin/bash

verify_cookie_security() {
    echo "🔍 Verifying Cookie Security Settings..."
    
    if [ ! -f cookies.txt ]; then
        echo "❌ No cookies.txt file found"
        return 1
    fi
    
    # 检查refresh_token cookie存在
    if grep -q "refresh_token" cookies.txt; then
        echo "✅ Refresh token cookie exists"
    else
        echo "❌ Refresh token cookie not found"
        return 1
    fi
    
    # 检查安全属性
    local cookie_line=$(grep "refresh_token" cookies.txt)
    
    # HttpOnly检查
    if echo "$cookie_line" | grep -q "#HttpOnly"; then
        echo "✅ HttpOnly attribute set"
    else
        echo "❌ HttpOnly attribute missing"
    fi
    
    # Secure检查 (生产环境)
    if echo "$cookie_line" | grep -q "Secure"; then
        echo "✅ Secure attribute set"
    else
        echo "⚠️  Secure attribute not set (expected in development over HTTP)"
    fi
    
    # SameSite检查
    if echo "$cookie_line" | grep -q "SameSite=Strict"; then
        echo "✅ SameSite=Strict set"
    else
        echo "⚠️  SameSite attribute not detected"
    fi
}
```

## 🍪 **HttpOnly Cookie 跨域限制与解决方案** (重要补充)

### 🚨 **同域限制确实存在**

HttpOnly Cookie 受到浏览器的**同源策略**严格限制：

```javascript
// Cookie 的域限制规则
Set-Cookie: refresh_token=xxx; 
    HttpOnly;                    // 防止 JavaScript 访问
    Domain=auth.company.com;     // 只在此域有效
    Path=/;                      // 路径范围
    SameSite=Strict;            // 严格同站策略
    Secure;                     // 仅 HTTPS
```

### 🌐 **典型跨域场景问题**

```
企业级部署架构:
├── 前端应用: https://app.company.com
├── 认证服务器: https://auth.company.com  ⬅️ Cookie 设置在这里
├── API 服务器: https://api.company.com   ⬅️ 无法访问 auth 域的Cookie
└── 管理后台: https://admin.company.com   ⬅️ 无法访问 auth 域的Cookie

❌ 问题: Cookie 无法跨子域传递，每个域需要独立认证
```

### ✅ **方案A: 子域名共享 (推荐实施)**

#### A.1 **顶级域名Cookie设置**
```javascript
// 🔧 修改后端 Cookie 设置
Set-Cookie: refresh_token=xxx; 
    Domain=.company.com;         // ⚠️ 注意前面的点号
    HttpOnly; 
    Secure; 
    SameSite=Lax;               // 允许同站跨子域
    Path=/;
    Max-Age=2592000;            // 30天
```

#### A.2 **具体实施配置**

**Spring Boot 应用配置**：
```yaml
# application.yml
server:
  servlet:
    session:
      cookie:
        domain: .company.com     # 顶级域名共享
        http-only: true
        secure: true
        same-site: lax

oauth2:
  security:
    cookie:
      domain: .company.com       # refresh_token Cookie 域名
      secure: true               # 生产环境必须开启
      same-site: lax            # 允许同站但跨子域
```

#### A.3 **域名配置要求**
```bash
# 🔧 DNS 配置示例
auth.company.com    IN  A   192.168.1.10   # 认证服务器
app.company.com     IN  A   192.168.1.11   # 前端应用
api.company.com     IN  A   192.168.1.12   # API 服务器
admin.company.com   IN  A   192.168.1.13   # 管理后台

# 🎯 所有子域名都能共享 .company.com 下的 Cookie
```

## 📱 **微信小程序替代安全方案** (详细阐述)

### 🚫 **微信小程序 Cookie 限制**

微信小程序**完全不支持**传统浏览器Cookie机制：

```javascript
// ❌ 小程序中无法使用的API
document.cookie          // 不存在
Set-Cookie响应头         // 被忽略
HttpOnly Cookie         // 无效
```

### 🔧 **方案1: 加密本地存储 (短期)**

```javascript
// 微信小程序安全存储实现
const CryptoJS = require('crypto-js');

class SecureStorage {
  static setRefreshToken(token) {
    // 使用设备唯一ID + 时间戳作为密钥
    const deviceKey = wx.getStorageSync('device_uuid') || this.generateDeviceUUID();
    const encryptKey = deviceKey + Date.now().toString().slice(-6);
    
    // AES加密
    const encrypted = CryptoJS.AES.encrypt(token, encryptKey).toString();
    
    wx.setStorageSync('refresh_token_encrypted', encrypted);
    wx.setStorageSync('token_timestamp', Date.now());
  }
  
  static getRefreshToken() {
    try {
      const encrypted = wx.getStorageSync('refresh_token_encrypted');
      const timestamp = wx.getStorageSync('token_timestamp');
      
      // 检查过期（30天）
      if (Date.now() - timestamp > 30 * 24 * 60 * 60 * 1000) {
        this.clearTokens();
        return null;
      }
      
      const deviceKey = wx.getStorageSync('device_uuid');
      const encryptKey = deviceKey + timestamp.toString().slice(-6);
      
      const decrypted = CryptoJS.AES.decrypt(encrypted, encryptKey);
      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error('Token decryption failed:', error);
      return null;
    }
  }
}
```

### 🛡️ **方案2: 双重认证机制 (推荐长期)**

```javascript
// 微信小程序专用认证流程
class WeChatMiniAuth {
  // 短期 access_token 存储
  static setAccessToken(token) {
    wx.setStorageSync('access_token', token);
    wx.setStorageSync('access_token_time', Date.now());
  }
  
  // refresh_token 后端存储，小程序只存储会话ID
  static async login(code) {
    const response = await wx.request({
      url: 'https://auth.company.com/wechat/mini-login',
      method: 'POST',
      data: { code },
    });
    
    // 只存储短期 access_token 和会话ID
    this.setAccessToken(response.access_token);
    wx.setStorageSync('session_id', response.session_id);
    
    // refresh_token 存储在后端，通过 session_id 关联
  }
  
  // 自动刷新机制
  static async refreshIfNeeded() {
    const sessionId = wx.getStorageSync('session_id');
    
    const response = await wx.request({
      url: 'https://auth.company.com/wechat/mini-refresh',
      method: 'POST',
      data: { session_id: sessionId },
      // 后端使用 session_id 查找对应的 refresh_token
    });
    
    if (response.access_token) {
      this.setAccessToken(response.access_token);
    }
  }
}
```

## 🎯 **方案A实施计划：子域名共享Cookie**

### Phase 1: 基础配置修改 (1天)

#### 1.1 **Spring Boot Cookie配置**
```java
// 新增文件：CookieSecurityConfig.java
@Configuration
public class CookieSecurityConfig {
    
    @Value("${oauth2.cookie.domain:.localhost}")
    private String cookieDomain;
    
    @Value("${oauth2.cookie.secure:false}")
    private boolean cookieSecure;
    
    @Bean
    public CookieHelper cookieHelper() {
        return new CookieHelper(cookieDomain, cookieSecure);
    }
}

// Cookie 工具类
@Component
public class CookieHelper {
    private final String domain;
    private final boolean secure;
    
    public CookieHelper(String domain, boolean secure) {
        this.domain = domain;
        this.secure = secure;
    }
    
    public ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refresh_token", refreshToken)
            .domain(domain)           // .company.com
            .httpOnly(true)
            .secure(secure)
            .sameSite("Lax")         // 允许同站跨子域
            .path("/")
            .maxAge(Duration.ofDays(30))
            .build();
    }
    
    public ResponseCookie clearRefreshTokenCookie() {
        return ResponseCookie.from("refresh_token", "")
            .domain(domain)
            .httpOnly(true)
            .secure(secure)
            .sameSite("Lax")
            .path("/")
            .maxAge(Duration.ZERO)
            .build();
    }
}
```

#### 1.2 **应用配置更新**
```yaml
# application.yml
oauth2:
  cookie:
    domain: ${COOKIE_DOMAIN:.localhost}      # 开发环境用 .localhost
    secure: ${COOKIE_SECURE:false}           # 生产环境设为 true
  clients:
    ffv-client:
      client-secret: ${CLIENT_SECRET:secret}  # 后端专用

# 生产环境变量
# COOKIE_DOMAIN=.company.com
# COOKIE_SECURE=true
# CLIENT_SECRET=actual_production_secret
```

### Phase 2: 端点安全改造 (2天)

#### 2.1 **微信刷新端点改造**
```java
// 修改文件：WeChatController.java
@PostMapping("/refresh-token")
public ResponseEntity<Map<String, Object>> refreshWeChatToken(
    @CookieValue(value = "refresh_token", required = false) String refreshToken,
    HttpServletRequest request,
    HttpServletResponse response) {
    
    if (refreshToken == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "No refresh token in cookie"));
    }
    
    try {
        // 使用后端存储的 client_secret
        OAuth2RefreshTokenRequest tokenRequest = OAuth2RefreshTokenRequest.builder()
            .refreshToken(refreshToken)
            .clientId(clientId)
            .clientSecret(clientSecret)  // 从配置读取，不再从前端传递
            .build();
        
        OAuth2AccessTokenResponse tokenResponse = oAuth2Service.refreshToken(tokenRequest);
        
        // 设置新的 refresh_token Cookie
        ResponseCookie newRefreshCookie = cookieHelper.createRefreshTokenCookie(
            tokenResponse.getRefreshToken());
        response.addHeader("Set-Cookie", newRefreshCookie.toString());
        
        // 只返回 access_token
        return ResponseEntity.ok(Map.of(
            "access_token", tokenResponse.getAccessToken(),
            "token_type", "Bearer",
            "expires_in", tokenResponse.getExpiresIn()
        ));
        
    } catch (Exception e) {
        log.error("WeChat refresh token failed", e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Refresh token invalid"));
    }
}
```

### Phase 3: 前端适配 (1天)

#### 3.1 **JavaScript Cookie处理**
```javascript
// 前端Cookie工具类
class AuthCookieManager {
  
  // 检查refresh_token Cookie是否存在
  static hasRefreshToken() {
    return document.cookie.includes('refresh_token=');
  }
  
  // 调用刷新API（无需传递参数）
  static async refreshAccessToken() {
    try {
      const response = await fetch('/wechat/refresh-token', {
        method: 'POST',
        credentials: 'include',  // 重要：包含Cookie
        headers: {
          'Content-Type': 'application/json',
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        // 只存储 access_token
        localStorage.setItem('access_token', data.access_token);
        return data.access_token;
      } else {
        this.handleRefreshFailure();
        return null;
      }
    } catch (error) {
      console.error('Refresh token failed:', error);
      this.handleRefreshFailure();
      return null;
    }
  }
  
  static handleRefreshFailure() {
    // 清除本地access_token
    localStorage.removeItem('access_token');
    // 重定向到登录页面
    window.location.href = '/login';
  }
}
```

### Phase 4: 测试脚本更新 (1天)

#### 4.1 **新增Cookie测试脚本**
```bash
# 新建文件：scripts/test-cookie-security.sh
#!/bin/bash

print_section "Testing Cross-Subdomain Cookie Security"

# 测试Cookie设置
test_cookie_setting() {
    local response=$(curl -s -I "${BASE_URL}/wechat/login?loginCode=test" \
        -H "Accept: application/json")
    
    if echo "$response" | grep -q "Set-Cookie.*domain=\.localhost"; then
        print_result "success" "✅ Cookie domain correctly set to .localhost"
    else
        print_result "error" "❌ Cookie domain not properly configured"
    fi
}

# 测试跨子域访问
test_cross_subdomain_access() {
    # 模拟从不同子域名访问
    local cookie_header="refresh_token=test_token_value"
    
    local response=$(curl -s "${BASE_URL}/wechat/refresh-token" \
        -H "Cookie: $cookie_header" \
        -H "Content-Type: application/json" \
        -w "%{http_code}")
    
    print_result "info" "Cross-subdomain cookie test: HTTP $response"
}

test_cookie_setting
test_cross_subdomain_access
```

### Phase 5: 部署配置 (1天)

#### 5.1 **Nginx代理配置**
```nginx
# nginx.conf - 跨子域名代理
server {
    listen 443 ssl;
    server_name *.company.com;
    
    # SSL配置
    ssl_certificate /path/to/wildcard-cert.pem;
    ssl_certificate_key /path/to/wildcard-key.pem;
    
    # 认证服务器
    location ~ ^/auth/ {
        proxy_pass http://auth-backend:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Cookie代理设置
        proxy_cookie_domain localhost .company.com;
        proxy_cookie_flags refresh_token httponly secure samesite=lax;
    }
    
    # 前端应用
    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
    }
}
```

## 🧪 **验证测试计划**

### 测试场景
1. **同域测试**: `auth.localhost` → `auth.localhost`
2. **跨子域测试**: `auth.localhost` → `app.localhost`
3. **Cookie安全测试**: HttpOnly, Secure, SameSite验证
4. **过期处理测试**: Cookie过期自动清理
5. **错误恢复测试**: 无效Cookie的处理

### 成功标准
- ✅ Cookie能在所有子域名间共享
- ✅ refresh_token完全不暴露给前端JavaScript
- ✅ client_secret完全后端化
- ✅ 所有现有测试脚本正常运行
- ✅ 跨子域名认证流程正常

## ⚠️ **注意事项**

### 安全考虑
1. **生产环境必须使用HTTPS** - Cookie secure标志
2. **域名证书必须是通配符证书** - 支持所有子域名
3. **SameSite=Lax平衡** - 既允许跨子域又防CSRF
4. **定期Cookie轮换** - 降低泄露风险

### 兼容性
1. **旧版浏览器支持** - 测试IE11+, Safari 12+
2. **移动端兼容** - iOS Safari, Android Chrome
3. **微信小程序独立处理** - 不依赖Cookie机制

---

**下一步**: 开始实施方案A的Phase 1配置修改

## 📝 后续计划

### 中期目标 (1-2个月)
- 完整后端代理模式实现
- 微信小程序专用安全方案
- 统一的客户端安全策略

### 长期目标 (3-6个月)
- JWT 与 Session 混合策略
- 多端统一认证方案
- 企业级安全合规审计

## 📚 相关文档

- [OAuth2 安全最佳实践](../oauth2-client-integration-guide.md)
- [Spring Security 配置指南](../security-configuration-guide.md)
- [微信小程序集成方案](./wechat-miniprogram-integration-plan.md)

## 🔍 **关键检查点** (扩展)

### 开发阶段
- SecurityConfig.java 配置完整性
- Cookie 安全属性正确设置
- client_secret 配置注入正常
- **所有6个Controller的client_secret移除**

### 测试阶段
- 浏览器开发者工具检查 Cookie
- 网络请求中无 client_secret 暴露
- 不同浏览器兼容性测试
- **所有测试脚本的Cookie模式验证**

### 部署阶段
- 生产环境 Cookie Secure 属性
- HTTPS 配置验证
- 负载均衡器 Cookie 透传
- **测试脚本在生产环境的适配**

## 🚨 **重点关注** (新增)

### 测试脚本修改重点
1. **移除所有 `Authorization: Basic` header**
2. **添加 `-b cookies.txt -c cookies.txt` 到所有curl命令**
3. **添加Cookie安全属性验证**
4. **保持测试逻辑的完整性**

### 端点修改重点  
1. **统一使用 `OAuth2AuthenticationHelper`**
2. **所有refresh端点支持Cookie读取**
3. **登录端点设置HttpOnly Cookie**
4. **保持API响应格式兼容**

---

**注意**: 此方案为短期安全修复，主要解决 client_secret 暴露问题。微信小程序等特殊客户端需要独立的安全策略。所有6个测试脚本的Cookie适配是验收的关键指标。 