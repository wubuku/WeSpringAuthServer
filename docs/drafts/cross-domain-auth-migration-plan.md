# Spring Authorization Server跨域认证迁移实施计划

## 计划概述
本文档详细规划了将当前基于Cookie/Session的Spring Authorization Server改造为支持跨域认证的具体实施步骤。

## 总体迁移策略

采用**渐进式迁移**策略，分4个阶段实施：
1. **准备阶段**: 代码结构优化和基础设施准备
2. **JWT增强阶段**: 完善JWT功能，支持双模式认证
3. **API迁移阶段**: 逐步迁移API端点到JWT认证
4. **全面无状态阶段**: 完全移除Session依赖（可选）

## 详细实施计划

### 阶段1: 准备阶段 (预计5-7天)

#### 1.1 代码结构调整

**目标**: 为双模式认证做好代码架构准备

**具体任务**:

1. **创建认证模式配置类**
```java
// 新建: src/main/java/org/dddml/ffvtraceability/auth/config/AuthModeProperties.java
@ConfigurationProperties(prefix = "auth.mode")
public class AuthModeProperties {
    private boolean jwtEnabled = false;
    private boolean sessionEnabled = true;
    private String defaultMode = "session"; // session, jwt, hybrid
    // ... getter/setter
}
```

2. **重构SecurityConfig**
```java
// 修改: src/main/java/org/dddml/ffvtraceability/auth/config/SecurityConfig.java
@Configuration
@EnableConfigurationProperties({AuthStateProperties.class, AuthModeProperties.class})
public class SecurityConfig {
    
    @Bean
    @Order(1)
    @ConditionalOnProperty(name = "auth.mode.jwt-enabled", havingValue = "true")
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        // JWT认证的安全配置
    }
    
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // 现有的Session认证配置
    }
}
```

3. **创建JWT认证服务**
```java
// 新建: src/main/java/org/dddml/ffvtraceability/auth/service/JwtAuthenticationService.java
@Service
public class JwtAuthenticationService {
    public String generateToken(Authentication authentication) { ... }
    public Authentication validateToken(String token) { ... }
    public void blacklistToken(String token) { ... }
}
```

#### 1.2 配置文件调整

**修改 application.yml**:
```yaml
# 新增认证模式配置
auth:
  mode:
    jwt-enabled: ${JWT_AUTH_ENABLED:false}
    session-enabled: ${SESSION_AUTH_ENABLED:true}  
    default-mode: ${DEFAULT_AUTH_MODE:session}
  jwt:
    access-token-validity: ${JWT_ACCESS_TOKEN_VALIDITY:3600}  # 1小时
    refresh-token-validity: ${JWT_REFRESH_TOKEN_VALIDITY:2592000}  # 30天
    allow-refresh: ${JWT_ALLOW_REFRESH:true}

# 增强CORS配置
auth-server:
  cors:
    allowed-origins: ${CORS_ALLOWED_ORIGINS:http://localhost:3000,http://127.0.0.1:3000}
    allowed-methods: GET,POST,PUT,DELETE,OPTIONS,PATCH
    allowed-headers: Authorization,Content-Type,Accept,X-Requested-With,Origin,X-XSRF-TOKEN
    exposed-headers: X-XSRF-TOKEN,Authorization
    allow-credentials: true
    max-age: 3600
```

#### 1.3 数据库准备

**创建JWT黑名单表**:
```sql
-- 新建: src/main/resources/db/migration/V1_1__create_jwt_blacklist.sql
CREATE TABLE IF NOT EXISTS jwt_blacklist (
    id BIGSERIAL PRIMARY KEY,
    token_id VARCHAR(255) NOT NULL UNIQUE,
    expired_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(500)
);

CREATE INDEX idx_jwt_blacklist_token_id ON jwt_blacklist(token_id);
CREATE INDEX idx_jwt_blacklist_expired_at ON jwt_blacklist(expired_at);
```

### 阶段2: JWT增强阶段 (预计8-10天)

#### 2.1 JWT认证Filter实现

**创建JWT认证过滤器**:
```java
// 新建: src/main/java/org/dddml/ffvtraceability/auth/filter/JwtAuthenticationFilter.java
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
            HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        
        // 1. 提取JWT Token (从Header或Cookie)
        String token = extractToken(request);
        
        if (token != null && jwtAuthenticationService.validateToken(token)) {
            // 2. 验证Token并设置认证上下文
            Authentication authentication = jwtAuthenticationService.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String extractToken(HttpServletRequest request) {
        // 优先从Authorization Header获取
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        
        // 备选：从Cookie获取
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        
        return null;
    }
}
```

#### 2.2 Token管理服务实现

**完善JWT认证服务**:
```java
// 增强: src/main/java/org/dddml/ffvtraceability/auth/service/JwtAuthenticationService.java
@Service
public class JwtAuthenticationService {
    
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final JwtBlacklistService blacklistService;
    
    public JwtTokenPair generateTokenPair(Authentication authentication) {
        String accessToken = generateAccessToken(authentication);
        String refreshToken = generateRefreshToken(authentication);
        return new JwtTokenPair(accessToken, refreshToken);
    }
    
    public String refreshAccessToken(String refreshToken) {
        if (!validateRefreshToken(refreshToken)) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        
        // 从refresh token中提取用户信息
        Authentication authentication = getAuthenticationFromRefreshToken(refreshToken);
        return generateAccessToken(authentication);
    }
    
    public void revokeToken(String token) {
        String tokenId = extractTokenId(token);
        blacklistService.addToBlacklist(tokenId, extractExpiration(token));
    }
}
```

#### 2.3 双模式认证支持

**修改AuthorizationServerConfig**:
```java
// 修改: src/main/java/org/dddml/ffvtraceability/auth/config/AuthorizationServerConfig.java
@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    
    // 配置CORS
    http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
    
    // 根据配置启用JWT资源服务器支持
    if (authModeProperties.isJwtEnabled()) {
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.decoder(jwtDecoder()))
        );
        
        // 添加JWT认证过滤器
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
    
    // 配置Token生成器
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
    authorizationServerConfigurer.tokenGenerator(tokenGenerator());
    
    return http.build();
}
```

### 阶段3: API端点迁移阶段 (预计10-12天)

#### 3.1 创建JWT专用API端点

**新增JWT认证端点**:
```java
// 新建: src/main/java/org/dddml/ffvtraceability/auth/controller/JwtAuthController.java
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "${auth-server.cors.allowed-origins}")
public class JwtAuthController {
    
    @PostMapping("/login")
    public ResponseEntity<JwtLoginResponse> login(@RequestBody LoginRequest request, 
            HttpServletResponse response) {
        
        Authentication authentication = authenticate(request);
        JwtTokenPair tokenPair = jwtAuthenticationService.generateTokenPair(authentication);
        
        // 设置HttpOnly Cookie (推荐方式)
        Cookie accessTokenCookie = new Cookie("access_token", tokenPair.getAccessToken());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(3600); // 1小时
        response.addCookie(accessTokenCookie);
        
        Cookie refreshTokenCookie = new Cookie("refresh_token", tokenPair.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setPath("/api/auth");
        refreshTokenCookie.setMaxAge(2592000); // 30天
        response.addCookie(refreshTokenCookie);
        
        return ResponseEntity.ok(new JwtLoginResponse(
            tokenPair.getAccessToken(), // 同时返回给前端，供选择存储方式
            tokenPair.getRefreshToken(),
            3600,
            "Bearer"
        ));
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<JwtRefreshResponse> refresh(HttpServletRequest request, 
            HttpServletResponse response) {
        
        String refreshToken = extractRefreshTokenFromCookie(request);
        String newAccessToken = jwtAuthenticationService.refreshAccessToken(refreshToken);
        
        // 更新access token cookie
        Cookie accessTokenCookie = new Cookie("access_token", newAccessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(3600);
        response.addCookie(accessTokenCookie);
        
        return ResponseEntity.ok(new JwtRefreshResponse(newAccessToken, 3600));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        
        String accessToken = extractAccessTokenFromCookie(request);
        String refreshToken = extractRefreshTokenFromCookie(request);
        
        // 撤销Token
        if (accessToken != null) {
            jwtAuthenticationService.revokeToken(accessToken);
        }
        if (refreshToken != null) {
            jwtAuthenticationService.revokeToken(refreshToken);
        }
        
        // 清除Cookie
        clearTokenCookies(response);
        
        return ResponseEntity.ok().build();
    }
}
```

#### 3.2 创建受保护的API端点

**示例受保护资源**:
```java
// 新建: src/main/java/org/dddml/ffvtraceability/auth/controller/UserApiController.java
@RestController
@RequestMapping("/api/users")
@PreAuthorize("hasAuthority('Users_Read')")
public class UserApiController {
    
    @GetMapping("/profile")
    public ResponseEntity<UserProfile> getCurrentUserProfile(Authentication authentication) {
        // JWT认证下，authentication包含从Token解析的用户信息
        UserProfile profile = userService.getUserProfile(authentication.getName());
        return ResponseEntity.ok(profile);
    }
    
    @GetMapping("/permissions")
    public ResponseEntity<Set<String>> getCurrentUserPermissions(Authentication authentication) {
        Set<String> authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());
        return ResponseEntity.ok(authorities);
    }
}
```

#### 3.3 前端适配

**JavaScript Token管理示例**:
```javascript
// 新建前端Token管理工具
class AuthTokenManager {
    constructor() {
        this.accessToken = null;
        this.refreshToken = null;
        this.tokenRefreshTimer = null;
    }
    
    async login(credentials) {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // 包含Cookie
            body: JSON.stringify(credentials)
        });
        
        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access_token;
            this.scheduleTokenRefresh(data.expires_in);
            return true;
        }
        return false;
    }
    
    scheduleTokenRefresh(expiresIn) {
        // 在Token过期前5分钟刷新
        const refreshTime = (expiresIn - 300) * 1000;
        this.tokenRefreshTimer = setTimeout(() => {
            this.refreshToken();
        }, refreshTime);
    }
    
    async refreshToken() {
        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access_token;
            this.scheduleTokenRefresh(data.expires_in);
        } else {
            // 刷新失败，重定向到登录页
            window.location.href = '/login';
        }
    }
    
    async apiRequest(url, options = {}) {
        const defaultOptions = {
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.accessToken}`
            }
        };
        
        const response = await fetch(url, { ...defaultOptions, ...options });
        
        if (response.status === 401) {
            // Token可能过期，尝试刷新
            await this.refreshToken();
            // 重试原请求
            return fetch(url, { ...defaultOptions, ...options });
        }
        
        return response;
    }
}

// 全局Token管理器实例
window.authManager = new AuthTokenManager();
```

### 阶段4: 完全无状态阶段 (可选，预计5-7天)

#### 4.1 移除Session依赖

**如果决定完全无状态，需要**:

1. **修改application.yml**:
```yaml
spring:
  session:
    store-type: none  # 禁用Session存储
```

2. **更新SecurityConfig**:
```java
@Bean
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement(session -> 
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(csrf -> csrf.disable()) // 无状态下禁用CSRF
        // ... 其他配置
}
```

3. **迁移所有认证逻辑到JWT**

## 测试和验证计划

### 功能测试

1. **登录流程测试**
   - 用户名/密码登录
   - 短信验证码登录  
   - 微信登录
   - 跨域登录测试

2. **Token管理测试**
   - Token生成和验证
   - Token刷新机制
   - Token撤销功能
   - 过期Token处理

3. **权限控制测试**
   - API端点访问控制
   - 角色和权限验证
   - 跨域权限检查

### 安全测试

1. **CORS安全测试**
   - 跨域请求验证
   - 预检请求处理
   - Origin验证

2. **JWT安全测试**
   - Token签名验证
   - Token篡改检测
   - 密钥安全性测试

3. **XSS/CSRF防护测试**
   - 跨站脚本攻击防护
   - 跨站请求伪造防护

### 性能测试

1. **JWT验证性能**
   - Token验证响应时间
   - 并发认证性能
   - 内存使用情况

2. **跨域请求性能**
   - 预检请求开销
   - Token传输效率

## 部署和运维

### 配置管理

**生产环境配置示例**:
```yaml
# 生产环境配置
auth:
  mode:
    jwt-enabled: true
    session-enabled: false
    default-mode: jwt

auth-server:
  cors:
    allowed-origins: https://app.domain.com,https://admin.domain.com
    allow-credentials: true

security:
  jwt:
    key-store: /etc/ssl/private/jwt-signing-keys.jks
    key-store-password: ${JWT_KEYSTORE_PASSWORD}
    access-token-validity: 1800  # 30分钟
    refresh-token-validity: 604800  # 7天
```

### 监控和告警

**关键监控指标**:
1. JWT验证成功/失败率
2. Token刷新频率
3. 跨域请求统计
4. 安全异常事件

**告警配置**:
1. JWT验证失败率超过阈值
2. Token黑名单异常增长
3. 跨域请求异常

## 风险控制和回滚方案

### 风险点

1. **前端兼容性问题**
2. **Token存储安全风险**  
3. **CORS配置错误**
4. **JWT密钥泄露**

### 回滚方案

1. **快速回滚**: 通过配置开关快速禁用JWT认证
2. **数据备份**: Session数据和用户状态备份
3. **渐进式回滚**: 逐步关闭JWT功能

### 应急响应

1. **安全事件响应流程**
2. **Token批量撤销机制**
3. **临时访问控制措施**

## 总结

本迁移计划采用渐进式方法，确保在保持系统稳定性的同时，逐步实现跨域认证功能。通过双模式支持，可以平滑过渡，降低风险。整个迁移过程预计需要25-35个工作日，具体时间取决于测试的深度和发现问题的复杂度。 