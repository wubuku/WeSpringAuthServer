# 第一步：认证模式切换详细实施规划

## 目标
实现应用配置文件控制的认证模式切换：
- **Session模式**: 保持现有的Cookie/Session认证机制
- **JWT模式**: 实现无状态的JWT Token跨域认证

同一时间只支持一种认证模式，通过配置文件切换。

## 核心设计思路

### 配置驱动的模式切换
```yaml
# application.yml
auth:
  mode: ${AUTH_MODE:session}  # session | jwt
```

### 条件化Bean配置
使用Spring的`@ConditionalOnProperty`注解实现不同模式下的Bean注册：
- Session模式：激活现有的SecurityFilterChain
- JWT模式：激活新的JWT SecurityFilterChain和相关组件

## 详细实施计划

### 1. 配置属性类创建

**新建文件**: `src/main/java/org/dddml/ffvtraceability/auth/config/AuthModeProperties.java`
```java
package org.dddml.ffvtraceability.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth")
public class AuthModeProperties {
    
    public enum Mode {
        SESSION, JWT
    }
    
    private Mode mode = Mode.SESSION;
    
    // JWT相关配置
    private Jwt jwt = new Jwt();
    
    // Getters and Setters
    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }
    
    public boolean isSessionMode() { return mode == Mode.SESSION; }
    public boolean isJwtMode() { return mode == Mode.JWT; }
    
    public static class Jwt {
        private int accessTokenValiditySeconds = 3600; // 1小时
        private int refreshTokenValiditySeconds = 2592000; // 30天
        private boolean allowRefresh = true;
        private String issuer = "http://localhost:9000";
        
        // Getters and Setters
        public int getAccessTokenValiditySeconds() { return accessTokenValiditySeconds; }
        public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) { 
            this.accessTokenValiditySeconds = accessTokenValiditySeconds; 
        }
        public int getRefreshTokenValiditySeconds() { return refreshTokenValiditySeconds; }
        public void setRefreshTokenValiditySeconds(int refreshTokenValiditySeconds) { 
            this.refreshTokenValiditySeconds = refreshTokenValiditySeconds; 
        }
        public boolean isAllowRefresh() { return allowRefresh; }
        public void setAllowRefresh(boolean allowRefresh) { this.allowRefresh = allowRefresh; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
    }
}
```

### 2. 重构SecurityConfig

**修改文件**: `src/main/java/org/dddml/ffvtraceability/auth/config/SecurityConfig.java`

**核心修改**:
1. 将现有配置改为Session专用
2. 添加JWT模式的条件化配置

```java
package org.dddml.ffvtraceability.auth.config;

// ... 现有imports
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

@Configuration
@EnableConfigurationProperties({AuthStateProperties.class, AuthModeProperties.class})
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private AuthModeProperties authModeProperties;
    
    // Session模式专用配置
    @Bean("sessionSecurityFilterChain")
    @Order(2)
    @ConditionalOnProperty(name = "auth.mode", havingValue = "session", matchIfMissing = true)
    public SecurityFilterChain sessionSecurityFilterChain(HttpSecurity http) throws Exception {
        logger.info("配置Session认证模式");
        
        // 保持现有的完整配置
        http.cors(cors -> cors.configurationSource(corsConfigurationSource))
                .csrf(csrf ->
                        csrf.ignoringRequestMatchers("/web-clients/oauth2/**"
                                , "/api/sms/send-code"))
                .sessionManagement(session -> 
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(authorize -> authorize
                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                .requestMatchers("/**").permitAll()
                        )
                .authenticationProvider(usernamePasswordAuthenticationProvider)
                .authenticationProvider(smsAuthenticationProvider)
                .authenticationProvider(wechatAuthenticationProvider)
                .formLogin(form -> form
                        .loginPage("/login")
                        .failureHandler(new UsernamePasswordAuthenticationFailureHandler())
                        .successHandler(authenticationSuccessHandler))
                .apply(new SmsAuthenticationConfigurer<>())
                .successHandler(authenticationSuccessHandler)
                .failureHandler(new SmsAuthenticationFailureHandler());
        
        http.apply(new WechatAuthenticationConfigurer<>())
                .successHandler(authenticationSuccessHandler)
                .failureHandler(new WechatAuthenticationFailureHandler());
                
        return http.build();
    }
    
    // JWT模式专用配置
    @Bean("jwtSecurityFilterChain")
    @Order(2)
    @ConditionalOnProperty(name = "auth.mode", havingValue = "jwt")
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        logger.info("配置JWT认证模式");
        
        http.cors(cors -> cors.configurationSource(corsConfigurationSource))
                .csrf(csrf -> csrf.disable()) // JWT模式下禁用CSRF
                .sessionManagement(session -> 
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/api/auth/**").permitAll() // JWT认证端点
                        .requestMatchers("/oauth2/**").permitAll() // OAuth2端点
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
                );
                
        return http.build();
    }
    
    // JWT Decoder - 仅在JWT模式下激活
    @Bean
    @ConditionalOnProperty(name = "auth.mode", havingValue = "jwt")
    public JwtDecoder jwtDecoder() {
        // 使用现有的AuthorizationServerConfig中的jwkSource
        return NimbusJwtDecoder.withJwkSetUri(authModeProperties.getJwt().getIssuer() + "/oauth2/jwks").build();
    }
}
```

### 3. 修改AuthorizationServerConfig

**修改文件**: `src/main/java/org/dddml/ffvtraceability/auth/config/AuthorizationServerConfig.java`

**关键修改点**:
1. 根据认证模式调整OAuth2 Token生成策略
2. 在JWT模式下优化Token Claims

```java
// 在现有的tokenGenerator()方法中添加模式判断
private OAuth2TokenGenerator<?> tokenGenerator() {
    JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
    JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);

    // JWT模式下增强Token Claims
    if (authModeProperties.isJwtMode()) {
        jwtGenerator.setJwtCustomizer(context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                JwtClaimsSet.Builder claims = context.getClaims();
                Authentication authentication = context.getPrincipal();

                // 添加更多用户信息到JWT中，支持无状态验证
                Set<String> authorities = authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                claims.claim("authorities", authorities);
                claims.claim("username", authentication.getName());
                
                // 添加自定义Claims
                Object details = authentication.getDetails();
                if (details instanceof Map) {
                    Map<String, Object> detailsMap = (Map<String, Object>) details;
                    if (detailsMap.containsKey("groups")) {
                        claims.claim("groups", detailsMap.get("groups"));
                    }
                    if (detailsMap.containsKey("tenantId")) {
                        claims.claim("tenant_id", detailsMap.get("tenantId"));
                    }
                }
                
                // 设置更长的过期时间（JWT模式下）
                claims.expiresAt(Instant.now().plusSeconds(authModeProperties.getJwt().getAccessTokenValiditySeconds()));
            }
        });
    } else {
        // Session模式保持原有逻辑
        jwtGenerator.setJwtCustomizer(context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                JwtClaimsSet.Builder claims = context.getClaims();
                Authentication authentication = context.getPrincipal();

                Set<String> authorities = authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                claims.claim("authorities", authorities);

                Object details = authentication.getDetails();
                if (details instanceof Map) {
                    Map<String, Object> detailsMap = (Map<String, Object>) details;
                    if (detailsMap.containsKey("groups")) {
                        claims.claim("groups", detailsMap.get("groups"));
                    }
                }
            }
        });
    }

    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

    return new DelegatingOAuth2TokenGenerator(
            jwtGenerator,
            accessTokenGenerator,
            refreshTokenGenerator);
}
```

### 4. 创建JWT认证Controller

**新建文件**: `src/main/java/org/dddml/ffvtraceability/auth/controller/JwtAuthController.java`
```java
package org.dddml.ffvtraceability.auth.controller;

import org.dddml.ffvtraceability.auth.config.AuthModeProperties;
import org.dddml.ffvtraceability.auth.service.JwtAuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/auth")
@ConditionalOnProperty(name = "auth.mode", havingValue = "jwt")
@CrossOrigin(origins = "${auth-server.cors.allowed-origins}")
public class JwtAuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthController.class);
    
    private final JwtAuthenticationService jwtAuthenticationService;
    private final AuthenticationManager authenticationManager;
    private final AuthModeProperties authModeProperties;
    
    public JwtAuthController(JwtAuthenticationService jwtAuthenticationService,
                           AuthenticationManager authenticationManager,
                           AuthModeProperties authModeProperties) {
        this.jwtAuthenticationService = jwtAuthenticationService;
        this.authenticationManager = authenticationManager;
        this.authModeProperties = authModeProperties;
    }
    
    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(@RequestBody JwtAuthRequest request, 
                                               HttpServletResponse response) {
        logger.info("JWT模式登录请求: {}", request.getUsername());
        
        try {
            // 使用现有的认证管理器进行认证
            Authentication authRequest = new UsernamePasswordAuthenticationToken(
                request.getUsername(), request.getPassword());
            Authentication authentication = authenticationManager.authenticate(authRequest);
            
            // 生成JWT Token
            String accessToken = jwtAuthenticationService.generateAccessToken(authentication);
            String refreshToken = null;
            
            if (authModeProperties.getJwt().isAllowRefresh()) {
                refreshToken = jwtAuthenticationService.generateRefreshToken(authentication);
            }
            
            // 设置HttpOnly Cookie (推荐方式)
            setTokenCookies(response, accessToken, refreshToken);
            
            return ResponseEntity.ok(new JwtAuthResponse(
                accessToken,
                refreshToken,
                authModeProperties.getJwt().getAccessTokenValiditySeconds(),
                "Bearer"
            ));
            
        } catch (Exception e) {
            logger.error("JWT登录失败", e);
            return ResponseEntity.badRequest().build();
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        // 清除Token Cookies
        clearTokenCookies(response);
        return ResponseEntity.ok().build();
    }
    
    private void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Access Token Cookie
        Cookie accessTokenCookie = new Cookie("access_token", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true); // 生产环境启用
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(authModeProperties.getJwt().getAccessTokenValiditySeconds());
        response.addCookie(accessTokenCookie);
        
        // Refresh Token Cookie (如果启用)
        if (refreshToken != null) {
            Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/api/auth");
            refreshTokenCookie.setMaxAge(authModeProperties.getJwt().getRefreshTokenValiditySeconds());
            response.addCookie(refreshTokenCookie);
        }
    }
    
    private void clearTokenCookies(HttpServletResponse response) {
        Cookie accessToken = new Cookie("access_token", "");
        accessToken.setMaxAge(0);
        accessToken.setPath("/");
        response.addCookie(accessToken);
        
        Cookie refreshToken = new Cookie("refresh_token", "");
        refreshToken.setMaxAge(0);
        refreshToken.setPath("/api/auth");
        response.addCookie(refreshToken);
    }
    
    // Request/Response DTOs
    public static class JwtAuthRequest {
        private String username;
        private String password;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
    
    public static class JwtAuthResponse {
        private String accessToken;
        private String refreshToken;
        private int expiresIn;
        private String tokenType;
        
        public JwtAuthResponse(String accessToken, String refreshToken, int expiresIn, String tokenType) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
            this.tokenType = tokenType;
        }
        
        // Getters
        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
        public int getExpiresIn() { return expiresIn; }
        public String getTokenType() { return tokenType; }
    }
}
```

### 5. 创建JWT认证服务

**新建文件**: `src/main/java/org/dddml/ffvtraceability/auth/service/JwtAuthenticationService.java`
```java
package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.config.AuthModeProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@ConditionalOnProperty(name = "auth.mode", havingValue = "jwt")
public class JwtAuthenticationService {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationService.class);
    
    private final JwtEncoder jwtEncoder;
    private final AuthModeProperties authModeProperties;
    
    public JwtAuthenticationService(JwtEncoder jwtEncoder, AuthModeProperties authModeProperties) {
        this.jwtEncoder = jwtEncoder;
        this.authModeProperties = authModeProperties;
    }
    
    public String generateAccessToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(authModeProperties.getJwt().getAccessTokenValiditySeconds());
        
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authModeProperties.getJwt().getIssuer())
                .subject(authentication.getName())
                .audience(Set.of("ffv-client"))
                .issuedAt(now)
                .expiresAt(expiry)
                .id(UUID.randomUUID().toString())
                .claim("authorities", authorities)
                .claim("auth_mode", "jwt")
                .build();
        
        return jwtEncoder.encode(JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256).build())
                .claims(claims).build()).getTokenValue();
    }
    
    public String generateRefreshToken(Authentication authentication) {
        if (!authModeProperties.getJwt().isAllowRefresh()) {
            return null;
        }
        
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(authModeProperties.getJwt().getRefreshTokenValiditySeconds());
        
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authModeProperties.getJwt().getIssuer())
                .subject(authentication.getName())
                .audience(Set.of("ffv-client"))
                .issuedAt(now)
                .expiresAt(expiry)
                .id(UUID.randomUUID().toString())
                .claim("token_type", "refresh")
                .claim("auth_mode", "jwt")
                .build();
        
        return jwtEncoder.encode(JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256).build())
                .claims(claims).build()).getTokenValue();
    }
}
```

### 6. 修改application.yml配置

**修改文件**: `src/main/resources/application.yml`

**添加认证模式配置**:
```yaml
# 在现有配置基础上添加
auth:
  mode: ${AUTH_MODE:session}  # session | jwt
  jwt:
    access-token-validity-seconds: ${JWT_ACCESS_TOKEN_VALIDITY:3600}  # 1小时
    refresh-token-validity-seconds: ${JWT_REFRESH_TOKEN_VALIDITY:2592000}  # 30天
    allow-refresh: ${JWT_ALLOW_REFRESH:true}
    issuer: ${AUTH_SERVER_ISSUER:http://localhost:9000}

# Session配置 - 仅在session模式下有效
spring:
  session:
    store-type: jdbc
    jdbc:
      initialize-schema: always
      schema: classpath:org/springframework/session/jdbc/schema-postgresql.sql
      table-name: SPRING_SESSION
    timeout: 30m
```

### 7. 创建模式切换脚本

**新建文件**: `scripts/switch-auth-mode.sh`
```bash
#!/bin/bash

MODE=${1:-session}

if [ "$MODE" != "session" ] && [ "$MODE" != "jwt" ]; then
    echo "用法: $0 [session|jwt]"
    echo "默认模式: session"
    exit 1
fi

echo "切换认证模式到: $MODE"

# 设置环境变量
export AUTH_MODE=$MODE

if [ "$MODE" == "jwt" ]; then
    echo "JWT模式配置："
    echo "- 无状态认证"
    echo "- 跨域支持"
    echo "- Token有效期: 1小时"
    export SESSION_ENABLED=false
else
    echo "Session模式配置："
    echo "- 有状态认证"
    echo "- Cookie/Session"
    echo "- Session超时: 30分钟"
    export SESSION_ENABLED=true
fi

echo "重启应用以应用新配置..."
# 这里可以添加重启应用的命令
```

### 8. 单元测试

**新建文件**: `src/test/java/org/dddml/ffvtraceability/auth/config/AuthModeConfigTest.java`
```java
package org.dddml.ffvtraceability.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.SecurityFilterChain;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AuthModeConfigTest {
    
    @Autowired
    private ApplicationContext applicationContext;
    
    @Test
    @TestPropertySource(properties = "auth.mode=session")
    void testSessionModeConfiguration() {
        assertTrue(applicationContext.containsBean("sessionSecurityFilterChain"));
        assertFalse(applicationContext.containsBean("jwtSecurityFilterChain"));
    }
    
    @Test
    @TestPropertySource(properties = "auth.mode=jwt")
    void testJwtModeConfiguration() {
        assertFalse(applicationContext.containsBean("sessionSecurityFilterChain"));
        assertTrue(applicationContext.containsBean("jwtSecurityFilterChain"));
        assertTrue(applicationContext.containsBean("jwtAuthenticationService"));
    }
}
```

## 使用方式

### Session模式（默认）
```bash
# 启动应用（默认为Session模式）
./mvnw spring-boot:run

# 或显式指定
AUTH_MODE=session ./mvnw spring-boot:run
```

### JWT模式
```bash
# 设置环境变量启动
AUTH_MODE=jwt ./mvnw spring-boot:run

# 或使用脚本
./scripts/switch-auth-mode.sh jwt
```

### 验证模式切换

**Session模式验证**:
```bash
curl -X POST http://localhost:9000/login \
  -d "username=user1&password=password" \
  -c cookies.txt

curl -X GET http://localhost:9000/user-management \
  -b cookies.txt
```

**JWT模式验证**:
```bash
# 登录获取Token
curl -X POST http://localhost:9000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password"}' \
  -c jwt-cookies.txt

# 使用Token访问API
curl -X GET http://localhost:9000/api/users/profile \
  -b jwt-cookies.txt
```

## 预期效果

1. **Session模式**: 保持现有功能不变，所有现有流程正常工作
2. **JWT模式**: 提供无状态的跨域认证能力，支持前后端分离
3. **配置切换**: 通过环境变量轻松切换模式，无需修改代码
4. **向后兼容**: Session模式下所有现有功能保持不变

## 估计工作量

- **配置类和属性**: 1天
- **SecurityConfig重构**: 2天  
- **JWT服务和Controller**: 2天
- **配置文件调整**: 0.5天
- **测试和验证**: 1.5天

**总计**: 约7个工作日 