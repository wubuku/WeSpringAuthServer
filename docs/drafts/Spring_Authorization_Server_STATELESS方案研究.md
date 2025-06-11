<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# Spring Authorization Server STATELESS（无状态）认证方案研究

## 核心问题分析

Spring Authorization Server默认采用基于Cookie的Session机制进行认证状态管理，在分布式架构和API访问场景下存在以下技术限制：

1. **状态依赖问题**：Session信息存储在服务器内存或数据库中，在微服务架构下需要Session复制或集中存储方案，增加基础设施复杂度[^14]
2. **可扩展性约束**：HttpSession存储授权请求状态[^3][^12]，限制了服务的水平扩展能力
3. **API访问复杂性**：现代SPA和移动应用更适合使用Token进行API访问，而非Cookie机制

**重要澄清**：
- 🔐 **认证过程**：仍然在授权服务器的同域环境中安全进行（无论是否STATELESS）
- ⚡ **STATELESS核心价值**：简化服务器架构，消除状态依赖，提升可扩展性
- 📱 **架构收益**：减少基础设施复杂度，对分布式部署更加友好

**注意**：项目已支持API跨域访问（通过JWT），STATELESS主要是架构简化，而非功能增强

最新稳定版（1.5.0）的Spring Authorization Server[^4][^5]提供了完整的无状态认证支持，可通过以下技术方案实现STATELESS架构。

---

## STATELESS（无状态）JWT认证实施指南

### 1. 基础环境配置

```java
// pom.xml依赖配置
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>1.5.0</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.5</version>
</dependency>
```

### 2. 无状态安全配置

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain authServerFilterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(s -> s
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .csrf(c -> c.disable())
            .cors(c -> c.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/oauth2/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(o -> o
                .jwt(j -> j
                    .decoder(jwtDecoder())
                )
            );
        return http.build();
    }

    // JWT解码器配置
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey()).build();
    }
}
```

### 3. JWT令牌定制化

```java
@Bean
OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
    return context -> {
        Authentication principal = context.getPrincipal();
        context.getClaims()
            .claim("tenant_id", resolveTenantId(principal))
            .claim("auth_source", "oauth2");
    };
}

@Bean
JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    return new ImmutableJWKSet<>(new JWKSet(rsaKey));
}
```

---

## STATELESS架构的技术实现

### CORS配置策略

```java
@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.asList("https://app.domain.com"));
    config.setAllowedMethods(Arrays.asList("GET","POST"));
    config.setAllowedHeaders(Arrays.asList("Authorization","Content-Type"));
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

### 前端Token管理

```javascript
// 认证：在同域环境中安全进行
async function login(credentials) {
    // 注意：登录仍然在授权服务器的同域中进行
    const response = await fetch('https://auth.domain.com/oauth2/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            grant_type: 'password',
            username: credentials.username,
            password: credentials.password,
            client_id: 'web-client'
        })
    });
    
    const { access_token, expires_in } = await response.json();
    sessionStorage.setItem('access_token', access_token);
    scheduleTokenRefresh(expires_in);
}

// API访问：使用JWT进行无状态访问（本来就支持跨域）
async function callAPI(endpoint) {
    const token = sessionStorage.getItem('access_token');
    return fetch(`https://api.domain.com${endpoint}`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
}
```

---

## 架构差异对比

### 传统Session架构 vs STATELESS架构

| 层面 | Session架构 | STATELESS架构 |
|------|------------|---------------|
| **认证过程** | 同域认证 ✅ | 同域认证 ✅ |
| **状态存储** | 服务器Session | 客户端JWT |
| **API访问** | Cookie传输 | Bearer Token |
| **架构复杂度** | 需要Session管理 | 无状态简化 |
| **水平扩展** | 需要Session共享 | 天然无状态 |
| **基础设施** | 依赖Session存储 | 架构简化 |

### 安全边界澄清

```mermaid
graph TB
    A[用户浏览器] --> B[认证服务器 - 同域安全认证]
    B --> C[颁发JWT Token - 一次性认证]
    C --> D[客户端获得Token]
    D --> E[使用Token访问API - 无状态验证]
    
    style B fill:#ff9999,stroke:#333,stroke-width:2px
    style E fill:#99ff99,stroke:#333,stroke-width:2px
    
    B -.->|"🔐 认证阶段<br/>同域安全"| B
    E -.->|"⚡ API访问阶段<br/>无状态验证"| E
```

---

## 安全增强措施

### 1. Token存储策略对比

| 方案 | XSS风险 | CSRF风险 | 实现复杂度 | 适用场景 |
| :-- | :-- | :-- | :-- | :-- |
| HttpOnly Cookie | 低 | 中 | 中 | 同源/子域部署 |
| Memory存储 | 中 | 低 | 高 | 高安全SPA应用 |
| Encrypted LocalStorage | 中 | 低 | 高 | API访问优化 |

### 2. 关键防护配置

```properties
# application.properties
spring.security.oauth2.authorizationserver.token.issuer=https://auth.domain.com
spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://auth.domain.com/oauth2/jwks

# JWT有效期配置（无状态架构推荐较短有效期）
spring.security.oauth2.authorizationserver.token.access-token-time-to-live=15m
spring.security.oauth2.authorizationserver.token.refresh-token-time-to-live=30d
```

### 3. 技术概念澄清

**准确的技术表述**：
- ❌ "跨域认证" - 认证本身无法跨域
- ❌ "支持跨域API访问" - API跨域访问本来就支持（通过JWT）
- ✅ "STATELESS认证架构" - 强调无状态特性和架构简化

**核心理解**：
1. **认证过程**：始终在授权服务器同域中安全进行（无论是否STATELESS）
2. **STATELESS价值**：消除服务器状态依赖，简化架构，提升可扩展性
3. **功能对比**：API功能基本相同，主要差异在架构复杂度

---

## 架构验证方案

1. **同域认证测试**
```http
POST /oauth2/token HTTP/1.1
Host: auth.domain.com
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user&password=pass
```

2. **跨域API访问测试**
```http
GET /api/userinfo HTTP/1.1
Host: resource.domain.com
Origin: https://app.domain.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```
