# WeSpringAuthServer 集成指南

> 🎯 **目标**: 让您的 Spring Boot 应用快速集成 WeSpringAuthServer 作为 OAuth2 资源服务器

## ⚡ 快速开始

### 第一步：添加依赖

在您的 `pom.xml` 中添加：

```xml
<dependencies>
    <!-- Spring Boot OAuth2 资源服务器 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
    
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- 如需权限缓存（可选） -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
    <dependency>
        <groupId>com.github.ben-manes.caffeine</groupId>
        <artifactId>caffeine</artifactId>
    </dependency>
    
    <!-- 如需访问权限数据库（可选） -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-jdbc</artifactId>
    </dependency>
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
    </dependency>
</dependencies>
```

### 第二步：配置 application.yml

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # 替换为您的 WeSpringAuthServer 地址
          jwk-set-uri: http://localhost:9000/oauth2/jwks
          
  # 如需访问权限数据库，配置数据源
  datasource:
    url: jdbc:postgresql://localhost:5432/your_auth_db
    username: your_username
    password: your_password
    
  # 权限缓存配置（可选）
  cache:
    caffeine:
      spec: maximumSize=100,expireAfterWrite=3600s

server:
  port: 8081  # 您的应用端口
```

### 第三步：创建安全配置

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // 启用方法级安全，支持 @PreAuthorize 等注解
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // 公开端点
                .requestMatchers("/api/public/**").permitAll()
                // 管理端点需要管理员权限
                .requestMatchers("/api/admin/**").hasAuthority("ROLE_ADMIN")
                // 其他受保护端点需要认证
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable());
            
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new CustomJwtAuthenticationConverter();
    }
}
```

### 第四步：创建权限转换器

```java
@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomJwtAuthenticationConverter.class);
    
    // 如需组权限支持，注入组权限服务（可选）
    @Autowired(required = false)
    private GroupAuthorityService groupAuthorityService;
    
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        logger.debug("Converting JWT to Authentication for subject: {}", jwt.getSubject());
        
        // 1. 添加直接权限
        // WeSpringAuthServer在JWT的"authorities"声明中包含用户的直接权限
        Set<String> directAuthorities = getClaimAsSet(jwt, "authorities");
        logger.debug("Direct authorities from JWT: {}", directAuthorities);
        directAuthorities.stream()
            .map(SimpleGrantedAuthority::new)
            .forEach(authorities::add);
            
        // 2. 从组获取权限（如果配置了组权限服务）
        // WeSpringAuthServer在JWT的"groups"声明中包含用户所属的组
        if (groupAuthorityService != null) {
            Set<String> groups = getClaimAsSet(jwt, "groups");
            logger.debug("Groups from JWT: {}", groups);
            
            groups.stream()
                .map(group -> {
                    Set<String> groupAuths = groupAuthorityService.getGroupAuthorities(group);
                    logger.debug("Authorities for group {}: {}", group, groupAuths);
                    return groupAuths;
                })
                .flatMap(Set::stream)
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);
        }
        
        logger.debug("Final combined authorities: {}", authorities);
        return new JwtAuthenticationToken(jwt, authorities);
    }
    
    /**
     * 从JWT声明中获取字符串集合
     */
    @SuppressWarnings("unchecked")
    private Set<String> getClaimAsSet(Jwt jwt, String claimName) {
        Object claim = jwt.getClaims().get(claimName);
        if (claim instanceof Collection) {
            return new HashSet<>((Collection<String>) claim);
        }
        logger.debug("No {} found in JWT claims", claimName);
        return Collections.emptySet();
    }
}
```

### 第五步：创建测试 API 控制器（可选）

> 💡 **说明**: 这一步是可选的，主要用于测试集成是否成功。您可以直接在现有的控制器中应用相应的权限注解。

```java
@RestController
@RequestMapping("/api")
public class TestApiController {

    // 公开端点 - 用于测试应用是否正常运行
    @GetMapping("/public/hello")
    public Map<String, Object> publicHello() {
        return Map.of(
            "message", "Hello from public endpoint!",
            "timestamp", System.currentTimeMillis()
        );
    }

    // 需要认证的端点 - 用于测试 JWT 认证是否正常
    @GetMapping("/protected/user-info")
    public Map<String, Object> userInfo(Authentication authentication) {
        return Map.of(
            "user", authentication.getName(),
            "authorities", authentication.getAuthorities()
        );
    }

    // 需要特定权限的端点 - 用于测试权限控制是否正常
    @GetMapping("/protected/users")
    @PreAuthorize("hasAuthority('Users_Read')")
    public Map<String, Object> getUsers() {
        return Map.of("users", "List of users");
    }

    // 管理员端点 - 用于测试管理员权限是否正常
    @GetMapping("/admin/system-info")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Map<String, Object> systemInfo() {
        return Map.of("system", "System information");
    }
}
```

**在您现有的业务控制器中**，只需要添加相应的权限注解：

> ⚠️ **注意**: 要使用 `@PreAuthorize` 等权限注解，必须在安全配置类上添加 `@EnableMethodSecurity` 注解（第三步已包含）

```java
@RestController
public class YourBusinessController {
    
    @GetMapping("/api/your-business-endpoint")
    @PreAuthorize("hasAuthority('YOUR_REQUIRED_PERMISSION')")
    public ResponseEntity<?> yourBusinessMethod() {
        // 您的业务逻辑
        return ResponseEntity.ok().build();
    }
}
```

## 🔧 高级配置

### 启用组权限支持

如果您的用户通过用户组获得权限，以下是一个**使用数据库查询的示例实现**。您可以根据自己的业务架构选择其他实现方式（如 REST API 调用、配置文件映射、外部权限服务等）：

1. **配置权限数据源**（数据库方式示例）：
```java
@Configuration
public class DataSourceConfig {
    
    @Bean
    @ConfigurationProperties("spring.security.datasource")
    public DataSource securityDataSource() {
        return DataSourceBuilder.create().build();
    }
    
    @Bean
    public JdbcTemplate securityJdbcTemplate(@Qualifier("securityDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
}
```

2. **创建组权限服务**（数据库查询示例）：
```java
@Service
public class GroupAuthorityService {
    
    private static final Logger logger = LoggerFactory.getLogger(GroupAuthorityService.class);
    
    @Autowired
    private JdbcTemplate securityJdbcTemplate;
    
    /**
     * 获取指定组的所有权限
     * 
     * @param groupName 组名（包含GROUP_前缀，如"GROUP_ADMIN_GROUP"）
     * @return 该组拥有的所有权限集合
     */
    @Cacheable(value = "groupAuthorities", key = "#groupName")
    public Set<String> getGroupAuthorities(String groupName) {
        logger.debug("Loading authorities from database for group: {}", groupName);
        
        // 查询组权限的SQL（基于WeSpringAuthServer的实际表结构）
        String sql = """
            SELECT ga.authority 
            FROM group_authorities ga
            JOIN groups g ON ga.group_id = g.id 
            WHERE g.group_name = ?
            """;
            
        // 移除GROUP_前缀来匹配数据库中的组名
        // WeSpringAuthServer在JWT中使用GROUP_前缀，但数据库中存储的是不带前缀的组名
        String dbGroupName = groupName.replace("GROUP_", "");
        
        Set<String> authorities = new HashSet<>(
            securityJdbcTemplate.queryForList(sql, String.class, dbGroupName)
        );
        
        logger.debug("Loaded {} authorities from database for group: {}", authorities.size(), groupName);
        return authorities;
    }
}
```

> 💡 **其他实现方式**: 您也可以通过以下方式实现组权限获取：
> - **REST API 调用**: 调用外部权限管理服务
> - **配置文件映射**: 在 application.yml 中配置组与权限的映射关系
> - **LDAP/AD 查询**: 从企业目录服务获取组权限
> - **缓存服务**: 从 Redis 等缓存中获取预计算的组权限
> - **消息队列**: 通过 MQ 异步获取权限信息

3. **更新权限转换器**（完整示例实现）：
```java
@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomJwtAuthenticationConverter.class);
    
    @Autowired
    private GroupAuthorityService groupAuthorityService;
    
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        logger.debug("Converting JWT to Authentication for subject: {}", jwt.getSubject());
        
        // 1. 添加直接权限
        Set<String> directAuthorities = getClaimAsSet(jwt, "authorities");
        logger.debug("Direct authorities from JWT: {}", directAuthorities);
        directAuthorities.stream()
            .map(SimpleGrantedAuthority::new)
            .forEach(authorities::add);
            
        // 2. 从组获取权限
        Set<String> groups = getClaimAsSet(jwt, "groups");
        logger.debug("Groups from JWT: {}", groups);
        
        groups.stream()
            .map(group -> {
                Set<String> groupAuths = groupAuthorityService.getGroupAuthorities(group);
                logger.debug("Authorities for group {}: {}", group, groupAuths);
                return groupAuths;
            })
            .flatMap(Set::stream)
            .map(SimpleGrantedAuthority::new)
            .forEach(authorities::add);
        
        logger.debug("Final combined authorities: {}", authorities);
        return new JwtAuthenticationToken(jwt, authorities);
    }
    
    @SuppressWarnings("unchecked")
    private Set<String> getClaimAsSet(Jwt jwt, String claimName) {
        Object claim = jwt.getClaims().get(claimName);
        if (claim instanceof Collection) {
            return new HashSet<>((Collection<String>) claim);
        }
        logger.debug("No {} found in JWT claims", claimName);
        return Collections.emptySet();
    }
}
```

### 配置缓存

```java
@Configuration
@EnableCaching
public class CacheConfig {
    
    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager("groupAuthorities");
        cacheManager.setCaffeine(Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterWrite(Duration.ofHours(1)));
        return cacheManager;
    }
}
```

## 🧪 测试集成

### 1. 启动应用

```bash
mvn spring-boot:run
```

### 2. 测试公开端点

```bash
curl http://localhost:8081/api/public/hello
```

### 3. 获取访问令牌

从 WeSpringAuthServer 获取访问令牌（参考 WeSpringAuthServer 文档）

### 4. 测试受保护端点

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8081/api/protected/user-info
```

## ❓ 常见问题

**Q: JWT 验证失败怎么办？**
A: 检查 `jwk-set-uri` 配置，确保 WeSpringAuthServer 正在运行

**Q: 权限不足错误？**
A: 检查用户权限配置，确认 JWT 中包含所需权限

**Q: 如何调试权限问题？**
A: 启用调试日志：
```yaml
logging:
  level:
    org.springframework.security: DEBUG
```

## 📚 更多资源

- [完整示例代码](../example-resource-server/)
- [WeSpringAuthServer 文档](../README.md)
- [Spring Security OAuth2 官方文档](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html)

---

🎉 **恭喜！** 您的应用现在已经成功集成了 WeSpringAuthServer！ 