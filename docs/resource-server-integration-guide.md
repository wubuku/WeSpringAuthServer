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

> ⚠️ **双数据源配置重要说明**
> 
> 如果您需要使用组权限功能，你可能想要配置**双数据源**：业务数据源 + 权限查询数据源

**基础配置（仅JWT验证，无组权限）**：
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # 替换为您的 WeSpringAuthServer 地址
          jwk-set-uri: http://localhost:9000/oauth2/jwks
```

**完整配置（支持组权限的双数据源）**：
```yaml
spring:
  # 业务数据源配置（主数据源）
  datasource:
    url: jdbc:postgresql://localhost:5432/your_business_db
    username: your_username
    password: your_password
    # driver-class-name 通常由Spring Boot自动推断

  security:
    # 权限查询专用数据源配置
    datasource:
      url: jdbc:postgresql://localhost:5432/your_auth_db
      username: your_username  
      password: your_password
      driver-class-name: org.postgresql.Driver  # 建议显式指定
    oauth2:
      resourceserver:
        jwt:
          # 替换为您的 WeSpringAuthServer 地址
          jwk-set-uri: http://localhost:9000/oauth2/jwks
          
  # 权限缓存配置（推荐启用）
  cache:
    caffeine:
      spec: maximumSize=200,expireAfterWrite=1800s  # 30分钟过期

# 调试日志配置（开发阶段推荐）
logging:
  level:
    org.springframework.security: DEBUG
    # 您的权限相关包名: DEBUG
```

> 💡 **配置说明**：
> - **业务数据源**：`spring.datasource` - 用于您的主要业务数据
> - **权限数据源**：`spring.security.datasource` - 专门查询用户组权限
> - **两个数据源可以指向同一个数据库**，但配置必须分开声明
> - **缓存配置**：建议启用，可显著减少权限查询的数据库压力

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
        
        // 记录转换开始
        logger.debug("Converting JWT to Authentication for subject: {}", jwt.getSubject());
        
        // 1. 添加直接权限
        Set<String> directAuthorities = getClaimAsSet(jwt, "authorities");
        logger.debug("Direct authorities from JWT: {}", directAuthorities);
        directAuthorities.stream()
            .map(SimpleGrantedAuthority::new)
            .forEach(authorities::add);
            
        // 2. 从组恢复权限
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

> ⚠️ **重要提醒 - 双数据源配置陷阱**
> 
> 如果直接使用 `DataSourceBuilder.create().build()` 配置双数据源，**很可能遇到启动错误**：
> ```
> jdbcUrl is required with driverClassName
> ```
> 
> **正确的做法是使用 `DataSourceProperties`**，这是参考成功项目总结的最佳实践：

```java
@Configuration
@EnableTransactionManagement  // 启用事务管理
public class SecurityDataSourceConfig {
    
    /**
     * 业务数据源属性配置
     * 使用 DataSourceProperties 确保配置正确绑定
     */
    @Primary
    @Bean
    @ConfigurationProperties("spring.datasource")
    public DataSourceProperties businessDataSourceProperties() {
        return new DataSourceProperties();
    }
    
    /**
     * 安全数据源属性配置
     * 专门用于权限查询
     */
    @Bean
    @ConfigurationProperties("spring.security.datasource")
    public DataSourceProperties securityDataSourceProperties() {
        return new DataSourceProperties();
    }
    
    /**
     * 业务数据源（主数据源）
     * 必须标记为 @Primary 避免Spring Boot自动配置冲突
     */
    @Primary
    @Bean
    public DataSource businessDataSource(
            @Qualifier("businessDataSourceProperties") DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().build();
    }
    
    /**
     * 安全数据源（权限查询专用）
     * 通过 initializeDataSourceBuilder() 确保配置正确
     */
    @Bean
    public DataSource securityDataSource(
            @Qualifier("securityDataSourceProperties") DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().build();
    }
    
    /**
     * 业务数据源的JdbcTemplate（主）
     */
    @Primary
    @Bean
    public JdbcTemplate jdbcTemplate(@Qualifier("businessDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
    
    /**
     * 安全数据源的JdbcTemplate（权限查询专用）
     * 注意Bean名称要与GroupAuthorityService中的@Qualifier匹配
     */
    @Bean("securityJdbcTemplate")
    public JdbcTemplate securityJdbcTemplate(@Qualifier("securityDataSource") DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
    
    /**
     * 业务数据源事务管理器（主）
     * 标记为 @Primary，确保默认 @Transactional 使用此事务管理器
     */
    @Primary
    @Bean
    public PlatformTransactionManager businessTransactionManager(
            @Qualifier("businessDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }
    
    /**
     * 安全数据源事务管理器
     * 权限查询专用，通常配置为只读事务
     */
    @Bean("securityTransactionManager")
    public PlatformTransactionManager securityTransactionManager(
            @Qualifier("securityDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }
}
```

**配置文件对应关系**：
```yaml
spring:
  # 业务数据源配置（主）
  datasource:
    url: jdbc:postgresql://localhost:5432/your_business_db
    username: your_username
    password: your_password
    # driver-class-name 可选，Spring Boot会自动推断

  security:
    # 安全权限查询专用数据源配置
    datasource:
      url: jdbc:postgresql://localhost:5432/your_auth_db
      username: your_username
      password: your_password
      driver-class-name: org.postgresql.Driver  # 建议显式指定
```

> 💡 **技术要点总结**：
> 1. **使用 `DataSourceProperties`**：确保配置属性正确绑定到数据源，避免Spring Boot自动配置问题
> 2. **`@Primary` 注解必须**：多数据源环境下必须明确指定主数据源
> 3. **`initializeDataSourceBuilder().build()`**：这是创建数据源的正确方式
> 4. **配置路径安全**：`spring.security.datasource` 路径不会与Spring Boot默认配置冲突
> 5. **Bean命名一致性**：确保JdbcTemplate的Bean名称与服务层的@Qualifier注解匹配
> 6. **事务管理器必须手动配置**：多数据源场景下Spring Boot不会自动配置事务管理器

### ⚠️ **重要：多数据源事务管理说明**

> **关键理解**：Spring Boot 只在**单一数据源**场景下自动配置事务管理器。一旦定义多个 DataSource，必须手动配置事务管理器，否则 `@Transactional` 注解将失效！

**为什么需要手动配置事务管理器？**

1. **单数据源场景**：Spring Boot 自动创建 `DataSourceTransactionManager`
2. **多数据源场景**：Spring Boot 无法确定应该为哪个数据源创建事务管理器，因此跳过自动配置
3. **解决方案**：手动为每个数据源定义对应的 `PlatformTransactionManager`

**对现有代码的影响最小化**：

- ✅ **业务代码中的 `@Transactional`**：无需修改，会自动使用 `@Primary` 标记的事务管理器
- ✅ **权限查询事务**：需要时可以使用 `@Transactional("securityTransactionManager")`

**实际使用示例**：

```java
@Service
public class YourBusinessService {
    
    // 使用默认（主）事务管理器，无需修改
    @Transactional
    public void businessOperation() {
        // 业务操作
    }
}

@Service  
public class SecurityAuditService {
    
    // 使用安全数据源事务管理器
    @Transactional("securityTransactionManager")
    public void logSecurityEvent() {
        // 安全审计日志
    }
    
    // 只读事务优化
    @Transactional(value = "securityTransactionManager", readOnly = true)
    public List<String> getAuditLogs() {
        // 查询审计日志
    }
}
```

2. **创建组权限服务**（数据库查询示例）：
```java
@Service
public class GroupAuthorityService {
    
    private static final Logger logger = LoggerFactory.getLogger(GroupAuthorityService.class);
    
    @Autowired
    @Qualifier("securityJdbcTemplate")  // 使用专用的安全数据源
    private JdbcTemplate securityJdbcTemplate;
    
    /**
     * 获取指定组的所有权限
     * 
     * @param groupName 组名（包含GROUP_前缀，如"GROUP_ADMIN_GROUP"）
     * @return 该组拥有的所有权限集合
     */
    @Cacheable(value = "groupAuthorities", key = "#groupName")
    public Set<String> getGroupAuthorities(String groupName) {
        logger.info("Cache MISS - Loading authorities from database for group: {}", groupName);
        
        // 查询组权限的SQL（基于生产环境的实际实现）
        // group_authorities表直接存储权限字符串，无需关联authority_definitions表
        String sql = """
            SELECT authority 
            FROM group_authorities ga 
            JOIN groups g ON ga.group_id = g.id 
            WHERE g.group_name = ?
            """;
        // 假设不使用 authority_definitions 表。
        /*
        String sql = """
            SELECT ad.authority_name 
            FROM group_authority_definitions gad
            JOIN groups g ON gad.group_id = g.id 
            JOIN authority_definitions ad ON gad.authority_definition_id = ad.id
            WHERE g.group_name = ?
            """;
        */
        // 移除GROUP_前缀来匹配数据库中的组名
        // WeSpringAuthServer在JWT中使用GROUP_前缀，但数据库中存储的是不带前缀的组名
        Set<String> authorities = new HashSet<>(securityJdbcTemplate.queryForList(sql, String.class,
            groupName.replace("GROUP_", "")));
        
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

### 🔧 双数据源配置问题

**Q: 应用启动失败，报错 "jdbcUrl is required with driverClassName"？**
A: 这是双数据源配置的常见陷阱！解决方案：
- ❌ 错误做法：直接使用 `DataSourceBuilder.create().build()`
- ✅ 正确做法：使用 `DataSourceProperties` + `initializeDataSourceBuilder().build()`
- 参考本文档中的 "双数据源配置陷阱" 部分

**Q: 启动时提示找不到主数据源？**
A: 确保业务数据源标记了 `@Primary` 注解：
```java
@Primary
@Bean
public DataSource businessDataSource(...) { ... }
```

**Q: SecurityJdbcTemplate 注入失败？**
A: 检查Bean名称是否匹配：
```java
// 配置类中
@Bean("securityJdbcTemplate")
public JdbcTemplate securityJdbcTemplate(...) { ... }

// 服务类中
@Qualifier("securityJdbcTemplate")
private JdbcTemplate securityJdbcTemplate;
```

**Q: @Transactional 注解突然不生效了？**
A: 这是多数据源的经典问题！解决方案：
- **原因**：Spring Boot 检测到多个 DataSource 后，不再自动配置事务管理器
- **解决**：手动添加事务管理器 Bean，并为主数据源标记 `@Primary`
- **验证**：检查是否添加了 `@EnableTransactionManagement` 注解

### 🔍 JWT 和权限问题

**Q: JWT 验证失败怎么办？**
A: 检查 `jwk-set-uri` 配置，确保 WeSpringAuthServer 正在运行

**Q: 权限不足错误？**
A: 检查用户权限配置，确认 JWT 中包含所需权限

**Q: 组权限没有生效？**
A: 检查以下几点：
1. JWT 中是否包含 "groups" claim
2. CustomJwtAuthenticationConverter 是否正确注册
3. GroupAuthorityService 是否能正常查询数据库
4. 查看调试日志确认权限转换过程

**Q: 如何调试权限问题？**
A: 启用调试日志：
```yaml
logging:
  level:
    org.springframework.security: DEBUG
    # 您的权限相关包: DEBUG
```

### 📊 性能和缓存问题

**Q: 权限查询太频繁，影响数据库性能？**
A: 启用缓存配置：
```yaml
spring:
  cache:
    caffeine:
      spec: maximumSize=200,expireAfterWrite=1800s
```

**Q: 如何监控缓存效果？**
A: 查看 GroupAuthorityService 日志中的 "Cache MISS" 信息，正常情况下应该很少出现

## 🚨 重要提醒：双数据源配置最佳实践

> ⚠️ **这是最容易踩坑的地方，请务必注意！**

### 关键成功要素

1. **使用 DataSourceProperties**（必须）
   ```java
   // ✅ 正确做法
   @Bean
   @ConfigurationProperties("spring.security.datasource")
   public DataSourceProperties securityDataSourceProperties() {
       return new DataSourceProperties();
   }
   
   @Bean
   public DataSource securityDataSource(DataSourceProperties properties) {
       return properties.initializeDataSourceBuilder().build();
   }
   ```

2. **标记主数据源**（必须）
   ```java
   // ✅ 必须添加 @Primary
   @Primary
   @Bean
   public DataSource businessDataSource(...) { ... }
   ```

3. **配置路径安全**
   ```yaml
   # ✅ 安全的配置路径，不会冲突
   spring:
     datasource: # 业务数据源
     security:
       datasource: # 权限数据源
   ```

### 常见错误（务必避免）

❌ **错误一：直接使用 DataSourceBuilder**
```java
// 这样配置会导致启动失败！
@Bean
public DataSource securityDataSource() {
    return DataSourceBuilder.create().build();
}
```

❌ **错误二：忘记 @Primary 注解**
```java
// 会导致 Spring Boot 不知道使用哪个数据源作为主数据源
@Bean
public DataSource businessDataSource(...) { ... }  // 缺少 @Primary
```

❌ **错误三：Bean 名称不匹配**
```java
// 配置类
@Bean("myJdbcTemplate")  // 名称A
public JdbcTemplate jdbcTemplate(...) { ... }

// 服务类
@Qualifier("securityJdbcTemplate")  // 名称B - 不匹配！
private JdbcTemplate jdbcTemplate;
```

### 验证配置成功

启动应用后，检查日志中是否有以下信息：
```
✅ DataSource successfully initialized
✅ Multiple DataSource beans found, using primary
✅ SecurityJdbcTemplate bean created successfully
```

如果看到以下错误，说明配置有问题：
```
❌ jdbcUrl is required with driverClassName
❌ No qualifying bean of type 'javax.sql.DataSource'
❌ No qualifying bean of type 'org.springframework.jdbc.core.JdbcTemplate'
```

## 📚 更多资源

- [完整示例代码](../example-resource-server/)
- [WeSpringAuthServer 文档](../README.md)
- [Spring Security OAuth2 官方文档](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html)
- [Spring Boot 多数据源官方指南](https://spring.io/guides/gs/accessing-data-mysql/)

---

🎉 **恭喜！** 您的应用现在已经成功集成了 WeSpringAuthServer！

> 💡 **提示**：如果在配置过程中遇到问题，请优先检查双数据源配置部分，这是最容易出错的地方。参考本文档中的最佳实践，可以避免99%的常见问题！ 