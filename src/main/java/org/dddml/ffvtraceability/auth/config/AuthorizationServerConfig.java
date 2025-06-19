package org.dddml.ffvtraceability.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties({JwtKeyProperties.class, AuthServerProperties.class})
public class AuthorizationServerConfig {
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    private final JwtKeyProperties jwtKeyProperties;
    private final AuthServerProperties authServerProperties;

    public AuthorizationServerConfig(JwtKeyProperties jwtKeyProperties, AuthServerProperties authServerProperties) {
        this.jwtKeyProperties = jwtKeyProperties;
        this.authServerProperties = authServerProperties;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class);


        authorizationServerConfigurer
                .clientAuthentication(clientAuth -> {
                    clientAuth.authenticationProviders(providers -> providers
                            .removeIf(provider -> provider.getClass().getSimpleName().startsWith("X509")));
                })
                .tokenGenerator(tokenGenerator())
                .oidc(Customizer.withDefaults());

        http.exceptionHandling((exceptionHandlingConfigurer) -> exceptionHandlingConfigurer
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        String[] origins = authServerProperties.getCors().getAllowedOrigins().split(",");
        configuration.setAllowedOriginPatterns(Arrays.asList(origins));

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-Requested-With",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"));

        configuration.setAllowCredentials(true);

        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);

        // 🎯 智能JWT定制器：兼容WeChat登录的安全解决方案
        // 根据测试结果和源码分析，采用防御性编程确保兼容性
        jwtGenerator.setJwtCustomizer(context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                try {
                    JwtClaimsSet.Builder claims = context.getClaims();
                    Authentication authentication = context.getPrincipal();

                    // 安全检查：确保AuthorizationServerContext存在
                    if (context.getAuthorizationServerContext() == null) {
                        logger.debug("AuthorizationServerContext is null, skipping JWT customization for safety");
                        return;
                    }

                    // 添加issuer字段 - 对资源服务器很重要
                    String issuer = authServerProperties.getIssuer();
                    if (issuer != null && !issuer.trim().isEmpty()) {
                        claims.issuer(issuer);
                        logger.debug("Added issuer to JWT: {}", issuer);
                    } else {
                        claims.issuer("http://localhost:9000");
                        logger.debug("Added default issuer to JWT");
                    }

                    // 安全地添加权限信息
                    if (authentication != null) {
                        try {
                            Set<String> authorities = authentication.getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .collect(Collectors.toSet());
                            if (!authorities.isEmpty()) {
                                claims.claim("authorities", authorities);
                                logger.debug("Added {} authorities to JWT", authorities.size());
                            }
                        } catch (Exception e) {
                            logger.debug("Failed to add authorities to JWT: {}", e.getMessage());
                        }

                        // 安全地添加组信息 - 从Authentication details中获取
                        try {
                            Object details = authentication.getDetails();
                            if (details instanceof Map) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> detailsMap = (Map<String, Object>) details;
                                if (detailsMap.containsKey("groups")) {
                                    Object groups = detailsMap.get("groups");
                                    if (groups != null) {
                                        claims.claim("groups", groups);
                                        logger.debug("Added groups to JWT: {}", groups);
                                    }
                                }
                            }
                        } catch (Exception e) {
                            logger.debug("Failed to add groups to JWT: {}", e.getMessage());
                        }
                    }

                    logger.debug("JWT customization completed successfully");
                } catch (Exception e) {
                    logger.warn("JWT customization failed, continuing without custom claims: {}", e.getMessage());
                    // 不抛出异常，让token生成继续进行
                }
            }
        });

        logger.info("智能JWT customizer已启用 - 对WeChat登录和标准OAuth2都安全兼容");

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * 配置OAuth2授权服务，使用专门的ObjectMapper确保正确的序列化/反序列化
     * <p>
     * 修改说明：
     * 1. 使用oauth2ObjectMapper替代通用ObjectMapper，避免序列化冲突
     * 2. 配置OAuth2AuthorizationParametersMapper，确保参数正确序列化
     * 3. 添加日志记录，便于调试和问题诊断
     * <p>
     * 这些修改主要解决了refresh token功能中的ObjectMapper配置问题，
     * 确保OAuth2Authorization对象能够正确保存和读取access_token字段
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository,
            ObjectMapper oauth2ObjectMapper) {

        logger.info("Creating OAuth2AuthorizationService with ObjectMapper: {}", oauth2ObjectMapper.getClass().getName());
        logger.info("ObjectMapper registered modules: {}", oauth2ObjectMapper.getRegisteredModuleIds());

        // 创建标准的ObjectMapper，避免activateDefaultTyping的兼容性问题
        ObjectMapper authServiceMapper = new ObjectMapper();
        authServiceMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        authServiceMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // 移除activateDefaultTyping - 这是造成序列化问题的根源
        // 使用Spring Security推荐的标准配置
        logger.info("AuthorizationService ObjectMapper configured with standard Spring Security modules");

        JdbcOAuth2AuthorizationService service = new JdbcOAuth2AuthorizationService(
                jdbcTemplate,
                registeredClientRepository);

        // 使用标准配置的ObjectMapper
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper rowMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository);
        rowMapper.setObjectMapper(authServiceMapper);
        service.setAuthorizationRowMapper(rowMapper);

        // 重要：也要设置参数映射器的ObjectMapper，确保完整的序列化支持
        JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper parametersMapper =
                new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
        parametersMapper.setObjectMapper(authServiceMapper);
        service.setAuthorizationParametersMapper(parametersMapper);

        logger.info("OAuth2AuthorizationService configured with standard Spring Security ObjectMapper");
        return service;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // 1. 加载 RSA 密钥对（私钥签名，公钥验证）
        KeyPair keyPair = loadKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 2. 构建 RSAKey（包含公钥和私钥）
        // 获取配置的密钥ID，如果没有配置则使用默认值
        String keyId = jwtKeyProperties.getKeyAlias() != null
                ? jwtKeyProperties.getKeyAlias() + "-jwk"
                : "ffv-jwt-key-2025";

        logger.info("JWT密钥ID设置为: {}", keyId);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)  // 私钥仅用于签名，不对外暴露
                .keyID(keyId)  // 使用稳定的密钥ID，基于配置生成
                .build();

        // 3. 包装为 JWKSet
        JWKSet jwkSet = new JWKSet(rsaKey);

        // 4. 返回 ImmutableJWKSet（不可变的安全实现）
        return new ImmutableJWKSet<>(jwkSet);
    }


    private KeyPair loadKeyPair() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(
                    jwtKeyProperties.getKeyStore().getInputStream(),
                    jwtKeyProperties.getKeyStorePassword().toCharArray());

            Key key = keyStore.getKey(
                    jwtKeyProperties.getKeyAlias(),
                    jwtKeyProperties.getPrivateKeyPassphrase().toCharArray());

            Certificate cert = keyStore.getCertificate(jwtKeyProperties.getKeyAlias());
            PublicKey publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, (PrivateKey) key);
        } catch (Exception e) {
            logger.error("Error loading JWT key pair", e);
            throw new RuntimeException("Could not load JWT key pair", e);
        }
    }

    /**
     * 配置 OAuth2 授权服务器设置，包括重要的 issuer 设置
     * <p>
     * issuer字段的重要性：
     * 1. JWT安全性 - 标识 token 的发行者，防止 token 被其他系统错误接受
     * 2. RFC 7519标准 - JWT 标准推荐包含 iss（issuer）字段
     * 3. 微服务环境 - 在多服务环境中识别 token 来源
     * 4. 审计和调试 - 帮助跟踪 token 的发行者
     * </p>
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        String issuer = authServerProperties.getIssuer();
        if (issuer == null || issuer.trim().isEmpty()) {
            logger.warn("AuthServer issuer is null or empty, using default: http://localhost:9000");
            issuer = "http://localhost:9000";
        }
        logger.info("AuthorizationServerSettings using issuer: {}", issuer);
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /*
     * @Bean
     * public ObjectMapper objectMapper() {
     * ObjectMapper mapper = new ObjectMapper();
     *
     * // 注册 Spring Security 核心模块
     * ClassLoader classLoader = getClass().getClassLoader();
     * List<com.fasterxml.jackson.databind.Module> securityModules =
     * SecurityJackson2Modules.getModules(classLoader);
     * mapper.registerModules(securityModules);
     *
     * // 注册 OAuth2 相关的模块
     * mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
     *
     * // 注册我们的自定义模块
     * mapper.registerModule(new CustomJacksonModule());
     *
     * return mapper;
     * }
     */

}