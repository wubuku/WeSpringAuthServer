package org.dddml.ffvtraceability.auth.config;

import org.dddml.ffvtraceability.auth.authentication.*;
import org.dddml.ffvtraceability.auth.security.handler.CustomAuthenticationSuccessHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableConfigurationProperties(AuthStateProperties.class)
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    @Autowired
    private CorsConfigurationSource corsConfigurationSource;
    @Autowired
    private SmsAuthenticationProvider smsAuthenticationProvider;
    @Autowired
    private WechatAuthenticationProvider wechatAuthenticationProvider;
    @Autowired
    private UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;
    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

    /**
     * 配置SessionRegistry - OIDC logout端点的必要依赖
     * 用于跟踪用户的session信息，支持OpenID Connect logout功能
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain mobileApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/sms/**", "/wechat/**", "/api/sms/**")  // 微信小程序和移动端API
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // 无状态
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()  // 这些端点有自己的业务逻辑验证
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**", "/auth-srv/**", "/web-sms/**")  // Web管理界面API + 旧API路径
                .csrf(c -> c.disable())  // API禁用CSRF，因为前端会通过headers发送token
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))  // 支持session
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/web-sms/**").permitAll()  // Web SMS验证端点
                        // 新API路径 (/api/**) 权限配置
                        .requestMatchers("/api/users/**").hasAuthority("ROLE_ADMIN") // "Users_Read")
                        .requestMatchers("/api/groups/**").hasAuthority("ROLE_ADMIN") // "Roles_Read")
                        .requestMatchers("/api/authorities/**").hasAuthority("ROLE_ADMIN")
                        // 旧API路径 (/auth-srv/**) 权限配置 - 采用保守策略，全部需要ADMIN权限
                        .requestMatchers("/auth-srv/users/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/auth-srv/groups/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/auth-srv/authorities/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/auth-srv/password/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/auth-srv/password-tokens/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/auth-srv/emails/**").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()
                )
                .authenticationProvider(usernamePasswordAuthenticationProvider)
                .httpBasic(basic -> basic.realmName("FFV Auth Server API"));
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(s -> s
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        // 配置session并发控制，支持OIDC logout功能
                        .maximumSessions(10)  // 每个用户最多10个并发session
                        .sessionRegistry(sessionRegistry())  // 使用我们配置的SessionRegistry
                        .and()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**", "/oauth2/**", "/sms/**", "/wechat/**"))
                // 添加安全头配置，提升安全防护
                .headers(headers -> headers
                        .frameOptions().deny()  // 防止点击劫持
                        .contentTypeOptions().and()   // 防止MIME类型混淆攻击
                        // 注意：不设置HSTS，因为生产环境由负载均衡器处理HTTPS
                        .referrerPolicy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                                "/oauth2/**",
                                "/web-clients/oauth2/**",
                                "/login",
                                "/error",
                                "/oauth2-test",
                                "/oauth2-test-callback",
                                "/password/change",
                                "/",
                                "/static/**",
                                "/images/**",
                                "/css/**",
                                "/js/**",
                                "/favicon.ico",
                                "/sms/**",
                                "/wechat/**",
                                "/demo/**",
                                "/.well-known/**"
                        ).permitAll()
                        .requestMatchers("/user-management", "/auth-srv/user-management")
                        .hasAuthority("Users_Read")
                        .requestMatchers("/group-management", "/auth-srv/group-management")
                        .hasAuthority("Roles_Read")
                        .requestMatchers(
                                "/pre-register", "/pre-register/**", "/auth-srv/pre-register",
                                "/authority-settings",
                                "/authority-management/**",
                                "/auth-srv/authority-management/**"
                        ).hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()
                )
                .authenticationProvider(usernamePasswordAuthenticationProvider)
                .authenticationProvider(smsAuthenticationProvider)
                .authenticationProvider(wechatAuthenticationProvider)
                .formLogin(form -> form
                        .loginPage("/login")
                        .failureHandler(new UsernamePasswordAuthenticationFailureHandler())
                        .successHandler(authenticationSuccessHandler))

                // SMS认证配置 - 使用现代的 with() 方法替代过时的 apply()
                .with(new SmsAuthenticationConfigurer<>(), sms -> sms
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler(new SmsAuthenticationFailureHandler()))

                // 微信认证配置 - 使用现代的 with() 方法替代过时的 apply()
                .with(new WechatAuthenticationConfigurer<>(), wechat -> wechat
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler(new WechatAuthenticationFailureHandler()));

        return http.build();
    }
}