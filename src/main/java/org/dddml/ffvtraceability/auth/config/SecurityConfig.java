package org.dddml.ffvtraceability.auth.config;

import jakarta.servlet.Filter;
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

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(s -> s
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(c -> c.disable())
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
                                    "/js/**"
                                ).permitAll()
                                .requestMatchers("/user-management")
                                    .hasAuthority("Users_Read")
                                .requestMatchers("/group-management")
                                    .hasAuthority("Roles_Read")
                                .requestMatchers(
                                    "/pre-register/**",
                                    "/authority-management/**"
                                )
                                    .hasAuthority("ROLE_ADMIN")
                                .anyRequest().authenticated()
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
        SecurityFilterChain securityFilterChain = http.build();
        for (Filter filter : securityFilterChain.getFilters()) {
            if (filter instanceof SmsAuthenticationFilter || filter instanceof WechatAuthenticationFilter) {
                securityFilterChain.getFilters().remove(filter);
                break;
            }
        }
        return securityFilterChain;
    }
}