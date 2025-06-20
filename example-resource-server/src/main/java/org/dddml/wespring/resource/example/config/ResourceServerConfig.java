package org.dddml.wespring.resource.example.config;

import org.dddml.wespring.resource.example.security.CustomJwtAuthenticationConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 资源服务器安全配置
 * 
 * 这个配置类展示了如何配置一个OAuth2资源服务器来与WeSpringAuthServer配合工作。
 * 主要配置包括：
 * 1. JWT令牌验证
 * 2. 权限转换（从JWT中提取权限和组信息）
 * 3. CORS配置
 * 4. 方法级安全
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // 启用方法级安全，允许在Controller方法上使用@PreAuthorize等注解
public class ResourceServerConfig {

    @Autowired
    private CustomJwtAuthenticationConverter jwtAuthenticationConverter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 启用CORS
                .cors(withDefaults())
                // 禁用CSRF（因为使用JWT令牌）
                .csrf(AbstractHttpConfigurer::disable)
                // 配置URL级别的权限控制
                .authorizeHttpRequests(authorize -> authorize
                        // 公开API端点，无需认证
                        .requestMatchers("/api/public/**").permitAll()
                        // 管理API端点需要特定权限（也可以在方法上使用@PreAuthorize注解）
                        .requestMatchers("/api/admin/**").hasAnyAuthority("DIRECT_ADMIN_AUTH", "ROLE_ADMIN")
                        // 其他所有请求都需要认证
                        .anyRequest().authenticated()
                )
                // 配置OAuth2资源服务器
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                // 使用自定义的JWT认证转换器
                                // 这个转换器会从JWT中提取用户权限和组信息
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)
                        )
                );

        return http.build();
    }

    /**
     * CORS配置
     * 允许前端应用访问资源服务器API
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 允许的前端应用域名
        configuration.addAllowedOrigin("http://localhost:3000"); // React/Vue等前端应用
        configuration.addAllowedOrigin("http://localhost:8080"); // 其他前端应用
        
        // 允许所有HTTP方法
        configuration.addAllowedMethod("*");
        
        // 允许所有请求头
        configuration.addAllowedHeader("*");
        
        // 允许携带凭证（如果需要）
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
} 