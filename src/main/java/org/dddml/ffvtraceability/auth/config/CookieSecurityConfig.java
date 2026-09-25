package org.dddml.ffvtraceability.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cookie安全配置
 * 实现方案A：子域名共享Cookie策略
 * 
 * 解决OAuth2安全问题：
 * 1. client_secret 完全后端化
 * 2. refresh_token 使用HttpOnly Cookie存储
 * 3. 支持跨子域名Cookie共享（.company.com）
 * 
 * @author WeSpringAuthServer
 * @since 2024-01-XX
 */
@Configuration
@EnableConfigurationProperties
public class CookieSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(CookieSecurityConfig.class);

    /**
     * Cookie帮助工具类
     * 负责HttpOnly Cookie的设置和获取
     */
    @Component
    public static class CookieHelper {
        
        private static final Logger logger = LoggerFactory.getLogger(CookieHelper.class);
        
        @Value("${oauth2.cookie.domain:}")
        private String domain;
        
        @Value("${oauth2.cookie.secure:false}")
        private boolean secure;
        
        @Value("${oauth2.cookie.same-site:Lax}")
        private String sameSite;

        @PostConstruct
        public void init() {
            logger.info("🍪 Cookie配置初始化 - Domain: {}, Secure: {}, SameSite: {}", 
                       domain.isEmpty() ? "[不设置域名]" : domain, secure, sameSite);
        }
        
        /**
         * 设置refresh_token的HttpOnly Cookie
         */
        public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
            logger.debug("🍪 设置refresh_token Cookie - Domain: {}, Secure: {}", 
                        domain.isEmpty() ? "[不设置域名]" : domain, secure);
            
            ResponseCookie cookie;
            if (!domain.isEmpty()) {
                cookie = ResponseCookie.from("refresh_token", refreshToken)
                        .httpOnly(true)
                        .secure(secure)
                        .sameSite(sameSite)
                        .domain(domain)
                        .path("/")
                        .maxAge(Duration.ofDays(30)) // 30天有效期
                        .build();
            } else {
                cookie = ResponseCookie.from("refresh_token", refreshToken)
                        .httpOnly(true)
                        .secure(secure)
                        .sameSite(sameSite)
                        .path("/")
                        .maxAge(Duration.ofDays(30)) // 30天有效期
                        .build();
            }
            
            response.addHeader("Set-Cookie", cookie.toString());
            
            logger.debug("🍪 Cookie已设置: name=refresh_token, secure={}, sameSite={}", secure, sameSite);
        }
        
        /**
         * 从请求中获取refresh_token Cookie
         */
        public String getRefreshTokenFromCookie(HttpServletRequest request) {
            logger.debug("🍪 尝试从Cookie读取refresh_token...");
            
            if (request.getCookies() != null) {
                logger.debug("🍪 找到 {} 个Cookie", request.getCookies().length);
                
                for (Cookie cookie : request.getCookies()) {
                    logger.debug("🍪 检查Cookie: {} (domain: {}, path: {})",
                               cookie.getName(), 
                               cookie.getDomain(), 
                               cookie.getPath());
                    
                    if ("refresh_token".equals(cookie.getName())) {
                        logger.debug("🍪 ✅ 找到refresh_token Cookie");
                        return cookie.getValue();
                    }
                }
                
                logger.warn("🍪 ❌ 在 {} 个Cookie中未找到refresh_token", request.getCookies().length);
            } else {
                logger.warn("🍪 ❌ 请求中没有任何Cookie");
            }
            
            return null;
        }
        
        /**
         * 清除refresh_token Cookie
         */
        public void clearRefreshTokenCookie(HttpServletResponse response) {
            logger.debug("🍪 清除refresh_token Cookie");
            
            ResponseCookie cookie;
            if (!domain.isEmpty()) {
                cookie = ResponseCookie.from("refresh_token", "")
                        .httpOnly(true)
                        .secure(secure)
                        .sameSite(sameSite)
                        .domain(domain)
                        .path("/")
                        .maxAge(Duration.ZERO) // 立即过期
                        .build();
            } else {
                cookie = ResponseCookie.from("refresh_token", "")
                        .httpOnly(true)
                        .secure(secure)
                        .sameSite(sameSite)
                        .path("/")
                        .maxAge(Duration.ZERO) // 立即过期
                        .build();
            }
            
            response.addHeader("Set-Cookie", cookie.toString());
        }
    }

    @Bean
    public CookieHelper cookieHelper() {
        return new CookieHelper();
    }

    /**
     * 设置refresh_token的HttpOnly Cookie
     */
    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        cookieHelper().setRefreshTokenCookie(response, refreshToken);
    }
    
    /**
     * 从请求中获取refresh_token Cookie
     */
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        return cookieHelper().getRefreshTokenFromCookie(request);
    }
    
    /**
     * 清除refresh_token Cookie
     */
    public void clearRefreshTokenCookie(HttpServletResponse response) {
        cookieHelper().clearRefreshTokenCookie(response);
    }

    /**
     * Cookie安全配置管理器
     * 从配置文件中读取并管理Cookie安全属性
     */
    @Component
    public static class CookieSecurityConfigManager {
        
        private static final Logger logger = LoggerFactory.getLogger(CookieSecurityConfigManager.class);
        
        // Cookie域名设置（支持跨子域名）
        @Value("${oauth2.cookie.domain:}")
        private String cookieDomain;
        
        // Cookie安全标志（生产环境必须为true）
        @Value("${oauth2.cookie.secure:false}")
        private boolean cookieSecure;
        
        // Cookie SameSite策略
        @Value("${oauth2.cookie.same-site:Lax}")
        private String cookieSameSite;
        
        // Cookie过期时间（秒）
        @Value("${oauth2.cookie.max-age:2592000}")
        private int cookieMaxAge;

        @PostConstruct
        public void init() {
            logger.info("🔒 Cookie安全配置管理器初始化完成: {}", this.toString());
            // 配置验证和初始化逻辑
            validateConfiguration();
        }

        /**
         * 验证配置的合理性
         */
        private void validateConfiguration() {
            // 验证SameSite值
            if (!isValidSameSiteValue(cookieSameSite)) {
                throw new IllegalArgumentException("Invalid SameSite value: " + cookieSameSite + 
                    ". Must be one of: None, Lax, Strict");
            }
            
            // 验证MaxAge
            if (cookieMaxAge <= 0) {
                throw new IllegalArgumentException("Cookie max-age must be positive: " + cookieMaxAge);
            }
            
            // 安全检查：生产环境必须启用Secure
            if (!cookieDomain.isEmpty() && !cookieDomain.equals(".localhost")) {
                // 生产环境配置 - 确保使用安全设置
                if (!cookieSecure) {
                    logger.warn("⚠️  Cookie Secure flag is disabled in production environment!");
                }
            }
        }

        /**
         * 验证SameSite值是否有效
         */
        private boolean isValidSameSiteValue(String sameSite) {
            return "None".equalsIgnoreCase(sameSite) || 
                   "Lax".equalsIgnoreCase(sameSite) || 
                   "Strict".equalsIgnoreCase(sameSite);
        }

        // Getter方法
        public String getCookieDomain() {
            return cookieDomain;
        }

        public boolean isCookieSecure() {
            return cookieSecure;
        }

        public String getCookieSameSite() {
            return cookieSameSite;
        }

        public int getCookieMaxAge() {
            return cookieMaxAge;
        }

        /**
         * 生成Cookie属性字符串（用于调试）
         */
        public String getCookieAttributesString() {
            return String.format("Domain=%s; Secure=%s; SameSite=%s; MaxAge=%d; HttpOnly=true",
                cookieDomain.isEmpty() ? "[不设置]" : cookieDomain, cookieSecure, cookieSameSite, cookieMaxAge);
        }

        @Override
        public String toString() {
            return String.format("CookieSecurityConfig{domain='%s', secure=%s, sameSite='%s', maxAge=%d}",
                cookieDomain.isEmpty() ? "[不设置域名]" : cookieDomain, cookieSecure, cookieSameSite, cookieMaxAge);
        }
    }
} 