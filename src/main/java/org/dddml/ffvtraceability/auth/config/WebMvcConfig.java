package org.dddml.ffvtraceability.auth.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dddml.ffvtraceability.auth.jackson.CustomJacksonModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Web MVC配置类
 * <p>
 * 重要说明：
 * 1. oauth2ObjectMapper - 专用于OAuth2序列化，现在包含HashSet支持以处理CustomUserDetails
 * 2. defaultObjectMapper - 通用ObjectMapper，包含CustomJacksonModule以支持CustomUserDetails等
 * <p>
 * 这种双重策略确保OAuth2功能正常工作，同时保持对CustomUserDetails的序列化支持
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(WebMvcConfig.class);

    /**
     * OAuth2专用ObjectMapper - 使用安全的allowlist机制
     * 解决LinkedHashMap转换OAuth2AuthorizationRequest的问题
     * <p>
     * 参考：Spring Security GitHub issue #15491
     */
    @Bean
    public ObjectMapper oauth2ObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();

        // 注册Spring Security和OAuth2相关的模块
        objectMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // 关键修复：注册我们的安全OAuth2模块来解决LinkedHashMap转换问题
        objectMapper.registerModule(new org.dddml.ffvtraceability.auth.jackson.OAuth2SecurityJacksonModule());

        logger.info("OAuth2ObjectMapper configured with OAuth2SecurityJacksonModule for safe deserialization");

        return objectMapper;
    }

    /**
     * 默认ObjectMapper - 包含CustomJacksonModule
     * 用于通用序列化需求
     */
    @Bean
    @Primary
    public ObjectMapper defaultObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.registerModule(new CustomJacksonModule());  // 支持CustomUserDetails
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    /**
     * 配置HTTP消息转换器
     */
    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new MappingJackson2HttpMessageConverter(defaultObjectMapper()));
    }

    /**
     * 配置CORS
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}

