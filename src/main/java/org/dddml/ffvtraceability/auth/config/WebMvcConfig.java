package org.dddml.ffvtraceability.auth.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.dddml.ffvtraceability.auth.jackson.CustomJacksonModule;
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
 * 
 * 重要说明：
 * 1. oauth2ObjectMapper - 专用于OAuth2序列化，不包含CustomJacksonModule以避免干扰
 * 2. defaultObjectMapper - 通用ObjectMapper，包含CustomJacksonModule以支持CustomUserDetails等
 * 
 * 这种双重策略确保OAuth2功能正常工作，同时保持对CustomUserDetails的序列化支持
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     * OAuth2专用ObjectMapper - 不包含可能干扰的自定义模块
     * 专门用于OAuth2Authorization的序列化/反序列化
     */
    @Bean
    public ObjectMapper oauth2ObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        // 只注册Spring Security和OAuth2相关的模块
        objectMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        // 重要：不包含CustomJacksonModule，避免JsonTypeInfo干扰OAuth2序列化
        return objectMapper;
    }

    /**
     * 默认ObjectMapper - 包含所有必要的模块和原有配置
     * 用于一般的JSON序列化，包括CustomUserDetails
     * 
     * 重要：保持@Primary以确保其他地方的正常功能不受影响
     * 包含原来restApiObjectMapper的所有重要配置以确保向后兼容
     */
    @Bean
    @Primary
    public ObjectMapper defaultObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        
        // 原有的重要配置 - 确保不破坏现有功能
        // 注册 Java 8 时间模块（支持 LocalDateTime 等）
        objectMapper.registerModule(new JavaTimeModule());
        // 禁用反序列化时未知属性的警告
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        // 禁用日期时间戳格式（使用 ISO-8601 格式）
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                // 禁用空 Bean 序列化失败
                .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
                // 禁用默认的类型信息（防止安全漏洞）
                .setDefaultTyping(null);  // 关键：禁用类型信息
        
        // 注册Spring Security和Custom模块（为REST API优化配置）
        // 注意：故意不包含OAuth2AuthorizationServerJackson2Module以避免冲突
        // 因为：
        // 1. 一般REST API不需要序列化OAuth2Authorization对象
        // 2. OAuth2Authorization序列化由专用的oauth2ObjectMapper处理
        // 3. 避免CustomJacksonModule的@JsonTypeInfo与OAuth2模块冲突
        objectMapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
        objectMapper.registerModule(new CustomJacksonModule()); // 保留以支持CustomUserDetails
        return objectMapper;
    }

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        // 移除所有现有的 JSON 转换器
        converters.removeIf(converter -> converter instanceof MappingJackson2HttpMessageConverter);

        // 添加我们的 REST API 转换器
        MappingJackson2HttpMessageConverter restApiConverter = new MappingJackson2HttpMessageConverter(defaultObjectMapper());
        converters.add(0, restApiConverter);  // 添加到第一位，确保优先使用
    }
}

