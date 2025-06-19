package org.dddml.ffvtraceability.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.mvc.Controller;
import org.springframework.web.servlet.mvc.UrlFilenameViewController;

import java.util.Properties;

/**
 * API路径映射配置
 * 为解决前端页面使用 /api/ 前缀但后端使用 /auth-srv/ 前缀的问题
 * 通过URL重写实现路径映射
 */
@Configuration
public class ApiPathMappingConfig {

    // 由于Spring Boot的复杂性，我们采用更直接的方法：
    // 为每个API控制器创建额外的@RequestMapping注解
    // 这个配置类暂时保留，以便将来扩展其他URL映射功能
} 