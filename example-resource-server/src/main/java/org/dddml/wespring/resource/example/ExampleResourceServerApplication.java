package org.dddml.wespring.resource.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

/**
 * 示例资源服务器应用程序
 * 演示如何配置资源服务器与 WeSpringAuthServer 配合使用
 */
@SpringBootApplication
@EnableCaching
public class ExampleResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleResourceServerApplication.class, args);
    }
} 