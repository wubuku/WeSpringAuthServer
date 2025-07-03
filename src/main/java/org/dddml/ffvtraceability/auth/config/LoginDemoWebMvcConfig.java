package org.dddml.ffvtraceability.auth.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Web配置类
 * 配置静态资源服务和SMS登录演示页面的路由
 */
@Configuration
public class LoginDemoWebMvcConfig implements WebMvcConfigurer {

    /**
     * 配置静态资源处理器
     * 添加SMS登录演示的静态资源映射
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 添加SMS登录演示的静态资源映射
        registry.addResourceHandler("/demo/**")
                .addResourceLocations("file:" + getSmsLoginDemoPath() + "/")
                .setCachePeriod(0); // 开发环境不缓存，便于调试
    }

    /**
     * 获取SMS登录演示的路径
     *
     * @return 演示文件的绝对路径
     */
    private String getSmsLoginDemoPath() {
        // 获取项目根目录下的sms-login-demo路径
        String projectRoot = System.getProperty("user.dir");
        return projectRoot + "/sms-login-demo";
    }

    /**
     * SMS登录演示控制器
     */
    @Controller
    public static class SmsLoginDemoController {

        /**
         * 服务SMS登录演示页面
         * 支持 /demo 和 /demo/ 路径访问
         */
        @GetMapping({"/demo", "/demo/"})
        @ResponseBody
        public void serveSmsLoginDemo(HttpServletResponse response) throws IOException {
            try {
                String projectRoot = System.getProperty("user.dir");
                Path indexPath = Paths.get(projectRoot, "sms-login-demo", "index.html");

                if (!Files.exists(indexPath)) {
                    response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                    response.getWriter().write("SMS Login Demo not found. Please ensure sms-login-demo/index.html exists.");
                    return;
                }

                // 设置响应头
                response.setContentType(MediaType.TEXT_HTML_VALUE);
                response.setCharacterEncoding("UTF-8");

                // 读取并返回文件内容
                String content = Files.readString(indexPath);
                response.getWriter().write(content);

            } catch (Exception e) {
                // 记录错误但不暴露详细信息
                System.err.println("Error serving SMS login demo: " + e.getMessage());
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Internal server error");
            }
        }
    }
} 