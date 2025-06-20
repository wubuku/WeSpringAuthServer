package org.dddml.wespring.resource.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * 示例控制器
 * 
 * 展示如何在资源服务器中实现不同级别的权限控制：
 * 1. 公开端点（无需认证）
 * 2. 需要认证的端点
 * 3. 需要特定权限的端点（使用@PreAuthorize注解）
 * 4. 管理员专用端点
 */
@RestController
@RequestMapping("/api")
public class ExampleController {

    /**
     * 公开端点 - 无需认证
     */
    @GetMapping("/public/hello")
    public Map<String, Object> publicHello() {
        return Map.of(
            "message", "Hello from public endpoint!",
            "timestamp", System.currentTimeMillis(),
            "authentication", "not required"
        );
    }

    /**
     * 需要认证的端点
     */
    @GetMapping("/protected/user-info")
    public Map<String, Object> userInfo(Authentication authentication) {
        return Map.of(
            "message", "Hello authenticated user!",
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()),
            "timestamp", System.currentTimeMillis()
        );
    }

    /**
     * 需要特定权限的端点 - 用户读取权限
     */
    @GetMapping("/protected/users")
    @PreAuthorize("hasAuthority('Users_Read')")
    public Map<String, Object> getUsers(Authentication authentication) {
        return Map.of(
            "message", "Users data (requires Users_Read permission)",
            "username", authentication.getName(),
            "data", "This would be user list data...",
            "timestamp", System.currentTimeMillis()
        );
    }

    /**
     * 需要特定权限的端点 - 角色读取权限
     */
    @GetMapping("/protected/roles")
    @PreAuthorize("hasAuthority('Roles_Read')")
    public Map<String, Object> getRoles(Authentication authentication) {
        return Map.of(
            "message", "Roles data (requires Roles_Read permission)",
            "username", authentication.getName(),
            "data", "This would be roles list data...",
            "timestamp", System.currentTimeMillis()
        );
    }

    /**
     * 管理员专用端点 - 需要ROLE_ADMIN权限
     */
    @GetMapping("/admin/system-info")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Map<String, Object> getSystemInfo(Authentication authentication) {
        return Map.of(
            "message", "System information (admin only)",
            "username", authentication.getName(),
            "systemInfo", Map.of(
                "javaVersion", System.getProperty("java.version"),
                "osName", System.getProperty("os.name"),
                "availableProcessors", Runtime.getRuntime().availableProcessors(),
                "maxMemory", Runtime.getRuntime().maxMemory()
            ),
            "timestamp", System.currentTimeMillis()
        );
    }

    /**
     * 管理员专用端点 - 可以通过URL路径权限控制（在SecurityConfig中配置）
     */
    @GetMapping("/admin/cache-stats")
    public Map<String, Object> getCacheStats(Authentication authentication) {
        return Map.of(
            "message", "Cache statistics (admin only - protected by URL pattern)",
            "username", authentication.getName(),
            "cacheStats", "This would show cache statistics...",
            "timestamp", System.currentTimeMillis()
        );
    }

    /**
     * 需要组合权限的端点
     */
    @GetMapping("/protected/user-management")
    @PreAuthorize("hasAuthority('Users_Read') and hasAuthority('Users_Write')")
    public Map<String, Object> userManagement(Authentication authentication) {
        return Map.of(
            "message", "User management (requires both Users_Read and Users_Write)",
            "username", authentication.getName(),
            "data", "This would be user management interface...",
            "timestamp", System.currentTimeMillis()
        );
    }
} 