package org.dddml.ffvtraceability.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 处理Chrome DevTools自动工作空间文件夹功能的请求
 * 避免404错误影响日志和重定向逻辑
 */
@RestController
public class ChromeDevToolsController {

    @GetMapping("/.well-known/appspecific/com.chrome.devtools.json")
    public ResponseEntity<Map<String, Object>> handleDevToolsWorkspace() {
        // 返回空的工作空间配置，Chrome会正常处理
        // 这样可以避免404错误，同时不启用任何特殊功能
        return ResponseEntity.ok(Map.of(
            "workspace", Map.of(
                "root", "",
                "uuid", ""
            )
        ));
    }
} 