package org.dddml.ffvtraceability.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Favicon控制器
 * 专门处理favicon.ico请求，避免重定向循环
 */
@Controller
public class FaviconController {

    @GetMapping("/favicon.ico")
    public ResponseEntity<Void> favicon() {
        // 返回204 No Content，避免重定向循环
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
} 