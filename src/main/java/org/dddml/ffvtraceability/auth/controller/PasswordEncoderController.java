package org.dddml.ffvtraceability.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 密码编码工具API
 * 
 * 🔒 安全注意：
 * - 仅在开发环境启用 (@Profile("dev"))
 * - 生产环境自动禁用
 * - 用于系统初始化和测试阶段的密码生成
 */
@RestController
@RequestMapping("/dev-tools/password-encoder")
@Profile("dev")  // 🔒 仅开发环境启用
@ConditionalOnProperty(
    name = "auth-server.dev-tools.enabled", 
    havingValue = "true", 
    matchIfMissing = true  // 开发环境默认启用
)
public class PasswordEncoderController {
    
    private static final Logger logger = LoggerFactory.getLogger(PasswordEncoderController.class);
    private final PasswordEncoder passwordEncoder;
    
    public PasswordEncoderController() {
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    
    /**
     * 编码单个密码
     * 
     * @param request 包含原始密码的请求
     * @return 编码后的密码
     */
    @PostMapping("/encode")
    public ResponseEntity<Map<String, Object>> encodePassword(@RequestBody PasswordRequest request) {
        logger.info("Password encoding request received for development purposes");
        
        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Password cannot be empty",
                "success", false
            ));
        }
        
        String rawPassword = request.getPassword();
        String encodedPassword = passwordEncoder.encode(rawPassword);
        
        // 🔐 安全日志：不记录明文密码
        logger.debug("Password encoded successfully: [HIDDEN] -> {}", encodedPassword);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("rawPassword", rawPassword);  // 仅开发环境返回
        response.put("encodedPassword", encodedPassword);
        response.put("algorithm", "bcrypt");
        response.put("note", "This encoded password can be used in data.sql or database directly");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * 批量编码密码（用于生成测试用户密码）
     * 
     * @param request 包含多个用户密码的请求
     * @return 批量编码结果
     */
    @PostMapping("/encode-batch")
    public ResponseEntity<Map<String, Object>> encodeBatchPasswords(@RequestBody BatchPasswordRequest request) {
        logger.info("Batch password encoding request received for {} users", request.getUsers().size());
        
        Map<String, Map<String, String>> results = new HashMap<>();
        
        for (UserPasswordPair user : request.getUsers()) {
            if (user.getUsername() == null || user.getPassword() == null) {
                continue;
            }
            
            String encodedPassword = passwordEncoder.encode(user.getPassword());
            
            Map<String, String> userResult = new HashMap<>();
            userResult.put("username", user.getUsername());
            userResult.put("rawPassword", user.getPassword());
            userResult.put("encodedPassword", encodedPassword);
            
            results.put(user.getUsername(), userResult);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("count", results.size());
        response.put("users", results);
        response.put("sqlTemplate", "INSERT INTO users (username, password, enabled) VALUES ('{username}', '{encodedPassword}', true);");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * 验证密码是否匹配
     * 
     * @param request 包含原始密码和编码密码的请求
     * @return 验证结果
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyPassword(@RequestBody PasswordVerifyRequest request) {
        logger.info("Password verification request received");
        
        boolean matches = passwordEncoder.matches(request.getRawPassword(), request.getEncodedPassword());
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("matches", matches);
        response.put("rawPassword", request.getRawPassword());
        response.put("encodedPassword", request.getEncodedPassword());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * 生成OAuth2客户端密钥和Basic Auth头
     * 
     * @param request 包含客户端ID和密钥的请求
     * @return 编码结果和Basic Auth头
     */
    @PostMapping("/encode-client-secret")
    public ResponseEntity<Map<String, Object>> encodeClientSecret(@RequestBody ClientSecretRequest request) {
        logger.info("Client secret encoding request received for client: {}", request.getClientId());
        
        String encodedSecret = passwordEncoder.encode(request.getClientSecret());
        String basicAuthValue = Base64.getEncoder().encodeToString(
            (request.getClientId() + ":" + request.getClientSecret()).getBytes()
        );
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("clientId", request.getClientId());
        response.put("rawSecret", request.getClientSecret());
        response.put("encodedSecret", encodedSecret);
        response.put("basicAuthHeader", "Basic " + basicAuthValue);
        response.put("curlExample", String.format(
            "curl -H \"Authorization: Basic %s\" http://localhost:9000/oauth2/token", 
            basicAuthValue
        ));
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * 获取常用测试密码的编码结果
     */
    @GetMapping("/common-passwords")
    public ResponseEntity<Map<String, Object>> getCommonEncodedPasswords() {
        logger.info("Common passwords encoding request received");
        
        String[] commonPasswords = {"admin", "password", "123456", "test", "dev"};
        Map<String, String> encodedPasswords = new HashMap<>();
        
        for (String password : commonPasswords) {
            encodedPasswords.put(password, passwordEncoder.encode(password));
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("passwords", encodedPasswords);
        response.put("note", "These are common passwords for development/testing only");
        response.put("warning", "⚠️ Never use these passwords in production!");
        
        return ResponseEntity.ok(response);
    }
    
    // Request/Response DTOs
    public static class PasswordRequest {
        private String password;
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
    
    public static class BatchPasswordRequest {
        private java.util.List<UserPasswordPair> users;
        
        public java.util.List<UserPasswordPair> getUsers() { return users; }
        public void setUsers(java.util.List<UserPasswordPair> users) { this.users = users; }
    }
    
    public static class UserPasswordPair {
        private String username;
        private String password;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
    
    public static class PasswordVerifyRequest {
        private String rawPassword;
        private String encodedPassword;
        
        public String getRawPassword() { return rawPassword; }
        public void setRawPassword(String rawPassword) { this.rawPassword = rawPassword; }
        public String getEncodedPassword() { return encodedPassword; }
        public void setEncodedPassword(String encodedPassword) { this.encodedPassword = encodedPassword; }
    }
    
    public static class ClientSecretRequest {
        private String clientId;
        private String clientSecret;
        
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    }
}