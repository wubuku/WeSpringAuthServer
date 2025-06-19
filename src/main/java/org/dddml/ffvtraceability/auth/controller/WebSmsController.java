package org.dddml.ffvtraceability.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.SmsService;
import org.dddml.ffvtraceability.auth.service.SmsVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Web页面SMS控制器 - 专为Web管理界面设计
 * 提供基于session的SMS验证服务
 * 
 * 注意：此控制器的所有端点都使用session认证，适用于：
 * - Web管理界面
 * - 传统的HTML页面登录
 * 
 * 微信小程序请使用 SmsLoginController！
 */
@RestController
@RequestMapping("/web-sms")
public class WebSmsController {

    private static final Logger logger = LoggerFactory.getLogger(WebSmsController.class);

    @Autowired
    private SmsService smsService;
    @Autowired
    private SmsVerificationService smsVerificationService;

    /**
     * 发送SMS验证码 - Web页面使用 (POST方法)
     * 基于session的API
     */
    @PostMapping("/send-code")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCode(@RequestBody Map<String, String> request) {
        String mobileNumber = request.get("phoneNumber");
        return processSmsCodeRequest(mobileNumber);
    }
    
    /**
     * 发送SMS验证码 - Web页面使用 (GET方法)
     * 为了兼容性支持GET方法
     * GET格式: /send-code?mobileNumber=13800138000
     */
    @GetMapping("/send-code")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCodeGet(@RequestParam("mobileNumber") String mobileNumber) {
        return processSmsCodeRequest(mobileNumber);
    }
    
    /**
     * 处理SMS验证码发送的通用逻辑
     */
    private ResponseEntity<Map<String, Object>> processSmsCodeRequest(String mobileNumber) {
        Map<String, Object> response = new HashMap<>();

        if (mobileNumber == null || mobileNumber.isEmpty()) {
            response.put("success", false);
            response.put("message", "Mobile number is required");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            // Generate a verification code
            String code = smsService.generateVerificationCode();

            // Send the verification code
            boolean sent = smsService.sendVerificationCode(mobileNumber, code);

            if (sent) {
                response.put("success", true);
                response.put("message", "Verification code sent");
                return ResponseEntity.ok(response);
            } else {
                response.put("success", false);
                response.put("message", "Failed to send verification code");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
            }
        } catch (Exception e) {
            logger.error("Error sending SMS verification code", e);
            response.put("success", false);
            response.put("message", "Internal server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * SMS验证端点 - 为Web页面登录提供验证服务
     * 接收JSON请求，验证成功后创建登录会话
     */
    @PostMapping("/verify")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifySmsCode(@RequestBody Map<String, String> request,
                                                             HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();
        
        String phoneNumber = request.get("phoneNumber");
        String code = request.get("code");

        if (phoneNumber == null || phoneNumber.isEmpty() || code == null || code.isEmpty()) {
            response.put("success", false);
            response.put("message", "Phone number and verification code are required");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            CustomUserDetails userDetails = smsVerificationService.processSmsLogin(phoneNumber, code);
            if (userDetails != null) {
                // 创建登录会话 - 使用Spring Security的方式
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                
                SecurityContextHolder.getContext().setAuthentication(authToken);
                
                // 保存到session
                httpRequest.getSession().setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    SecurityContextHolder.getContext()
                );

                response.put("success", true);
                response.put("message", "Verification successful");
                return ResponseEntity.ok(response);
            } else {
                response.put("success", false);
                response.put("message", "Invalid verification code or expired");
                return ResponseEntity.badRequest().body(response);
            }
        } catch (Exception e) {
            logger.error("SMS verification failed for phone: {}", phoneNumber, e);
            response.put("success", false);
            response.put("message", "Verification failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
} 