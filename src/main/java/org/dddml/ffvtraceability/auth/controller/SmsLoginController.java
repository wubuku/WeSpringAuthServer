package org.dddml.ffvtraceability.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.OAuth2AuthenticationHelper;
import org.dddml.ffvtraceability.auth.service.SmsService;
import org.dddml.ffvtraceability.auth.service.SmsVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * SMS登录控制器 - 专为微信小程序等移动端设计
 * 提供无状态的SMS验证码服务，返回OAuth2 token
 * 
 * 注意：此控制器的所有端点都是无状态的，适用于：
 * - 微信小程序
 * - 移动APP
 * - 第三方API调用
 * - Web应用的无状态登录
 * 
 * 不要在此控制器中添加需要session的端点！
 */
@RestController
@RequestMapping({"/sms", "/api/sms"})
public class SmsLoginController {

    // Constants
    private static final String DEFAULT_CLIENT_ID = "ffv-client";
    private static final String MSG_SMS_AUTH_FAILED = "SMS authentication failed: ";

    private static final Logger logger = LoggerFactory.getLogger(SmsLoginController.class);

    @Autowired
    private SmsService smsService;
    @Autowired
    private SmsVerificationService smsVerificationService;
    @Autowired
    private OAuth2AuthenticationHelper oAuth2AuthenticationHelper;

    /**
     * 发送SMS验证码 - JSON格式 (新的微信小程序使用)
     * JSON格式: {"phoneNumber": "13800138000"}
     */
    @PostMapping(value = "/send-code", consumes = "application/json")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCodeJson(@RequestBody Map<String, String> request) {
        String mobileNumber = request.get("phoneNumber");
        return processSmsCodeRequest(mobileNumber);
    }
    
    /**
     * 发送SMS验证码 - Form格式 (原有测试脚本使用)
     * Form格式: mobileNumber=13800138000
     */
    @PostMapping(value = "/send-code", consumes = "application/x-www-form-urlencoded")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCodeForm(@RequestParam("mobileNumber") String mobileNumber) {
        return processSmsCodeRequest(mobileNumber);
    }
    
    /**
     * 发送SMS验证码 - GET方法 (为了兼容性支持)
     * 虽然不是典型的REST实践，但为了兼容某些客户端需求
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
     * SMS登录认证 - 微信小程序使用
     * 无状态API，返回OAuth2 access_token和refresh_token
     */
    @GetMapping("/auth")
    public void smsAuth(@RequestParam(value = "clientId", defaultValue = DEFAULT_CLIENT_ID) String clientId,
                        @RequestParam("mobileNumber") String mobileNumber,
                        @RequestParam("verificationCode") String verificationCode,
                        @RequestParam(value = "referrerId", required = false) String referrerId,
                        HttpServletResponse response) throws IOException {
        try {
            CustomUserDetails userDetails = smsVerificationService.processSmsLogin(mobileNumber, verificationCode, referrerId);
            Authentication authentication = oAuth2AuthenticationHelper.createAuthentication(userDetails);
            RegisteredClient registeredClient = oAuth2AuthenticationHelper.getRegisteredClient(clientId);

            OAuth2AuthenticationHelper.TokenPair tokenPair = oAuth2AuthenticationHelper.generateTokenPair(registeredClient, authentication);
            oAuth2AuthenticationHelper.createAndSaveAuthorization(registeredClient, userDetails, tokenPair);

            oAuth2AuthenticationHelper.writeTokenResponse(response, tokenPair);

        } catch (AuthenticationException e) {
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, MSG_SMS_AUTH_FAILED);
        } catch (Exception e) {
            logger.error("Unexpected error during SMS authentication", e);
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, "Internal server error: ");
        }
    }

    /**
     * SMS登录认证 - Web端使用
     * 无状态API，返回OAuth2 access_token和refresh_token
     */
    @GetMapping("/login")
    public void smsLogin(@RequestParam(value = "clientId", defaultValue = DEFAULT_CLIENT_ID) String clientId,
                         @RequestParam("mobileNumber") String mobileNumber,
                         @RequestParam("verificationCode") String verificationCode,
                         @RequestParam(value = "referrerId", required = false) String referrerId,
                         HttpServletResponse response) throws IOException {
        // 使用相同的逻辑
        smsAuth(clientId, mobileNumber, verificationCode, referrerId, response);
    }

    /**
     * 刷新Token端点 - 统一的OAuth2 refresh token处理
     */
    @PostMapping("/refresh-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenValue,
            @RequestParam(value = "client_id", defaultValue = DEFAULT_CLIENT_ID) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest request) {
        
        // 使用OAuth2AuthenticationHelper统一处理刷新token逻辑
        return oAuth2AuthenticationHelper.processRefreshToken(grantType, refreshTokenValue, clientId, clientSecret, request);
    }
}