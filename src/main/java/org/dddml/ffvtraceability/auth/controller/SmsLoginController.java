package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.OAuth2TokenService;
import org.dddml.ffvtraceability.auth.service.SmsService;
import org.dddml.ffvtraceability.auth.service.SmsVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
 * 
 * 不要在此控制器中添加需要session的端点！
 */
@RestController
@RequestMapping({"/sms", "/api/sms"})
public class SmsLoginController {

    // Constants
    private static final String DEFAULT_CLIENT_ID = "ffv-client";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final String ERROR_AUTHENTICATION_FAILED = "authentication_failed";
    private static final String MSG_SMS_AUTH_FAILED = "SMS authentication failed: ";
    private static final String EXCEPTION_REGISTERED_CLIENT_NOT_FOUND = "Registered client for SMS not found, clientId: ";

    private static final Logger logger = LoggerFactory.getLogger(SmsLoginController.class);

    @Autowired
    private SmsService smsService;
    @Autowired
    private SmsVerificationService smsVerificationService;
    @Autowired
    private OAuth2TokenService oAuth2TokenService;
    @Autowired
    private RegisteredClientRepository registeredClientRepository;

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
                        HttpServletResponse response) throws IOException {
        try {
            CustomUserDetails userDetails = smsVerificationService.processSmsLogin(mobileNumber, verificationCode);
            Authentication authentication = oAuth2TokenService.createAuthentication(userDetails);
            RegisteredClient registeredClient = getRegisteredClient(clientId);

            OAuth2TokenService.TokenPair tokenPair = oAuth2TokenService.generateTokenPair(registeredClient, authentication);
            oAuth2TokenService.createAndSaveAuthorization(registeredClient, userDetails, tokenPair);

            writeTokenResponse(response, tokenPair);

        } catch (AuthenticationException e) {
            handleAuthenticationError(response, e);
        }
    }

    /**
     * SMS登录端点 - 为其他合作方保留的兼容性端点
     * 无状态API，与 /auth 端点功能完全相同
     */
    @GetMapping("/login")
    public void smsLogin(@RequestParam(value = "clientId", defaultValue = DEFAULT_CLIENT_ID) String clientId,
                         @RequestParam("mobileNumber") String mobileNumber,
                         @RequestParam("verificationCode") String verificationCode,
                         HttpServletResponse response) throws IOException {
        // 直接调用 smsAuth 方法，保持完全相同的逻辑
        smsAuth(clientId, mobileNumber, verificationCode, response);
    }

    // Private helper methods

    private RegisteredClient getRegisteredClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalStateException(EXCEPTION_REGISTERED_CLIENT_NOT_FOUND + clientId);
        }
        return registeredClient;
    }

    private void writeTokenResponse(HttpServletResponse response, OAuth2TokenService.TokenPair tokenPair) throws IOException {
        Map<String, Object> responseBody = oAuth2TokenService.createTokenResponseBody(tokenPair.getAccessToken(),
                tokenPair.getRefreshToken());

        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseBody));
    }

    private void handleAuthenticationError(HttpServletResponse response, AuthenticationException e) throws IOException {
        logger.warn("SMS authentication failed: {}", e.getMessage());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> errorResponse = Map.of(
                "error", ERROR_AUTHENTICATION_FAILED,
                "error_description", MSG_SMS_AUTH_FAILED + e.getMessage());

        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }
}