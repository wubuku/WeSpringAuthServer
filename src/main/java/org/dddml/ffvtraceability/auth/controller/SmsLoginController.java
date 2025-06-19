package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
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
 * SMS相关API控制器
 * 处理短信验证码发送和短信登录功能
 */
@RestController
@RequestMapping({"/sms", "/api/sms"})
public class SmsLoginController {

    // Constants
    private static final String DEFAULT_CLIENT_ID = "ffv-client";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final String ERROR_AUTHENTICATION_FAILED = "authentication_failed";
    private static final String MSG_SMS_AUTH_FAILED = "SMS authentication failed";
    private static final String EXCEPTION_REGISTERED_CLIENT_NOT_FOUND = "Registered client for SMS not found, clientId:";

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
     * Send SMS verification code - 从 SocialLoginController 移动过来
     * 支持JSON格式请求以兼容Web页面
     */
    @PostMapping("/send-code")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCode(@RequestBody Map<String, String> request) {
        String mobileNumber = request.get("phoneNumber");
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
     * SMS登录端点 - 从SocialLoginController移动过来
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
     */
    @GetMapping("/login")
    public void smsLogin(@RequestParam(value = "clientId", defaultValue = DEFAULT_CLIENT_ID) String clientId,
                         @RequestParam("mobileNumber") String mobileNumber,
                         @RequestParam("verificationCode") String verificationCode,
                         HttpServletResponse response) throws IOException {
        // 直接调用 smsAuth 方法，保持完全相同的逻辑
        smsAuth(clientId, mobileNumber, verificationCode, response);
    }

    /**
     * SMS验证端点 - 为Web页面登录提供验证服务
     * 接收JSON请求，验证成功后创建登录会话
     */
    @PostMapping("/verify")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifySmsCode(@RequestBody Map<String, String> request,
                                                             HttpServletRequest httpRequest,
                                                             HttpServletResponse httpResponse) {
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
                org.springframework.security.authentication.UsernamePasswordAuthenticationToken authToken = 
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                
                org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authToken);
                
                // 保存到session
                httpRequest.getSession().setAttribute(
                    org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    org.springframework.security.core.context.SecurityContextHolder.getContext()
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