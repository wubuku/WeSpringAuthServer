package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.config.CookieSecurityConfig;
import org.dddml.ffvtraceability.auth.config.OAuth2ClientSecurityConfig;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.OAuth2AuthenticationHelper;
import org.dddml.ffvtraceability.auth.service.SmsService;
import org.dddml.ffvtraceability.auth.service.SmsVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
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
 * <p>
 * 注意：此控制器的所有端点都是无状态的，适用于：
 * - 微信小程序
 * - 移动APP
 * - 第三方API调用
 * - Web应用的无状态登录
 * <p>
 * 🔒 安全升级 (2024-01-XX)：
 * - 实现HttpOnly Cookie存储refresh_token
 * - 移除前端client_secret传输
 * - 后端统一管理OAuth2客户端凭据
 * <p>
 * 不要在此控制器中添加需要session的端点！
 */
@RestController
@RequestMapping({"/sms", "/api/sms"})
public class SmsLoginController {

    // Constants
    private static final String MSG_SMS_AUTH_FAILED = "SMS authentication failed: ";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final Logger logger = LoggerFactory.getLogger(SmsLoginController.class);
    // Configurable properties
    @Value("${auth-server.default-client-id}")
    private String defaultClientId;
    @Autowired
    private SmsService smsService;
    @Autowired
    private SmsVerificationService smsVerificationService;
    @Autowired
    private OAuth2AuthenticationHelper oAuth2AuthenticationHelper;
    @Autowired
    private CookieSecurityConfig cookieSecurityConfig;
    @Autowired
    private OAuth2ClientSecurityConfig.OAuth2ClientCredentialsManager oAuth2ClientCredentialsManager;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        // 应用启动后立即打印配置值，用于调试配置是否正确加载
        logger.info("🔧 APPLICATION STARTUP: default-client-id configuration: {}", defaultClientId);

        /*
        // 注入ConfigurableEnvironment来获取更多调试信息
        org.springframework.core.env.ConfigurableEnvironment env = org.springframework.beans.factory.BeanFactory.class.cast(this).getBean(org.springframework.core.env.ConfigurableEnvironment.class);

        // 打印活跃的profiles
        logger.info("🔧 DEBUG: Active profiles: {}", java.util.Arrays.toString(env.getActiveProfiles()));

        // 打印包含此属性的所有PropertySource
        logger.info("🔧 DEBUG: Property sources containing 'auth-server.default-client-id':");
        for (org.springframework.core.env.PropertySource<?> ps : env.getPropertySources()) {
            if (ps.containsProperty("auth-server.default-client-id")) {
                logger.info("  - {}: {}", ps.getName(), ps.getProperty("auth-server.default-client-id"));
            }
        }
        */
    }

    /**
     * 发送SMS验证码 - JSON格式 (新的微信小程序使用)
     * JSON格式: {"mobileNumber": "13800138000"}
     */
    @PostMapping(value = "/send-code", consumes = "application/json")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCodeJson(@RequestBody Map<String, String> request) {

        String mobileNumber = request.get("mobileNumber");
        if (mobileNumber == null && request.containsKey("phoneNumber")) {
            //兼容 `{"mobileNumber": "13800138000"}`
            mobileNumber = request.get("phoneNumber");
        }
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
     * <p>
     * 🔒 安全升级：成功登录时设置HttpOnly Cookie存储refresh_token
     *
     * @param legacyMode 兼容模式：true=在响应体中返回refresh_token（适用于微信小程序），false=仅使用Cookie（默认，适用于Web）
     */
    @GetMapping("/auth")
    public void smsAuth(@RequestParam(value = "clientId", required = false) String clientId,
                        @RequestParam("mobileNumber") String mobileNumber,
                        @RequestParam("verificationCode") String verificationCode,
                        @RequestParam(value = "referrerId", required = false) String referrerId,
                        @RequestParam(value = "legacyMode", defaultValue = "false") boolean legacyMode,
                        HttpServletResponse response) throws IOException {
        try {
            // 详细的输入验证，提供友好的错误提示
            validateSmsLoginParameters(mobileNumber, verificationCode);

            // 使用配置的默认客户端ID
            if (clientId == null || clientId.trim().isEmpty()) {
                clientId = defaultClientId;
            }
            CustomUserDetails userDetails = smsVerificationService.processSmsLogin(mobileNumber, verificationCode, referrerId);
            Authentication authentication = oAuth2AuthenticationHelper.createAuthentication(userDetails);
            RegisteredClient registeredClient = oAuth2AuthenticationHelper.getRegisteredClient(clientId);

            OAuth2AuthenticationHelper.TokenPair tokenPair = oAuth2AuthenticationHelper.generateTokenPair(registeredClient, authentication);
            oAuth2AuthenticationHelper.createAndSaveAuthorization(registeredClient, userDetails, tokenPair, authentication);

            // 🔒 安全升级：设置HttpOnly Cookie存储refresh_token
            cookieSecurityConfig.setRefreshTokenCookie(response, tokenPair.getRefreshToken().getTokenValue());
            logger.debug("Set HttpOnly Cookie for refresh_token in SMS login");

            // 兼容模式控制：legacyMode=true时在响应体中返回refresh_token（微信小程序），false时仅使用Cookie（Web）
            boolean cookieMode = !legacyMode; // legacyMode=true -> cookieMode=false (返回refresh_token)
            oAuth2AuthenticationHelper.writeTokenResponse(response, tokenPair, cookieMode);

            if (legacyMode) {
                logger.debug("SMS login using legacy mode - refresh_token included in response body for miniprogram compatibility");
            } else {
                logger.debug("SMS login using cookie mode - refresh_token only in HttpOnly Cookie");
            }

        } catch (AuthenticationException e) {
            // 检查是否是验证码验证失败
            if (e.getMessage() != null && e.getMessage().contains("Invalid verification code")) {
                handleParameterValidationError(response, "验证码错误，请检查后重新输入");
            } else {
                oAuth2AuthenticationHelper.handleAuthenticationError(response, e, MSG_SMS_AUTH_FAILED);
            }
        } catch (IllegalArgumentException e) {
            // 处理参数验证错误
            handleParameterValidationError(response, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during SMS authentication", e);
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, "Internal server error: ");
        }
    }

    /**
     * SMS登录认证 - Web端使用
     * 无状态API，返回OAuth2 access_token和refresh_token
     * <p>
     * 🔒 安全升级：成功登录时设置HttpOnly Cookie存储refresh_token
     *
     * @param legacyMode 兼容模式：true=在响应体中返回refresh_token（适用于微信小程序），false=仅使用Cookie（默认，适用于Web）
     */
    @GetMapping("/login")
    public void smsLogin(@RequestParam(value = "clientId", required = false) String clientId,
                         @RequestParam("mobileNumber") String mobileNumber,
                         @RequestParam("verificationCode") String verificationCode,
                         @RequestParam(value = "referrerId", required = false) String referrerId,
                         @RequestParam(value = "legacyMode", defaultValue = "false") boolean legacyMode,
                         HttpServletResponse response) throws IOException {
        try {
            // 详细的输入验证，提供友好的错误提示
            validateSmsLoginParameters(mobileNumber, verificationCode);

            // 使用相同的逻辑，包括安全升级和兼容模式
            smsAuth(clientId, mobileNumber, verificationCode, referrerId, legacyMode, response);

        } catch (AuthenticationException e) {
            // 检查是否是验证码验证失败
            if (e.getMessage() != null && e.getMessage().contains("Invalid verification code")) {
                handleParameterValidationError(response, "验证码错误，请检查后重新输入");
            } else {
                oAuth2AuthenticationHelper.handleAuthenticationError(response, e, MSG_SMS_AUTH_FAILED);
            }
        } catch (IllegalArgumentException e) {
            // 处理参数验证错误
            handleParameterValidationError(response, e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during SMS login", e);
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, "Internal server error: ");
        }
    }

    /**
     * 刷新Token端点 - 统一的OAuth2 refresh token处理
     * <p>
     * 🔒 安全升级 (2024-01-XX)：
     * - 从HttpOnly Cookie读取refresh_token，不再从请求参数获取
     * - 从后端配置获取client_secret，不再从前端传输
     * - 成功刷新后更新Cookie中的refresh_token
     *
     * @param legacyMode 兼容模式：true=在响应体中返回refresh_token（适用于微信小程序），false=仅使用Cookie（默认，适用于Web）
     */
    @PostMapping("/refresh-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenFromParam,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "legacyMode", defaultValue = "false") boolean legacyMode,
            HttpServletRequest request,
            HttpServletResponse response) {

        logger.info("🔄 处理refresh-token请求 - ClientId: {}, GrantType: {}", clientId, grantType);

        try {
            // 使用配置的默认客户端ID
            if (clientId == null || clientId.trim().isEmpty()) {
                clientId = defaultClientId;
            }
            // 🔒 安全升级：优先从Cookie读取refresh_token
            logger.debug("🍪 尝试从Cookie读取refresh_token...");
            String refreshTokenValue = cookieSecurityConfig.getRefreshTokenFromCookie(request);

            logger.info("🍪 Cookie中的refresh_token: {}", refreshTokenValue != null ? "present" : "missing");

            if (refreshTokenValue == null && refreshTokenFromParam != null) {
                // 向后兼容：如果Cookie中没有，尝试从参数获取
                refreshTokenValue = refreshTokenFromParam;
                logger.warn("⚠️  使用参数中的refresh_token作为后备方案");
                logger.warn("Consider upgrading client to use Cookie-based authentication.");
            }

            if (refreshTokenValue == null) {
                logger.error("❌ 无法获取refresh_token - Cookie: missing, Parameter: {}",
                        refreshTokenFromParam != null ? "present" : "missing");
            }

            // 🔒 安全升级：从后端配置获取client_secret
            String clientSecret = oAuth2ClientCredentialsManager.getClientSecret(clientId);
            if (clientSecret == null) {
                logger.error("❌ Client secret not found for client: {}", clientId);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_client");
                errorResponse.put("error_description", "Client authentication failed");
                return ResponseEntity.status(401).body(errorResponse);
            }

            logger.debug("✅ Client secret retrieved for client: {}", clientId);

            // 兼容模式控制：legacyMode=true时在响应体中返回refresh_token（微信小程序），false时仅使用Cookie（Web）
            boolean cookieMode = !legacyMode; // legacyMode=true -> cookieMode=false (返回refresh_token)
            ResponseEntity<Map<String, Object>> result = oAuth2AuthenticationHelper.processRefreshToken(
                    grantType, refreshTokenValue, clientId, clientSecret, request, cookieMode);

            // 🔒 安全升级：如果刷新成功，从header读取新的refresh_token并更新Cookie
            if (result.getStatusCode().is2xxSuccessful()) {
                String newRefreshToken = result.getHeaders().getFirst("X-New-Refresh-Token");
                if (newRefreshToken != null) {
                    cookieSecurityConfig.setRefreshTokenCookie(response, newRefreshToken);
                    logger.info("✅ Updated HttpOnly Cookie with new refresh_token");
                } else {
                    logger.warn("⚠️  No new refresh_token found in response header for Cookie update");
                }
            } else {
                logger.warn("⚠️  Refresh token failed with status: {}", result.getStatusCode());
            }

            return result;

        } catch (Exception e) {
            logger.error("❌ Error in SMS refresh token endpoint: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Internal server error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    /**
     * 验证SMS登录参数，提供详细的错误信息
     */
    private void validateSmsLoginParameters(String mobileNumber, String verificationCode) {
        if (mobileNumber == null || mobileNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("手机号不能为空");
        }

        // 验证手机号格式（中国大陆手机号）
        if (!mobileNumber.matches("^1[3-9]\\d{9}$")) {
            throw new IllegalArgumentException("手机号格式不正确，请输入11位中国大陆手机号");
        }

        if (verificationCode == null || verificationCode.trim().isEmpty()) {
            throw new IllegalArgumentException("验证码不能为空");
        }

        // 验证验证码格式（6位数字）
        if (!verificationCode.matches("^\\d{4,6}$")) {
            throw new IllegalArgumentException("验证码格式不正确，请输入4-6位数字验证码");
        }
    }

    /**
     * 处理参数验证错误，返回友好的错误响应
     */
    private void handleParameterValidationError(HttpServletResponse response, String errorMessage) throws IOException {
        logger.warn("Parameter validation failed: {}", errorMessage);
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST); // 400 Bad Request

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "invalid_request");
        errorResponse.put("error_description", errorMessage);

        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }
}