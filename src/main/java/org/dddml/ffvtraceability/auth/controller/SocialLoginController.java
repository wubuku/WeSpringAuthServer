package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.config.AuthServerProperties;
import org.dddml.ffvtraceability.auth.config.CookieSecurityConfig;
import org.dddml.ffvtraceability.auth.config.OAuth2ClientSecurityConfig;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.OAuth2AuthenticationHelper;
import org.dddml.ffvtraceability.auth.service.WeChatService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 社交登录控制器 - 处理WeChat等第三方登录
 * 为微信小程序等移动端提供无状态OAuth2认证服务
 * 
 * 🔒 安全升级 (2024-01-XX)：
 * - 实现HttpOnly Cookie存储refresh_token
 * - 移除前端client_secret传输
 * - 后端统一管理OAuth2客户端凭据
 */
@Controller
public class SocialLoginController {

    // Constants
    private static final String MSG_WECHAT_AUTH_FAILED = "WeChat authentication failed: ";

    // Configurable properties
    @Value("${auth-server.default-client-id}")
    private String defaultClientId;

    // Exception constants
    private static final String EXCEPTION_WECHAT_LOGIN_CODE_EMPTY = "WeChat login code is empty"; // "微信小程序登录 Code 不能为空";

    private static final Logger logger = LoggerFactory.getLogger(SocialLoginController.class);

    @Autowired
    private WeChatService weChatService;

    @Autowired
    private OAuth2AuthenticationHelper oAuth2AuthenticationHelper;

    @Autowired
    private CookieSecurityConfig cookieSecurityConfig;

    @Autowired
    private OAuth2ClientSecurityConfig.OAuth2ClientCredentialsManager oAuth2ClientCredentialsManager;

    /**
     * WeChat登录端点
     * <p>
     * 重要修改说明（2025-06-14 refresh token修复）：
     * 1. 添加了正确的token类型转换：OAuth2Token -> OAuth2AccessToken
     * 2. 使用专用的Builder方法：accessToken() 和 refreshToken()
     * 3. 正确保存OAuth2Authorization到数据库，包含完整的token信息
     * 4. 增强了错误处理和日志记录
     * 5. 🔒 安全升级：成功登录时设置HttpOnly Cookie存储refresh_token
     * <p>
     * 这些修改不影响原有的WeChat登录流程，只是增强了token管理功能。
     * 原有的认证逻辑（weChatService.processWeChatLogin）保持不变。
     * 
     * @param legacyMode 兼容模式：true=在响应体中返回refresh_token（适用于微信小程序），false=仅使用Cookie（默认，适用于Web）
     */
    @GetMapping("/wechat/login")
    public void wechatLogin(@RequestParam(value = "clientId", required = false) String clientId,
                            @RequestParam("loginCode") String loginCode,
                            @RequestParam(value = "mobileCode", required = false) String mobileCode,
                            @RequestParam(value = "referrerId", required = false) String referrerId,
                            @RequestParam(value = "legacyMode", defaultValue = "false") boolean legacyMode,
                            HttpServletResponse response) throws IOException {
        try {
            validateLoginParameters(loginCode, mobileCode);

            // 使用配置的默认客户端ID
            if (clientId == null || clientId.trim().isEmpty()) {
                clientId = defaultClientId;
            }

            CustomUserDetails userDetails = weChatService.processWeChatLogin(loginCode, mobileCode, referrerId);
            Authentication authentication = createAuthentication(userDetails);
            RegisteredClient registeredClient = oAuth2AuthenticationHelper.getRegisteredClient(clientId);

            OAuth2AuthenticationHelper.TokenPair tokenPair = oAuth2AuthenticationHelper.generateTokenPair(registeredClient, authentication);
            oAuth2AuthenticationHelper.createAndSaveAuthorization(registeredClient, userDetails, tokenPair, authentication);

            // 🔒 安全升级：设置HttpOnly Cookie存储refresh_token
            cookieSecurityConfig.setRefreshTokenCookie(response, tokenPair.getRefreshToken().getTokenValue());
            logger.debug("Set HttpOnly Cookie for refresh_token in WeChat login");

            // 兼容模式控制：legacyMode=true时在响应体中返回refresh_token（微信小程序），false时仅使用Cookie（Web）
            boolean cookieMode = !legacyMode; // legacyMode=true -> cookieMode=false (返回refresh_token)
            oAuth2AuthenticationHelper.writeTokenResponse(response, tokenPair, cookieMode);
            
            if (legacyMode) {
                logger.debug("WeChat login using legacy mode - refresh_token included in response body for miniprogram compatibility");
            } else {
                logger.debug("WeChat login using cookie mode - refresh_token only in HttpOnly Cookie");
            }

        } catch (AuthenticationException e) {
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, MSG_WECHAT_AUTH_FAILED);
        } catch (Exception e) {
            logger.error("Unexpected error during WeChat authentication", e);
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, "Internal server error: ");
        }
    }

    @PostMapping("/wechat/login-with-phone")
    @ResponseBody
    public void wechatLoginWithPhone(@RequestBody RequiredPhoneLoginRequest request,
                                     HttpServletResponse response) throws IOException {
        try {
            if (request == null || request.loginCode() == null || request.loginCode().isBlank()
                    || request.mobileCode() == null || request.mobileCode().isBlank()) {
                throw new AuthenticationException("WeChat loginCode and mobileCode are required");
            }
            String clientId = request.clientId();
            if (clientId == null || clientId.isBlank()) {
                clientId = defaultClientId;
            }
            CustomUserDetails userDetails = weChatService.processWeChatLoginWithRequiredPhone(
                    request.loginCode(), request.mobileCode());
            Authentication authentication = createAuthentication(userDetails);
            RegisteredClient registeredClient = oAuth2AuthenticationHelper.getRegisteredClient(clientId);
            OAuth2AuthenticationHelper.TokenPair tokenPair =
                    oAuth2AuthenticationHelper.generateTokenPair(registeredClient, authentication);
            oAuth2AuthenticationHelper.createAndSaveAuthorization(registeredClient, userDetails, tokenPair, authentication);
            cookieSecurityConfig.setRefreshTokenCookie(response, tokenPair.getRefreshToken().getTokenValue());
            oAuth2AuthenticationHelper.writeTokenResponse(response, tokenPair, !request.legacyModeEnabled());
        } catch (AuthenticationException e) {
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, MSG_WECHAT_AUTH_FAILED);
        } catch (Exception e) {
            logger.error("Unexpected error during required-phone WeChat authentication", e);
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, "Internal server error: ");
        }
    }

    /**
     * 刷新Token端点 - 统一的OAuth2 refresh token处理
     * 
     * 🔒 安全升级 (2024-01-XX)：
     * - 从HttpOnly Cookie读取refresh_token，不再从请求参数获取
     * - 从后端配置获取client_secret，不再从前端传输
     * - 成功刷新后更新Cookie中的refresh_token
     * 
     * @param legacyMode 兼容模式：true=在响应体中返回refresh_token（适用于微信小程序），false=仅使用Cookie（默认，适用于Web）
     */
    @PostMapping("/wechat/refresh-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenFromParam,
            @RequestParam(value = "client_id", required = false) String clientId, // 注意这个方法使用了不一样的 URL 参数命名风格
            @RequestParam(value = "legacyMode", defaultValue = "false") boolean legacyMode,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        try {
            // 使用配置的默认客户端ID
            if (clientId == null || clientId.trim().isEmpty()) {
                clientId = defaultClientId;
            }

            // 🔒 安全升级：优先从Cookie读取refresh_token
            String refreshTokenValue = cookieSecurityConfig.getRefreshTokenFromCookie(request);
            if (refreshTokenValue == null && refreshTokenFromParam != null) {
                // 向后兼容：如果Cookie中没有，尝试从参数获取
                refreshTokenValue = refreshTokenFromParam;
                logger.warn("Using refresh_token from parameter for backward compatibility. Consider upgrading client to use Cookie-based authentication.");
            }

            // 🔒 安全升级：从后端配置获取client_secret
            String clientSecret = oAuth2ClientCredentialsManager.getClientSecret(clientId);
            if (clientSecret == null) {
                logger.error("Client secret not found for client: {}", clientId);
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_client");
                errorResponse.put("error_description", "Client authentication failed");
                return ResponseEntity.status(401).body(errorResponse);
            }

            // 兼容模式控制：legacyMode=true时在响应体中返回refresh_token（微信小程序），false时仅使用Cookie（Web）
            boolean cookieMode = !legacyMode; // legacyMode=true -> cookieMode=false (返回refresh_token)
            ResponseEntity<Map<String, Object>> result = oAuth2AuthenticationHelper.processRefreshToken(
                grantType, refreshTokenValue, clientId, clientSecret, request, cookieMode);

            // 🔒 安全升级：如果刷新成功，从header读取新的refresh_token并更新Cookie
            if (result.getStatusCode().is2xxSuccessful()) {
                String newRefreshToken = result.getHeaders().getFirst("X-New-Refresh-Token");
                if (newRefreshToken != null) {
                    cookieSecurityConfig.setRefreshTokenCookie(response, newRefreshToken);
                    logger.debug("Updated HttpOnly Cookie with new refresh_token from header");
                } else {
                    logger.warn("No new refresh_token found in response header for Cookie update");
                }
            }

            return result;

        } catch (Exception e) {
            logger.error("Error in WeChat refresh token endpoint: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Internal server error");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    // Private helper methods

    private void validateLoginParameters(String loginCode, String mobileCode) {
        if (loginCode == null || loginCode.trim().isEmpty()) {
            throw new IllegalArgumentException(EXCEPTION_WECHAT_LOGIN_CODE_EMPTY);
        }
        // Mobile code is now optional - no validation needed
    }

    private Authentication createAuthentication(CustomUserDetails userDetails) {
        // 修复说明：使用AuthenticationUtils确保groups信息正确设置到Authentication details中
        return org.dddml.ffvtraceability.auth.authentication.AuthenticationUtils
                .createAuthenticatedToken(userDetails, userDetails);
    }

    public record RequiredPhoneLoginRequest(String loginCode, String mobileCode,
                                            Boolean legacyMode, String clientId) {
        public boolean legacyModeEnabled() {
            return Boolean.TRUE.equals(legacyMode);
        }
    }
}
