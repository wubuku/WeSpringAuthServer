package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.config.AuthServerProperties;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.OAuth2AuthenticationHelper;
import org.dddml.ffvtraceability.auth.service.WeChatService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
 */
@Controller
public class SocialLoginController {

    // Constants
    private static final String DEFAULT_CLIENT_ID = "ffv-client";
    private static final String MSG_WECHAT_AUTH_FAILED = "WeChat authentication failed: ";

    // Exception constants
    private static final String EXCEPTION_WECHAT_LOGIN_CODE_EMPTY = "WeChat login code is empty"; // "微信小程序登录 Code 不能为空";

    private static final Logger logger = LoggerFactory.getLogger(SocialLoginController.class);

    @Autowired
    private WeChatService weChatService;

    @Autowired
    private OAuth2AuthenticationHelper oAuth2AuthenticationHelper;

    /**
     * WeChat登录端点
     * <p>
     * 重要修改说明（2025-06-14 refresh token修复）：
     * 1. 添加了正确的token类型转换：OAuth2Token -> OAuth2AccessToken
     * 2. 使用专用的Builder方法：accessToken() 和 refreshToken()
     * 3. 正确保存OAuth2Authorization到数据库，包含完整的token信息
     * 4. 增强了错误处理和日志记录
     * <p>
     * 这些修改不影响原有的WeChat登录流程，只是增强了token管理功能。
     * 原有的认证逻辑（weChatService.processWeChatLogin）保持不变。
     */
    @GetMapping("/wechat/login")
    public void wechatLogin(@RequestParam(value = "clientId", defaultValue = DEFAULT_CLIENT_ID) String clientId,
                            @RequestParam("loginCode") String loginCode,
                            @RequestParam(value = "mobileCode", required = false) String mobileCode,
                            @RequestParam(value = "referrerId", required = false) String referrerId,
                            HttpServletResponse response) throws IOException {
        try {
            validateLoginParameters(loginCode, mobileCode);

            CustomUserDetails userDetails = weChatService.processWeChatLogin(loginCode, mobileCode, referrerId);
            Authentication authentication = createAuthentication(userDetails);
            RegisteredClient registeredClient = oAuth2AuthenticationHelper.getRegisteredClient(clientId);

            OAuth2AuthenticationHelper.TokenPair tokenPair = oAuth2AuthenticationHelper.generateTokenPair(registeredClient, authentication);
            oAuth2AuthenticationHelper.createAndSaveAuthorization(registeredClient, userDetails, tokenPair);

            oAuth2AuthenticationHelper.writeTokenResponse(response, tokenPair);

        } catch (AuthenticationException e) {
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, MSG_WECHAT_AUTH_FAILED);
        } catch (Exception e) {
            logger.error("Unexpected error during WeChat authentication", e);
            oAuth2AuthenticationHelper.handleAuthenticationError(response, e, "Internal server error: ");
        }
    }

    /**
     * 刷新Token端点 - 统一的OAuth2 refresh token处理
     */
    @PostMapping("/wechat/refresh-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenValue,
            @RequestParam(value = "client_Id", defaultValue = DEFAULT_CLIENT_ID) String clientId, // 注意这个方法使用了不一样的 URL 参数命名风格
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest request) {
        
        // 使用OAuth2AuthenticationHelper统一处理刷新token逻辑
        return oAuth2AuthenticationHelper.processRefreshToken(grantType, refreshTokenValue, clientId, clientSecret, request);
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
}