package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.SmsService;
import org.dddml.ffvtraceability.auth.service.WeChatService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Controller
public class SocialLoginController {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final Logger logger = LoggerFactory.getLogger(SocialLoginController.class);

    private final WeChatService weChatService;

    private final SmsService smsService;

    @Autowired
    private OAuth2TokenGenerator tokenGenerator;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

    public SocialLoginController(SmsService smsService, WeChatService weChatService) {
        this.smsService = smsService;
        this.weChatService = weChatService;
    }

    static <T extends OAuth2Token> OAuth2AccessToken accessToken(OAuth2Authorization.Builder builder, T token,
                                                                 OAuth2TokenContext accessTokenContext) {

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token.getTokenValue(),
                token.getIssuedAt(), token.getExpiresAt(), accessTokenContext.getAuthorizedScopes());
        OAuth2TokenFormat accessTokenFormat = accessTokenContext.getRegisteredClient()
                .getTokenSettings()
                .getAccessTokenFormat();
        builder.token(accessToken, (metadata) -> {
            if (token instanceof ClaimAccessor claimAccessor) {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
            }
            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
            metadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
        });

        return accessToken;
    }

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
    public void wechatLogin(@RequestParam("code") String code,
                            HttpServletRequest request,
                            HttpServletResponse response) throws IOException {
        try {
            // 原有认证逻辑保持不变 - 处理WeChat登录
            CustomUserDetails userDetails = weChatService.processWeChatLogin(code);
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                    userDetails.getAuthorities());

            // 获取注册的客户端 - 原有逻辑保持不变
            RegisteredClient registeredClient = registeredClientRepository.findByClientId("ffv-client");
            if (registeredClient == null) {
                throw new IllegalStateException("Registered client for WeChat not found");
            }

            // 关键修复：获取或创建AuthorizationServerContext - 解决"value cannot be null"问题
            AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();

            // 如果AuthorizationServerContext为null，手动创建一个
            if (authorizationServerContext == null) {
                // 创建AuthorizationServerContext，确保JWT customizer能正常工作
                final AuthorizationServerSettings settings = authorizationServerSettings != null ?
                        authorizationServerSettings :
                        AuthorizationServerSettings.builder()
                                .issuer("http://localhost:9000")
                                .build();

                authorizationServerContext = new AuthorizationServerContext() {
                    @Override
                    public String getIssuer() {
                        return settings.getIssuer();
                    }

                    @Override
                    public AuthorizationServerSettings getAuthorizationServerSettings() {
                        return settings;
                    }
                };
                logger.debug("Created AuthorizationServerContext with issuer: {}", authorizationServerContext.getIssuer());
            }

            // 创建token上下文 - 完整版本，包含AuthorizationServerContext
            DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(authentication)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrant(authentication)
                    .authorizedScopes(Set.of("openid", "profile"))
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN);

            // 现在确保总是有AuthorizationServerContext
            tokenContextBuilder.authorizationServerContext(authorizationServerContext);
            logger.debug("Added AuthorizationServerContext to token context: {}",
                    authorizationServerContext.getIssuer());

            // 生成访问令牌 - 原有逻辑保持不变
            OAuth2TokenContext tokenContext = tokenContextBuilder.build();
            OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

            if (generatedAccessToken == null) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the access token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            // 关键修复：正确的token类型转换，确保数据库能正确保存
            OAuth2AccessToken accessToken = null;
            if (generatedAccessToken instanceof OAuth2AccessToken) {
                accessToken = (OAuth2AccessToken) generatedAccessToken;
            } else {
                // 创建正确类型的OAuth2AccessToken
                accessToken = new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        generatedAccessToken.getTokenValue(),
                        generatedAccessToken.getIssuedAt(),
                        generatedAccessToken.getExpiresAt(),
                        Set.of("openid", "profile")
                );
            }

            // 生成刷新令牌 - 重新构建context确保包含AuthorizationServerContext
            DefaultOAuth2TokenContext.Builder refreshTokenContextBuilder = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(authentication)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrant(authentication)
                    .authorizedScopes(Set.of("openid", "profile"))
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN);

            // 关键：为refresh token也添加AuthorizationServerContext
            if (authorizationServerContext != null) {
                refreshTokenContextBuilder.authorizationServerContext(authorizationServerContext);
                logger.debug("Added AuthorizationServerContext to refresh token context");
            }

            tokenContext = refreshTokenContextBuilder.build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            OAuth2RefreshToken refreshToken = null;
            if (generatedRefreshToken != null
                    && generatedRefreshToken.getTokenValue() != null
                    && generatedRefreshToken instanceof OAuth2RefreshToken) {
                logger.trace("Generated refresh token");
                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            } else {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate a valid refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            // **关键修复：正确创建和保存OAuth2Authorization**
            // 这是主要的新增功能，不影响原有登录流程
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                    .withRegisteredClient(registeredClient)
                    .principalName(userDetails.getUsername())
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(Set.of("openid", "profile"))
                    .attribute("code", code);

            // 使用专用方法添加tokens - 关键修复
            authorizationBuilder.accessToken(accessToken);
            authorizationBuilder.refreshToken(refreshToken);

            // 保存授权信息到数据库 - 新增功能，支持refresh token
            OAuth2Authorization authorization = authorizationBuilder.build();
            try {
                logger.info("Attempting to save OAuth2Authorization for user: {} with client: {}",
                        userDetails.getUsername(), registeredClient.getClientId());
                authorizationService.save(authorization);
                logger.info("Successfully saved OAuth2Authorization for user: {} with client: {}",
                        userDetails.getUsername(), registeredClient.getClientId());
            } catch (Exception e) {
                logger.error("Failed to save OAuth2Authorization for user: {} with client: {}. Error: {}",
                        userDetails.getUsername(), registeredClient.getClientId(), e.getMessage(), e);
                // 继续处理，但记录错误 - 不影响用户登录体验
            }

            // 创建响应 - 原有逻辑，使用正确的token类型
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("access_token", accessToken.getTokenValue());
            responseBody.put("refresh_token", refreshToken.getTokenValue());
            responseBody.put("token_type", "Bearer");
            if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
                responseBody.put("expires_in", accessToken.getExpiresAt().getEpochSecond() -
                        accessToken.getIssuedAt().getEpochSecond());
            }

            // 写入响应 - 原有逻辑保持不变
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(new ObjectMapper().writeValueAsString(responseBody));

        } catch (AuthenticationException e) {
            // 错误处理 - 原有逻辑保持不变
            logger.error("WeChat authentication failed", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "authentication_failed");
            errorResponse.put("error_description", "WeChat authentication failed" + e.getMessage());
            response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
        }
    }

    /**
     * WeChat刷新令牌端点
     * <p>
     * **新增功能说明（2025-06-14）：**
     * 这是全新增加的端点，实现OAuth2 refresh token功能。
     * <p>
     * 功能特性：
     * 1. 支持HTTP Basic认证和表单参数认证
     * 2. 完整的客户端凭据验证（使用PasswordEncoder）
     * 3. 刷新令牌验证和新令牌生成
     * 4. 优雅的错误处理和日志记录
     * 5. 当找不到access token时自动重新生成
     * <p>
     * 此功能不影响任何现有的登录或认证流程，
     * 只是为已经认证的用户提供令牌刷新能力。
     */
    @PostMapping("/wechat/refresh-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenValue,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest request) {

        logger.debug("WeChat refresh token request received");

        try {
            // Extract client credentials from Authorization header or form parameters
            String requestClientId = clientId;
            String requestClientSecret = clientSecret;

            // Check Authorization header first (Basic authentication)
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Basic ")) {
                try {
                    String base64Credentials = authHeader.substring("Basic ".length());
                    String credentials = new String(Base64.getDecoder().decode(base64Credentials));
                    String[] parts = credentials.split(":", 2);
                    if (parts.length == 2) {
                        requestClientId = parts[0];
                        requestClientSecret = parts[1];
                        logger.debug("Extracted client credentials from Authorization header: {}", requestClientId);
                    }
                } catch (Exception e) {
                    logger.warn("Failed to decode Authorization header", e);
                }
            }

            // Validate required parameters
            if (!"refresh_token".equals(grantType)) {
                Map<String, Object> errorResponse = Map.of(
                        "error", "unsupported_grant_type",
                        "error_description", "Grant type must be 'refresh_token'"
                );
                return ResponseEntity.badRequest().body(errorResponse);
            }

            if (refreshTokenValue == null || refreshTokenValue.isEmpty()) {
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_request",
                        "error_description", "Refresh token is required"
                );
                return ResponseEntity.badRequest().body(errorResponse);
            }

            if (requestClientId == null || requestClientSecret == null) {
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_client",
                        "error_description", "Client authentication required"
                );
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Validate client credentials
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(requestClientId);
            if (registeredClient == null) {
                logger.warn("Client not found: {}", requestClientId);
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_client",
                        "error_description", "Client not found"
                );
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Validate client secret using password encoder
            String storedSecret = registeredClient.getClientSecret();
            boolean secretMatches = passwordEncoder.matches(requestClientSecret, storedSecret);
            logger.debug("Client secret validation - provided secret length: {}, stored secret: {}, matches: {}",
                    requestClientSecret.length(), storedSecret, secretMatches);

            if (!secretMatches) {
                logger.warn("Invalid client secret for client: {}", requestClientId);
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_client",
                        "error_description", "Invalid client credentials"
                );
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Find the authorization by refresh token
            OAuth2Authorization authorization = authorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);
            if (authorization == null) {
                logger.warn("Refresh token not found or expired: {}", refreshTokenValue.substring(0, Math.min(refreshTokenValue.length(), 20)));
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_grant",
                        "error_description", "Refresh token not found or expired"
                );
                return ResponseEntity.badRequest().body(errorResponse);
            }

            // Verify the refresh token belongs to the authenticated client
            // Compare the authorization's registered client ID with the found RegisteredClient's ID
            if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
                logger.warn("Refresh token does not belong to client: found_client_id='{}', stored_client_id='{}'",
                        registeredClient.getId(), authorization.getRegisteredClientId());
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_grant",
                        "error_description", "Refresh token does not belong to client"
                );
                return ResponseEntity.badRequest().body(errorResponse);
            }

            // Check if refresh token is expired
            OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMetadata = authorization.getRefreshToken();
            if (refreshTokenMetadata == null || refreshTokenMetadata.isExpired()) {
                logger.warn("Refresh token is expired for client: {}", requestClientId);
                Map<String, Object> errorResponse = Map.of(
                        "error", "invalid_grant",
                        "error_description", "Refresh token expired"
                );
                return ResponseEntity.badRequest().body(errorResponse);
            }

            // **ROBUST FIX: Handle missing access token gracefully**
            OAuth2Authorization.Token<OAuth2AccessToken> existingAccessToken = authorization.getAccessToken();
            if (existingAccessToken == null || existingAccessToken.getToken() == null) {
                logger.warn("Access token is missing for authorization: {}. This may be due to incomplete data migration or previous bugs. Proceeding to generate new access token.", authorization.getId());
            } else {
                logger.debug("Found existing access token for authorization: {}", authorization.getId());
            }

            // Create authentication for token generation
            Authentication principal = new UsernamePasswordAuthenticationToken(
                    authorization.getPrincipalName(),
                    null,
                    Set.of() // empty authorities
            );

            // Generate new access token - 修复：添加AuthorizationServerContext
            // 获取或创建AuthorizationServerContext，确保JWT customizer能正常工作
            AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
            if (authorizationServerContext == null) {
                final AuthorizationServerSettings settings = authorizationServerSettings != null ?
                        authorizationServerSettings :
                        AuthorizationServerSettings.builder()
                                .issuer("http://localhost:9000")
                                .build();

                authorizationServerContext = new AuthorizationServerContext() {
                    @Override
                    public String getIssuer() {
                        return settings.getIssuer();
                    }

                    @Override
                    public AuthorizationServerSettings getAuthorizationServerSettings() {
                        return settings;
                    }
                };
                logger.debug("Created AuthorizationServerContext for refresh token with issuer: {}", authorizationServerContext.getIssuer());
            }

            DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(principal)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizedScopes(authorization.getAuthorizedScopes())
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN);

            // 确保总是有AuthorizationServerContext
            tokenContextBuilder.authorizationServerContext(authorizationServerContext);
            logger.debug("Added AuthorizationServerContext to refresh token context: {}",
                    authorizationServerContext.getIssuer());

            OAuth2TokenContext tokenContext = tokenContextBuilder.build();
            OAuth2Token newAccessToken = tokenGenerator.generate(tokenContext);

            if (newAccessToken == null) {
                Map<String, Object> errorResponse = Map.of(
                        "error", "server_error",
                        "error_description", "Failed to generate new access token"
                );
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
            }

            // Convert to OAuth2AccessToken
            OAuth2AccessToken accessToken;
            if (newAccessToken instanceof OAuth2AccessToken) {
                accessToken = (OAuth2AccessToken) newAccessToken;
            } else {
                accessToken = new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        newAccessToken.getTokenValue(),
                        newAccessToken.getIssuedAt(),
                        newAccessToken.getExpiresAt(),
                        authorization.getAuthorizedScopes()
                );
            }

            // Update the authorization with the new access token
            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
            authorizationBuilder.accessToken(accessToken);

            // Save the updated authorization
            OAuth2Authorization updatedAuthorization = authorizationBuilder.build();
            try {
                authorizationService.save(updatedAuthorization);
                logger.info("Successfully updated OAuth2Authorization with new access token for user: {}", authorization.getPrincipalName());
            } catch (Exception e) {
                logger.error("Failed to save updated OAuth2Authorization: {}", e.getMessage(), e);
                // Continue anyway, client will get the token even if save fails
            }

            // Create response
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("access_token", accessToken.getTokenValue());
            responseBody.put("refresh_token", refreshTokenMetadata.getToken().getTokenValue());
            responseBody.put("token_type", "Bearer");
            if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
                responseBody.put("expires_in", accessToken.getExpiresAt().getEpochSecond() -
                        accessToken.getIssuedAt().getEpochSecond());
            }

            return ResponseEntity.ok(responseBody);

        } catch (Exception e) {
            logger.error("Error processing refresh token request", e);
            Map<String, Object> errorResponse = Map.of(
                    "error", "server_error",
                    "error_description", "Internal server error"
            );
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Send SMS verification code
     */
    @PostMapping("/api/sms/send-code")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCode(@RequestBody Map<String, String> request) {
        String phoneNumber = request.get("phoneNumber");
        Map<String, Object> response = new HashMap<>();

        if (phoneNumber == null || phoneNumber.isEmpty()) {
            response.put("success", false);
            response.put("message", "Phone number is required");
            return ResponseEntity.badRequest().body(response);
        }

        // Generate a verification code
        String code = smsService.generateVerificationCode();

        // Send the verification code
        boolean sent = smsService.sendVerificationCode(phoneNumber, code);

        if (sent) {
            response.put("success", true);
            response.put("message", "Verification code sent");
            return ResponseEntity.ok(response);
        } else {
            response.put("success", false);
            response.put("message", "Failed to send verification code");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}