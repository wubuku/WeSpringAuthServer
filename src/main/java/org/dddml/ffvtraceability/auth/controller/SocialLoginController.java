package org.dddml.ffvtraceability.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.config.AuthServerProperties;
import org.dddml.ffvtraceability.auth.exception.AuthenticationException;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
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
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 社交登录控制器
 * 目前主要处理微信登录相关的功能
 * <p>
 * 包含的功能：
 * - 微信小程序登录
 * - 微信登录令牌刷新
 */
@Controller
public class SocialLoginController {

    // Constants
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final String DEFAULT_CLIENT_ID = "ffv-client";
    private static final String BEARER_TOKEN_TYPE = "Bearer";
    private static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";
    private static final String BASIC_AUTH_PREFIX = "Basic ";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final String DEFAULT_ISSUER = "http://localhost:9000";
    private static final Set<String> DEFAULT_SCOPES = Set.of("openid", "profile");
    private static final String CREDENTIALS_SEPARATOR = ":";
    private static final int EXPECTED_CREDENTIAL_PARTS = 2;
    private static final int TOKEN_PREVIEW_LENGTH = 20;

    // Error codes
    private static final String ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    private static final String ERROR_INVALID_REQUEST = "invalid_request";
    private static final String ERROR_INVALID_CLIENT = "invalid_client";
    private static final String ERROR_INVALID_GRANT = "invalid_grant";
    private static final String ERROR_SERVER_ERROR = "server_error";
    private static final String ERROR_AUTHENTICATION_FAILED = "authentication_failed";

    // Error messages
    private static final String MSG_GRANT_TYPE_MUST_BE_REFRESH_TOKEN = "Grant type must be 'refresh_token'";
    private static final String MSG_REFRESH_TOKEN_REQUIRED = "Refresh token is required";
    private static final String MSG_CLIENT_AUTH_REQUIRED = "Client authentication required";
    private static final String MSG_CLIENT_NOT_FOUND = "Client not found";
    private static final String MSG_INVALID_CLIENT_CREDENTIALS = "Invalid client credentials";
    private static final String MSG_REFRESH_TOKEN_NOT_FOUND = "Refresh token not found or expired";
    private static final String MSG_REFRESH_TOKEN_NOT_BELONG_TO_CLIENT = "Refresh token does not belong to client";
    private static final String MSG_REFRESH_TOKEN_EXPIRED = "Refresh token expired";
    private static final String MSG_FAILED_TO_GENERATE_ACCESS_TOKEN = "Failed to generate new access token";
    private static final String MSG_INTERNAL_SERVER_ERROR = "Internal server error";
    private static final String MSG_WECHAT_AUTH_FAILED = "WeChat authentication failed";

    // Exception messages
    private static final String EXCEPTION_WECHAT_LOGIN_CODE_EMPTY = "WeChat login code is empty"; // "微信小程序登录 Code 不能为空";
    private static final String EXCEPTION_MOBILE_CODE_EMPTY = "Mobile code is empty"; // "手机授权 Code 不能为空";
    private static final String EXCEPTION_REGISTERED_CLIENT_NOT_FOUND = "Registered client for WeChat not found, clientId:";
    private static final String EXCEPTION_TOKEN_GENERATOR_FAILED_ACCESS = "The token generator failed to generate the access token.";
    private static final String EXCEPTION_TOKEN_GENERATOR_FAILED_REFRESH = "The token generator failed to generate a valid refresh token.";

    private static final Logger logger = LoggerFactory.getLogger(SocialLoginController.class);

    @Autowired
    private WeChatService weChatService;

    @Autowired
    private AuthServerProperties authServerProperties;

    @Autowired
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

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
                            @RequestParam("mobileCode") String mobileCode,
                            HttpServletResponse response) throws IOException {

        validateLoginParameters(loginCode, mobileCode);

        try {
            CustomUserDetails userDetails = weChatService.processWeChatLogin(loginCode, mobileCode);
            Authentication authentication = createAuthentication(userDetails);
            RegisteredClient registeredClient = getRegisteredClient(clientId);

            TokenPair tokenPair = generateTokenPair(registeredClient, authentication);
            OAuth2Authorization authorization = createAndSaveAuthorization(registeredClient, userDetails, tokenPair,
                    loginCode);

            writeTokenResponse(response, tokenPair);

        } catch (AuthenticationException e) {
            handleAuthenticationError(response, e);
        }
    }

    /**
     * WeChat刷新令牌端点
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
            ClientCredentials credentials = extractClientCredentials(request, clientId, clientSecret);

            ResponseEntity<Map<String, Object>> validationError = validateRefreshTokenRequest(grantType,
                    refreshTokenValue, credentials);
            if (validationError != null) {
                return validationError;
            }

            RegisteredClient registeredClient = validateClientCredentials(credentials);
            OAuth2Authorization authorization = validateRefreshToken(refreshTokenValue, registeredClient);

            OAuth2AccessToken newAccessToken = generateNewAccessToken(registeredClient, authorization);
            updateAuthorizationWithNewToken(authorization, newAccessToken);

            return createTokenResponse(newAccessToken, authorization.getRefreshToken().getToken());

        } catch (Exception e) {
            logger.error("Error processing refresh token request", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse(ERROR_SERVER_ERROR, MSG_INTERNAL_SERVER_ERROR));
        }
    }

    // Helper methods

    private void validateLoginParameters(String loginCode, String mobileCode) {
        if (loginCode == null || loginCode.trim().isEmpty()) {
            throw new IllegalArgumentException(EXCEPTION_WECHAT_LOGIN_CODE_EMPTY);
        }
        if (mobileCode == null || mobileCode.trim().isEmpty()) {
            throw new IllegalArgumentException(EXCEPTION_MOBILE_CODE_EMPTY);
        }
    }

    private Authentication createAuthentication(CustomUserDetails userDetails) {
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private RegisteredClient getRegisteredClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalStateException(EXCEPTION_REGISTERED_CLIENT_NOT_FOUND + clientId);
        }
        return registeredClient;
    }

    private AuthorizationServerContext getOrCreateAuthorizationServerContext() {
        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();

        if (context == null) {
            final AuthorizationServerSettings settings = authorizationServerSettings != null
                    ? authorizationServerSettings
                    : AuthorizationServerSettings.builder()
                    .issuer(authServerProperties != null ? authServerProperties.getIssuer() : DEFAULT_ISSUER)
                    .build();

            context = new AuthorizationServerContext() {
                @Override
                public String getIssuer() {
                    return settings.getIssuer();
                }

                @Override
                public AuthorizationServerSettings getAuthorizationServerSettings() {
                    return settings;
                }
            };
            logger.debug("Created AuthorizationServerContext with issuer: {}", context.getIssuer());
        }

        return context;
    }

    private OAuth2TokenContext createTokenContext(RegisteredClient registeredClient,
                                                  Authentication authentication,
                                                  AuthorizationGrantType grantType,
                                                  OAuth2TokenType tokenType,
                                                  Set<String> scopes) {

        DefaultOAuth2TokenContext.Builder builder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationGrantType(grantType)
                .authorizedScopes(scopes)
                .tokenType(tokenType)
                .authorizationServerContext(getOrCreateAuthorizationServerContext());

        if (grantType == AuthorizationGrantType.AUTHORIZATION_CODE) {
            builder.authorizationGrant(authentication);
        }

        return builder.build();
    }

    private OAuth2AccessToken generateAccessToken(RegisteredClient registeredClient, Authentication authentication) {
        OAuth2TokenContext tokenContext = createTokenContext(
                registeredClient, authentication, AuthorizationGrantType.AUTHORIZATION_CODE,
                OAuth2TokenType.ACCESS_TOKEN, DEFAULT_SCOPES);

        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        if (generatedToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    EXCEPTION_TOKEN_GENERATOR_FAILED_ACCESS, ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        return convertToAccessToken(generatedToken, DEFAULT_SCOPES);
    }

    private OAuth2RefreshToken generateRefreshToken(RegisteredClient registeredClient, Authentication authentication) {
        OAuth2TokenContext tokenContext = createTokenContext(
                registeredClient, authentication, AuthorizationGrantType.AUTHORIZATION_CODE,
                OAuth2TokenType.REFRESH_TOKEN, DEFAULT_SCOPES);

        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        if (!(generatedToken instanceof OAuth2RefreshToken)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    EXCEPTION_TOKEN_GENERATOR_FAILED_REFRESH, ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        return (OAuth2RefreshToken) generatedToken;
    }

    private OAuth2AccessToken convertToAccessToken(OAuth2Token token, Set<String> scopes) {
        if (token instanceof OAuth2AccessToken) {
            return (OAuth2AccessToken) token;
        }

        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                token.getTokenValue(),
                token.getIssuedAt(),
                token.getExpiresAt(),
                scopes);
    }

    private TokenPair generateTokenPair(RegisteredClient registeredClient, Authentication authentication) {
        OAuth2AccessToken accessToken = generateAccessToken(registeredClient, authentication);
        OAuth2RefreshToken refreshToken = generateRefreshToken(registeredClient, authentication);
        return new TokenPair(accessToken, refreshToken);
    }

    private OAuth2Authorization createAndSaveAuthorization(RegisteredClient registeredClient,
                                                           CustomUserDetails userDetails,
                                                           TokenPair tokenPair,
                                                           String loginCode) {
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(userDetails.getUsername())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(DEFAULT_SCOPES)
                .attribute("code", loginCode)
                .accessToken(tokenPair.getAccessToken())
                .refreshToken(tokenPair.getRefreshToken());

        OAuth2Authorization authorization = authorizationBuilder.build();

        try {
            authorizationService.save(authorization);
            logger.info("Successfully saved OAuth2Authorization for user: {} with client: {}",
                    userDetails.getUsername(), registeredClient.getClientId());
        } catch (Exception e) {
            logger.error("Failed to save OAuth2Authorization for user: {} with client: {}. Error: {}",
                    userDetails.getUsername(), registeredClient.getClientId(), e.getMessage(), e);
        }

        return authorization;
    }

    private void writeTokenResponse(HttpServletResponse response, TokenPair tokenPair) throws IOException {
        Map<String, Object> responseBody = createTokenResponseBody(tokenPair.getAccessToken(),
                tokenPair.getRefreshToken());

        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseBody));
    }

    private Map<String, Object> createTokenResponseBody(OAuth2AccessToken accessToken,
                                                        OAuth2RefreshToken refreshToken) {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("access_token", accessToken.getTokenValue());
        responseBody.put("refresh_token", refreshToken.getTokenValue());
        responseBody.put("token_type", BEARER_TOKEN_TYPE);

        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            responseBody.put("expires_in", accessToken.getExpiresAt().getEpochSecond() -
                    accessToken.getIssuedAt().getEpochSecond());
        }

        return responseBody;
    }

    private void handleAuthenticationError(HttpServletResponse response, AuthenticationException e) throws IOException {
        logger.warn("WeChat authentication failed: {}", e.getMessage());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> errorResponse = createErrorResponse(ERROR_AUTHENTICATION_FAILED,
                MSG_WECHAT_AUTH_FAILED + e.getMessage());

        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }

    private ClientCredentials extractClientCredentials(HttpServletRequest request, String clientId,
                                                       String clientSecret) {
        String requestClientId = clientId;
        String requestClientSecret = clientSecret;

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith(BASIC_AUTH_PREFIX)) {
            try {
                String base64Credentials = authHeader.substring(BASIC_AUTH_PREFIX.length());
                String credentials = new String(Base64.getDecoder().decode(base64Credentials));
                String[] parts = credentials.split(CREDENTIALS_SEPARATOR, EXPECTED_CREDENTIAL_PARTS);
                if (parts.length == EXPECTED_CREDENTIAL_PARTS) {
                    requestClientId = parts[0];
                    requestClientSecret = parts[1];
                    logger.debug("Extracted client credentials from Authorization header: {}", requestClientId);
                }
            } catch (Exception e) {
                logger.debug("Failed to decode Authorization header: {}", e.getMessage());
            }
        }

        return new ClientCredentials(requestClientId, requestClientSecret);
    }

    private ResponseEntity<Map<String, Object>> validateRefreshTokenRequest(String grantType,
                                                                            String refreshTokenValue,
                                                                            ClientCredentials credentials) {
        if (!REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse(ERROR_UNSUPPORTED_GRANT_TYPE, MSG_GRANT_TYPE_MUST_BE_REFRESH_TOKEN));
        }

        if (refreshTokenValue == null || refreshTokenValue.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse(ERROR_INVALID_REQUEST, MSG_REFRESH_TOKEN_REQUIRED));
        }

        if (credentials.getClientId() == null || credentials.getClientSecret() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse(ERROR_INVALID_CLIENT, MSG_CLIENT_AUTH_REQUIRED));
        }

        return null; // No validation errors
    }

    private RegisteredClient validateClientCredentials(ClientCredentials credentials) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(credentials.getClientId());
        if (registeredClient == null) {
            logger.warn("Client not found: {}", credentials.getClientId());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(ERROR_INVALID_CLIENT, MSG_CLIENT_NOT_FOUND, ERROR_URI));
        }

        String storedSecret = registeredClient.getClientSecret();
        boolean secretMatches = passwordEncoder.matches(credentials.getClientSecret(), storedSecret);

        if (!secretMatches) {
            logger.warn("Invalid client secret for client: {}", credentials.getClientId());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(ERROR_INVALID_CLIENT, MSG_INVALID_CLIENT_CREDENTIALS, ERROR_URI));
        }

        return registeredClient;
    }

    private OAuth2Authorization validateRefreshToken(String refreshTokenValue, RegisteredClient registeredClient) {
        OAuth2Authorization authorization = authorizationService.findByToken(refreshTokenValue,
                OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            logger.warn("Refresh token not found or expired: {}",
                    refreshTokenValue.substring(0, Math.min(refreshTokenValue.length(), TOKEN_PREVIEW_LENGTH)));
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(ERROR_INVALID_GRANT, MSG_REFRESH_TOKEN_NOT_FOUND, ERROR_URI));
        }

        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            logger.warn("Refresh token does not belong to client: found_client_id='{}', stored_client_id='{}'",
                    registeredClient.getId(), authorization.getRegisteredClientId());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(ERROR_INVALID_GRANT, MSG_REFRESH_TOKEN_NOT_BELONG_TO_CLIENT, ERROR_URI));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenMetadata = authorization.getRefreshToken();
        if (refreshTokenMetadata == null || refreshTokenMetadata.isExpired()) {
            logger.warn("Refresh token is expired for client: {}", registeredClient.getClientId());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(ERROR_INVALID_GRANT, MSG_REFRESH_TOKEN_EXPIRED, ERROR_URI));
        }

        return authorization;
    }

    private OAuth2AccessToken generateNewAccessToken(RegisteredClient registeredClient,
                                                     OAuth2Authorization authorization) {
        Authentication principal = new UsernamePasswordAuthenticationToken(
                authorization.getPrincipalName(), null, Set.of());

        OAuth2TokenContext tokenContext = createTokenContext(
                registeredClient, principal, AuthorizationGrantType.REFRESH_TOKEN,
                OAuth2TokenType.ACCESS_TOKEN, authorization.getAuthorizedScopes());

        OAuth2Token newToken = tokenGenerator.generate(tokenContext);
        if (newToken == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(ERROR_SERVER_ERROR, MSG_FAILED_TO_GENERATE_ACCESS_TOKEN, ERROR_URI));
        }

        return convertToAccessToken(newToken, authorization.getAuthorizedScopes());
    }

    private void updateAuthorizationWithNewToken(OAuth2Authorization authorization, OAuth2AccessToken newAccessToken) {
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
        authorizationBuilder.accessToken(newAccessToken);

        OAuth2Authorization updatedAuthorization = authorizationBuilder.build();
        try {
            authorizationService.save(updatedAuthorization);
            logger.info("Successfully updated OAuth2Authorization with new access token for user: {}",
                    authorization.getPrincipalName());
        } catch (Exception e) {
            logger.error("Failed to save updated OAuth2Authorization: {}", e.getMessage(), e);
        }
    }

    private ResponseEntity<Map<String, Object>> createTokenResponse(OAuth2AccessToken accessToken,
                                                                    OAuth2RefreshToken refreshToken) {
        Map<String, Object> responseBody = createTokenResponseBody(accessToken, refreshToken);
        return ResponseEntity.ok(responseBody);
    }

    private Map<String, Object> createErrorResponse(String error, String errorDescription) {
        return Map.of(
                "error", error,
                "error_description", errorDescription);
    }

    // Traditional classes for data transfer
    private static class TokenPair {
        private final OAuth2AccessToken accessToken;
        private final OAuth2RefreshToken refreshToken;

        public TokenPair(OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }

        public OAuth2AccessToken getAccessToken() {
            return accessToken;
        }

        public OAuth2RefreshToken getRefreshToken() {
            return refreshToken;
        }
    }

    private static class ClientCredentials {
        private final String clientId;
        private final String clientSecret;

        public ClientCredentials(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret;
        }

        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }
    }
}