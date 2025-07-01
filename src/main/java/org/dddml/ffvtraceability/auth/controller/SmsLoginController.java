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
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

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
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final String ERROR_AUTHENTICATION_FAILED = "authentication_failed";
    private static final String MSG_SMS_AUTH_FAILED = "SMS authentication failed: ";
    private static final String EXCEPTION_REGISTERED_CLIENT_NOT_FOUND = "Registered client for SMS not found, clientId: ";

    // Refresh token constants
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final String BEARER_TOKEN_TYPE = "Bearer";
    private static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";
    private static final String BASIC_AUTH_PREFIX = "Basic ";
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

    private static final Logger logger = LoggerFactory.getLogger(SmsLoginController.class);

    @Autowired
    private SmsService smsService;
    @Autowired
    private SmsVerificationService smsVerificationService;
    @Autowired
    private OAuth2TokenService oAuth2TokenService;
    @Autowired
    private RegisteredClientRepository registeredClientRepository;
    @Autowired
    private OAuth2TokenGenerator<?> tokenGenerator;
    @Autowired
    private OAuth2AuthorizationService authorizationService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

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
                         @RequestParam(value = "referrerId", required = false) String referrerId,
                         HttpServletResponse response) throws IOException {
        // 直接调用 smsAuth 方法，保持完全相同的逻辑
        smsAuth(clientId, mobileNumber, verificationCode, referrerId, response);
    }

    /**
     * SMS刷新令牌端点
     * 支持Form和JSON格式的请求
     * 
     * Form格式:
     * grant_type=refresh_token&refresh_token=xxx&client_id=xxx&client_secret=xxx
     * 
     * 也支持Basic Authentication:
     * Authorization: Basic base64(client_id:client_secret)
     */
    @PostMapping("/refresh-token")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenValue,
            @RequestParam(value = "client_id", defaultValue = DEFAULT_CLIENT_ID) String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest request) {

        logger.debug("SMS refresh token request received");

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

        } catch (OAuth2AuthenticationException e) {
            logger.warn("OAuth2 authentication error during token refresh: {}", e.getError().getDescription());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse(e.getError().getErrorCode(), e.getError().getDescription()));
        } catch (Exception e) {
            logger.error("Error processing refresh token request", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse(ERROR_SERVER_ERROR, MSG_INTERNAL_SERVER_ERROR));
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

    // Refresh token helper methods (复用自SocialLoginController)

    private ClientCredentials extractClientCredentials(HttpServletRequest request,
                                                       String clientId,
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

    private AuthorizationServerContext getOrCreateAuthorizationServerContext() {
        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();

        if (context == null) {
            final AuthorizationServerSettings settings = authorizationServerSettings != null
                    ? authorizationServerSettings
                    : AuthorizationServerSettings.builder()
                    .issuer(DEFAULT_ISSUER)
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

    private Map<String, Object> createErrorResponse(String error, String errorDescription) {
        return Map.of(
                "error", error,
                "error_description", errorDescription);
    }

    // Helper classes
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