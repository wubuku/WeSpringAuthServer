package org.dddml.ffvtraceability.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.config.AuthServerProperties;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * OAuth2认证帮助服务 - 抽取Controller中的重复逻辑
 * 提供统一的OAuth2 Token生成、验证、刷新等功能
 */
@Service
public class OAuth2AuthenticationHelper {

    // Constants
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final String BEARER_TOKEN_TYPE = "Bearer";
    private static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";
    private static final String BASIC_AUTH_PREFIX = "Basic ";
    private static final String CONTENT_TYPE_JSON = "application/json;charset=UTF-8";
    private static final String DEFAULT_ISSUER = "http://localhost:9000";
    private static final Set<String> DEFAULT_SCOPES = Set.of("openid", "profile");
    private static final String CREDENTIALS_SEPARATOR = ":";
    private static final int EXPECTED_CREDENTIAL_PARTS = 2;

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

    private static final String EXCEPTION_REGISTERED_CLIENT_NOT_FOUND = "Registered client not found, clientId: ";
    private static final String EXCEPTION_TOKEN_GENERATOR_FAILED_ACCESS = "The token generator failed to generate the access token.";
    private static final String EXCEPTION_TOKEN_GENERATOR_FAILED_REFRESH = "The token generator failed to generate a valid refresh token.";

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationHelper.class);

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private AuthServerProperties authServerProperties;

    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

    /**
     * 获取注册客户端
     */
    public RegisteredClient getRegisteredClient(String clientId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalStateException(EXCEPTION_REGISTERED_CLIENT_NOT_FOUND + clientId);
        }
        return registeredClient;
    }

    /**
     * 生成Token对
     */
    public TokenPair generateTokenPair(RegisteredClient registeredClient, Authentication authentication) {
        OAuth2AccessToken accessToken = generateAccessToken(registeredClient, authentication);
        OAuth2RefreshToken refreshToken = generateRefreshToken(registeredClient, authentication);
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 创建并保存OAuth2Authorization
     */
    public OAuth2Authorization createAndSaveAuthorization(RegisteredClient registeredClient,
                                                          CustomUserDetails userDetails,
                                                          TokenPair tokenPair) {
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(userDetails.getUsername())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(DEFAULT_SCOPES)
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

    /**
     * 写入Token响应
     */
    public void writeTokenResponse(HttpServletResponse response, TokenPair tokenPair) throws IOException {
        Map<String, Object> responseBody = createTokenResponseBody(tokenPair.getAccessToken(),
                tokenPair.getRefreshToken());

        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseBody));
    }

    /**
     * 处理认证错误
     */
    public void handleAuthenticationError(HttpServletResponse response, Exception e, String errorPrefix) throws IOException {
        logger.warn("Authentication failed: {}", e.getMessage());
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> errorResponse = createErrorResponse("authentication_failed",
                errorPrefix + e.getMessage());

        response.setContentType(CONTENT_TYPE_JSON);
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
    }

    /**
     * 刷新Token处理
     */
    public ResponseEntity<Map<String, Object>> processRefreshToken(String grantType,
                                                                   String refreshTokenValue,
                                                                   String clientId,
                                                                   String clientSecret,
                                                                   HttpServletRequest request) {
        try {
            // Extract and validate client credentials
            ClientCredentials credentials = extractClientCredentials(request, clientId, clientSecret);
            
            // Validate request parameters
            ResponseEntity<Map<String, Object>> validationError = validateRefreshTokenRequest(grantType, refreshTokenValue, credentials);
            if (validationError != null) {
                return validationError;
            }

            // Validate client
            RegisteredClient registeredClient = validateClientCredentials(credentials);

            // Validate refresh token
            OAuth2Authorization authorization = validateRefreshToken(refreshTokenValue, registeredClient);

            // Generate new access token
            OAuth2AccessToken newAccessToken = generateNewAccessToken(registeredClient, authorization);

            // Update authorization with new token
            updateAuthorizationWithNewToken(authorization, newAccessToken);

            // Return success response
            OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
            return createTokenResponse(newAccessToken, refreshToken);

        } catch (Exception e) {
            logger.error("Error processing refresh token: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(createErrorResponse(ERROR_SERVER_ERROR, MSG_INTERNAL_SERVER_ERROR));
        }
    }

    // Private methods

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

    public Map<String, Object> createErrorResponse(String error, String errorDescription) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", error);
        errorResponse.put("error_description", errorDescription);
        return errorResponse;
    }

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
            return ResponseEntity.badRequest().body(createErrorResponse(ERROR_UNSUPPORTED_GRANT_TYPE, MSG_GRANT_TYPE_MUST_BE_REFRESH_TOKEN));
        }

        if (refreshTokenValue == null || refreshTokenValue.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(createErrorResponse(ERROR_INVALID_REQUEST, MSG_REFRESH_TOKEN_REQUIRED));
        }

        if (credentials.getClientId() == null || credentials.getClientId().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(createErrorResponse(ERROR_INVALID_CLIENT, MSG_CLIENT_AUTH_REQUIRED));
        }

        return null; // No validation error
    }

    private RegisteredClient validateClientCredentials(ClientCredentials credentials) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(credentials.getClientId());
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_CLIENT, MSG_CLIENT_NOT_FOUND, ERROR_URI));
        }

        // Validate client secret if required
        if (credentials.getClientSecret() != null) {
            // Add client secret validation logic here if needed
            logger.debug("Client secret provided for validation");
        }

        logger.debug("Client validation successful: {}", credentials.getClientId());
        return registeredClient;
    }

    private OAuth2Authorization validateRefreshToken(String refreshTokenValue, RegisteredClient registeredClient) {
        OAuth2Authorization authorization = authorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, MSG_REFRESH_TOKEN_NOT_FOUND, ERROR_URI));
        }

        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, MSG_REFRESH_TOKEN_NOT_BELONG_TO_CLIENT, ERROR_URI));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken.getToken().getExpiresAt() != null && refreshToken.getToken().getExpiresAt().isBefore(Instant.now())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_INVALID_GRANT, MSG_REFRESH_TOKEN_EXPIRED, ERROR_URI));
        }

        logger.debug("Refresh token validation successful for client: {}", registeredClient.getClientId());
        return authorization;
    }

    private OAuth2AccessToken generateNewAccessToken(RegisteredClient registeredClient,
                                                     OAuth2Authorization authorization) {
        // Create authentication from authorization
        Authentication authentication = authorization.getAttribute(Authentication.class.getName());
        if (authentication == null) {
            // Fallback: create a simple authentication if not found
            authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                    authorization.getPrincipalName(), null);
        }

        OAuth2TokenContext tokenContext = createTokenContext(
                registeredClient, authentication, AuthorizationGrantType.REFRESH_TOKEN,
                OAuth2TokenType.ACCESS_TOKEN, authorization.getAuthorizedScopes());

        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        if (generatedToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(ERROR_SERVER_ERROR, MSG_FAILED_TO_GENERATE_ACCESS_TOKEN, ERROR_URI));
        }

        logger.debug("Generated new access token for client: {}", registeredClient.getClientId());
        return convertToAccessToken(generatedToken, authorization.getAuthorizedScopes());
    }

    private void updateAuthorizationWithNewToken(OAuth2Authorization authorization, OAuth2AccessToken newAccessToken) {
        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                .accessToken(newAccessToken)
                .build();

        authorizationService.save(updatedAuthorization);
        logger.debug("Updated authorization with new access token: {}", authorization.getId());
    }

    private ResponseEntity<Map<String, Object>> createTokenResponse(OAuth2AccessToken accessToken,
                                                                    OAuth2RefreshToken refreshToken) {
        Map<String, Object> tokenResponse = createTokenResponseBody(accessToken, refreshToken);
        logger.debug("Created token response with access token: {}...", accessToken.getTokenValue().substring(0, Math.min(accessToken.getTokenValue().length(), 20)));
        return ResponseEntity.ok(tokenResponse);
    }

    // Inner classes

    public static class TokenPair {
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

    public static class ClientCredentials {
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