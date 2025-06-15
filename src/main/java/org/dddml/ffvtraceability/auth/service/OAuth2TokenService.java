package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.config.AuthServerProperties;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * OAuth2令牌服务
 * 提取SocialLoginController和SmsController中重复的OAuth2令牌生成逻辑
 */
@Service
public class OAuth2TokenService {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2TokenService.class);

    // Constants
    private static final String DEFAULT_ISSUER = "http://localhost:9000";
    private static final Set<String> DEFAULT_SCOPES = Set.of("openid", "profile");
    private static final String BEARER_TOKEN_TYPE = "Bearer";
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    // Exception messages
    private static final String EXCEPTION_TOKEN_GENERATOR_FAILED_ACCESS = "The token generator failed to generate the access token.";
    private static final String EXCEPTION_TOKEN_GENERATOR_FAILED_REFRESH = "The token generator failed to generate a valid refresh token.";

    @Autowired
    private AuthServerProperties authServerProperties;
    @Autowired
    private OAuth2TokenGenerator<?> tokenGenerator;
    @Autowired
    private OAuth2AuthorizationService authorizationService;
    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

    /**
     * 创建认证对象
     */
    public Authentication createAuthentication(CustomUserDetails userDetails) {
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    /**
     * 生成令牌对
     */
    public TokenPair generateTokenPair(RegisteredClient registeredClient, Authentication authentication) {
        OAuth2AccessToken accessToken = generateAccessToken(registeredClient, authentication);
        OAuth2RefreshToken refreshToken = generateRefreshToken(registeredClient, authentication);
        return new TokenPair(accessToken, refreshToken);
    }

    /**
     * 创建并保存授权
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
     * 创建令牌响应体
     */
    public Map<String, Object> createTokenResponseBody(OAuth2AccessToken accessToken,
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

    // Private helper methods

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

    /**
     * 令牌对数据类
     */
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
} 