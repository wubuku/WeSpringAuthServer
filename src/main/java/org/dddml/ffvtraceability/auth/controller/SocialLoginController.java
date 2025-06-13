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
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;

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
     * WeChat login
     */
    @GetMapping("/wechat/login")
    public void wechatLogin(@RequestParam("code") String code,
                            HttpServletRequest request,
                            HttpServletResponse response) throws IOException {
        try {
            // Process the WeChat login
            CustomUserDetails userDetails = weChatService.processWeChatLogin(code);
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                    userDetails.getAuthorities());
            // Get registered client
            RegisteredClient registeredClient = registeredClientRepository.findByClientId("ffv-client");
            if (registeredClient == null) {
                throw new IllegalStateException("Registered client for WeChat not found");
            }
//            OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
//                    null,
//                    new Object());

            // Create token context
            DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(authentication)
                    .authorizationGrantType(CLIENT_CREDENTIALS)//(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    //.authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(Set.of("openid", "profile"))
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN);

            // Generate access token
            OAuth2TokenContext tokenContext = tokenContextBuilder.build();
            OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

            if (generatedAccessToken == null) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the access token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }
            OAuth2RefreshToken refreshToken = null;
            // Do not issue refresh token to public client
            //if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null
                    && generatedRefreshToken.getTokenValue() != null
                    && generatedRefreshToken instanceof OAuth2RefreshToken) {
                if (logger.isTraceEnabled()) {
                    logger.trace("Generated refresh token");
                }
                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            } else {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate a valid refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }
//}
//            OidcIdToken idToken = null;
//            Map<String, Object> additionalParameters = Collections.emptyMap();
//            if (idToken != null) {
//                additionalParameters = new HashMap<>();
//                additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
//            }
//            Authentication oAuth2AccessTokenAuthenticationToken =
//                    new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, generatedAccessToken, null,
//                            additionalParameters);
//            new OAuth2AccessTokenResponseAuthenticationSuccessHandler().onAuthenticationSuccess(request, response,
//                    oAuth2AccessTokenAuthenticationToken);
            // Create response with token
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("access_token", generatedAccessToken.getTokenValue());
            responseBody.put("refresh_token", refreshToken.getTokenValue());
            responseBody.put("token_type", "Bearer");
            //if (generatedAccessToken instanceof OAuth2AccessToken accessToken) {
            if (generatedAccessToken.getIssuedAt() != null && generatedAccessToken.getExpiresAt() != null) {
                responseBody.put("expires_in", generatedAccessToken.getExpiresAt().getEpochSecond() -
                        generatedAccessToken.getIssuedAt().getEpochSecond());
            }
            //}
            // Write response
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(new ObjectMapper().writeValueAsString(responseBody));

        } catch (AuthenticationException e) {
            logger.error("WeChat authentication failed", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "authentication_failed");
            errorResponse.put("error_description", "WeChat authentication failed" + e.getMessage());
            response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
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