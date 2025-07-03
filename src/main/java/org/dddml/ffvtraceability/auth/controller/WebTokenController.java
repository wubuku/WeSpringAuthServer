package org.dddml.ffvtraceability.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.config.CookieSecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Web客户端Token处理Controller
 * 
 * 🔒 安全升级 (2024-01-XX)：
 * - 添加HttpOnly Cookie支持存储refresh_token
 * - 从响应中移除refresh_token，提高安全性
 */
@RestController
@RequestMapping("/web-clients/oauth2")
public class WebTokenController {

    private static final Logger logger = LoggerFactory.getLogger(WebTokenController.class);
    
    private final OAuth2AuthorizationService authorizationService;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    
    @Autowired
    private CookieSecurityConfig cookieSecurityConfig;
    
    @Value("${auth-server.web-clients.allowed-client-ids}")
    private String[] allowedClientIds;
    @Value("${auth-server.web-clients.client-secrets}")
    private String[] clientSecrets;

    public WebTokenController(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * OAuth2 Token端点 - 授权码交换access_token
     * 
     * 🔒 安全升级：成功获取token后设置HttpOnly Cookie存储refresh_token
     */
    @PostMapping("/token")
    public ResponseEntity<String> getToken(
            @RequestParam("client_id") String clientId,
            @RequestParam("code") String code,
            @RequestParam("code_verifier") String codeVerifier,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "cookie_mode", defaultValue = "true") boolean cookieMode,
            HttpServletRequest request,
            HttpServletResponse response) {

        logger.info("🔄 处理Web OAuth2 token请求 - ClientId: {}, CookieMode: {}", clientId, cookieMode);

        // 1. 验证 client_id 是否在允许列表中
        int clientIndex = -1;
        for (int i = 0; i < allowedClientIds.length; i++) {
            if (allowedClientIds[i].equals(clientId)) {
                clientIndex = i;
                break;
            }
        }

        if (clientIndex == -1) {
            logger.warn("❌ Unauthorized client_id: {}", clientId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"unauthorized_client\"}");
        }

        try {
            // 2. 构建请求头和请求体
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(clientId, clientSecrets[clientIndex]);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("code", code);
            body.add("redirect_uri", redirectUri);
            body.add("code_verifier", codeVerifier);

            HttpEntity<MultiValueMap<String, String>> requestEntity =
                    new HttpEntity<>(body, headers);

            // 3. 调用本地 token endpoint
            ResponseEntity<String> originalResponse = restTemplate.postForEntity(
                    "http://localhost:" + request.getServerPort() + "/oauth2/token",
                    requestEntity,
                    String.class
            );

            if (originalResponse.getStatusCode().is2xxSuccessful() && cookieMode) {
                // 🔒 安全升级：处理Cookie模式响应
                return handleCookieModeResponse(originalResponse, response);
            } else {
                // 传统模式：直接返回原始响应
                logger.debug("✅ Token请求成功 (传统模式)");
                return ResponseEntity.status(originalResponse.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(originalResponse.getBody());
            }

        } catch (Exception e) {
            logger.error("❌ Token request failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"internal_server_error\",\"error_description\":\""
                            + e.getMessage() + "\"}");
        }
    }

    /**
     * 🔒 安全升级：处理Cookie模式响应
     * - 提取refresh_token并设置HttpOnly Cookie
     * - 从响应中移除refresh_token
     */
    private ResponseEntity<String> handleCookieModeResponse(ResponseEntity<String> originalResponse, 
                                                           HttpServletResponse response) {
        try {
            JsonNode jsonResponse = objectMapper.readTree(originalResponse.getBody());
            
            if (jsonResponse.has("refresh_token")) {
                String refreshToken = jsonResponse.get("refresh_token").asText();
                
                // 🔒 设置HttpOnly Cookie存储refresh_token
                cookieSecurityConfig.setRefreshTokenCookie(response, refreshToken);
                logger.info("✅ 设置HttpOnly Cookie存储refresh_token: {}...", 
                           refreshToken.substring(0, Math.min(20, refreshToken.length())));
                
                // 🔒 从响应中移除refresh_token
                ((com.fasterxml.jackson.databind.node.ObjectNode) jsonResponse).remove("refresh_token");
                
                String secureResponseBody = objectMapper.writeValueAsString(jsonResponse);
                
                logger.debug("✅ Token请求成功 (Cookie安全模式)");
                return ResponseEntity.status(originalResponse.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(secureResponseBody);
            } else {
                logger.warn("⚠️  响应中没有refresh_token，按原样返回");
                return ResponseEntity.status(originalResponse.getStatusCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(originalResponse.getBody());
            }
            
        } catch (Exception e) {
            logger.error("❌ 处理Cookie模式响应失败: {}", e.getMessage(), e);
            // 发生错误时返回原始响应
            return ResponseEntity.status(originalResponse.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(originalResponse.getBody());
        }
    }
} 