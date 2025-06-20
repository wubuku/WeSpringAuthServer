package org.dddml.wespring.resource.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * 端到端OAuth2授权流程测试
 * 
 * 这个测试类展示了完整的OAuth2授权码流程，包括：
 * 1. 生成PKCE参数
 * 2. 用户登录和授权
 * 3. 获取授权码
 * 4. 交换访问令牌
 * 5. 使用访问令牌访问资源服务器API
 * 
 * 运行此测试前需要：
 * 1. 启动WeSpringAuthServer (localhost:9000)
 * 2. 启动示例资源服务器 (localhost:8081)
 * 3. 确保数据库中有测试用户数据
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class E2EAuthFlowTests {

    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // WeSpringAuthServer配置
    private final String AUTH_SERVER = "http://localhost:9000";
    private final String CLIENT_ID = "ffv-client"; // 需要在授权服务器中配置
    private final String CLIENT_SECRET = "secret";
    private final String REDIRECT_URI = "http://127.0.0.1:3000/callback";
    
    // 测试用户配置
    private final String TEST_ADMIN_NAME = "admin";
    private final String TEST_USER_NAME = "user";
    private final String TEST_PASSWORD = "admin";
    private final String NEW_PASSWORD = "newPassword123!";
    
    // OAuth2配置
    private final String[] OAUTH2_SCOPES = { "openid", "profile" };
    private final String FORMATTED_SCOPES = String.join("+", OAUTH2_SCOPES);
    
    // HTTP客户端配置
    private final BasicCookieStore cookieStore = new BasicCookieStore();
    private final HttpClientContext context = HttpClientContext.create();
    
    @LocalServerPort
    private int port; // 资源服务器端口

    /**
     * 测试管理员用户的完整授权流程
     */
    @Test
    public void testAdminUserAuthorizationFlow() throws Exception {
        System.out.println("\n🚀 Testing OAuth2 Authorization Code Flow with Admin User\n");
        executeAuthFlowAndTest(TEST_ADMIN_NAME);
    }

    /**
     * 测试普通用户的授权流程（应该无法访问管理员API）
     */
    @Test
    public void testNormalUserAuthorizationFlow() throws Exception {
        System.out.println("\n🚀 Testing OAuth2 Authorization Code Flow with Normal User\n");
        executeAuthFlowAndTest(TEST_USER_NAME);
    }

    /**
     * 执行完整的OAuth2授权流程并测试资源访问
     */
    private void executeAuthFlowAndTest(String username) throws Exception {
        context.setCookieStore(cookieStore);
        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultCookieStore(cookieStore)
                .disableRedirectHandling()
                .build()) {
            
            // 1. 生成PKCE参数
            String codeVerifier = generateCodeVerifier();
            System.out.println("🔑 Code Verifier: " + codeVerifier);

            String codeChallenge = generateCodeChallenge(codeVerifier);
            System.out.println("🔒 Code Challenge: " + codeChallenge);

            // 2. 获取授权码
            System.out.println("\n📨 Starting Authorization Code Request...");
            String authorizationCode = getAuthorizationCode(client, codeChallenge, username);
            System.out.println("✅ Authorization Code: " + authorizationCode);

            // 3. 交换访问令牌
            System.out.println("\n🔄 Exchanging Authorization Code for Access Token...");
            String accessToken = getAccessToken(client, authorizationCode, codeVerifier);
            System.out.println("✅ Access Token: " + accessToken.substring(0, 50) + "...");

            // 4. 测试资源访问
            System.out.println("\n🧪 Testing Resource Access...");
            testResourceAccess(client, accessToken, username);
        }
    }

    /**
     * 生成PKCE代码验证器
     */
    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    /**
     * 生成PKCE代码挑战
     */
    private String generateCodeChallenge(String codeVerifier) throws Exception {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes);
        byte[] digest = messageDigest.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /**
     * 获取授权码（包含登录和授权步骤）
     */
    private String getAuthorizationCode(CloseableHttpClient client, String codeChallenge, String username)
            throws Exception {
        
        // 1. 获取登录页面和CSRF token
        System.out.println("📝 Getting login page and CSRF token...");
        HttpGet loginPageRequest = new HttpGet(AUTH_SERVER + "/login");
        loginPageRequest.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9");
        String csrfToken = null;

        try (CloseableHttpResponse response = client.execute(loginPageRequest, context)) {
            String html = EntityUtils.toString(response.getEntity());
            Document doc = Jsoup.parse(html);
            Element csrfElement = doc.selectFirst("input[name=_csrf]");
            if (csrfElement != null) {
                csrfToken = csrfElement.attr("value");
                System.out.println("🔐 CSRF Token: " + csrfToken);
            }
        }

        // 2. 执行登录
        System.out.println("\n🔑 Performing login...");
        HttpPost loginRequest = new HttpPost(AUTH_SERVER + "/login");
        loginRequest.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9");
        loginRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
        loginRequest.setHeader("Origin", AUTH_SERVER);
        loginRequest.setHeader("Referer", AUTH_SERVER + "/login");

        String formData = String.format("username=%s&password=%s&_csrf=%s",
                username, TEST_PASSWORD, csrfToken);
        loginRequest.setEntity(new StringEntity(formData, ContentType.APPLICATION_FORM_URLENCODED));

        try (CloseableHttpResponse response = client.execute(loginRequest, context)) {
            System.out.println("📤 Login Response Status: " + response.getCode());
            if (response.getHeader("Location") != null) {
                String location = response.getHeader("Location").getValue();
                System.out.println("📍 Login Response Location: " + location);

                // 处理密码修改要求（如果需要）
                if (location.contains("/password/change")) {
                    System.out.println("\n🔄 Password change required, handling password change...");
                    handlePasswordChange(client);
                    
                    // 重新登录
                    System.out.println("\n🔑 Re-logging in with new password...");
                    formData = String.format("username=%s&password=%s&_csrf=%s",
                            username, NEW_PASSWORD, csrfToken);
                    loginRequest.setEntity(new StringEntity(formData, ContentType.APPLICATION_FORM_URLENCODED));

                    try (CloseableHttpResponse reLoginResponse = client.execute(loginRequest, context)) {
                        System.out.println("📤 Re-login Response Status: " + reLoginResponse.getCode());
                    }
                }
            }
        }

        // 3. 发起OAuth2授权请求
        System.out.println("\n🔐 Initiating OAuth2 authorization request...");
        String authorizationUrl = AUTH_SERVER + "/oauth2/authorize?" +
                "response_type=code" +
                "&client_id=" + CLIENT_ID +
                "&redirect_uri=" + REDIRECT_URI +
                "&scope=" + FORMATTED_SCOPES +
                "&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256";
        System.out.println("🌐 Authorization URL: " + authorizationUrl);

        HttpGet authorizationRequest = new HttpGet(authorizationUrl);
        authorizationRequest.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9");

        try (CloseableHttpResponse response = client.execute(authorizationRequest, context)) {
            System.out.println("📤 Authorization Response Status: " + response.getCode());

            if (response.getCode() == 200) {
                // 需要用户同意授权
                System.out.println("👉 Consent required, processing consent form...");
                String html = EntityUtils.toString(response.getEntity());
                Document doc = Jsoup.parse(html);
                Element csrfElement = doc.selectFirst("input[name=_csrf]");
                Element stateElement = doc.selectFirst("input[name=state]");

                if (csrfElement != null && stateElement != null) {
                    String consentCsrfToken = csrfElement.attr("value");
                    String state = stateElement.attr("value");
                    System.out.println("🔐 Consent CSRF Token: " + consentCsrfToken);

                    HttpPost consentRequest = new HttpPost(AUTH_SERVER + "/oauth2/authorize");
                    consentRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
                    consentRequest.setHeader("Origin", AUTH_SERVER);
                    consentRequest.setHeader("Referer", authorizationUrl);

                    String consentData = String.format("client_id=%s&state=%s&scope=openid&scope=profile&_csrf=%s",
                            CLIENT_ID, state, consentCsrfToken);

                    consentRequest.setEntity(new StringEntity(consentData, ContentType.APPLICATION_FORM_URLENCODED));

                    try (CloseableHttpResponse consentResponse = client.execute(consentRequest, context)) {
                        System.out.println("📤 Consent Response Status: " + consentResponse.getCode());
                        return extractCode(consentResponse.getHeader("Location").getValue());
                    }
                }
            } else if (response.getCode() == 302) {
                // 直接重定向（用户已经授权过）
                return extractCode(response.getHeader("Location").getValue());
            }
        }

        throw new RuntimeException("Failed to get authorization code");
    }

    /**
     * 处理密码修改流程
     */
    private void handlePasswordChange(CloseableHttpClient client) throws Exception {
        // 获取密码修改页面
        HttpGet changePasswordPageRequest = new HttpGet(AUTH_SERVER + "/password/change");
        changePasswordPageRequest.setHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9");

        String newCsrfToken = null;
        String stateToken = null;

        try (CloseableHttpResponse response = client.execute(changePasswordPageRequest, context)) {
            String html = EntityUtils.toString(response.getEntity());
            Document doc = Jsoup.parse(html);
            Element csrfElement = doc.selectFirst("input[name=_csrf]");
            Element stateElement = doc.selectFirst("input[name=state]");

            if (csrfElement != null) {
                newCsrfToken = csrfElement.attr("value");
            }
            if (stateElement != null) {
                stateToken = stateElement.attr("value");
            }
        }

        // 提交密码修改
        HttpPost changePasswordRequest = new HttpPost(AUTH_SERVER + "/password/change");
        changePasswordRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
        changePasswordRequest.setHeader("Origin", AUTH_SERVER);
        changePasswordRequest.setHeader("Referer", AUTH_SERVER + "/password/change");

        String formData = String.format("_csrf=%s&state=%s&currentPassword=%s&newPassword=%s&confirmPassword=%s",
                newCsrfToken, stateToken, TEST_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
        changePasswordRequest.setEntity(new StringEntity(formData, ContentType.APPLICATION_FORM_URLENCODED));

        try (CloseableHttpResponse response = client.execute(changePasswordRequest, context)) {
            if (response.getCode() == 302) {
                System.out.println("✅ Password changed successfully");
            } else {
                throw new RuntimeException("Failed to change password");
            }
        }
    }

    /**
     * 使用授权码获取访问令牌
     */
    private String getAccessToken(CloseableHttpClient client, String code, String codeVerifier) throws Exception {
        System.out.println("\n🔄 Requesting Access Token...");
        HttpPost tokenRequest = new HttpPost(AUTH_SERVER + "/oauth2/token");
        
        // 设置Basic认证
        String auth = CLIENT_ID + ":" + CLIENT_SECRET;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        tokenRequest.setHeader("Authorization", "Basic " + encodedAuth);

        String tokenRequestBody = "grant_type=authorization_code" +
                "&code=" + code +
                "&redirect_uri=" + REDIRECT_URI +
                "&code_verifier=" + codeVerifier;

        tokenRequest.setEntity(new StringEntity(tokenRequestBody, ContentType.APPLICATION_FORM_URLENCODED));

        try (CloseableHttpResponse response = client.execute(tokenRequest)) {
            int statusCode = response.getCode();
            String json = EntityUtils.toString(response.getEntity());

            System.out.println("📤 Token Response Status: " + statusCode);
            System.out.println("📄 Token Response Body: " + json);

            if (statusCode < 200 || statusCode >= 300) {
                throw new RuntimeException("Token request failed with status " + statusCode + ": " + json);
            }

            JsonNode node = objectMapper.readTree(json);
            if (!node.has("access_token")) {
                throw new RuntimeException("Token response does not contain access_token: " + json);
            }

            return node.get("access_token").asText();
        }
    }

    /**
     * 测试资源服务器API访问
     */
    private void testResourceAccess(CloseableHttpClient client, String accessToken, String username) throws Exception {
        // 解码并显示JWT内容
        String[] parts = accessToken.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        System.out.println("\n📝 Access Token Claims:");
        System.out.println(objectMapper.readTree(payload).toPrettyString());

        String resourceServerUrl = "http://localhost:" + port;

        // 测试公开API
        System.out.println("\n🧪 Testing Public API...");
        testApiEndpoint(client, resourceServerUrl + "/api/public/hello", null, 200);

        // 测试需要认证的API
        System.out.println("\n🧪 Testing Protected API...");
        testApiEndpoint(client, resourceServerUrl + "/api/protected/user-info", accessToken, 200);

        // 测试需要特定权限的API
        System.out.println("\n🧪 Testing Users API (requires Users_Read)...");
        testApiEndpoint(client, resourceServerUrl + "/api/protected/users", accessToken, 
                username.equals(TEST_ADMIN_NAME) ? 200 : 403);

        System.out.println("\n🧪 Testing Roles API (requires Roles_Read)...");
        testApiEndpoint(client, resourceServerUrl + "/api/protected/roles", accessToken, 
                username.equals(TEST_ADMIN_NAME) ? 200 : 403);

        // 测试管理员API
        System.out.println("\n🧪 Testing Admin API...");
        testApiEndpoint(client, resourceServerUrl + "/api/admin/system-info", accessToken, 
                username.equals(TEST_ADMIN_NAME) ? 200 : 403);

        testApiEndpoint(client, resourceServerUrl + "/api/admin/cache-stats", accessToken, 
                username.equals(TEST_ADMIN_NAME) ? 200 : 403);
    }

    /**
     * 测试单个API端点
     */
    private void testApiEndpoint(CloseableHttpClient client, String url, String accessToken, int expectedStatus) 
            throws Exception {
        HttpGet request = new HttpGet(url);
        if (accessToken != null) {
            request.setHeader("Authorization", "Bearer " + accessToken);
        }

        try (CloseableHttpResponse response = client.execute(request)) {
            int actualStatus = response.getCode();
            String body = EntityUtils.toString(response.getEntity());
            
            System.out.println("📤 " + url + " - Status: " + actualStatus);
            System.out.println("📄 Response: " + body);
            
            if (actualStatus != expectedStatus) {
                throw new AssertionError(String.format(
                    "Expected status %d but got %d for %s. Response: %s", 
                    expectedStatus, actualStatus, url, body));
            }
        }
    }

    /**
     * 从重定向URL中提取授权码
     */
    private String extractCode(String location) {
        int codeIndex = location.indexOf("code=");
        if (codeIndex == -1) return null;
        
        String code = location.substring(codeIndex + 5);
        int andIndex = code.indexOf("&");
        if (andIndex != -1) {
            code = code.substring(0, andIndex);
        }
        return code;
    }
} 