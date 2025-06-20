package org.dddml.wespring.resource.example;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;

/**
 * 缓存测试客户端
 * 
 * 这个客户端用于测试资源服务器的缓存机制。
 * 它会重复调用需要权限验证的API端点，
 * 你可以在资源服务器的日志中观察缓存的命中和未命中情况。
 * 
 * 使用方法：
 * 1. 启动WeSpringAuthServer
 * 2. 启动示例资源服务器
 * 3. 获取有效的访问令牌（通过E2E测试或其他方式）
 * 4. 设置ACCESS_TOKEN环境变量
 * 5. 运行此客户端：mvn exec:java -Dexec.mainClass="org.dddml.wespring.resource.example.CacheTestClient"
 */
public class CacheTestClient {
    
    private static final String RESOURCE_SERVER_URL = "http://localhost:8081";
    private static final int REQUEST_INTERVAL_MS = 2000; // 2秒间隔
    private static final int TOTAL_REQUESTS = 20; // 总请求数

    public static void main(String[] args) throws Exception {
        String accessToken = System.getenv("ACCESS_TOKEN");
        if (accessToken == null || accessToken.trim().isEmpty()) {
            System.err.println("❌ ACCESS_TOKEN environment variable is not set!");
            System.err.println("Please set it with a valid access token from WeSpringAuthServer");
            System.err.println("Example: export ACCESS_TOKEN=eyJhbGciOiJSUzI1...");
            System.exit(1);
        }

        System.out.println("🚀 Starting Cache Test Client");
        System.out.println("📍 Resource Server: " + RESOURCE_SERVER_URL);
        System.out.println("🔑 Access Token: " + accessToken.substring(0, 20) + "...");
        System.out.println("⏱️  Request Interval: " + REQUEST_INTERVAL_MS + "ms");
        System.out.println("📊 Total Requests: " + TOTAL_REQUESTS);
        System.out.println();

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            for (int i = 1; i <= TOTAL_REQUESTS; i++) {
                System.out.println("📡 Request #" + i + " - " + getCurrentTime());
                
                // 测试需要权限验证的API端点
                // 这会触发GroupAuthorityService.getGroupAuthorities()方法
                testProtectedEndpoint(client, accessToken, "/api/protected/user-info");
                testProtectedEndpoint(client, accessToken, "/api/protected/users");
                testProtectedEndpoint(client, accessToken, "/api/admin/system-info");
                
                System.out.println("✅ Request #" + i + " completed");
                System.out.println();

                if (i < TOTAL_REQUESTS) {
                    Thread.sleep(REQUEST_INTERVAL_MS);
                }
            }
        }

        System.out.println("🎉 Cache test completed!");
        System.out.println("📝 Check the resource server logs to observe cache behavior:");
        System.out.println("   - Look for 'Cache MISS' messages (should only appear on first request for each group)");
        System.out.println("   - Subsequent requests should not show cache miss messages");
        System.out.println("   - After cache expiration (default 1 hour), you'll see cache miss messages again");
    }

    private static void testProtectedEndpoint(CloseableHttpClient client, String accessToken, String endpoint) 
            throws Exception {
        String url = RESOURCE_SERVER_URL + endpoint;
        HttpGet request = new HttpGet(url);
        request.setHeader("Authorization", "Bearer " + accessToken);

        try (CloseableHttpResponse response = client.execute(request)) {
            int status = response.getCode();
            String body = EntityUtils.toString(response.getEntity());
            
            System.out.println("  📤 " + endpoint + " -> " + status);
            if (status != 200 && status != 403) {
                System.out.println("  ⚠️  Unexpected status: " + status);
                System.out.println("  📄 Response: " + body);
            }
        }
    }

    private static String getCurrentTime() {
        return java.time.LocalTime.now().toString();
    }
} 