package org.dddml.ffvtraceability.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoderTest {
    
    @Test
    public void testPasswordEncoding() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String rawPassword = "admin";
        String encodedPassword = encoder.encode(rawPassword);
        System.out.println("Raw password: " + rawPassword);
        System.out.println("Encoded password: " + encodedPassword);
        
        // 验证现有密码
        String existingEncodedPassword = "{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky";
        boolean matches = encoder.matches(rawPassword, existingEncodedPassword);
        System.out.println("Existing password matches: " + matches);
    }

    @Test
    public void generateTestUserPasswords() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        
        // 为测试用户生成容易记忆的密码
        String[][] testUsers = {
            {"hq_admin", "hq123"},
            {"distributor_admin", "dist123"},
            {"store_admin", "store123"},
            {"consultant", "cons123"},
            {"distributor_employee", "emp123"}
        };
        
        System.out.println("=== 测试用户密码编码结果 ===");
        for (String[] user : testUsers) {
            String username = user[0];
            String rawPassword = user[1];
            String encodedPassword = encoder.encode(rawPassword);
            System.out.println("用户: " + username);
            System.out.println("原始密码: " + rawPassword);
            System.out.println("编码密码: " + encodedPassword);
            System.out.println("---");
        }
    }

    @Test
    public void testClientSecretEncoding() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String rawClientSecret = "secret";
        String encodedClientSecret = encoder.encode(rawClientSecret);
        System.out.println("Raw client secret: " + rawClientSecret);
        System.out.println("Encoded client secret: " + encodedClientSecret);
        
        // 验证数据库中存储的客户端密钥
        String existingEncodedSecret = "{bcrypt}$2a$10$RxycSRXenJ6CeGMP0.LGIOzesA2VwJXBOlmq33t9dn.yU8nX1fqsK";
        boolean matches = encoder.matches(rawClientSecret, existingEncodedSecret);
        System.out.println("Existing client secret matches: " + matches);
        
        // 额外验证：确保Base64编码正确
        String basicAuth = java.util.Base64.getEncoder().encodeToString(
            ("ffv-client:secret").getBytes());
        System.out.println("Basic Auth header value: " + basicAuth);
    }
}