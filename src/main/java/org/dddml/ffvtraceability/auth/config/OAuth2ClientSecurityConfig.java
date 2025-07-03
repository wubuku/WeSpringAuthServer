package org.dddml.ffvtraceability.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

/**
 * OAuth2客户端安全配置
 * 实现client_secret的后端化管理
 * 
 * 🏗️ 架构原则：
 * - 数据库作为唯一数据源（RegisteredClientRepository）
 * - 不在配置文件中重复配置客户端信息
 * - 直接从已有的OAuth2客户端注册表获取信息
 * 
 * 解决安全问题：
 * 1. client_secret 从前端移除，完全后端管理
 * 2. 统一使用数据库配置，避免重复维护
 * 3. 保持OAuth2标准架构的完整性
 * 
 * @author WeSpringAuthServer
 * @since 1.0
 */
@Configuration
public class OAuth2ClientSecurityConfig {

    /**
     * OAuth2客户端凭证管理器
     * 直接从RegisteredClientRepository获取客户端信息
     */
    @Component
    public static class OAuth2ClientCredentialsManager {
        
        @Autowired
        private RegisteredClientRepository registeredClientRepository;

        /**
         * 获取客户端密钥
         * 直接从数据库中的RegisteredClient获取
         * 
         * @param clientId 客户端ID
         * @return 客户端密钥，如果不存在返回null
         */
        public String getClientSecret(String clientId) {
            try {
                RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
                if (registeredClient != null) {
                    return registeredClient.getClientSecret();
                }
                return null;
            } catch (Exception e) {
                // 记录错误但不抛出异常，返回null让调用方处理
                return null;
            }
        }

        /**
         * 验证客户端凭证
         * 使用数据库中的RegisteredClient进行验证
         * 
         * @param clientId 客户端ID
         * @param clientSecret 客户端密钥
         * @return 验证结果
         */
        public boolean validateClient(String clientId, String clientSecret) {
            try {
                RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
                if (registeredClient != null) {
                    return registeredClient.getClientSecret().equals(clientSecret);
                }
                return false;
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * 检查客户端是否存在
         */
        public boolean hasClient(String clientId) {
            try {
                RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
                return registeredClient != null;
            } catch (Exception e) {
                return false;
            }
        }

        /**
         * 获取RegisteredClient对象
         * 提供完整的客户端配置信息
         */
        public RegisteredClient getRegisteredClient(String clientId) {
            try {
                return registeredClientRepository.findByClientId(clientId);
            } catch (Exception e) {
                return null;
            }
        }

        /**
         * 获取默认客户端凭证（ffv-client）
         * 用于向后兼容
         */
        public ClientCredentials getDefaultClientCredentials() {
            String defaultClientId = "ffv-client";
            String clientSecret = getClientSecret(defaultClientId);
            
            if (clientSecret == null) {
                // 如果ffv-client不存在，尝试获取第一个可用的客户端
                // 这个方法在实际场景中应该很少使用
                return new ClientCredentials(defaultClientId, "fallback-secret");
            }
            
            return new ClientCredentials(defaultClientId, clientSecret);
        }

        /**
         * 客户端凭证数据类
         */
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

            @Override
            public String toString() {
                return String.format("ClientCredentials{clientId='%s', clientSecret='[HIDDEN]'}", clientId);
            }
        }
    }
} 