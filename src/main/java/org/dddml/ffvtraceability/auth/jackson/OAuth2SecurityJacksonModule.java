package org.dddml.ffvtraceability.auth.jackson;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.jsontype.NamedType;

/**
 * 安全的OAuth2 Jackson模块，解决LinkedHashMap转换OAuth2AuthorizationRequest的问题
 * 
 * 参考Spring Security GitHub issue #15491和#4370的解决方案
 */
public class OAuth2SecurityJacksonModule extends SimpleModule {

    public OAuth2SecurityJacksonModule() {
        super(OAuth2SecurityJacksonModule.class.getName(), Version.unknownVersion());
    }

    @Override
    public void setupModule(SetupContext context) {
        super.setupModule(context);

        // 注册OAuth2相关类型到allowlist中
        // 这解决了LinkedHashMap无法转换为OAuth2AuthorizationRequest的问题
        context.registerSubtypes(new NamedType(
            org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.class,
            "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest"
        ));
        
        // 如果需要，也可以注册其他OAuth2相关类型
        try {
            // 尝试注册其他可能需要的OAuth2类型
            Class<?> pkceClass = Class.forName("org.springframework.security.oauth2.core.endpoint.PkceParameterNames");
            context.registerSubtypes(new NamedType(pkceClass, pkceClass.getName()));
        } catch (ClassNotFoundException e) {
            // PKCE类不存在，忽略
        }
        
        // 确保基本的集合类型被正确处理
        context.registerSubtypes(new NamedType(java.util.LinkedHashMap.class, "java.util.LinkedHashMap"));
        context.registerSubtypes(new NamedType(java.util.HashMap.class, "java.util.HashMap"));
        context.registerSubtypes(new NamedType(java.util.ArrayList.class, "java.util.ArrayList"));
        context.registerSubtypes(new NamedType(java.util.LinkedHashSet.class, "java.util.LinkedHashSet"));
        context.registerSubtypes(new NamedType(java.util.HashSet.class, "java.util.HashSet"));
    }
} 