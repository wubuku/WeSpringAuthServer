package org.dddml.wespring.resource.example.security;

import org.dddml.wespring.resource.example.service.GroupAuthorityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * 自定义JWT认证转换器
 * 
 * 这个转换器负责从JWT令牌中提取用户的权限信息，包括：
 * 1. 直接权限（authorities）- 用户直接拥有的权限
 * 2. 组权限（groups）- 通过用户所属组间接获得的权限
 * 
 * WeSpringAuthServer在生成JWT令牌时会包含这些信息，
 * 资源服务器需要正确解析这些信息来进行权限控制。
 */
@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomJwtAuthenticationConverter.class);
    
    @Autowired
    private GroupAuthorityService groupAuthorityService;
    
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // 记录转换开始
        logger.debug("Converting JWT to Authentication for subject: {}", jwt.getSubject());
        
        // 1. 添加直接权限
        // WeSpringAuthServer在JWT的"authorities"声明中包含用户的直接权限
        Set<String> directAuthorities = getClaimAsSet(jwt, "authorities");
        logger.debug("Direct authorities from JWT: {}", directAuthorities);
        directAuthorities.stream()
            .map(SimpleGrantedAuthority::new)
            .forEach(authorities::add);
            
        // 2. 从组获取权限
        // WeSpringAuthServer在JWT的"groups"声明中包含用户所属的组
        // 我们需要查询数据库获取这些组对应的权限
        Set<String> groups = getClaimAsSet(jwt, "groups");
        logger.debug("Groups from JWT: {}", groups);
        
        groups.stream()
            .map(group -> {
                Set<String> groupAuths = groupAuthorityService.getGroupAuthorities(group);
                logger.debug("Authorities for group {}: {}", group, groupAuths);
                return groupAuths;
            })
            .flatMap(Set::stream)
            .map(SimpleGrantedAuthority::new)
            .forEach(authorities::add);
        
        logger.debug("Final combined authorities: {}", authorities);
        return new JwtAuthenticationToken(jwt, authorities);
    }
    
    /**
     * 从JWT声明中获取字符串集合
     * 
     * @param jwt JWT令牌
     * @param claimName 声明名称
     * @return 字符串集合，如果声明不存在则返回空集合
     */
    @SuppressWarnings("unchecked")
    private Set<String> getClaimAsSet(Jwt jwt, String claimName) {
        Object claim = jwt.getClaims().get(claimName);
        if (claim instanceof Collection) {
            return new HashSet<>((Collection<String>) claim);
        }
        logger.debug("No {} found in JWT claims", claimName);
        return Collections.emptySet();
    }
} 