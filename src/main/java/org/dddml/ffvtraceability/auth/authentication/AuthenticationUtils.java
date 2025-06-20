package org.dddml.ffvtraceability.auth.authentication;

import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 认证工具类
 * 
 * 提供通用的认证相关工具方法，避免在多个认证提供者中重复代码。
 */
public class AuthenticationUtils {

    /**
     * 为CustomUserDetails创建包含用户详细信息的Authentication details
     * 
     * @param user 用户详情对象
     * @return 包含用户信息的details Map
     */
    public static Map<String, Object> createUserDetailsMap(CustomUserDetails user) {
        Map<String, Object> details = new HashMap<>();
        
        // 添加组信息（必需）
        details.put("groups", user.getGroups());
        
        // 添加手机号（如果存在）
        if (StringUtils.hasText(user.getPhoneNumber())) {
            details.put("phoneNumber", user.getPhoneNumber());
        }
        
        // 可以在这里添加其他通用的用户信息
        // 例如：用户ID、显示名称等
        
        return details;
    }

    /**
     * 为认证结果设置用户详细信息
     * 
     * 这个方法会检查用户是否为CustomUserDetails类型，
     * 如果是，则设置相应的details信息到Authentication对象中。
     * 
     * @param authentication 要设置details的Authentication对象
     * @param user 用户详情对象
     */
    public static void setUserDetailsToAuthentication(Authentication authentication, UserDetails user) {
        if (user instanceof CustomUserDetails customUser && 
            authentication instanceof UsernamePasswordAuthenticationToken token) {
            Map<String, Object> details = createUserDetailsMap(customUser);
            token.setDetails(details);
        }
    }

    /**
     * 创建包含用户详细信息的已认证token
     * 
     * 这是一个便利方法，用于创建已认证的UsernamePasswordAuthenticationToken
     * 并自动设置用户详细信息。
     * 
     * @param principal 主体（通常是UserDetails对象）
     * @param user 用户详情对象
     * @return 已认证的Authentication对象
     */
    public static Authentication createAuthenticatedToken(Object principal, UserDetails user) {
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                principal,
                null, // 认证后不需要凭证
                user.getAuthorities()
        );
        
        // 设置用户详细信息
        setUserDetailsToAuthentication(result, user);
        
        return result;
    }
} 