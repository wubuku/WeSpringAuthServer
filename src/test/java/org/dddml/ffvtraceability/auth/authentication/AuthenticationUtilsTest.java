package org.dddml.ffvtraceability.auth.authentication;

import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AuthenticationUtils的单元测试
 * 验证重构后的认证工具类功能正确性
 */
public class AuthenticationUtilsTest {

    private CustomUserDetails createTestUser(String username, List<String> groups, String phoneNumber) {
        return new CustomUserDetails(
                username,
                "password",
                true, // enabled
                true, // accountNonExpired
                true, // credentialsNonExpired
                true, // accountNonLocked
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Collections.emptyMap(), // additionalDetails
                groups,
                phoneNumber,
                false, // passwordChangeRequired
                OffsetDateTime.now(), // passwordLastChanged
                false // firstLogin
        );
    }

    @Test
    public void testCreateUserDetailsMap_WithGroups() {
        // 准备测试数据
        CustomUserDetails user = createTestUser("testuser", Arrays.asList("ADMIN_GROUP", "USER_GROUP"), null);
        
        // 执行测试
        Map<String, Object> details = AuthenticationUtils.createUserDetailsMap(user);
        
        // 验证结果
        assertNotNull(details);
        assertTrue(details.containsKey("groups"));
        assertEquals(Arrays.asList("ADMIN_GROUP", "USER_GROUP"), details.get("groups"));
    }

    @Test
    public void testCreateUserDetailsMap_WithPhoneNumber() {
        // 准备测试数据
        CustomUserDetails user = createTestUser("testuser", Arrays.asList("USER_GROUP"), "13900000000");
        
        // 执行测试
        Map<String, Object> details = AuthenticationUtils.createUserDetailsMap(user);
        
        // 验证结果
        assertNotNull(details);
        assertTrue(details.containsKey("groups"));
        assertTrue(details.containsKey("phoneNumber"));
        assertEquals("13900000000", details.get("phoneNumber"));
    }

    @Test
    public void testCreateUserDetailsMap_WithoutPhoneNumber() {
        // 准备测试数据
        CustomUserDetails user = createTestUser("testuser", Arrays.asList("USER_GROUP"), null);
        
        // 执行测试
        Map<String, Object> details = AuthenticationUtils.createUserDetailsMap(user);
        
        // 验证结果
        assertNotNull(details);
        assertTrue(details.containsKey("groups"));
        assertFalse(details.containsKey("phoneNumber"));
    }

    @Test
    public void testSetUserDetailsToAuthentication() {
        // 准备测试数据
        CustomUserDetails user = createTestUser("testuser", Arrays.asList("ADMIN_GROUP"), "13900000000");
        
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                user, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        
        // 执行测试
        AuthenticationUtils.setUserDetailsToAuthentication(auth, user);
        
        // 验证结果
        assertNotNull(auth.getDetails());
        assertTrue(auth.getDetails() instanceof Map);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> details = (Map<String, Object>) auth.getDetails();
        assertEquals(Arrays.asList("ADMIN_GROUP"), details.get("groups"));
        assertEquals("13900000000", details.get("phoneNumber"));
    }

    @Test
    public void testCreateAuthenticatedToken() {
        // 准备测试数据
        CustomUserDetails user = createTestUser("testuser", Arrays.asList("USER_GROUP"), "13900000000");
        
        // 执行测试
        Authentication auth = AuthenticationUtils.createAuthenticatedToken(user, user);
        
        // 验证结果
        assertNotNull(auth);
        assertTrue(auth instanceof UsernamePasswordAuthenticationToken);
        assertEquals(user, auth.getPrincipal());
        assertNull(auth.getCredentials()); // 认证后凭证应为null
        assertEquals(1, auth.getAuthorities().size());
        assertTrue(auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")));
        
        // 验证details
        assertNotNull(auth.getDetails());
        assertTrue(auth.getDetails() instanceof Map);
        
        @SuppressWarnings("unchecked")
        Map<String, Object> details = (Map<String, Object>) auth.getDetails();
        assertEquals(Arrays.asList("USER_GROUP"), details.get("groups"));
        assertEquals("13900000000", details.get("phoneNumber"));
    }

    @Test
    public void testSetUserDetailsToAuthentication_WithNonCustomUser() {
        // 准备测试数据 - 使用非CustomUserDetails用户
        org.springframework.security.core.userdetails.User springUser = 
                new org.springframework.security.core.userdetails.User(
                        "testuser", "password", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                springUser, null, springUser.getAuthorities());
        
        // 执行测试
        AuthenticationUtils.setUserDetailsToAuthentication(auth, springUser);
        
        // 验证结果 - 对于非CustomUserDetails用户，不应设置details
        assertNull(auth.getDetails());
    }
} 