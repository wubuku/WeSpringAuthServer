package org.dddml.ffvtraceability.auth.authentication;

import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication provider for UsernamePassword login
 */
public class UsernamePasswordAuthenticationProvider extends DaoAuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(UsernamePasswordAuthenticationProvider.class);

    @Override
    protected Authentication createSuccessAuthentication(Object principal,
                                                         Authentication authentication, UserDetails user) {
        Authentication result = super.createSuccessAuthentication(
                principal, authentication, user);

        // 如果是我们的 CustomUserDetails，保存组信息到 Authentication details
        if (user instanceof CustomUserDetails customUser) {
            Map<String, Object> details = new HashMap<>();
            details.put("groups", customUser.getGroups());
            ((UsernamePasswordAuthenticationToken) result).setDetails(details);
        }
        return result;
    }
} 