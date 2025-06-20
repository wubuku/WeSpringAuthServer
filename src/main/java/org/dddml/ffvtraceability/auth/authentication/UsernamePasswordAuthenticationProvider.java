package org.dddml.ffvtraceability.auth.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

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

        // 使用工具类设置用户详细信息
        AuthenticationUtils.setUserDetailsToAuthentication(result, user);
        
        return result;
    }
} 