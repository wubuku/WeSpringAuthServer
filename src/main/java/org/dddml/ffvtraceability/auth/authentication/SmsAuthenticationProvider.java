package org.dddml.ffvtraceability.auth.authentication;

import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.service.SmsVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * Authentication provider for SMS login
 */
@Component
public class SmsAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(SmsAuthenticationProvider.class);

    @Autowired
    private SmsVerificationService smsVerificationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        SmsAuthenticationToken token = (SmsAuthenticationToken) authentication;
        String phoneNumber = token.getPhoneNumber();
        String code = token.getCredentials().toString();
        CustomUserDetails userDetails = smsVerificationService.processSmsLogin(phoneNumber, code);
        userDetails.setPhoneNumber(phoneNumber);
        return createAuthenticatedToken(userDetails, authentication, userDetails);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SmsAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Create an authenticated token for the phone number
     * This is used after verification of SMS code
     *
     * @return An authenticated token
     */
    public Authentication createAuthenticatedToken(Object principal,
                                                   Authentication authentication, UserDetails user) {
        // 使用工具类创建已认证的token
        return AuthenticationUtils.createAuthenticatedToken(principal, user);
    }
} 