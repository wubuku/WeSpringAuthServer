package org.dddml.ffvtraceability.auth.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class SmsAuthenticationToken extends AbstractAuthenticationToken {
    private final String phoneNumber;
    private final Object credentials;

    /**
     * Constructor for unauthenticated token
     */
    public SmsAuthenticationToken(String phoneNumber, Object credentials) {
        super(null);
        this.phoneNumber = phoneNumber;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**
     * Constructor for authenticated token
     */
    public SmsAuthenticationToken(
            String phoneNumber,
            Object credentials,
            java.util.Collection<SimpleGrantedAuthority> authorities,
            boolean authenticated) {
        super(authorities);
        this.phoneNumber = phoneNumber;
        this.credentials = credentials;
        setAuthenticated(authenticated);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return phoneNumber;
    }

    /**
     * Get the phone number
     */
    public String getPhoneNumber() {
        return phoneNumber;
    }
}