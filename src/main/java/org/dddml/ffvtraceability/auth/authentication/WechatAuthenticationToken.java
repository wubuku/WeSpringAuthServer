package org.dddml.ffvtraceability.auth.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class WechatAuthenticationToken extends AbstractAuthenticationToken {
    private final String code;
    private String username;

    /**
     * Constructor for unauthenticated token
     */
    public WechatAuthenticationToken(String code) {
        super(null);
        this.code = code;
        setAuthenticated(false);
    }

    /**
     * Constructor for authenticated token
     */
    public WechatAuthenticationToken(String code,
                                     java.util.Collection<SimpleGrantedAuthority> authorities,
                                     boolean authenticated) {
        super(authorities);
        this.code = code;
        setAuthenticated(authenticated);
    }

    public String getCode() {
        return code;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}