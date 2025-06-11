package org.dddml.ffvtraceability.auth.authentication;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SmsAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationFilterConfigurer<H, SmsAuthenticationConfigurer<H>, SmsAuthenticationFilter> {

    public SmsAuthenticationConfigurer() {
        super(new SmsAuthenticationFilter(), "/login/sms");

    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    @Override
    public void configure(H http) throws Exception {
        http.addFilterBefore(this.getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        super.configure(http);
    }
}