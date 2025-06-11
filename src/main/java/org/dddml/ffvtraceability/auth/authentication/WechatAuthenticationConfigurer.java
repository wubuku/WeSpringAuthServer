package org.dddml.ffvtraceability.auth.authentication;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class WechatAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationFilterConfigurer<H, WechatAuthenticationConfigurer<H>, WechatAuthenticationFilter> {

    public WechatAuthenticationConfigurer() {
        super(new WechatAuthenticationFilter(), "/login/wechat");

    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "GET");
    }

    @Override
    public void configure(H http) throws Exception {
        http.addFilterBefore(this.getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        super.configure(http);
    }
}