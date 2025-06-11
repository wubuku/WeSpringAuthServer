package org.dddml.ffvtraceability.auth.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Configuration
public class AuthenticationHandlerConfig {

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new AuthenticationSuccessHandlerImpl();
    }

    public static class AuthenticationSuccessHandlerImpl implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            RequestCache requestCache = new HttpSessionRequestCache();
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            if (savedRequest != null) {
                String targetUrl = savedRequest.getRedirectUrl();
                response.sendRedirect(targetUrl);
            } else {
                // 重定向到 "/"
                // response.sendRedirect("/");
                CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                response.setHeader(token.getHeaderName(), token.getToken());
                // response.setContentType("text/plain;charset=UTF-8");
                // response.addCookie(new Cookie("XSRF-TOKEN", token.getToken()));
                response.setStatus(HttpServletResponse.SC_OK);
                // response.getWriter().flush();
            }
        }
    }
}
