package org.dddml.ffvtraceability.auth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class WechatAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse
    response, AuthenticationException exception) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String errorMessage;
        if (exception instanceof DisabledException) {
            errorMessage = "User is disabled";
        } else if (exception instanceof BadCredentialsException) {
            errorMessage = exception.getMessage();
        } else {
            errorMessage = exception.getMessage();
        }
        String jsonResponse = String.format("{\"error\": \"%s\"}", errorMessage);
        response.getWriter().write(jsonResponse);
    }
}
