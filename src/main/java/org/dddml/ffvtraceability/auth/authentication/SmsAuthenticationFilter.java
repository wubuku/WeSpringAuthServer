package org.dddml.ffvtraceability.auth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String SPRING_SECURITY_FORM_PHONE_NUMBER_KEY = "phoneNumber";
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/login/sms", "POST");

    private String phoneNumberParameter = SPRING_SECURITY_FORM_PHONE_NUMBER_KEY;
    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;
    private boolean postOnly = true;

    public SmsAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public SmsAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }
        String phoneNumber = obtainPhoneNumber(request);
        phoneNumber = phoneNumber == null ? "" : phoneNumber.trim();
        String code = obtainCode(request);
        code = code == null ? "" : code.trim();

        SmsAuthenticationToken authRequest = new SmsAuthenticationToken(phoneNumber, code);
        // 允许子类设置详细信息
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    protected String obtainPhoneNumber(HttpServletRequest request) {
        return request.getParameter(phoneNumberParameter);
    }

    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }

    protected void setDetails(HttpServletRequest request,
                              SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }
}
