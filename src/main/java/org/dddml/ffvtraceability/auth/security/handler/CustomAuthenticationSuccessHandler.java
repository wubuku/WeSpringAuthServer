package org.dddml.ffvtraceability.auth.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.dddml.ffvtraceability.auth.util.UrlStateEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final UrlStateEncoder urlStateEncoder;

    public CustomAuthenticationSuccessHandler(UrlStateEncoder urlStateEncoder) {
        this.urlStateEncoder = urlStateEncoder;
        setDefaultTargetUrl("/");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (!(authentication.getPrincipal() instanceof CustomUserDetails userDetails)) {
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        String originalUrl = request.getParameter("continue");
        
        // 验证原始URL是否安全
        originalUrl = validateAndSanitizeUrl(originalUrl);

        // 检查是否需要修改密码
        if (userDetails.isPasswordChangeRequired() ||
                userDetails.isFirstLogin() ||
                userDetails.isPasswordExpired()) {

            String redirectUrl = UriComponentsBuilder
                    .fromPath("/password/change")
                    .queryParam("state", urlStateEncoder.encode(originalUrl))
                    .build()
                    .toUriString();

            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
            return;
        }

        // 如果有原始URL，使用它
        if (StringUtils.hasText(originalUrl)) {
            getRedirectStrategy().sendRedirect(request, response, originalUrl);
            return;
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * 验证并清理重定向URL，防止开放重定向攻击和Chrome DevTools URL问题
     */
    private String validateAndSanitizeUrl(String url) {
        if (!StringUtils.hasText(url)) {
            return null;
        }

        // 过滤掉Chrome DevTools相关的URL
        if (url.contains("chrome.devtools") || 
            url.contains(".well-known/appspecific") ||
            url.startsWith("chrome://") ||
            url.startsWith("chrome-extension://")) {
            logger.debug("Blocked Chrome DevTools URL: {}", url);
            return null;
        }

        // 确保URL是相对路径或本域名路径
        if (url.startsWith("/")) {
            // 相对路径，安全
            return url;
        }

        // 如果是绝对URL，检查是否是本域名
        if (url.startsWith("http://") || url.startsWith("https://")) {
            try {
                java.net.URI uri = java.net.URI.create(url);
                String host = uri.getHost();
                // 只允许localhost和127.0.0.1
                if ("localhost".equals(host) || "127.0.0.1".equals(host)) {
                    return url;
                }
                logger.warn("Blocked external URL redirect: {}", url);
                return null;
            } catch (Exception e) {
                logger.warn("Invalid URL format: {}", url);
                return null;
            }
        }

        // 其他格式的URL，为安全起见拒绝
        logger.debug("Blocked unrecognized URL format: {}", url);
        return null;
    }
} 