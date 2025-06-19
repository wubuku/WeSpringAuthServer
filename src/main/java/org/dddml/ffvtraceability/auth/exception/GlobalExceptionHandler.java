package org.dddml.ffvtraceability.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGeneralException(Exception ex, HttpServletRequest request) {
        logger.info("Handling exception: {}", ex.getMessage(), ex);
        
        // 检查请求是否为API请求
        String requestUri = request.getRequestURI();
        String acceptHeader = request.getHeader("Accept");
        boolean isApiRequest = requestUri.startsWith("/api/") ||
                             (acceptHeader != null && acceptHeader.contains(MediaType.APPLICATION_JSON_VALUE));
        
        if (isApiRequest) {
            // API请求返回JSON格式的错误响应
            ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    ex.getMessage()
            );
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
        } else {
            // Web页面请求重定向到错误页面
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header("Location", "/error?message=" + ex.getMessage())
                    .build();
        }
    }
}