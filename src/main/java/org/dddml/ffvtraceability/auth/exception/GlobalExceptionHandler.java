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
    public Object handleGeneralException(Exception ex, WebRequest request) {
        logger.info("Handling exception: {}", ex.getMessage(), ex);
        
        // 检查请求是否接受JSON响应
        String acceptHeader = request.getHeader("Accept");
        boolean isApiRequest = request.getDescription(false).contains("/api/") ||
                             (acceptHeader != null && acceptHeader.contains(MediaType.APPLICATION_JSON_VALUE));
        
        if (isApiRequest) {
            // API请求返回JSON格式的错误
            return ProblemDetail.forStatusAndDetail(
                    HttpStatus.BAD_REQUEST,
                    ex.getMessage()
            );
        } else {
            // Web页面请求返回错误页面
            ModelAndView modelAndView = new ModelAndView("error");
            modelAndView.addObject("error", ex.getMessage());
            modelAndView.addObject("status", HttpStatus.BAD_REQUEST.value());
            return modelAndView;
        }
    }
}