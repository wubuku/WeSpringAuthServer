package org.dddml.ffvtraceability.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {
    private static final Logger logger = LoggerFactory.getLogger(PasswordEncoderConfig.class);

    @Bean
    public PasswordEncoder passwordEncoder() {
        DelegatingPasswordEncoder delegatingPasswordEncoder = (DelegatingPasswordEncoder) PasswordEncoderFactories
                .createDelegatingPasswordEncoder();

        // 添加日志记录
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                String encoded = delegatingPasswordEncoder.encode(rawPassword);
                logger.debug("Password encoding - Raw length: {}, Encoded: [HIDDEN]",
                        rawPassword.length());
                return encoded;
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                boolean matches = delegatingPasswordEncoder.matches(rawPassword, encodedPassword);
                logger.debug("Password matching - Raw length: {}, Encoded: [HIDDEN], Matches: {}",
                        rawPassword.length(), matches);
                return matches;
            }
        };
    }
}