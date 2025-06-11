package org.dddml.ffvtraceability.auth.authentication;

import org.dddml.ffvtraceability.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
public class UsernamePasswordAuthenticationConfig {
    private static final Logger logger = LoggerFactory.getLogger(UsernamePasswordAuthenticationConfig.class);

    @Autowired
    private UserService userService;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userService.getUserDetails(username);
    }

    @Bean
    public UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider(UserDetailsService userDetailsService) {
        UsernamePasswordAuthenticationProvider provider = new UsernamePasswordAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}