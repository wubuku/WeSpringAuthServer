package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.config.PasswordTokenProperties;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserServiceTest {
    private final JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
    private final UserService userService = new UserService(
            jdbcTemplate, mock(PasswordEncoder.class), mock(PasswordTokenProperties.class));

    @Test
    void currentMobileNumberMayBeNullForNewUser() {
        stubMobileNumbers(Collections.singletonList(null));
        assertNull(userService.getCurrentMobileNumber("new-user"));
    }

    @Test
    void currentMobileNumberReturnsExistingValue() {
        stubMobileNumbers(List.of("13900000000"));
        assertEquals("13900000000", userService.getCurrentMobileNumber("existing-user"));
    }

    @Test
    void currentMobileNumberIsNullWhenUserDoesNotExist() {
        stubMobileNumbers(List.of());
        assertNull(userService.getCurrentMobileNumber("missing-user"));
    }

    private void stubMobileNumbers(List<String> mobileNumbers) {
        when(jdbcTemplate.query(eq("SELECT mobile_number FROM users WHERE username = ?"),
                org.mockito.ArgumentMatchers.<RowMapper<String>>any(), any(String.class)))
                .thenReturn(mobileNumbers);
    }
}
