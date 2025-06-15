package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.dto.UserDto;
import org.dddml.ffvtraceability.auth.security.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Database implementation of SMS verification service
 */
@Service
public class DatabaseSmsVerificationService implements SmsVerificationService {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseSmsVerificationService.class);

    // Constants
    private static final String MOBILE_NUMBER_TYPE = "MOBILE_NUMBER";
    private static final String USERNAME_PREFIX = "mp_";
    private static final int USERNAME_SUFFIX_LENGTH = 20; // Increased from 10 to 20 for better uniqueness

    // Rate limit constants
    private static final int RATE_LIMIT_PER_MINUTE = 1;
    private static final int RATE_LIMIT_PER_HOUR = 5;
    private static final int RATE_LIMIT_PER_DAY = 10;

    // Time constants (in minutes/hours/days)
    private static final int RATE_CHECK_MINUTES = 1;
    private static final int RATE_CHECK_HOURS = 1;
    private static final int RATE_CHECK_DAYS = 1;

    // SQL queries
    private static final String INSERT_VERIFICATION_CODE_SQL =
            "INSERT INTO sms_verification_codes (phone_number, code, expire_time) VALUES (?, ?, ?)";

    private static final String SELECT_VERIFICATION_CODE_SQL =
            "SELECT id FROM sms_verification_codes " +
                    "WHERE phone_number = ? AND code = ? AND expire_time > ? AND used = FALSE " +
                    "ORDER BY created_at DESC LIMIT 1 FOR UPDATE";

    private static final String UPDATE_CODE_USED_SQL =
            "UPDATE sms_verification_codes SET used = TRUE WHERE id = ?";

    private static final String COUNT_SEND_RECORDS_SQL =
            "SELECT COUNT(*) FROM sms_send_records WHERE phone_number = ? AND send_time > ?";

    private static final String INSERT_SEND_RECORD_SQL =
            "INSERT INTO sms_send_records (phone_number, provider, success, message) VALUES (?, ?, ?, ?)";

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    private UserIdentificationService userIdentificationService;
    @Autowired
    private UserService userService;
    @Value("${sms.code-expiration-minutes:5}")
    private int defaultExpirationMinutes;

    @Autowired
    public DatabaseSmsVerificationService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional
    public void saveVerificationCode(String phoneNumber, String code, int expirationMinutes) {
        LocalDateTime expireTime = LocalDateTime.now().plusMinutes(expirationMinutes);

        jdbcTemplate.update(INSERT_VERIFICATION_CODE_SQL, phoneNumber, code, Timestamp.valueOf(expireTime));

        logger.debug("Saved verification code for phone number: {}, expires at: {}", phoneNumber, expireTime);
    }

    @Transactional
    public CustomUserDetails processSmsLogin(String phoneNumber, String code) {
        if (!verifyCode(phoneNumber, code)) {
            logger.debug("Failed to verify SMS code for phone number: {}", phoneNumber);
            throw new BadCredentialsException("Invalid verification code");
        }

        String username = findOrCreateUserByMobileNumber(phoneNumber);
        return userService.getUserDetails(username);
    }

    /**
     * Find existing user by mobile number or create new user
     */
    private String findOrCreateUserByMobileNumber(String mobileNumber) {
        Optional<String> existingUsername = userIdentificationService.findUsernameByIdentifier(MOBILE_NUMBER_TYPE, mobileNumber);
        return existingUsername.orElseGet(() -> createUserByMobileNumber(mobileNumber));
    }

    /**
     * Create a new user with mobile number
     */
    private String createUserByMobileNumber(String mobileNumber) {
        // Generate a random username and password
        String username = USERNAME_PREFIX + UUID.randomUUID().toString().replace("-", "").substring(0, USERNAME_SUFFIX_LENGTH);
        String password = UUID.randomUUID().toString();

        logger.info("Creating new mobile user: username={}, mobile number={}", username, mobileNumber);

        // Create the user
        UserDto userDto = new UserDto();
        userDto.setUsername(username);
        userDto.setMobileNumber(mobileNumber);
        userDto.setEnabled(true);

        OffsetDateTime now = OffsetDateTime.now();

        // Create the user in the database
        userService.createUser(userDto, password);
        userIdentificationService.addUserIdentification(username, MOBILE_NUMBER_TYPE, mobileNumber, true, now);

        return username;
    }

    @Override
    @Transactional
    public boolean verifyCode(String phoneNumber, String code) {
        try {
            return Boolean.TRUE.equals(jdbcTemplate.execute((Connection conn) ->
                    verifyAndMarkCodeAsUsed(conn, phoneNumber, code)));
        } catch (Exception e) {
            logger.error("Error verifying SMS code for phone number: {}", phoneNumber, e);
            return false;
        }
    }

    /**
     * Verify code and mark it as used in a single transaction
     */
    private Boolean verifyAndMarkCodeAsUsed(Connection conn, String phoneNumber, String code) {
        try (PreparedStatement ps = conn.prepareStatement(SELECT_VERIFICATION_CODE_SQL)) {
            ps.setString(1, phoneNumber);
            ps.setString(2, code);
            ps.setTimestamp(3, Timestamp.valueOf(LocalDateTime.now()));

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    long id = rs.getLong("id");
                    markCodeAsUsed(conn, id);
                    logger.debug("Successfully verified SMS code for phone number: {}", phoneNumber);
                    return true;
                }
                logger.debug("No valid SMS code found for phone number: {}", phoneNumber);
                return false;
            }
        } catch (Exception e) {
            logger.error("Error in verifyAndMarkCodeAsUsed", e);
            return false;
        }
    }

    /**
     * Mark verification code as used
     */
    private void markCodeAsUsed(Connection conn, long codeId) throws Exception {
        try (PreparedStatement updatePs = conn.prepareStatement(UPDATE_CODE_USED_SQL)) {
            updatePs.setLong(1, codeId);
            updatePs.executeUpdate();
        }
    }

    @Override
    public boolean checkRateLimit(String phoneNumber) {
        return checkMinuteRateLimit(phoneNumber) &&
                checkHourlyRateLimit(phoneNumber) &&
                checkDailyRateLimit(phoneNumber);
    }

    /**
     * Check minute rate limit
     */
    private boolean checkMinuteRateLimit(String phoneNumber) {
        int count = getSendRecordCount(phoneNumber, RATE_CHECK_MINUTES, "MINUTE");
        if (count >= RATE_LIMIT_PER_MINUTE) {
            logger.debug("Minute rate limit exceeded for phone number: {} ({} per minute)", phoneNumber, RATE_LIMIT_PER_MINUTE);
            return false;
        }
        return true;
    }

    /**
     * Check hourly rate limit
     */
    private boolean checkHourlyRateLimit(String phoneNumber) {
        int count = getSendRecordCount(phoneNumber, RATE_CHECK_HOURS, "HOUR");
        if (count >= RATE_LIMIT_PER_HOUR) {
            logger.debug("Hourly rate limit exceeded for phone number: {} ({} per hour)", phoneNumber, RATE_LIMIT_PER_HOUR);
            return false;
        }
        return true;
    }

    /**
     * Check daily rate limit
     */
    private boolean checkDailyRateLimit(String phoneNumber) {
        int count = getSendRecordCount(phoneNumber, RATE_CHECK_DAYS, "DAY");
        if (count >= RATE_LIMIT_PER_DAY) {
            logger.debug("Daily rate limit exceeded for phone number: {} ({} per day)", phoneNumber, RATE_LIMIT_PER_DAY);
            return false;
        }
        return true;
    }

    /**
     * Get send record count for specified time period
     */
    private int getSendRecordCount(String phoneNumber, int timeValue, String timeUnit) {
        LocalDateTime cutoffTime;
        switch (timeUnit) {
            case "MINUTE":
                cutoffTime = LocalDateTime.now().minusMinutes(timeValue);
                break;
            case "HOUR":
                cutoffTime = LocalDateTime.now().minusHours(timeValue);
                break;
            case "DAY":
                cutoffTime = LocalDateTime.now().minusDays(timeValue);
                break;
            default:
                throw new IllegalArgumentException("Unsupported time unit: " + timeUnit);
        }

        return jdbcTemplate.queryForObject(COUNT_SEND_RECORDS_SQL, Integer.class, phoneNumber, Timestamp.valueOf(cutoffTime));
    }

    @Override
    @Transactional
    public void recordSendAttempt(String phoneNumber, String provider, boolean success, String message) {
        jdbcTemplate.update(INSERT_SEND_RECORD_SQL, phoneNumber, provider, success, message);

        logger.debug("Recorded SMS send attempt for phone number: {}, provider: {}, success: {}",
                phoneNumber, provider, success);
    }
} 