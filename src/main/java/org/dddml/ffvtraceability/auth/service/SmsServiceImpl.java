package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.service.sms.SmsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Random;

/**
 * Default implementation of the SMS service
 */
@Service
public class SmsServiceImpl implements SmsService {
    private static final Logger logger = LoggerFactory.getLogger(SmsServiceImpl.class);

    private final SmsVerificationService smsVerificationService;
    private final SmsProvider smsProvider;

    @Value("${sms.code-length:6}")
    private int codeLength;

    @Value("${sms.code-expiration-minutes:5}")
    private int expirationMinutes;

    @Autowired
    public SmsServiceImpl(SmsVerificationService smsVerificationService,
                          SmsProvider smsProvider) {
        this.smsVerificationService = smsVerificationService;
        this.smsProvider = smsProvider;
    }

    @Override
    public boolean sendVerificationCode(String phoneNumber, String code) {
        // Check rate limiting
        if (!smsVerificationService.checkRateLimit(phoneNumber)) {
            logger.warn("Rate limit exceeded for phone number: {}", phoneNumber);
            return false;
        }
        // Send the SMS using the configured provider
        logger.info("Sending SMS verification code to phone number: {}", phoneNumber);
        try {
            smsProvider.sendVerificationCode(phoneNumber, code);
            // Save the code to the database
            smsVerificationService.saveVerificationCode(phoneNumber, code, expirationMinutes);
            smsVerificationService.recordSendAttempt(phoneNumber, smsProvider.getProviderName(), true, "SMS sent successfully");
            return true;
        } catch (Exception e) {
            logger.error("Error sending SMS verification code :{}", e.getMessage());
            try {
                smsVerificationService.recordSendAttempt(phoneNumber, smsProvider.getProviderName(), false, "Failed to send SMS" + e.getMessage());
            } catch (Exception ignored) {
            }
            return false;
        }
    }

    @Override
    public String generateVerificationCode() {
        Random random = new Random();
        StringBuilder sb = new StringBuilder(codeLength);
        for (int i = 0; i < codeLength; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

    @Override
    public Authentication verifyCodeAndLogin(String phoneNumber, String code) {
//        boolean verified = smsVerificationService.verifyCode(phoneNumber, code);
//
//        if (!verified) {
//            logger.warn("Failed to verify SMS code for phone number: {}", phoneNumber);
//            return null;
//        }
//
//        // Use the authentication provider to create an authenticated token
//        return smsAuthenticationProvider.createAuthenticatedToken(phoneNumber);
        return null;
    }
} 