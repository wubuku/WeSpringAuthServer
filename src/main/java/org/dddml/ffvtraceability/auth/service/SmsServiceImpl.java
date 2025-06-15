package org.dddml.ffvtraceability.auth.service;

import org.dddml.ffvtraceability.auth.service.sms.SmsProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
    public boolean sendVerificationCode(String mobileNumber, String code) {
        // Check rate limiting
        if (!smsVerificationService.checkRateLimit(mobileNumber)) {
            logger.warn("Rate limit exceeded for mobile number: {}", mobileNumber);
            return false;
        }
        // Send the SMS using the configured provider
        logger.info("Sending SMS verification code to mobile number: {}", mobileNumber);
        try {
            // Save the code to the database first
            smsVerificationService.saveVerificationCode(mobileNumber, code, expirationMinutes);
            smsProvider.sendVerificationCode(mobileNumber, code);
            smsVerificationService.recordSendAttempt(mobileNumber, smsProvider.getProviderName(), true, "SMS sent successfully");
            return true;
        } catch (Exception e) {
            logger.error("Error sending SMS verification code :{}", e.getMessage());
            try {
                smsVerificationService.recordSendAttempt(mobileNumber, smsProvider.getProviderName(), false, "Failed to send SMS" + e.getMessage());
            } catch (Exception ignored) {
                // Ignore
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
}