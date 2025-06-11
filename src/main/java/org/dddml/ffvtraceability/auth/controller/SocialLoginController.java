package org.dddml.ffvtraceability.auth.controller;

import org.dddml.ffvtraceability.auth.service.SmsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
public class SocialLoginController {
    private static final Logger logger = LoggerFactory.getLogger(SocialLoginController.class);

    private final SmsService smsService;

    public SocialLoginController(SmsService smsService) {
        this.smsService = smsService;
    }

    /**
     * Send SMS verification code
     */
    @PostMapping("/api/sms/send-code")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> sendSmsCode(@RequestBody Map<String, String> request) {
        String phoneNumber = request.get("phoneNumber");
        Map<String, Object> response = new HashMap<>();

        if (phoneNumber == null || phoneNumber.isEmpty()) {
            response.put("success", false);
            response.put("message", "Phone number is required");
            return ResponseEntity.badRequest().body(response);
        }

        // Generate a verification code
        String code = smsService.generateVerificationCode();

        // Send the verification code
        boolean sent = smsService.sendVerificationCode(phoneNumber, code);

        if (sent) {
            response.put("success", true);
            response.put("message", "Verification code sent");
            return ResponseEntity.ok(response);
        } else {
            response.put("success", false);
            response.put("message", "Failed to send verification code");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
} 