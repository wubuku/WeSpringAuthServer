package org.dddml.ffvtraceability.auth.service.sms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.volcengine.model.request.SmsSendRequest;
import com.volcengine.model.response.SmsSendResponse;
import com.volcengine.service.sms.SmsService;
import com.volcengine.service.sms.SmsServiceInfoConfig;
import com.volcengine.service.sms.impl.SmsServiceImpl;
import org.dddml.ffvtraceability.auth.config.SmsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Implementation of SmsProvider for Huoshan (ByteDance Volcano Engine) SMS service
 */
public class HuoshanSmsProvider implements SmsProvider {
    private static final Logger logger = LoggerFactory.getLogger(HuoshanSmsProvider.class);
    
    // 常量定义
    private static final String ACTION = "SendSms";
    private static final String VERSION = "2020-01-01";
    private static final String SERVICE = "volcSMS";
    private static final String PROVIDER_NAME = "huoshan";
    private static final String TEMPLATE_PARAM_CODE_FORMAT = "{\"code\":\"%s\"}";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final String AUTHORIZATION_FORMAT = "HMAC-SHA256 Credential=%s/%s/%s/%s/request, SignedHeaders=content-type;host;x-date;x-service, Signature=%s";
    private static final String CANONICAL_REQUEST_FORMAT = "POST\n/\n" +
            "action=%s&version=%s\n" +
            "content-type:application/json\n" +
            "host:%s\n" +
            "x-date:%s\n" +
            "x-service:%s\n\n" +
            "content-type;host;x-date;x-service";
    
    private final SmsProperties.Huoshan config;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public HuoshanSmsProvider(SmsProperties.Huoshan config, RestTemplate restTemplate) {
        this.config = config;
        this.restTemplate = restTemplate;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public boolean sendVerificationCode(String phoneNumber, String code) {
        SmsSendRequest request = new SmsSendRequest();
        request.setSmsAccount(config.getSmsAccount());
        request.setSign(config.getSignName());
        request.setTemplateId(config.getTemplateId());
        request.setTemplateParam(String.format(TEMPLATE_PARAM_CODE_FORMAT, code));
        request.setPhoneNumbers(phoneNumber);
        
        SmsServiceInfoConfig smsServiceInfoConfig = new SmsServiceInfoConfig(config.getAccessKeyId(), config.getSecretKey());
        SmsService smsService = SmsServiceImpl.getInstance(smsServiceInfoConfig);
        
        try {
            SmsSendResponse smsSendResponse = smsService.send(request);
            if (smsSendResponse.getResponseMetadata().getError() != null) {
                throw new RuntimeException("Error sending SMS via Huoshan:" + smsSendResponse.getResponseMetadata().getError().getMessage());
            }
            logger.info("Sent SMS via Huoshan to {}, response: {}", phoneNumber, smsSendResponse);
            return true;
        } catch (Exception e) {
            logger.error("Error sending SMS via Huoshan", e);
            throw new RuntimeException("Error sending SMS via Huoshan", e);
        }
    }

    private String generateAuthorization(Map<String, Object> bodyParams, String action, String timestamp) {
        try {
            // 生成标准的HMAC-SHA256授权头格式
            String host = config.getEndpoint().replace("https://", "");
            String canonicalRequest = String.format(CANONICAL_REQUEST_FORMAT,
                    action, VERSION, host, timestamp, SERVICE);

            // Create signing key
            String signingKey = config.getSecretKey();
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), HMAC_SHA256_ALGORITHM));

            // Calculate signature
            byte[] signatureBytes = mac.doFinal(canonicalRequest.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signatureBytes);

            // Generate authorization header
            String region = host.split("\\.")[0];
            String dateStamp = timestamp.substring(0, 8);
            
            return String.format(AUTHORIZATION_FORMAT,
                    config.getAccessKeyId(), dateStamp, region, SERVICE, signature);
        } catch (Exception e) {
            logger.error("Error generating Huoshan authorization header", e);
            return "";
        }
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }
} 