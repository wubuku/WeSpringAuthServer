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
    private static final String ACTION = "SendSms";
    private static final String VERSION = "2020-01-01";
    private static final String SERVICE = "volcSMS";
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
        request.setTemplateParam("{\"code\":\"" + code + "\"}");
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
            String canonicalRequest = "POST\n/" +
                    "\n" +
                    "action=" + action + "&" +
                    "version=" + VERSION + "\n" +
                    "content-type:application/json\n" +
                    "host:" + config.getEndpoint().replace("https://", "") + "\n" +
                    "x-date:" + timestamp + "\n" +
                    "x-service:" + SERVICE + "\n" +
                    "\n" +
                    "content-type;host;x-date;x-service";

            // Create signing key
            String signingKey = config.getSecretKey();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));

            // Calculate signature
            byte[] signatureBytes = mac.doFinal(canonicalRequest.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signatureBytes);

            // Generate authorization header
            return "HMAC-SHA256 Credential=" + config.getAccessKeyId() + "/" +
                    timestamp.substring(0, 8) + "/" +
                    config.getEndpoint().replace("https://", "").split("\\.")[0] + "/" +
                    SERVICE + "/request, " +
                    "SignedHeaders=content-type;host;x-date;x-service, " +
                    "Signature=" + signature;
        } catch (Exception e) {
            logger.error("Error generating Huoshan authorization header", e);
            return "";
        }
    }

    @Override
    public String getProviderName() {
        return "huoshan";
    }
} 