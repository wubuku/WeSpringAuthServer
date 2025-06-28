package org.dddml.ffvtraceability.auth.service.sms;

import com.aliyun.dysmsapi20170525.Client;
import com.aliyun.dysmsapi20170525.models.SendSmsRequest;
import com.aliyun.dysmsapi20170525.models.SendSmsResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dddml.ffvtraceability.auth.config.SmsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of SmsProvider for Aliyun SMS service using V2.0 SDK
 */
public class AliyunSmsProvider implements SmsProvider {
    private static final Logger logger = LoggerFactory.getLogger(AliyunSmsProvider.class);
    
    // 常量定义
    private static final String TEMPLATE_PARAM_CODE = "code";
    private static final String SUCCESS_CODE = "OK";
    private static final String PROVIDER_NAME = "aliyun";
    
    private final Client client;
    private final SmsProperties.Aliyun config;
    private final ObjectMapper objectMapper;

    public AliyunSmsProvider(Client client, SmsProperties.Aliyun config) {
        this.client = client;
        this.config = config;
        this.objectMapper = new ObjectMapper();
        logger.info("AliyunSmsProvider initialized with V2.0 SDK");
    }

    @Override
    public boolean sendVerificationCode(String phoneNumber, String code) {
        try {
            // 构建模板参数
            Map<String, String> templateParam = new HashMap<>();
            templateParam.put(TEMPLATE_PARAM_CODE, code);
            String templateParamJson = objectMapper.writeValueAsString(templateParam);
            
            // 构建请求
            SendSmsRequest request = new SendSmsRequest()
                    .setPhoneNumbers(phoneNumber)
                    .setSignName(config.getSignName())
                    .setTemplateCode(config.getTemplateCode())
                    .setTemplateParam(templateParamJson);
            
            // 发送请求
            SendSmsResponse response = client.sendSms(request);
            
            // 检查响应
            boolean success = SUCCESS_CODE.equalsIgnoreCase(response.getBody().getCode());
            
            if (success) {
                logger.info("Successfully sent SMS via Aliyun V2.0 SDK to {}, BizId: {}", 
                    phoneNumber, response.getBody().getBizId());
            } else {
                logger.error("Failed to send SMS via Aliyun V2.0 SDK to {}, Code: {}, Message: {}", 
                    phoneNumber, response.getBody().getCode(), response.getBody().getMessage());
            }
            
            return success;
        } catch (Exception e) {
            logger.error("Error sending SMS via Aliyun V2.0 SDK to " + phoneNumber, e);
            return false;
        }
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }
} 