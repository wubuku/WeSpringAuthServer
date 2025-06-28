package org.dddml.ffvtraceability.auth.config;

import com.aliyun.dysmsapi20170525.Client;
import com.aliyun.teaopenapi.models.Config;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dddml.ffvtraceability.auth.service.sms.AliyunSmsProvider;
import org.dddml.ffvtraceability.auth.service.sms.HuoshanSmsProvider;
import org.dddml.ffvtraceability.auth.service.sms.SimulatorSmsProvider;
import org.dddml.ffvtraceability.auth.service.sms.SmsProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.client.RestTemplate;

/**
 * Configuration for SMS providers
 */
@Configuration
public class SmsProviderConfig {

    /**
     * 阿里云短信服务客户端（V2.0 SDK）
     */
    @Bean
    public Client aliyunSmsClient(SmsProperties smsProperties) throws Exception {
        SmsProperties.Aliyun aliyunConfig = smsProperties.getAliyun();
        
        Config config = new Config()
                // 优先从环境变量获取AccessKey，如果没有则使用配置文件
                .setAccessKeyId(getAccessKeyId(aliyunConfig))
                .setAccessKeySecret(getAccessKeySecret(aliyunConfig));
        
        // 配置端点
        config.endpoint = "dysmsapi.aliyuncs.com";
        
        return new Client(config);
    }
    
    /**
     * 获取AccessKeyId，优先从环境变量获取
     */
    private String getAccessKeyId(SmsProperties.Aliyun aliyunConfig) {
        String envKeyId = System.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID");
        if (envKeyId != null && !envKeyId.trim().isEmpty()) {
            return envKeyId;
        }
        return aliyunConfig.getAccessKeyId();
    }
    
    /**
     * 获取AccessKeySecret，优先从环境变量获取
     */
    private String getAccessKeySecret(SmsProperties.Aliyun aliyunConfig) {
        String envKeySecret = System.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        if (envKeySecret != null && !envKeySecret.trim().isEmpty()) {
            return envKeySecret;
        }
        return aliyunConfig.getAccessKeySecret();
    }
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
    
    @Bean
    public AliyunSmsProvider aliyunSmsProvider(Client aliyunSmsClient, SmsProperties smsProperties) {
        return new AliyunSmsProvider(aliyunSmsClient, smsProperties.getAliyun());
    }
    
    @Bean
    public HuoshanSmsProvider huoshanSmsProvider(SmsProperties smsProperties, RestTemplate restTemplate) {
        return new HuoshanSmsProvider(smsProperties.getHuoshan(), restTemplate);
    }
    
    @Bean
    public SimulatorSmsProvider simulatorSmsProvider() {
        return new SimulatorSmsProvider();
    }
    
    @Bean
    @Primary
    public SmsProvider smsProvider(
            SmsProperties smsProperties,
            AliyunSmsProvider aliyunSmsProvider,
            HuoshanSmsProvider huoshanSmsProvider,
            SimulatorSmsProvider simulatorSmsProvider) {
        
        String provider = smsProperties.getProvider();
        
        switch (provider.toLowerCase()) {
            case "aliyun":
                return aliyunSmsProvider;
            case "huoshan":
                return huoshanSmsProvider;
            case "simulator":
            default:
                return simulatorSmsProvider;
        }
    }
} 