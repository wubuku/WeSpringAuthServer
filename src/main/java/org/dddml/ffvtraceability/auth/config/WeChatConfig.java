package org.dddml.ffvtraceability.auth.config;

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.api.impl.WxMaServiceImpl;
import cn.binarywang.wx.miniapp.config.impl.WxMaDefaultConfigImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WeChatConfig {

    @Value("${wechat.mp.app-id}")
    private String appId;

    @Value("${wechat.mp.app-secret}")
    private String appSecret;

    @Value("${wechat.mp.token:#{null}}")
    private String token;

    @Value("${wechat.mp.aes-key:#{null}}")
    private String aesKey;

    @Value("${wechat.mp.redirect-uri}")
    private String redirectUri;

    @Bean
    public WxMaService wxMaService() {
        WxMaDefaultConfigImpl config = new WxMaDefaultConfigImpl();
        config.setAppid(appId);
        config.setSecret(appSecret);
        config.setToken(token);
        config.setAesKey(aesKey);

        WxMaService service = new WxMaServiceImpl();
        service.setWxMaConfig(config);
        return service;
    }

//    @Bean
//    public WxMpService wxMpService() {
//        WxMpDefaultConfigImpl config = new WxMpDefaultConfigImpl();
//        config.setAppId(appId);
//        config.setSecret(appSecret);
//        config.setToken(token);
//        config.setAesKey(aesKey);
//
//        WxMpService service = new WxMpServiceImpl();
//        service.setWxMpConfigStorage(config);
//        return service;
//    }

    public String getRedirectUri() {
        return redirectUri;
    }
} 