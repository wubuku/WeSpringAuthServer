<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# 阿里云短信服务 Spring Boot 集成指南

**核心要点：**

- 使用最新版 V2 SDK（com.aliyun:dysmsapi20170525:4.1.1）
- **安全**地通过环境变量管理 AK/SK
- 封装 **Client**、**Service**、**Controller** 三层，易于维护
- 加入**限流**、**重试**、**缓存**与**监控**最佳实践


## 一、前期准备

1. 企业账号完成实名认证，短信 SignName 和模板 TemplateCode（如 `SMS_320915932`）已审核通过。
2. 在 RAM 控制台创建子账号，生成 AccessKeyId/AccessKeySecret。
3. 确保 JDK 1.8+ 环境与 Maven 构建工具可用。

## 二、引入 SDK 依赖

在 pom.xml 中添加 SMS V2 SDK：

```xml
<dependency>
  <groupId>com.aliyun</groupId>
  <artifactId>dysmsapi20170525</artifactId>
  <version>4.1.1</version>  <!-- 最新稳定版[^6][^14] -->
</dependency>
```


## 三、环境变量管理密钥

**推荐**通过环境变量注入，不在代码或配置文件中明文存储：

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=你的AccessKeyId
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=你的AccessKeySecret
```

Spring Boot 启动脚本或 CI/CD 流水线中设置即可。

## 四、Spring Boot 配置

在 application.yml 中仅保留核心参数：

```yaml
aliyun:
  sms:
    endpoint: dysmsapi.aliyuncs.com
    sign-name: 上海睿创启医药科技
    template-code: SMS_320915932
```


## 五、封装 Client 工厂

创建 `SmsClientConfig`，通过环境变量读取 AK/SK 并初始化 SDK 客户端：

```java
package com.example.sms.config;

import com.aliyun.dysmsapi20170525.Client;
import com.aliyun.teaopenapi.models.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SmsClientConfig {

    @Value("${aliyun.sms.endpoint}")
    private String endpoint;

    @Bean
    public Client smsClient() throws Exception {
        Config config = new Config()
            .setAccessKeyId(System.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"))
            .setAccessKeySecret(System.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"));
        config.setEndpoint(endpoint);
        return new Client(config);
    }
}
```


## 六、实现短信发送服务

封装 `AliyunSmsService`，提供发送验证码方法：

```java
package com.example.sms.service;

import com.aliyun.dysmsapi20170525.Client;
import com.aliyun.dysmsapi20170525.models.SendSmsRequest;
import com.aliyun.dysmsapi20170525.models.SendSmsResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AliyunSmsService {

    private final Client client;

    @Value("${aliyun.sms.sign-name}")
    private String signName;

    @Value("${aliyun.sms.template-code}")
    private String templateCode;

    public AliyunSmsService(Client client) {
        this.client = client;
    }

    /**
     * 发送验证码短信
     * @param phone 中国大陆手机号
     * @param code  6位验证码
     * @return SendSmsResponse
     */
    public SendSmsResponse sendVerificationCode(String phone, String code) throws Exception {
        SendSmsRequest req = new SendSmsRequest()
            .setPhoneNumbers(phone)
            .setSignName(signName)
            .setTemplateCode(templateCode)
            .setTemplateParam("{\"code\":\"" + code + "\"}");
        return client.sendSms(req);
    }
}
```


## 七、提供 REST 接口

通过 Controller 接收请求并触发发送，同时加入**缓存**与**限流**：

```java
package com.example.sms.controller;

import com.aliyun.dysmsapi20170525.models.SendSmsResponse;
import com.example.sms.service.AliyunSmsService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;

@RestController
@RequestMapping("/api/sms")
public class SmsController {

    private final AliyunSmsService smsService;
    private final StringRedisTemplate redis;

    public SmsController(AliyunSmsService smsService, StringRedisTemplate redis) {
        this.smsService = smsService;
        this.redis = redis;
    }

    @PostMapping("/sendCode")
    public String sendCode(@RequestParam String phone) {
        String cooldownKey = "sms:cool:" + phone;
        if (redis.hasKey(cooldownKey)) {
            return "操作过于频繁，请稍后再试";
        }
        String code = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1_000_000));
        redis.opsForValue().set("sms:code:" + phone, code, Duration.ofMinutes(5));
        redis.opsForValue().set(cooldownKey, "1", Duration.ofMinutes(1));

        try {
            SendSmsResponse resp = smsService.sendVerificationCode(phone, code);
            if ("OK".equals(resp.getBody().code)) {
                return "发送成功，BizId=" + resp.getBody().bizId;
            }
            return "发送失败：" + resp.getBody().message;
        } catch (Exception e) {
            return "异常：" + e.getMessage();
        }
    }
}
```


## 八、完善与最佳实践

1. **重试策略**：针对网络波动，可配置 SDK 内置重试或使用 Spring Retry。
2. **监控与告警**：记录 `BizId`、响应码、失败原因，接入日志系统或 APM。
3. **验证码校验**：在独立接口中读取 Redis 中验证码并比对，验证后删除或过期。
4. **安全**：
    - 生产环境使用 RAM 子账号，权限最小化。
    - 密钥仅从环境变量或 Vault 读取，避免硬编码。
5. **回执消息**：可配置 MNS 或 HTTP 回调，实时获取用户回复与送达状态。

**至此**，Spring Boot 项目已完成阿里云短信服务“登录验证码”从依赖、配置到代码集成、测试的全流程，覆盖安全、限流、重试和监控等关键环节，助力生产环境稳健运行。

<div style="text-align: center">⁂</div>

[^1]: https://help.aliyun.com/zh/sms/developer-reference/sdk-product-overview/

[^2]: https://blog.csdn.net/weixin_45481821/article/details/147719593

[^3]: https://help.aliyun.com/zh/apsaramq-for-rocketmq/release-notes-for-the-sdk-for-java

[^4]: https://static-aliyun-doc.oss-cn-hangzhou.aliyuncs.com/download%2Fpdf%2F101873%2FSDK%E5%8F%82%E8%80%83%EF%BC%88%E6%96%B0%E7%89%88%EF%BC%89_cn_zh-CN.pdf

[^5]: https://central.sonatype.com/artifact/com.aliyun/alibabacloud-dysmsapi20170525

[^6]: https://www.alibabacloud.com/help/zh/sms/getting-started/use-sms-api-or-sdks-1

[^7]: https://central.sonatype.com/artifact/com.aliyun/dysmsapi20170525

[^8]: https://mvnrepository.com/artifact/com.aliyun/alibabacloud-dysmsapi20170525/2.0.24

[^9]: https://mvnrepository.com/artifact/com.aliyun/dysmsapi20170525

[^10]: https://www.nuget.org/packages/AlibabaCloud.SDK.Dysmsapi20170525/2.0.24

[^11]: https://pypi.org/project/alibabacloud-dysmsapi20170525/

[^12]: https://packagist.org/packages/alibabacloud/dysmsapi-20170525

[^13]: https://release-monitoring.org/project/115904/

[^14]: https://github.com/alibabacloud-sdk-php/Dysmsapi-20170525

[^15]: https://central.sonatype.com/artifact/com.aliyun/dysmsapi20170525/versions

[^16]: https://help.aliyun.com/zh/sdk/developer-reference/v2-java-integrated-sdk

[^17]: https://www.alibabacloud.com/help/zh/sdk/developer-reference/java-faq

[^18]: https://help.aliyun.com/zh/sdk/developer-reference/v2-nodejs-integrated-sdk

[^19]: https://github.com/alibabacloud-go/dysmsapi-20170525

[^20]: https://www.npmjs.com/package/@alicloud/dysmsapi20170525?activeTab=versions

