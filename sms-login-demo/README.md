# SMS登录演示 - WeSpring Auth Server (Cookie安全模式)

这是一个基于WeSpring Auth Server的SMS登录单页面演示应用，展示了如何使用短信验证码进行用户认证，**现已升级支持HttpOnly Cookie安全模式**！

## 🔥 **重要升级说明 - Cookie安全模式**

**⚠️ 架构变更警告**: 本项目已升级到HttpOnly Cookie安全模式，这涉及重要的同域部署要求！

### 🛡️ 安全升级亮点
- ✅ **HttpOnly Cookie**: refresh_token现在存储在安全的HttpOnly Cookie中，防止XSS攻击
- ✅ **client_secret后端化**: 前端不再需要存储或传输敏感的client_secret
- ✅ **自动Cookie管理**: 服务器自动设置和管理安全Cookie
- ✅ **向后兼容**: 支持传统localStorage模式和新Cookie模式

### 🎯 部署方案选择

| 方案 | 适用场景 | 优点 | 缺点 | 推荐度 |
|------|----------|------|------|--------|
| **方案A: 同域部署** | 生产环境 | 最安全，Cookie共享 | 需要配置反向代理 | ⭐⭐⭐⭐⭐ |
| **方案B: Spring静态资源** | 开发测试 | 简单，一键启动 | 仅适合开发环境 | ⭐⭐⭐⭐ |
| **方案C: 跨域模式** | 调试开发 | 灵活性高 | 安全性降低 | ⭐⭐⭐ |

## 🏗️ 方案A: 同域部署 (生产推荐)

### 原理说明
```
┌─────────────────────────────────────────┐
│          同一域名: example.com          │
├─────────────────────┬───────────────────┤
│   前端静态资源      │   后端API服务     │
│  example.com        │ example.com:9000  │
│  (Nginx/Apache)     │ (Spring Boot)     │
└─────────────────────┴───────────────────┘
       ↓                       ↓
   🍪 Cookie可以在同域名下自由共享 🍪
```

### Nginx配置示例
```nginx
server {
    listen 80;
    server_name example.com;
    
    # 前端静态资源
    location / {
        root /var/www/sms-login-demo;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
    
    # 后端API代理
    location /api/ {
        proxy_pass http://localhost:9000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Cookie支持
        proxy_cookie_domain localhost $host;
        proxy_cookie_path / /;
    }
    
    # 生产环境HTTPS配置
    # SSL相关配置...
}
```

### 部署步骤
```bash
# 1. 构建前端资源
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer/sms-login-demo
cp index.html /var/www/sms-login-demo/

# 2. 配置Nginx
sudo cp nginx.conf /etc/nginx/sites-available/sms-demo
sudo ln -s /etc/nginx/sites-available/sms-demo /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 3. 启动后端服务
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
./mvnw spring-boot:run

# 4. 访问应用
open https://example.com
```

## 🚀 方案B: Spring静态资源服务 (开发推荐)

### 原理说明
让Spring Boot应用直接服务静态文件，实现真正的同域部署：

```
┌─────────────────────────────────────────────┐
│        Spring Boot (localhost:9000)        │
├─────────────────────┬───────────────────────┤
│   静态资源映射      │     API端点           │
│   GET /demo/*       │   GET /sms/*          │
│   ↓                 │   POST /sms/*         │
│   return index.html │   return JSON         │
└─────────────────────┴───────────────────────┘
           ↓
    🍪 完美的同域Cookie共享 🍪
```

### 实施步骤

#### 1. 配置Spring Boot静态资源映射

在`src/main/java/org/dddml/ffvtraceability/auth/config/WebConfig.java`中添加：

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 添加SMS登录演示的静态资源映射
        registry.addResourceHandler("/demo/**")
                .addResourceLocations("file:" + getSmsLoginDemoPath() + "/")
                .setCachePeriod(0); // 开发环境不缓存
    }
    
    private String getSmsLoginDemoPath() {
        // 获取项目根目录下的sms-login-demo路径
        String projectRoot = System.getProperty("user.dir");
        return projectRoot + "/sms-login-demo";
    }
    
    @Bean
    public RouterFunction<ServerResponse> smsLoginDemoRoutes() {
        return route(GET("/demo"), this::serveSmsLoginDemo)
               .andRoute(GET("/demo/"), this::serveSmsLoginDemo);
    }
    
    public Mono<ServerResponse> serveSmsLoginDemo(ServerRequest request) {
        try {
            Path indexPath = Paths.get(getSmsLoginDemoPath(), "index.html");
            Resource resource = new FileSystemResource(indexPath.toFile());
            return ServerResponse.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(BodyInserters.fromResource(resource));
        } catch (Exception e) {
            return ServerResponse.notFound().build();
        }
    }
}
```

#### 2. 更新demo配置

修改`sms-login-demo/index.html`中的配置：

```javascript
const CONFIG = {
    // 🔥 重要：使用相对路径，确保同域
    AUTH_SERVER_BASE_URL: '',  // 空字符串表示同域
    // 或者明确指定: AUTH_SERVER_BASE_URL: 'http://localhost:9000',
    
    CLIENT_ID: 'ffv-client',
    // 🔒 安全：Cookie模式下不需要client_secret
    // CLIENT_SECRET: 'secret',  // ← 已移除，由后端管理
    
    // 🍪 启用Cookie安全模式
    COOKIE_MODE: true,
    
    STORAGE_KEYS: {
        ACCESS_TOKEN: 'sms_access_token',
        // REFRESH_TOKEN: 'sms_refresh_token', // ← Cookie模式下不再需要
        TOKEN_EXPIRY: 'sms_token_expiry',
        USER_INFO: 'sms_user_info'
    }
};
```

#### 3. 一键启动脚本

创建`start-cookie-demo.sh`：

```bash
#!/bin/bash

echo "🚀 启动SMS登录Cookie安全模式演示"
echo "=================================="

# 检查后端服务状态
if ! curl -s http://localhost:9000/actuator/health > /dev/null; then
    echo "⚠️  后端服务未运行，正在启动..."
    cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
    ./mvnw spring-boot:run &
    BACKEND_PID=$!
    
    echo "⏳ 等待后端服务启动..."
    sleep 10
fi

echo "✅ 后端服务运行在: http://localhost:9000"
echo "✅ SMS登录演示页面: http://localhost:9000/demo"
echo ""
echo "🍪 Cookie安全特性："
echo "   - HttpOnly Cookie存储refresh_token"
echo "   - 同域部署确保Cookie安全共享"
echo "   - client_secret完全后端化"
echo ""
echo "🎯 测试步骤："
echo "   1. 访问 http://localhost:9000/demo"
echo "   2. 输入手机号：13800138000"
echo "   3. 发送验证码并登录"
echo "   4. 观察Cookie设置和刷新过程"
echo ""

# 自动打开浏览器
open http://localhost:9000/demo

echo "🎉 演示启动完成！按Ctrl+C停止服务"
wait
```

#### 4. 使用方式

```bash
# 简单启动
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
bash start-cookie-demo.sh

# 直接访问
open http://localhost:9000/demo
```

## 🔧 方案C: 跨域模式 (兼容开发)

如果需要保持跨域开发（前端独立端口），需要配置CORS支持Cookie：

### 后端CORS配置
```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:*",
            "http://127.0.0.1:*"
        ));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true); // 🍪 支持Cookie
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 前端请求配置
```javascript
// 所有请求必须包含credentials
fetch('/sms/login', {
    method: 'GET',
    credentials: 'include', // 🍪 必须包含Cookie
    // ... 其他配置
});
```

## 🎯 **推荐的开发工作流**

### 开发阶段
```bash
# 使用方案B：Spring静态资源服务
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
bash start-cookie-demo.sh
open http://localhost:9000/demo
```

### 测试阶段
```bash
# 使用方案A：完整的同域部署
docker-compose up nginx spring-app
open https://test.example.com
```

### 生产部署
```bash
# 使用方案A：Nginx + Spring Boot
# 配置HTTPS、负载均衡、监控等
```

## 🌟 功能特点

- **🍪 HttpOnly Cookie安全**: refresh_token存储在HttpOnly Cookie中，防止XSS
- **🔒 client_secret后端化**: 前端不再暴露敏感的客户端凭据  
- **📱 SMS验证码登录**: 支持发送和验证短信验证码
- **🔄 自动Token刷新**: 自动管理token生命周期，无感知刷新
- **🔄 手动Token刷新**: 新增手动刷新按钮，显示详细的刷新过程和日志
- **💾 混合存储**: access_token存储在localStorage，refresh_token存储在Cookie
- **🎨 现代化UI**: 响应式设计，优雅的用户界面，全面优化移动端体验
- **📋 过程日志**: 详细显示token刷新的每个步骤和状态
- **🔒 安全保护**: 完整的token验证和错误处理
- **⚡ 单页应用**: 所有代码在一个HTML文件中，易于理解和部署

## 📱 移动端优化

本演示应用已全面优化移动端体验：

### 🎯 响应式设计
- **多断点适配**: 平板设备(768px)、移动设备(480px)、超小屏幕(360px)
- **触摸友好**: 按钮最小触摸目标48px，符合iOS/Android设计规范
- **防误触**: 添加`touch-action: manipulation`防止双击缩放

### 📐 布局优化
- **全屏布局**: 移动端使用全屏容器，减少边距浪费空间
- **垂直布局**: 手机号输入组改为垂直排列，提升可用性
- **卡片布局**: 业务功能卡片在移动端单列显示

### 🔤 字体与间距
- **防缩放字体**: 输入框使用16px字体防止iOS自动缩放
- **层次化字体**: 不同元素使用适当的字体大小层次
- **优化间距**: 移动端使用更紧凑的间距设计

### 🎨 Token信息优化
- **垂直布局**: Token信息行改为垂直布局，避免水平滚动
- **紧凑日志**: 刷新日志使用更小字体和高度，适合移动端查看
- **全宽按钮**: 刷新按钮在移动端使用全宽设计

### 🚫 禁用动画
- **触摸设备**: 自动检测并禁用hover动画效果
- **性能优化**: 减少不必要的动画提升移动端性能

## 📋 前置条件

1. **WeSpring Auth Server运行中**
   ```bash
   # 在项目根目录启动后端服务
   cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
   ./mvnw spring-boot:run
   
   # 或者使用启动脚本
   ./start.sh
   ```
   
   确保服务运行在 `http://localhost:9000`

2. **SMS服务配置**
   - 确保后端已正确配置SMS服务（阿里云短信等）
   - 测试用户数据已导入数据库

3. **Cookie安全配置**
   ```yaml
   # application.yml
   oauth2:
     cookie:
       domain: ${OAUTH2_COOKIE_DOMAIN:}      # 开发环境留空
       secure: ${OAUTH2_COOKIE_SECURE:false}  # 生产环境设为true
       same-site: ${OAUTH2_COOKIE_SAME_SITE:Lax}
   ```

## 🚀 运行Demo

### 🎯 方式1：Spring静态资源服务（强烈推荐）

```bash
# 🔥 一键启动Cookie安全模式演示
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
bash start-cookie-demo.sh

# 访问同域演示页面
open http://localhost:9000/demo
```

**优势**：
- ✅ 真正的同域部署，Cookie完美工作
- ✅ 一键启动，无需额外配置
- ✅ 最接近生产环境的部署方式

### 方式2：独立HTTP服务器

```bash
# 进入demo目录
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer/sms-login-demo

# 启动HTTP服务器
python3 -m http.server 8080

# 访问应用（需要配置CORS）
open http://localhost:8080
```

**注意**：此方式为跨域访问，需要后端配置CORS支持Cookie。

### 方式3：使用Node.js serve

```bash
# 安装serve（如果还没安装）
npm install -g serve

# 进入demo目录并启动
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer/sms-login-demo
serve -s . -p 8080

# 访问应用
open http://localhost:8080
```

### 方式4：VS Code Live Server

1. 在VS Code中打开 `sms-login-demo` 目录
2. 安装 "Live Server" 扩展
3. 右键点击 `index.html` 选择 "Open with Live Server"

**⚠️ 跨域注意事项**：方式2-4为跨域访问，Cookie功能可能受限。生产环境请使用方式1或Nginx同域部署。

## 🎯 使用流程

### 1. 访问应用
- **同域模式**: `http://localhost:9000/demo`（推荐）
- **跨域模式**: `http://localhost:8080`

### 2. SMS登录流程
1. **输入手机号**: 输入注册过的手机号码
2. **发送验证码**: 点击"发送验证码"按钮
3. **输入验证码**: 收到短信后输入6位验证码
4. **登录系统**: 点击"立即登录"完成认证

### 3. 观察Cookie安全特性
登录成功后：
- 🍪 查看浏览器开发者工具中的Cookie标签
- 🔒 确认refresh_token存储在HttpOnly Cookie中
- 🚫 确认响应中不包含refresh_token（安全）

### 4. 业务操作
登录成功后可以：
- 查看个人资料
- 浏览订单信息  
- 访问系统设置
- 测试API调用

### 5. Token管理
- **自动刷新**: Token即将过期时自动刷新（提前10分钟）
- **手动刷新**: 点击"🔄 手动刷新Token"按钮可主动刷新token
- **过程日志**: 手动刷新时显示详细的操作过程和状态日志
- **状态显示**: 实时显示token状态和过期时间
- **安全登出**: 清除所有本地存储的认证信息并清除Cookie

## 🔧 API端点说明

### SMS登录相关端点（Cookie安全模式）

| 端点 | 方法 | 功能 | 参数 | Cookie支持 |
|------|------|------|------|------------|
| `/sms/send-code` | POST | 发送SMS验证码 | `phoneNumber` | N/A |
| `/sms/login` | GET | SMS登录认证 | `mobileNumber`, `verificationCode`, `clientId` | ✅ 设置Cookie |
| `/sms/refresh-token` | POST | 刷新access token | `grant_type`, `client_id` | ✅ 从Cookie读取 |

### 请求示例（Cookie模式）

```javascript
// 发送验证码（无变化）
fetch('/sms/send-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phoneNumber: '13800138000' })
});

// SMS登录（同域，自动包含Cookie）
fetch('/sms/login?mobileNumber=13800138000&verificationCode=123456&clientId=ffv-client', {
    credentials: 'include' // 🍪 必须包含以支持Cookie
});

// 刷新Token（Cookie自动提供refresh_token）
fetch('/sms/refresh-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    credentials: 'include', // 🍪 必须包含Cookie
    body: 'grant_type=refresh_token&client_id=ffv-client'
    // 🔒 注意：不再需要refresh_token和client_secret参数！
});
```

## ⚙️ 配置选项

在 `index.html` 中的配置（Cookie安全模式）：

```javascript
const CONFIG = {
    // 🔥 同域配置：留空或使用相对路径
    AUTH_SERVER_BASE_URL: '',  // 同域部署
    // AUTH_SERVER_BASE_URL: 'http://localhost:9000',  // 跨域配置
    
    CLIENT_ID: 'ffv-client',
    
    // 🔒 安全：Cookie模式下不需要客户端存储client_secret
    // CLIENT_SECRET: 'secret',  // ← 已移除
    
    // 🍪 Cookie安全模式配置
    COOKIE_MODE: true,
    
    STORAGE_KEYS: {
        ACCESS_TOKEN: 'sms_access_token',
        // REFRESH_TOKEN: 'sms_refresh_token', // ← Cookie存储，不需要
        TOKEN_EXPIRY: 'sms_token_expiry',
        USER_INFO: 'sms_user_info'
    }
};
```

## 🔍 故障排查

### 1. Cookie不工作
```
Refresh token not found in cookie
```
**解决方案**: 
- 确保使用同域部署（推荐方案B）
- 检查CORS配置是否包含`credentials: true`
- 确认请求包含`credentials: 'include'`

### 2. CORS错误
```
Access to fetch blocked by CORS policy
```
**解决方案**: 
- 使用Spring静态资源服务（同域）
- 或配置后端CORS支持Cookie

### 3. 连接被拒绝
```
Failed to fetch: TypeError: Failed to fetch
```
**解决方案**: 确保WeSpring Auth Server正在运行在 `http://localhost:9000`。

### 4. SMS发送失败
```
发送失败: Failed to send verification code
```
**解决方案**: 
- 检查后端SMS服务配置
- 确认手机号格式正确
- 查看后端日志排查问题

### 5. 登录失败
```
登录失败: SMS authentication failed
```
**解决方案**:
- 确认验证码正确且未过期
- 检查手机号是否已注册
- 查看后端日志详细错误信息

### 6. Token刷新失败（Cookie模式）
```
Token refresh failed
```
**解决方案**:
- 检查Cookie是否正确设置（开发者工具 → Application → Cookies）
- 确认请求包含`credentials: 'include'`
- 确认使用同域部署或正确的跨域配置
- 重新登录获取新的Cookie

## 🛠️ 开发说明

### 核心组件

1. **TokenManager**: 负责token的存储、验证、刷新和自动管理
   - 🔄 **混合存储**: access_token → localStorage, refresh_token → Cookie
   - 🍪 **Cookie感知**: 自动检测Cookie模式并调整行为

2. **SmsLoginManager**: 处理SMS验证码发送和登录逻辑
   - 🔒 **Cookie登录**: 支持Cookie安全模式登录
   - 🚫 **client_secret移除**: 不再需要前端传输客户端密钥

3. **UI管理**: 界面切换、状态显示、用户交互
   - 🍪 **Cookie状态显示**: 显示Cookie存储的refresh_token状态
   - 🔒 **安全指示器**: 显示当前使用的安全模式

### 关键特性

- **🍪 Cookie优先**: 优先使用Cookie存储的refresh_token
- **🔄 混合刷新**: 自动检测存储方式并选择相应的刷新策略
- **🔒 安全升级**: 完全移除前端的敏感信息存储
- **📱 同域支持**: 完美支持同域Cookie共享
- **⚡ 向后兼容**: 保持对传统localStorage模式的兼容

### 安全考虑

- **🍪 HttpOnly Cookie**: refresh_token存储在HttpOnly Cookie中，防止XSS
- **🔒 SameSite保护**: 使用SameSite=Lax防止CSRF攻击
- **🚫 client_secret隐藏**: 完全移除前端的客户端密钥
- **🔐 自动过期**: Cookie自动过期管理
- **✅ 同域限制**: 利用同域限制增强安全性

## 📝 扩展建议

### 短期优化
1. **🍪 Cookie轮换**: 实现refresh_token的定期轮换
2. **📱 移动端优化**: 针对移动浏览器的Cookie优化
3. **🔍 调试工具**: 添加Cookie状态的可视化调试工具

### 中期扩展
1. **🔐 多因子认证**: 结合TOTP的双因子认证
2. **🌐 多域支持**: 支持多个子域名的Cookie共享
3. **📊 安全监控**: 添加Cookie安全事件的监控

### 长期规划
1. **🚀 OAuth2.1升级**: 升级到最新的OAuth2.1标准
2. **🛡️ WebAuthn集成**: 支持生物识别认证
3. **🌍 国际化**: 支持多语言和多地区部署

## 🤝 相关文档

- [WeSpring Auth Server 文档](../README.md)
- [OAuth2 安全修复完成总结](../docs/drafts/OAuth2-安全修复短期方案-完成总结与评估.md)
- [Cookie安全实施计划](../docs/drafts/oauth2-安全修复短期方案-HttpOnly-Cookie实施计划.md)
- [SMS服务配置指南](../docs/drafts/阿里云短信服务_Spring_Boot_集成指南.md)

---

## 🎉 **Cookie安全模式已就绪！**

**强烈推荐使用方案B（Spring静态资源服务）进行开发和测试，这提供了最接近生产环境的Cookie安全体验！**

```bash
# 🚀 一键启动Cookie安全演示
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer
bash start-cookie-demo.sh
open http://localhost:9000/demo
```

如有问题，请查看后端日志或联系开发团队。