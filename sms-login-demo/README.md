# SMS登录演示 - WeSpring Auth Server

这是一个基于WeSpring Auth Server的SMS登录单页面演示应用，展示了如何使用短信验证码进行用户认证，而无需复杂的OAuth2授权码流程。

## 🌟 功能特点

- **📱 SMS验证码登录**: 支持发送和验证短信验证码
- **🔄 自动Token刷新**: 自动管理token生命周期，无感知刷新
- **🔄 手动Token刷新**: 新增手动刷新按钮，显示详细的刷新过程和日志
- **💾 本地存储**: 使用localStorage保存token和用户信息  
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

## 🚀 运行Demo

### 方法一：使用Python HTTP服务器（推荐）

```bash
# 进入demo目录
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer/sms-login-demo

# 启动HTTP服务器
python3 -m http.server 8080

# 访问应用
open http://localhost:8080
```

### 方法二：使用Node.js serve

```bash
# 安装serve（如果还没安装）
npm install -g serve

# 进入demo目录
cd /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer/sms-login-demo

# 启动服务
serve -s . -p 8080

# 访问应用
open http://localhost:8080
```

### 方法三：使用VS Code Live Server

1. 在VS Code中打开 `sms-login-demo` 目录
2. 安装 "Live Server" 扩展
3. 右键点击 `index.html` 选择 "Open with Live Server"

### 方法四：直接用浏览器打开（可能有CORS限制）

```bash
# 直接打开HTML文件
open /Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer/sms-login-demo/index.html
```

**注意**: 直接用浏览器打开可能遇到CORS问题，推荐使用HTTP服务器。

## 🎯 使用流程

### 1. 访问应用
打开浏览器访问 `http://localhost:8080`，你会看到SMS登录界面。

### 2. SMS登录流程
1. **输入手机号**: 输入注册过的手机号码
2. **发送验证码**: 点击"发送验证码"按钮
3. **输入验证码**: 收到短信后输入6位验证码
4. **登录系统**: 点击"立即登录"完成认证

### 3. 业务操作
登录成功后可以：
- 查看个人资料
- 浏览订单信息  
- 访问系统设置
- 测试API调用

### 4. Token管理
- **自动刷新**: Token即将过期时自动刷新（提前10分钟）
- **手动刷新**: 点击"🔄 手动刷新Token"按钮可主动刷新token
- **过程日志**: 手动刷新时显示详细的操作过程和状态日志
- **状态显示**: 实时显示token状态和过期时间
- **安全登出**: 清除所有本地存储的认证信息

## 🔧 API端点说明

### SMS登录相关端点

| 端点 | 方法 | 功能 | 参数 |
|------|------|------|------|
| `/sms/send-code` | POST | 发送SMS验证码 | `phoneNumber` |
| `/sms/auth` | GET | SMS登录认证 | `mobileNumber`, `verificationCode`, `clientId` |
| `/sms/refresh-token` | POST | 刷新access token | `grant_type`, `refresh_token`, `client_id`, `client_secret` |

### 请求示例

```javascript
// 发送验证码
fetch('http://localhost:9000/sms/send-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phoneNumber: '13800138000' })
});

// SMS登录
fetch('http://localhost:9000/sms/auth?mobileNumber=13800138000&verificationCode=123456&clientId=ffv-client');

// 刷新Token
fetch('http://localhost:9000/sms/refresh-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=refresh_token&refresh_token=xxx&client_id=ffv-client&client_secret=secret'
});
```

## ⚙️ 配置选项

在 `index.html` 中可以修改以下配置：

```javascript
const CONFIG = {
    AUTH_SERVER_BASE_URL: 'http://localhost:9000',  // 后端服务地址
    CLIENT_ID: 'ffv-client',                        // OAuth2客户端ID
    CLIENT_SECRET: 'secret',                        // OAuth2客户端密钥
    STORAGE_KEYS: {                                 // 本地存储键名
        ACCESS_TOKEN: 'sms_access_token',
        REFRESH_TOKEN: 'sms_refresh_token',
        TOKEN_EXPIRY: 'sms_token_expiry',
        USER_INFO: 'sms_user_info'
    }
};
```

## 🔍 故障排查

### 1. CORS错误
```
Access to fetch at 'http://localhost:9000/sms/send-code' from origin 'null' has been blocked by CORS policy
```
**解决方案**: 使用HTTP服务器运行demo，不要直接打开HTML文件。

### 2. 连接被拒绝
```
Failed to fetch: TypeError: Failed to fetch
```
**解决方案**: 确保WeSpring Auth Server正在运行在 `http://localhost:9000`。

### 3. SMS发送失败
```
发送失败: Failed to send verification code
```
**解决方案**: 
- 检查后端SMS服务配置
- 确认手机号格式正确
- 查看后端日志排查问题

### 4. 登录失败
```
登录失败: SMS authentication failed
```
**解决方案**:
- 确认验证码正确且未过期
- 检查手机号是否已注册
- 查看后端日志详细错误信息

### 5. Token刷新失败
```
Token refresh failed
```
**解决方案**:
- 检查client_secret配置是否正确
- 确认refresh_token未过期
- 重新登录获取新的token

## 🛠️ 开发说明

### 核心组件

1. **TokenManager**: 负责token的存储、验证、刷新和自动管理
2. **SmsLoginManager**: 处理SMS验证码发送和登录逻辑
3. **UI管理**: 界面切换、状态显示、用户交互

### 关键特性

- **自动Token刷新**: 提前10分钟自动刷新token，避免用户感知
- **错误重试**: API调用失败时自动重试和token刷新
- **状态管理**: 完整的登录状态检查和维护
- **用户体验**: 优雅的加载动画、倒计时、错误提示

### 安全考虑

- Token存储在localStorage（生产环境建议使用httpOnly cookie）
- 自动清理过期token
- 安全的客户端认证
- 完整的错误处理

## 📝 扩展建议

1. **生产环境优化**:
   - 使用HTTPS
   - 实现httpOnly cookie存储
   - 添加CSRF保护
   - 实现设备指纹识别

2. **功能扩展**:
   - 支持多种登录方式
   - 添加用户注册功能
   - 实现密码登录
   - 支持社交登录

3. **UI/UX改进**:
   - 添加深色模式
   - 支持多语言
   - 优化移动端体验
   - 添加动画效果

## 🤝 相关文档

- [WeSpring Auth Server 文档](../README.md)
- [OAuth2 集成指南](../docs/oauth2-client-integration-guide.md)
- [SMS服务配置指南](../docs/drafts/阿里云短信服务_Spring_Boot_集成指南.md)

---

**🎉 享受你的SMS登录演示之旅！**

如有问题，请查看后端日志或联系开发团队。