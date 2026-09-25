# SMS登录接口错误处理改进

## 🎯 核心改进

| 错误类型 | 状态码 | 响应示例 |
|---------|--------|----------|
| **手机号为空** | 400 | `{"error":"invalid_request","error_description":"手机号不能为空"}` |
| **手机号格式错误** | 400 | `{"error":"invalid_request","error_description":"手机号格式不正确，请输入11位中国大陆手机号"}` |
| **验证码为空** | 400 | `{"error":"invalid_request","error_description":"验证码不能为空"}` |
| **验证码格式错误** | 400 | `{"error":"invalid_request","error_description":"验证码格式不正确，请输入4-6位数字验证码"}` |
| **验证码验证失败** | 400 | `{"error":"invalid_request","error_description":"验证码错误，请检查后重新输入"}` |
| **系统认证错误** | 401 | `{"error":"authentication_failed","error_description":"SMS authentication failed: ..."}` |
| **服务器错误** | 500 | `{"error":"server_error","error_description":"Internal server error"}` |

## 🔗 受影响接口
- `GET /sms/login` - Web端SMS登录
- `GET /sms/auth` - 小程序端SMS登录

## 💻 前端集成代码

```javascript
// 核心错误处理函数
function handleSmsLoginError(statusCode, errorData) {
  const desc = errorData.error_description;

  switch (statusCode) {
    case 400:
      // 手机号/验证码错误
      if (desc.includes('手机号')) return { field: 'mobile', message: desc };
      if (desc.includes('验证码')) return { field: 'code', message: desc };
      return { message: desc };

    case 401:
      return { message: '登录失败，请稍后重试' };

    case 500:
      return { message: '服务器繁忙，请稍后重试' };

    default:
      return { message: '未知错误，请稍后重试' };
  }
}
```

## ✅ 兼容性
- ✅ 现有成功登录流程保持不变
- ✅ 渐进式升级，老版本仍可工作
- ✅ 所有原有参数保持兼容

---