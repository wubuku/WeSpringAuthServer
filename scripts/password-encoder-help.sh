#!/bin/bash

# 密码编码服务的使用帮助打印脚本
# Password Encoder Service Usage Help Script

# 密码编码工具使用示例
# 🔒 注意：此工具仅在开发环境（dev profile）可用

# 询问用户要访问的后端服务的 base URL 地址
echo "请输入后端服务的 base URL 地址 (默认: http://localhost:9000):"
read -r user_input
if [ -z "$user_input" ]; then
    BASE_URL="http://localhost:9000"
else
    BASE_URL="$user_input"
fi
DEV_TOOLS_URL="$BASE_URL/dev-tools/password-encoder"

echo "🔐 WeSpringAuthServer 密码编码服务使用帮助"
echo "================================================"
echo "📍 服务地址: $BASE_URL"
echo "🔧 开发工具端点: $DEV_TOOLS_URL"
echo ""

# 检查服务是否运行
# 使用健康检查端点进行服务状态检查
echo "📡 检查服务状态..."
HEALTH_URL="$BASE_URL/health"
if ! curl -s "$HEALTH_URL" > /dev/null; then
    echo "❌ 服务未运行！请先启动开发环境："
    echo "   export SPRING_PROFILES_ACTIVE=dev"
    echo "   ./start.sh"
    echo "   健康检查端点: $HEALTH_URL"
    exit 1
fi

echo "✅ 服务运行中"
echo ""

# 帮助信息内容 - 密码编码服务的各种使用方法

# 1. 编码单个密码
echo "1️⃣ 编码单个密码"
echo "=================="
echo "curl -X POST $DEV_TOOLS_URL/encode \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"password\": \"mypassword123\"}'"
echo ""
echo "响应示例："
curl -s -X POST "$DEV_TOOLS_URL/encode" \
  -H "Content-Type: application/json" \
  -d '{"password": "mypassword123"}' | jq '.' 2>/dev/null || echo "需要安装jq来格式化JSON输出"
echo ""

# 2. 批量编码密码
echo "2️⃣ 批量编码用户密码"
echo "===================="
echo "curl -X POST $DEV_TOOLS_URL/encode-batch \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{"
echo "    \"users\": ["
echo "      {\"username\": \"admin\", \"password\": \"admin123\"},"
echo "      {\"username\": \"user1\", \"password\": \"user123\"}"
echo "    ]"
echo "  }'"
echo ""
echo "响应示例："
curl -s -X POST "$DEV_TOOLS_URL/encode-batch" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {"username": "admin", "password": "admin123"},
      {"username": "user1", "password": "user123"}
    ]
  }' | jq '.' 2>/dev/null || echo "需要安装jq来格式化JSON输出"
echo ""

# 3. 验证密码
echo "3️⃣ 验证密码匹配"
echo "================"
echo "curl -X POST $DEV_TOOLS_URL/verify \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{"
echo "    \"rawPassword\": \"admin\","
echo "    \"encodedPassword\": \"{bcrypt}\$2a\$10\$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky\""
echo "  }'"
echo ""
echo "响应示例："
curl -s -X POST "$DEV_TOOLS_URL/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "rawPassword": "admin",
    "encodedPassword": "{bcrypt}$2a$10$eKBDBSf4DBNzRwbF7fx5IetdKKjqzkYoST0F7Dkro84eRiDTBJYky"
  }' | jq '.' 2>/dev/null || echo "需要安装jq来格式化JSON输出"
echo ""

# 4. 编码OAuth2客户端密钥
echo "4️⃣ 编码OAuth2客户端密钥"
echo "======================="
echo "curl -X POST $DEV_TOOLS_URL/encode-client-secret \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{"
echo "    \"clientId\": \"my-client\","
echo "    \"clientSecret\": \"my-secret\""
echo "  }'"
echo ""
echo "响应示例："
curl -s -X POST "$DEV_TOOLS_URL/encode-client-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "my-client",
    "clientSecret": "my-secret"
  }' | jq '.' 2>/dev/null || echo "需要安装jq来格式化JSON输出"
echo ""

# 5. 获取常用密码编码
echo "5️⃣ 获取常用密码编码"
echo "=================="
echo "curl -X GET $DEV_TOOLS_URL/common-passwords"
echo ""
echo "响应示例："
curl -s -X GET "$DEV_TOOLS_URL/common-passwords" | jq '.' 2>/dev/null || echo "需要安装jq来格式化JSON输出"
echo ""

echo "🎯 使用场景："
echo "============="
echo "• 生成新用户密码用于data.sql"
echo "• 创建OAuth2客户端配置"
echo "• 验证现有密码是否正确"
echo "• 生成生产环境用户密码"
echo ""

echo "🔒 安全提醒："
echo "============="
echo "• 此工具仅在开发环境（dev profile）可用"
echo "• 生产环境自动禁用"
echo "• 生成的密码应安全存储"
echo "• 不要在日志中记录明文密码"
echo ""

echo "📝 生成SQL示例："
echo "================"
echo "# 1. 使用编码后的密码创建用户："
echo "INSERT INTO users (username, password, enabled) VALUES"
echo "  ('newuser', '{编码后的密码}', true);"
echo ""
echo "# 2. 为用户添加权限："
echo "INSERT INTO authorities (username, authority) VALUES"
echo "  ('newuser', 'ROLE_USER');"
echo ""
echo "# 3. 使用编码后的密钥创建OAuth2客户端（参考 data-prod.sql 模板）："
echo "INSERT INTO oauth2_registered_client ("
echo "    id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name,"
echo "    client_authentication_methods, authorization_grant_types,"
echo "    redirect_uris, post_logout_redirect_uris, scopes, client_settings, token_settings"
echo ") VALUES ("
echo "    'xxx-client-static-id',                    -- 修改: 客户端唯一ID"
echo "    'xxx-client',                              -- 修改: 客户端标识"
echo "    '2025-06-15 21:44:30.947',                -- 可选: 发布时间"
echo "    '{编码后的客户端密钥}',                      -- 使用编码工具生成"
echo "    NULL,                                      -- 密钥不过期"
echo "    'XXX Client',                             -- 修改: 客户端显示名称"
echo "    'client_secret_basic',                     -- 认证方式"
echo "    'authorization_code,refresh_token',        -- 授权类型"
echo "    'https://admin.xxx.com/auth/callback',     -- 修改: 回调地址"
echo "    'https://admin.xxx.com/login,https://admin.xxx.com/logout',  -- 修改: 登出重定向"
echo "    'openid,profile',                          -- 权限范围"
echo "    '{\"@class\":\"java.util.Collections\$UnmodifiableMap\",\"settings.client.require-proof-key\":true,\"settings.client.require-authorization-consent\":false}',"
echo "    '{\"@class\":\"java.util.Collections\$UnmodifiableMap\","
echo "      \"settings.token.reuse-refresh-tokens\":true,"
echo "      \"settings.token.access-token-time-to-live\":[\"java.time.Duration\",7200.000000000],"
echo "      \"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",7776000.000000000],"
echo "      \"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",600.000000000]}'"
echo ") ON CONFLICT (id) DO NOTHING;"
echo ""
echo "💡 使用提示："
echo "============="
echo "1. 使用本工具生成编码后的密码和客户端密钥"
echo "2. 替换 SQL 中的 {编码后的密码} 和 {编码后的客户端密钥}"
echo "3. 修改包含 'xxx' 和 'XXX' 的部分为实际值："
echo "   - xxx-client-static-id → 实际的客户端ID"
echo "   - xxx-client → 实际的客户端标识"
echo "   - XXX Client → 实际的客户端名称"
echo "   - https://admin.xxx.com → 实际的域名地址"
echo "4. 根据需要调整 token 有效期和其他设置"