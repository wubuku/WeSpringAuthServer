#!/bin/bash

# 密码编码工具使用示例
# 🔒 注意：此工具仅在开发环境（dev profile）可用

BASE_URL="http://localhost:9000"
DEV_TOOLS_URL="$BASE_URL/dev-tools/password-encoder"

echo "🔐 WeSpringAuthServer 密码编码工具使用示例"
echo "================================================"
echo ""

# 检查服务是否运行
echo "📡 检查服务状态..."
if ! curl -s "$BASE_URL" > /dev/null; then
    echo "❌ 服务未运行！请先启动开发环境："
    echo "   export SPRING_PROFILES_ACTIVE=dev"
    echo "   ./start.sh"
    exit 1
fi

echo "✅ 服务运行中"
echo ""

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
echo "# 使用编码后的密码创建用户："
echo "INSERT INTO users (username, password, enabled) VALUES"
echo "  ('newuser', '{编码后的密码}', true);"
echo ""
echo "# 使用编码后的密钥创建OAuth2客户端："
echo "INSERT INTO oauth2_registered_client (client_secret, ...) VALUES"
echo "  ('{编码后的客户端密钥}', ...);"