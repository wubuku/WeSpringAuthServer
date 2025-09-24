#!/bin/bash
set -euo pipefail

# 获取单个用户的JWT令牌（参数化版本）
# ============================================================================
# 用法:
#   ./get-user-token.sh [OPTIONS]
#
# 必需参数:
#   --base-url=URL, -b=URL     OAuth2服务器基础URL
#   --client-id=ID, -c=ID      OAuth2客户端ID
#   --username=USER, -u=USER   用户名
#
# 可选参数:
#   --redirect-uri=URI, -r=URI 重定向URI (默认: https://服务器域名/oauth2/callback)
#   --scope=SCOPE, -s=SCOPE    OAuth2权限范围 (默认: openid profile)
#   --pkce=YN, -p=YN           是否启用PKCE (y/n, 默认: y)
#   --help, -h                 显示帮助信息
#
# 敏感信息（优先级从高到低）:
#   1. 环境变量 CLIENT_SECRET, USER_PASSWORD
#   2. 交互式提示输入（密码隐藏显示）
#
# 环境变量:
#   CLIENT_SECRET      客户端密钥
#   USER_PASSWORD      用户密码
#
# 示例:
#   # 使用环境变量（推荐）
#   export CLIENT_SECRET=your_secret
#   ./get-user-token.sh --base-url=https://iam.ruichuangqi.com --client-id=ruichuangqi-client --username=hq_admin
#
#   # 使用短参数
#   export CLIENT_SECRET=your_secret
#   ./get-user-token.sh -b https://iam.ruichuangqi.com -c ruichuangqi-client -u hq_admin
#
#   # 混合使用
#   ./get-user-token.sh -b https://iam.ruichuangqi.com -c ruichuangqi-client -u hq_admin -r https://custom-callback.com
# ============================================================================

# 默认值
BASE_URL=""
CLIENT_ID=""
USERNAME=""
REDIRECT_URI=""
SCOPE="openid profile"
ENABLE_PKCE="true"

# 显示帮助信息
show_help() {
    cat << EOF
获取单个用户的JWT令牌（参数化版本）

用法:
  $0 [OPTIONS]

必需参数:
  --base-url=URL, -b=URL     OAuth2服务器基础URL
  --client-id=ID, -c=ID      OAuth2客户端ID
  --username=USER, -u=USER   用户名

可选参数:
  --redirect-uri=URI, -r=URI 重定向URI (默认: https://服务器域名/oauth2/callback)
  --scope=SCOPE, -s=SCOPE    OAuth2权限范围 (默认: openid profile)
  --pkce=YN, -p=YN           是否启用PKCE (y/n, 默认: y)
  --help, -h                 显示帮助信息

敏感信息（优先级从高到低）:
  1. 环境变量 CLIENT_SECRET, USER_PASSWORD
  2. 交互式提示输入（密码隐藏显示）

示例:
  export CLIENT_SECRET=your_secret
  $0 --base-url=https://iam.ruichuangqi.com --client-id=ruichuangqi-client --username=hq_admin

  $0 -b https://iam.ruichuangqi.com -c ruichuangqi-client -u hq_admin
EOF
    exit 0
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --base-url*|-b*)
            if [[ $1 == *=* ]]; then
                BASE_URL="${1#*=}"
            else
                BASE_URL="$2"
                shift
            fi
            ;;
        --client-id*|-c*)
            if [[ $1 == *=* ]]; then
                CLIENT_ID="${1#*=}"
            else
                CLIENT_ID="$2"
                shift
            fi
            ;;
        --username*|-u*)
            if [[ $1 == *=* ]]; then
                USERNAME="${1#*=}"
            else
                USERNAME="$2"
                shift
            fi
            ;;
        --redirect-uri*|-r*)
            if [[ $1 == *=* ]]; then
                REDIRECT_URI="${1#*=}"
            else
                REDIRECT_URI="$2"
                shift
            fi
            ;;
        --scope*|-s*)
            if [[ $1 == *=* ]]; then
                SCOPE="${1#*=}"
            else
                SCOPE="$2"
                shift
            fi
            ;;
        --pkce*|-p*)
            if [[ $1 == *=* ]]; then
                ENABLE_PKCE="${1#*=}"
            else
                ENABLE_PKCE="$2"
                shift
            fi
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo "❌ 未知参数: $1"
            echo "使用 --help 或 -h 查看帮助信息"
            exit 1
            ;;
    esac
    shift
done

# 验证必需参数
if [ -z "$BASE_URL" ] || [ -z "$CLIENT_ID" ] || [ -z "$USERNAME" ]; then
    echo "❌ 缺少必需参数"
    echo "必需参数: --base-url, --client-id, --username"
    echo "使用 --help 或 -h 查看帮助信息"
    exit 1
fi

# 处理敏感信息（优先级：环境变量 > 交互式输入）
echo "🔐 检查敏感信息配置..."

# 处理 CLIENT_SECRET
if [ -n "${CLIENT_SECRET:-}" ]; then
    echo "✅ 使用环境变量中的 CLIENT_SECRET"
else
    echo "❌ CLIENT_SECRET 环境变量未设置"
    read -s -p "请输入客户端密钥 (CLIENT_SECRET): " CLIENT_SECRET
    echo ""
    if [ -z "$CLIENT_SECRET" ]; then
        echo "❌ 客户端密钥是必需的参数"
        exit 1
    fi
    echo "✅ 使用交互式输入的 CLIENT_SECRET"
fi

# 处理 USER_PASSWORD
if [ -n "${USER_PASSWORD:-}" ]; then
    echo "✅ 使用环境变量中的 USER_PASSWORD"
else
    echo "❌ USER_PASSWORD 环境变量未设置"
    read -s -p "请输入 $USERNAME 的密码: " USER_PASSWORD
    echo ""
    if [ -z "$USER_PASSWORD" ]; then
        echo "❌ 用户密码是必需的参数"
        exit 1
    fi
    echo "✅ 使用交互式输入的密码"
fi

# 设置默认重定向URI（如果未指定）
if [ -z "$REDIRECT_URI" ]; then
    # 从BASE_URL中提取域名
    BASE_DOMAIN=$(echo "$BASE_URL" | sed 's|https*://||' | sed 's|/.*||')
    REDIRECT_URI="https://${BASE_DOMAIN}/oauth2/callback"
    echo "✅ 使用默认重定向URI: $REDIRECT_URI"
else
    echo "✅ 使用指定的重定向URI: $REDIRECT_URI"
fi

# 验证PKCE参数
if [ "$ENABLE_PKCE" = "y" ] || [ "$ENABLE_PKCE" = "Y" ] || [ "$ENABLE_PKCE" = "true" ] || [ "$ENABLE_PKCE" = "1" ]; then
    ENABLE_PKCE="true"
    echo "✅ PKCE: 启用"
elif [ "$ENABLE_PKCE" = "n" ] || [ "$ENABLE_PKCE" = "N" ] || [ "$ENABLE_PKCE" = "false" ] || [ "$ENABLE_PKCE" = "0" ]; then
    ENABLE_PKCE="false"
    echo "✅ PKCE: 禁用"
else
    ENABLE_PKCE="true"
    echo "✅ 使用默认PKCE设置: 启用"
fi

# 客户端凭据 Base64 编码
CLIENT_CREDENTIALS_B64=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

echo ""
echo "🔧 完整配置信息:"
echo "   Base URL: $BASE_URL"
echo "   Client ID: $CLIENT_ID"
echo "   Client Secret: [HIDDEN]"
echo "   Username: $USERNAME"
echo "   Password: [HIDDEN]"
echo "   Redirect URI: $REDIRECT_URI"
echo "   Scope: $SCOPE"
echo "   PKCE Enabled: $ENABLE_PKCE"
echo "   Client Credentials B64: $CLIENT_CREDENTIALS_B64"
echo ""

# Base64URL encode function (no padding)
base64url_encode() {
    base64 | tr '/+' '_-' | tr -d '='
}

# URL encode function
urlencode() {
    python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}

# Generate code_verifier (random string)
code_verifier=$(openssl rand -base64 32 | tr -d /=+ | cut -c -43)

# Generate code_challenge (base64url-encode(sha256(code_verifier)))
code_challenge=$(printf "%s" "$code_verifier" | openssl sha256 -binary | base64url_encode)

# 清理旧的 cookies
rm -f cookies.txt
echo "🔧 清理旧的 cookies 完成"

# 获取登录页面和 CSRF token
echo "🔐 获取登录页面..."
login_page=$(curl -c cookies.txt -b cookies.txt -s -H "Accept: text/html" "${BASE_URL}/login")
echo "🔧 登录页面获取完成，长度: ${#login_page}"

csrf_token=$(echo "$login_page" | grep -o 'name="_csrf".*value="[^"]*"' | sed 's/.*value="\([^"]*\)".*/\1/' | tr -d '\n')
echo "🔐 CSRF Token: $csrf_token"

# 检查 CSRF token 是否存在
if [ -z "$csrf_token" ]; then
    echo "❌ Error: Failed to get CSRF token"
    echo "Login page response (first 500 chars):"
    echo "$login_page" | head -c 500
    exit 1
fi

# 执行登录并捕获完整响应
echo "🔑 执行用户登录..."
echo "🔧 登录URL: ${BASE_URL}/login"
echo "🔧 登录参数: username=$USERNAME, _csrf=$csrf_token"

login_response=$(curl -v -X POST ${BASE_URL}/login \
    -c cookies.txt -b cookies.txt \
    -H "Accept: text/html,application/xhtml+xml" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$USERNAME" \
    -d "password=$USER_PASSWORD" \
    -d "_csrf=$csrf_token" \
    2>&1)

echo "🔧 登录响应长度: ${#login_response}"
echo "🔍 检查登录响应前500字符:"
echo "$login_response" | head -c 500
echo ""

echo "🔍 提取 Location 头..."
location=$(echo "$login_response" | grep -i "location:" | sed 's/.*Location: //' | tr -d '\r\n')
echo "🔧 Location: '$location'"

echo "🔍 提取 Set-Cookie 头..."
set_cookie_lines=$(echo "$login_response" | grep -i "set-cookie:")
echo "🔧 Set-Cookie 行数: $(echo "$set_cookie_lines" | wc -l)"
echo "🔧 Set-Cookie 内容: $set_cookie_lines"

cookie_session_id=$(echo "$login_response" | grep -i "set-cookie:" | grep -o "SESSION=[^;]*" | cut -d= -f2)
echo "🔧 Cookie Session ID: '$cookie_session_id'"

echo "🔍 提取 X-Auth-Token 头..."
x_auth_token_lines=$(echo "$login_response" | grep -i "x-auth-token:" || echo "未找到 X-Auth-Token")
echo "🔧 X-Auth-Token 行数: $(echo "$x_auth_token_lines" | grep -c "x-auth-token" || echo "0")"
echo "🔧 X-Auth-Token 内容: $x_auth_token_lines"

header_session_id=$(echo "$login_response" | grep -i "x-auth-token:" | sed 's/.*X-Auth-Token: //' | tr -d '\r\n' || echo "")
echo "🔧 Header Session ID: '$header_session_id'"

# 使用可用的会话标识符
session_id=${header_session_id:-$cookie_session_id}

# 验证登录是否成功
if echo "$location" | grep -q "/error\|/login?error"; then
    echo "❌ Login failed! Redirected to: $location"
    exit 1
elif [ -z "$location" ]; then
    echo "❌ Error: No redirect location found"
    exit 1
else
    echo "✅ Login successful! Redirected to: $location"
fi

echo "🔧 准备会话头..."
echo "🔧 Header Session ID: '$header_session_id'"
echo "🔧 Cookie Session ID: '$cookie_session_id'"

# 为后续请求准备会话头
if [ -n "$header_session_id" ]; then
    session_headers="-H \"X-Auth-Token: $header_session_id\""
    echo "✅ 使用 Header Session ID"
elif [ -n "$cookie_session_id" ]; then
    session_headers="-b cookies.txt"
    echo "✅ 使用 Cookie Session ID"
else
    session_headers=""
    echo "⚠️  未找到会话标识符"
fi
echo "🔧 Session Headers: '$session_headers'"

# 设置重定向 URI 并编码
# 注意：生产环境的OAuth2服务器通常要求redirect_uri与注册的一致
redirect_uri="http://127.0.0.1:3000/auth/callback"
echo "🔧 重定向URI: $redirect_uri"
encoded_redirect_uri=$(urlencode "$redirect_uri")
echo "🔧 编码后的重定向URI: $encoded_redirect_uri"

# 尝试使用与服务器域名相同的重定向URI
server_redirect_uri="https://iam.ruichuangqi.com/auth/callback"
encoded_server_redirect_uri=$(urlencode "$server_redirect_uri")
echo "🔧 服务器域名重定向URI: $server_redirect_uri"
echo "🔧 编码后的服务器重定向URI: $encoded_server_redirect_uri"

# 使用用户提供的参数构建OAuth2请求
echo "🔄 使用用户提供的参数构建OAuth2请求..."

# 对重定向URI进行URL编码
encoded_redirect_uri=$(urlencode "$REDIRECT_URI")
encoded_scope=$(urlencode "$SCOPE")

echo "🔧 编码后的参数:"
echo "   Encoded Redirect URI: $encoded_redirect_uri"
echo "   Encoded Scope: $encoded_scope"

# 根据PKCE设置构建请求URL
if [ "$ENABLE_PKCE" = "true" ]; then
    echo "🔧 使用PKCE模式..."
    auth_url="${BASE_URL}/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&scope=${encoded_scope}&redirect_uri=${encoded_redirect_uri}&code_challenge=${code_challenge}&code_challenge_method=S256"
else
    echo "🔧 使用非PKCE模式..."
    auth_url="${BASE_URL}/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&scope=${encoded_scope}&redirect_uri=${encoded_redirect_uri}"
fi

echo "🔧 完整授权URL: $auth_url"

auth_page=$(curl -s \
    $session_headers \
    -c cookies.txt \
    --max-redirs 0 \
    --no-location \
    "$auth_url" \
    -D - 2>/dev/null)

echo "🔧 授权响应长度: ${#auth_page}"

# 如果失败，提供详细的错误信息
if echo "$auth_page" | grep -q '"status":400'; then
    echo "❌ OAuth2授权请求失败"
    echo "🔍 错误详情:"
    echo "$auth_page"
    echo ""
    echo "🔧 故障排除信息:"
    echo "   使用的客户端ID: $CLIENT_ID"
    echo "   使用的重定向URI: $REDIRECT_URI"
    echo "   使用的Scope: $SCOPE"
    echo "   PKCE启用状态: $ENABLE_PKCE"
    echo ""
    echo "📋 请检查以下配置："
    echo "1. 确认客户端ID '$CLIENT_ID' 已正确注册"
    echo "2. 确认重定向URI '$REDIRECT_URI' 已添加到客户端配置"
    echo "3. 确认服务器支持 '$SCOPE' scope"
    echo "4. 确认服务器支持 PKCE: $ENABLE_PKCE"
    exit 1
fi

echo "🔍 检查授权页面内容..."
echo "🔧 授权页面前1000字符:"
echo "$auth_page" | head -c 1000
echo ""

# 成功情况：继续处理授权响应
echo "✅ OAuth2授权请求成功，响应长度: ${#auth_page}"

# 检查是否需要用户同意
if echo "$auth_page" | grep -q "Consent required"; then
    echo "🔑 需要用户同意"

    # 从授权页面提取 state 值
    state=$(echo "$auth_page" | sed -n 's/.*name="state" value="\([^"]*\).*/\1/p')
    echo "🔧 提取的 state: '$state'"

    if [ -z "$state" ]; then
        echo "❌ Error: Could not extract state from auth page"
        exit 1
    fi

    # 提交授权确认
    echo "🔄 提交授权确认..."
    auth_response=$(curl -s \
        $session_headers \
        -c cookies.txt \
        "${BASE_URL}/oauth2/authorize" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${CLIENT_ID}" \
        -d "state=$state" \
        -d "scope=openid" \
        -d "scope=profile" \
        -d "submit=Submit+Consent" \
        -D - 2>/dev/null)
    echo "🔧 授权确认响应长度: ${#auth_response}"
else
    echo "✅ 直接使用重定向响应"
    # 直接使用重定向响应
    auth_response="$auth_page"
fi

# 从重定向 URL 中提取授权码
location=$(echo "$auth_response" | grep -i "^location:" | sed 's/.*Location: //' | tr -d '\r\n')
auth_code=$(echo "$location" | grep -o 'code=[^&]*' | cut -d= -f2)

if [ -z "$auth_code" ]; then
    echo "❌ Authorization failed!"
    exit 1
fi

# 编码参数
encoded_code_verifier=$(urlencode "$code_verifier")
encoded_auth_code=$(urlencode "$auth_code")

# 获取访问令牌
token_response=$(curl -v -X POST "${BASE_URL}/oauth2/token" \
    ${session_headers:+-H "X-Auth-Token: $header_session_id"} \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: Basic $CLIENT_CREDENTIALS_B64" \
    -H "Accept: application/json" \
    -d "grant_type=authorization_code" \
    -d "code=$encoded_auth_code" \
    -d "redirect_uri=$encoded_redirect_uri" \
    -d "code_verifier=$encoded_code_verifier" \
    -d "scope=openid%20profile" \
    2>&1)

# 提取 JSON 部分
json_response=$(echo "$token_response" | grep -v "^[*<>}]" | tail -n 1)

# 检查响应是否包含错误
if echo "$json_response" | jq -e 'has("error")' > /dev/null; then
    echo "❌ Token request failed!"
    echo "Error: $(echo "$json_response" | jq -r '.error')"
    echo "Error description: $(echo "$json_response" | jq -r '.error_description // .message')"
    echo "Full JSON response:"
    echo "$json_response" | jq '.'
    exit 1
fi

# 提取令牌
access_token=$(echo "$json_response" | jq -r '.access_token')
refresh_token=$(echo "$json_response" | jq -r '.refresh_token')
id_token=$(echo "$json_response" | jq -r '.id_token')

# 验证是否成功获取到令牌
if [ "$access_token" = "null" ] || [ -z "$access_token" ]; then
    echo "❌ Failed to extract access token!"
    echo "Response:"
    echo "$json_response" | jq '.'
    exit 1
fi

echo "✅ Token request successful!"
echo "🔑 Access Token: ${access_token:0:50}..."

# 保存令牌供后续使用
upper_username=$(echo "$USERNAME" | tr '[:lower:]' '[:upper:]')
echo "export ${upper_username}_ACCESS_TOKEN=\"$access_token\""
if [ "$refresh_token" != "null" ] && [ -n "$refresh_token" ]; then
    echo "export ${upper_username}_REFRESH_TOKEN=\"$refresh_token\""
fi
