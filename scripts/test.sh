#!/usr/bin/env bash

# ============================================================================
# 🧪 OAuth2 标准授权码流程测试脚本
# ============================================================================
# 此脚本测试标准 OAuth2 授权码流程，包括：
# - 用户登录和授权（支持强制改密重定向与用户同意页）
# - 授权码交换 access_token
# - 刷新 token 功能测试（可选：TEST_REFRESH_TOKEN=true）
# - JWT 令牌解析和验证
# ============================================================================

set -euo pipefail

# 依赖检查
for cmd in curl jq openssl base64; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "❌ Error: 缺少依赖命令: $cmd" >&2
        exit 1
    }
done

# 临时工作目录（存放 cookies 与 HTTP 响应头，退出自动清理，避免污染当前目录）
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

COOKIE_JAR="$WORK_DIR/cookies.txt"
HEADER_FILE="$WORK_DIR/headers.txt"
BODY_FILE="$WORK_DIR/body.txt"

# 产物输出目录（默认当前目录以兼容直接运行；批量脚本可传独立目录隔离并发）
OUTPUT_DIR="${TEST_OUTPUT_DIR:-.}"
mkdir -p "$OUTPUT_DIR"

# 统一 curl 封装：本地回环绕过代理 + 设置超时，避免本机代理拦截或无限卡死
curl_local() {
    curl --noproxy 'localhost,127.0.0.1,[::1]' \
        --connect-timeout 5 \
        --max-time 20 \
        "$@"
}

# 大小写无关提取 HTTP 响应头（兼容 HTTP/1.1 与 HTTP/2，兼容 macOS BSD awk 与 GNU awk）
extract_header() {
    local file="$1"
    local target="$2"
    awk -v key="$(printf '%s' "$target" | tr '[:upper:]' '[:lower:]')" '
        {
            sub(/\r$/, "")
            idx = index($0, ":")
            if (idx > 0) {
                name = tolower(substr($0, 1, idx - 1))
                if (name == key) {
                    val = substr($0, idx + 1)
                    sub(/^[[:space:]]+/, "", val)
                    res = val
                }
            }
        }
        END { if (res != "") print res }
    ' "$file"
}

# 从 Set-Cookie 响应头提取 JSESSIONID
extract_jsessionid() {
    local file="$1"
    awk '
        {
            sub(/\r$/, "")
            idx = index($0, ":")
            if (idx > 0 && tolower(substr($0, 1, idx - 1)) == "set-cookie") {
                val = substr($0, idx + 1)
                if (match(val, /JSESSIONID=[^;[:space:]]+/)) {
                    res = substr(val, RSTART + 11, RLENGTH - 11)
                }
            }
        }
        END { if (res != "") print res }
    ' "$file"
}

# 跨平台 Base64 解码（兼容 macOS BSD base64 与 GNU base64，不强依赖 gbase64）
base64_decode() {
    if printf 'QQ==' | base64 -d >/dev/null 2>&1; then
        base64 -d
    elif printf 'QQ==' | base64 -D >/dev/null 2>&1; then
        base64 -D
    elif command -v gbase64 >/dev/null 2>&1; then
        gbase64 -d
    else
        echo "❌ Error: 无法找到可用的 base64 解码命令" >&2
        return 1
    fi
}

# 原子写入 tokens.env 并收紧权限
write_tokens_env() {
    local access="$1"
    local refresh="$2"
    local id="$3"
    local tmp_file="$WORK_DIR/tokens.env.tmp"
    {
        printf 'export ACCESS_TOKEN=%q\n' "$access"
        printf 'export REFRESH_TOKEN=%q\n' "$refresh"
        printf 'export ID_TOKEN=%q\n' "$id"
    } > "$tmp_file"
    chmod 600 "$tmp_file"
    mv "$tmp_file" "$OUTPUT_DIR/tokens.env"
}

# 🚨 测试用客户端凭据 - 仅用于开发测试！绝不能暴露到浏览器端！
# ⚠️  生产环境必须使用安全的客户端凭据管理方式
# 可用 TEST_CLIENT_ID / TEST_CLIENT_SECRET 覆盖；默认值保持不变
CLIENT_ID="${TEST_CLIENT_ID:-ffv-client}"
CLIENT_SECRET="${TEST_CLIENT_SECRET:-secret}"
CLIENT_CREDENTIALS_B64=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

# 🔧 测试配置开关
# 环境变量优先：若外部已设置 TEST_REFRESH_TOKEN，则使用其值；否则默认 false
TEST_REFRESH_TOKEN="${TEST_REFRESH_TOKEN:-false}"  # 设置为 false 可跳过刷新token测试

echo "🧪 OAuth2测试客户端凭据 (仅用于测试!):"
echo "   Client ID: $CLIENT_ID"
echo "   Client Secret: [HIDDEN]"
echo "   🚨 警告: 这些凭据仅用于开发测试，不得用于生产环境!"
echo ""

if [[ "$TEST_REFRESH_TOKEN" == "true" ]]; then
    echo "🔄 刷新Token测试: 启用"
else
    echo "⏭️  刷新Token测试: 跳过"
fi
echo ""

# 服务器配置
# 用 TEST_BASE_URL 覆盖可支持 dev.sh 的自定义端口；避免与 shell 内置 BASE_URL 撞名
BASE_URL="${TEST_BASE_URL:-http://localhost:9000}"

# 用户凭证配置
# 用 TEST_USERNAME / TEST_PASSWORD / TEST_NEW_PASSWORD 覆盖，
# 不用 USERNAME / PASSWORD，避免与 shell 环境变量（macOS 默认有 USERNAME）冲突
USERNAME="${TEST_USERNAME:-store_admin}" # admin / user
PASSWORD="${TEST_PASSWORD:-store123}"
NEW_PASSWORD="${TEST_NEW_PASSWORD:-$PASSWORD}"  # 当需要修改密码时使用的新密码

# Base64URL 编码（无 padding）
base64url_encode() {
    base64 | tr -d '\n' | tr '/+' '_-' | tr -d '='
}

# URL 编码（复用已依赖的 jq，避免额外依赖 python3）
urlencode() {
    jq -rn --arg v "$1" '$v | @uri'
}

# JWT 解码（兼容 macOS/Linux）
decode_jwt() {
    local jwt_part="$1"
    local rem=$(( ${#jwt_part} % 4 ))
    if [ "$rem" -eq 2 ]; then
        jwt_part="${jwt_part}=="
    elif [ "$rem" -eq 3 ]; then
        jwt_part="${jwt_part}="
    fi
    printf '%s' "$jwt_part" | tr '_-' '/+' | base64_decode 2>/dev/null
}

# 去除 GNU base64 可能产生的换行符
CLIENT_CREDENTIALS_B64="$(printf '%s' "$CLIENT_CREDENTIALS_B64" | tr -d '\n')"

# 清理目标目录下可能残留的旧 tokens.env，避免失败后被上层误读旧值
rm -f "$OUTPUT_DIR/tokens.env"

# 生成 PKCE code_verifier 与 code_challenge
code_verifier="$(openssl rand -base64 32 | tr -d '/=+\n' | cut -c -43)"
echo "🔑 Code Verifier: $code_verifier"

code_challenge="$(printf '%s' "$code_verifier" | openssl sha256 -binary | base64url_encode)"
echo "🔒 Code Challenge: $code_challenge"

if [ -z "$code_challenge" ]; then
    echo "❌ Error: Failed to generate code_challenge" >&2
    exit 1
fi

# 获取登录页面和 CSRF token
login_page="$(curl_local -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" -H "Accept: text/html" "${BASE_URL}/login")"
csrf_token="$(printf '%s' "$login_page" | grep -o 'name="_csrf"[^>]*value="[^"]*"' | sed 's/.*value="\([^"]*\)".*/\1/' | head -n 1 || true)"

echo "🔐 CSRF Token: $csrf_token"

if [ -z "$csrf_token" ]; then
    echo "❌ Error: Failed to get CSRF token from ${BASE_URL}/login" >&2
    printf '%s\n' "$login_page" | head -n 20 >&2
    exit 1
fi

# 执行登录并分离响应头与响应体（--data-urlencode 避免密码含特殊字符时被拆参）
curl_local -sS -X POST "${BASE_URL}/login" \
    -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -H "Accept: text/html,application/xhtml+xml" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=$USERNAME" \
    --data-urlencode "password=$PASSWORD" \
    --data-urlencode "_csrf=$csrf_token" \
    -D "$HEADER_FILE" -o "$BODY_FILE"

location="$(extract_header "$HEADER_FILE" "location")"
cookie_session_id="$(extract_jsessionid "$HEADER_FILE")"
header_session_id="$(extract_header "$HEADER_FILE" "x-auth-token")"

# 检查是否重定向到密码修改页面
if [[ "$location" == *"/password/change"* ]]; then
    echo "🔄 Redirected to password change page"

    extra_auth_args=()
    if [ -n "$header_session_id" ]; then
        extra_auth_args=(-H "X-Auth-Token: $header_session_id")
    fi

    change_password_page="$(curl_local -sS \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -H "Accept: text/html" \
        ${extra_auth_args[@]+"${extra_auth_args[@]}"} \
        "${BASE_URL}/password/change")"

    new_csrf_token="$(printf '%s' "$change_password_page" | grep -o 'name="_csrf"[^>]*value="[^"]*"' | sed 's/.*value="\([^"]*\)".*/\1/' | head -n 1 || true)"
    state_token="$(printf '%s' "$change_password_page" | grep -o 'name="state"[^>]*value="[^"]*"' | sed 's/.*value="\([^"]*\)".*/\1/' | head -n 1 || true)"

    echo "🔐 New CSRF Token: $new_csrf_token"
    echo "🔐 State Token: $state_token"

    curl_local -sS -X POST "${BASE_URL}/password/change" \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        ${extra_auth_args[@]+"${extra_auth_args[@]}"} \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "_csrf=$new_csrf_token" \
        --data-urlencode "state=$state_token" \
        --data-urlencode "currentPassword=$PASSWORD" \
        --data-urlencode "newPassword=$NEW_PASSWORD" \
        --data-urlencode "confirmPassword=$NEW_PASSWORD" \
        -D "$HEADER_FILE" -o "$BODY_FILE"

    change_loc="$(extract_header "$HEADER_FILE" "location")"
    if [[ "$change_loc" == *"error"* ]] || grep -qi "error" "$BODY_FILE"; then
        echo "❌ Password change failed!" >&2
        cat "$HEADER_FILE" >&2
        exit 1
    fi

    echo "✅ Password changed successfully"
    echo "🔄 Logging in with new password..."

    login_page="$(curl_local -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" -H "Accept: text/html" "${BASE_URL}/login")"
    csrf_token="$(printf '%s' "$login_page" | grep -o 'name="_csrf"[^>]*value="[^"]*"' | sed 's/.*value="\([^"]*\)".*/\1/' | head -n 1 || true)"

    curl_local -sS -X POST "${BASE_URL}/login" \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -H "Accept: text/html,application/xhtml+xml" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "username=$USERNAME" \
        --data-urlencode "password=$NEW_PASSWORD" \
        --data-urlencode "_csrf=$csrf_token" \
        -D "$HEADER_FILE" -o "$BODY_FILE"

    location="$(extract_header "$HEADER_FILE" "location")"
    cookie_session_id="$(extract_jsessionid "$HEADER_FILE")"
    header_session_id="$(extract_header "$HEADER_FILE" "x-auth-token")"
fi

session_id="${header_session_id:-$cookie_session_id}"
extra_auth_args=()
if [ -n "$header_session_id" ]; then
    extra_auth_args=(-H "X-Auth-Token: $header_session_id")
fi

echo "🔄 Redirect Location: $location"
echo "🎫 Session ID: $session_id (${header_session_id:+header}${cookie_session_id:+cookie})"

# 验证登录是否成功
if [[ "$location" == *"/error"* ]] || [[ "$location" == *"/login?error"* ]]; then
    echo "❌ Login failed! Redirected to: $location" >&2
    exit 1
elif [ -z "$location" ]; then
    echo "❌ Error: No redirect location found after login" >&2
    cat "$HEADER_FILE" >&2
    exit 1
else
    echo "✅ Login successful! Redirected to: $location"
fi

printf 'export SESSION_ID=%q\n' "$session_id" > "$OUTPUT_DIR/session.env"
chmod 600 "$OUTPUT_DIR/session.env"

# 设置重定向 URI 并编码
redirect_uri="http://127.0.0.1:3000/auth/callback"
encoded_redirect_uri="$(urlencode "$redirect_uri")"
echo "🌐 Redirect URI: $redirect_uri"

# 获取授权页面或授权码重定向
curl_local -sS \
    ${extra_auth_args[@]+"${extra_auth_args[@]}"} \
    -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    --max-redirs 0 \
    "${BASE_URL}/oauth2/authorize?client_id=${CLIENT_ID}&response_type=code&scope=openid%20profile&redirect_uri=${encoded_redirect_uri}&code_challenge=${code_challenge}&code_challenge_method=S256" \
    -D "$HEADER_FILE" -o "$BODY_FILE"

# 检查是否需要用户同意
if grep -q "Consent required" "$BODY_FILE"; then
    echo "🔑 Consent required"
    state="$(sed -n 's/.*name="state"[^>]*value="\([^"]*\)".*/\1/p' "$BODY_FILE" | head -n 1 || true)"

    if [ -z "$state" ]; then
        echo "❌ Error: Could not extract state from consent page" >&2
        head -n 30 "$BODY_FILE" >&2
        exit 1
    fi

    echo "🔐 State: $state"

    curl_local -sS \
        ${extra_auth_args[@]+"${extra_auth_args[@]}"} \
        -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "${BASE_URL}/oauth2/authorize" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "client_id=${CLIENT_ID}" \
        --data-urlencode "state=$state" \
        --data-urlencode "scope=openid" \
        --data-urlencode "scope=profile" \
        --data-urlencode "submit=Submit Consent" \
        -D "$HEADER_FILE" -o "$BODY_FILE"
fi

# 从重定向 URL 中提取授权码
auth_location="$(extract_header "$HEADER_FILE" "location")"
auth_code="$(printf '%s' "$auth_location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' | head -n 1 || true)"

if [ -z "$auth_code" ]; then
    echo "❌ Authorization failed! Location: ${auth_location:-<empty>}" >&2
    cat "$HEADER_FILE" >&2
    exit 1
fi

echo "✅ Authorization successful!"
echo "🎫 Authorization Code: $auth_code"

echo "⏳ Waiting for authorization code to be processed..."
sleep 0.1

printf 'export AUTH_CODE=%q\n' "$auth_code" > "$OUTPUT_DIR/auth.env"
chmod 600 "$OUTPUT_DIR/auth.env"

echo ""
echo "🔍 Debug Information:"
echo "Authorization Code: $auth_code"
echo "Code Verifier: $code_verifier"
echo "Redirect URI: $redirect_uri"
echo "Basic Auth: [HIDDEN]"

# 获取访问令牌（响应头与 JSON 响应体分离）
echo ""
echo "🔄 Requesting access token..."
http_code="$(curl_local -sS -X POST "${BASE_URL}/oauth2/token" \
    ${extra_auth_args[@]+"${extra_auth_args[@]}"} \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Authorization: Basic $CLIENT_CREDENTIALS_B64" \
    -H "Accept: application/json" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$auth_code" \
    --data-urlencode "redirect_uri=$redirect_uri" \
    --data-urlencode "code_verifier=$code_verifier" \
    --data-urlencode "scope=openid profile" \
    -D "$HEADER_FILE" -o "$BODY_FILE" -w '%{http_code}')"

if ! jq -e . "$BODY_FILE" >/dev/null 2>&1; then
    echo "❌ Token endpoint returned non-JSON response (HTTP $http_code)" >&2
    head -n 20 "$BODY_FILE" >&2
    exit 1
fi

if jq -e 'has("error")' "$BODY_FILE" >/dev/null 2>&1; then
    echo "❌ Token request failed (HTTP $http_code)!" >&2
    echo "Error: $(jq -r '.error' "$BODY_FILE")" >&2
    echo "Error description: $(jq -r '.error_description // .message // ""' "$BODY_FILE")" >&2
    exit 1
fi

access_token="$(jq -r '.access_token // empty' "$BODY_FILE")"
refresh_token="$(jq -r '.refresh_token // empty' "$BODY_FILE")"
id_token="$(jq -r '.id_token // empty' "$BODY_FILE")"

if [ -z "$access_token" ]; then
    echo "❌ Failed to extract access_token (HTTP $http_code)!" >&2
    jq '.' "$BODY_FILE" >&2
    exit 1
fi

echo "✅ Token request successful!"
echo "🔑 Access Token: ${access_token:0:50}..."
echo "🔄 Refresh Token: ${refresh_token:0:50}..."
echo "🎫 ID Token: ${id_token:0:50}..."

write_tokens_env "$access_token" "$refresh_token" "$id_token"

# 显示令牌信息（解码 JWT）
echo ""
echo "📝 Access Token Claims:"
token_body="$(printf '%s' "$access_token" | cut -d'.' -f2)"
decode_jwt "$token_body" | jq '.' || echo "❌ Failed to decode access token"

echo ""
echo "📝 ID Token Claims:"
if [ -n "$id_token" ]; then
    token_body="$(printf '%s' "$id_token" | cut -d'.' -f2)"
    decode_jwt "$token_body" | jq '.' || echo "❌ Failed to decode ID token"
else
    echo "ℹ️  No ID token returned"
fi

# ============================================================================
# 🔄 刷新令牌测试 (可选)
# ============================================================================

if [[ "$TEST_REFRESH_TOKEN" == "true" ]]; then
    echo ""
    echo "🔄 Testing refresh token..."

    if [ -z "$refresh_token" ]; then
        echo "❌ No refresh token available for testing" >&2
        exit 1
    fi

    echo "Using refresh token: ${refresh_token:0:50}..."

    refresh_http_code="$(curl_local -sS -X POST "${BASE_URL}/oauth2/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Authorization: Basic $CLIENT_CREDENTIALS_B64" \
        -H "Accept: application/json" \
        --data-urlencode "grant_type=refresh_token" \
        --data-urlencode "refresh_token=$refresh_token" \
        --data-urlencode "scope=openid profile" \
        -D "$HEADER_FILE" -o "$BODY_FILE" -w '%{http_code}')"

    if ! jq -e . "$BODY_FILE" >/dev/null 2>&1; then
        echo "❌ Refresh token endpoint returned non-JSON response (HTTP $refresh_http_code)" >&2
        head -n 20 "$BODY_FILE" >&2
        exit 1
    fi

    if jq -e 'has("error")' "$BODY_FILE" >/dev/null 2>&1; then
        echo "❌ Refresh token failed (HTTP $refresh_http_code)!" >&2
        echo "Error: $(jq -r '.error' "$BODY_FILE")" >&2
        echo "Error description: $(jq -r '.error_description // .message // ""' "$BODY_FILE")" >&2
        exit 1
    fi

    new_access_token="$(jq -r '.access_token // empty' "$BODY_FILE")"
    new_refresh_token="$(jq -r '.refresh_token // empty' "$BODY_FILE")"

    if [ -z "$new_access_token" ]; then
        echo "❌ Failed to extract new access_token from refresh response" >&2
        exit 1
    fi

    echo "✅ Refresh token successful!"
    echo "🔑 New Access Token: ${new_access_token:0:50}..."
    if [ -n "$new_refresh_token" ]; then
        echo "🔄 New Refresh Token: ${new_refresh_token:0:50}..."
    fi

    write_tokens_env "$new_access_token" "${new_refresh_token:-$refresh_token}" "$id_token"

    echo ""
    echo "📝 Refreshed Access Token Claims:"
    token_body="$(printf '%s' "$new_access_token" | cut -d'.' -f2)"
    decode_jwt "$token_body" | jq '.' || echo "❌ Failed to decode refreshed access token"
else
    echo ""
    echo "⏭️  Refresh token testing skipped (TEST_REFRESH_TOKEN=false)"
fi

echo ""
echo "🎉 OAuth2 test completed!"

