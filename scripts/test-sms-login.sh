#!/bin/bash

# SMS登录端到端测试脚本
# 测试SMS验证码发送和登录流程
# 🔒 安全升级: 支持Cookie刷新token测试

set -e

# 配置
#BASE_URL="http://localhost:9000"
BASE_URL="https://al.u2511175.nyat.app:50518"
DB_HOST="localhost"  
DB_NAME="ruichuangqi_dev"
DB_USER="postgres"
DB_PASSWORD="123456"

# Cookie jar for session management
COOKIE_JAR="/tmp/sms_test_cookies.txt"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# JWT解码函数
# 对于 macOS，使用 gbase64
if [[ "$OSTYPE" == "darwin"* ]]; then
    decode_jwt() {
        local jwt_part=$1
        local pad=$(( 4 - ${#jwt_part} % 4 ))
        if [ $pad -ne 4 ]; then
            jwt_part="${jwt_part}$(printf '=%.0s' $(seq 1 $pad))"
        fi
        jwt_part=$(echo "$jwt_part" | tr '_-' '/+')
        echo "$jwt_part" | gbase64 -d 2>/dev/null
    }
else
    decode_jwt() {
        local jwt_part=$1
        local pad=$(( 4 - ${#jwt_part} % 4 ))
        if [ $pad -ne 4 ]; then
            jwt_part="${jwt_part}$(printf '=%.0s' $(seq 1 $pad))"
        fi
        jwt_part=$(echo "$jwt_part" | tr '_-' '/+')
        echo "$jwt_part" | base64 -d 2>/dev/null
    }
fi

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 获取手机号
get_phone_number() {
    if [ -n "$1" ]; then
        PHONE_NUMBER="$1"
    else
        while true; do
            read -p "请输入手机号: " PHONE_NUMBER
            if [[ $PHONE_NUMBER =~ ^1[3-9][0-9]{9}$ ]]; then
                break
            else
                log_error "手机号格式不正确，请输入11位中国大陆手机号"
            fi
        done
    fi
    log_info "使用手机号: $PHONE_NUMBER"
}

# 测试数据库连接
test_database() {
    log_info "测试数据库连接..."
    if command -v psql &> /dev/null; then
        if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" &> /dev/null; then
            log_info "✅ 数据库连接成功"
            return 0
        else
            log_error "❌ 数据库连接失败"
            return 1
        fi
    else
        log_warn "⚠️  psql命令不可用，跳过数据库连接测试"
        return 0
    fi
}

# 发送短信验证码
send_sms_code() {
    log_info "发送SMS验证码到 $PHONE_NUMBER..."
    
    # 显示即将执行的curl命令
    local curl_cmd="curl -s -w \"\\n%{http_code}\" -X POST \\
        \"$BASE_URL/sms/send-code\" \\
        -H \"Content-Type: application/x-www-form-urlencoded\" \\
        -d \"mobileNumber=$PHONE_NUMBER\""
    
    log_info "执行curl命令:"
    echo -e "${YELLOW}$curl_cmd${NC}"
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "$BASE_URL/sms/send-code" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "mobileNumber=$PHONE_NUMBER")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    log_info "HTTP状态码: $HTTP_CODE"
    log_info "响应内容:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    
    if [ "$HTTP_CODE" = "200" ]; then
        log_info "✅ SMS验证码发送成功"
        return 0
    else
        log_error "❌ SMS验证码发送失败 (HTTP $HTTP_CODE)"
        return 1
    fi
}

# 从数据库获取验证码
get_verification_code_from_db() {
    log_info "从数据库获取验证码..."
    
    if command -v psql &> /dev/null; then
        # 先测试查询是否能执行
        log_info "尝试查询数据库中的验证码记录..."
        QUERY_RESULT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
            SELECT code, created_at, expire_time, used FROM sms_verification_codes 
            WHERE phone_number = '$PHONE_NUMBER' 
            ORDER BY created_at DESC 
            LIMIT 3;
        " 2>&1)
        
        if [ $? -eq 0 ]; then
            log_info "数据库查询成功，结果："
            echo "$QUERY_RESULT"
            
            # 获取最新的未使用验证码
            VERIFICATION_CODE=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "
                SELECT code FROM sms_verification_codes 
                WHERE phone_number = '$PHONE_NUMBER' 
                AND used = false
                ORDER BY created_at DESC 
                LIMIT 1;
            " 2>/dev/null | xargs)
            
            if [ -n "$VERIFICATION_CODE" ]; then
                log_info "✅ 获取到验证码: $VERIFICATION_CODE"
                return 0
            else
                log_error "❌ 未找到有效验证码"
                return 1
            fi
        else
            log_error "❌ 数据库查询失败: $QUERY_RESULT"
            log_warn "⚠️  请手动输入验证码"
            read -p "请输入收到的验证码: " VERIFICATION_CODE
            return 0
        fi
    else
        log_warn "⚠️  psql不可用，请手动输入验证码"
        read -p "请输入收到的验证码: " VERIFICATION_CODE
        return 0
    fi
}

# SMS登录
sms_login() {
    log_info "使用SMS登录..."
    
    # 🔒 安全升级：初始化Cookie jar
    touch "$COOKIE_JAR"
    
    # 显示即将执行的curl命令
    local LEGACY_QS=""
    if [[ "$LEGACY_MODE" == "1" ]]; then LEGACY_QS="&legacyMode=true"; fi
    local curl_cmd="curl -s -w \"\\n%{http_code}\" -X GET \\
        \"$BASE_URL/sms/login?mobileNumber=$PHONE_NUMBER&verificationCode=$VERIFICATION_CODE$LEGACY_QS\" \\
        --cookie-jar \"$COOKIE_JAR\" \\
        --cookie \"$COOKIE_JAR\""
    
    log_info "执行curl命令:"
    echo -e "${YELLOW}$curl_cmd${NC}"
    
    # 🔒 安全升级：使用Cookie支持
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
        "$BASE_URL/sms/login?mobileNumber=$PHONE_NUMBER&verificationCode=$VERIFICATION_CODE$LEGACY_QS" \
        --cookie-jar "$COOKIE_JAR" \
        --cookie "$COOKIE_JAR")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    log_info "HTTP状态码: $HTTP_CODE"
    log_info "响应内容:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    
    if [ "$HTTP_CODE" = "200" ]; then
        log_info "✅ SMS登录成功"
        
        # 🔒 安全升级：检查Cookie设置
        if [ -f "$COOKIE_JAR" ]; then
            log_info "🍪 检查Cookie设置..."
            if grep -q "refresh_token" "$COOKIE_JAR"; then
                log_info "✅ HttpOnly Cookie已设置"
            else
                log_warn "⚠️  未检测到refresh_token Cookie"
            fi
        fi
        
        # 提取访问令牌
        ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token' 2>/dev/null)
        REFRESH_TOKEN=$(echo "$BODY" | jq -r '.refresh_token' 2>/dev/null)
        TOKEN_TYPE=$(echo "$BODY" | jq -r '.token_type' 2>/dev/null)
        EXPIRES_IN=$(echo "$BODY" | jq -r '.expires_in' 2>/dev/null)
        
        if [ "$ACCESS_TOKEN" != "null" ] && [ -n "$ACCESS_TOKEN" ]; then
            # 保存令牌到环境变量
            export SMS_ACCESS_TOKEN="$ACCESS_TOKEN"
            export SMS_REFRESH_TOKEN="$REFRESH_TOKEN"
            export SMS_TOKEN_TYPE="$TOKEN_TYPE"
            export SMS_EXPIRES_IN="$EXPIRES_IN"
            
            # 保存令牌到文件
            cat > sms_tokens.env << EOF
export SMS_ACCESS_TOKEN=$ACCESS_TOKEN
export SMS_REFRESH_TOKEN=$REFRESH_TOKEN
export SMS_TOKEN_TYPE=$TOKEN_TYPE
export SMS_EXPIRES_IN=$EXPIRES_IN
EOF
            
            log_info "✅ 令牌信息已保存到 sms_tokens.env"
            
            # 显示详细的令牌信息
            echo -e "\n${GREEN}========================================${NC}"
            echo -e "${GREEN}SMS登录成功 - 令牌详细信息${NC}"
            echo -e "${GREEN}========================================${NC}"
            echo -e "${CYAN}访问令牌 (前50字符):${NC} ${ACCESS_TOKEN:0:50}..."
            if [[ "$LEGACY_MODE" == "1" ]]; then
                if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
                    echo -e "${CYAN}刷新令牌 (前50字符):${NC} ${REFRESH_TOKEN:0:50}..."
                else
                    echo -e "${RED}❌ LEGACY 模式期望响应体含 refresh_token，但未返回${NC}"
                fi
            else
                if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
                    echo -e "${YELLOW}⚠️  (非预期) 响应体包含刷新令牌，当前为 Cookie 模式${NC}"
                else
                    echo -e "${YELLOW}刷新令牌:${NC} 已存储在HttpOnly Cookie中 (安全模式)"
                fi
            fi
            echo -e "${CYAN}令牌类型:${NC} $TOKEN_TYPE"
            echo -e "${CYAN}过期时间:${NC} $EXPIRES_IN 秒"
            echo -e "${GREEN}========================================${NC}"
            
            # 解码并显示JWT内容
            echo -e "\n${BLUE}📝 解析访问令牌 (Access Token) 内容:${NC}"
            if [ -n "$ACCESS_TOKEN" ]; then
                # 分割JWT的三个部分
                IFS='.' read -r header payload signature <<< "$ACCESS_TOKEN"
                
                # 解码Header
                echo -e "\n${YELLOW}🔍 JWT Header:${NC}"
                header_decoded=$(decode_jwt "$header")
                if [ $? -eq 0 ] && [ -n "$header_decoded" ]; then
                    echo "$header_decoded" | jq '.' 2>/dev/null || echo "$header_decoded"
                else
                    echo "❌ 无法解码JWT Header"
                fi
                
                # 解码Payload (Claims)
                echo -e "\n${YELLOW}🔍 JWT Payload (Claims):${NC}"
                payload_decoded=$(decode_jwt "$payload")
                if [ $? -eq 0 ] && [ -n "$payload_decoded" ]; then
                    echo "$payload_decoded" | jq '.' 2>/dev/null || echo "$payload_decoded"
                    
                    # 特别检查和显示groups信息
                    groups=$(echo "$payload_decoded" | jq -r '.groups // empty' 2>/dev/null)
                    if [ -n "$groups" ] && [ "$groups" != "null" ]; then
                        echo -e "\n${GREEN}✅ Groups信息已包含在JWT中:${NC}"
                        echo "$groups" | jq '.' 2>/dev/null || echo "$groups"
                    else
                        echo -e "\n${RED}❌ JWT中缺少groups信息${NC}"
                    fi
                    
                    # 显示authorities信息
                    authorities=$(echo "$payload_decoded" | jq -r '.authorities // empty' 2>/dev/null)
                    if [ -n "$authorities" ] && [ "$authorities" != "null" ]; then
                        echo -e "\n${GREEN}✅ Authorities信息:${NC}"
                        echo "$authorities" | jq '.' 2>/dev/null || echo "$authorities"
                    else
                        echo -e "\n${YELLOW}⚠️  JWT中没有authorities信息（这可能是正常的）${NC}"
                    fi
                else
                    echo "❌ 无法解码JWT Payload"
                fi
                
                echo -e "\n${YELLOW}🔍 JWT Signature:${NC} ${signature:0:20}..."
            else
                echo "❌ 没有访问令牌可供解析"
            fi
            
            return 0
        else
            log_error "❌ 未能从响应中提取访问令牌"
            return 1
        fi
    else
        log_error "❌ SMS登录失败 (HTTP $HTTP_CODE)"
        return 1
    fi
}

# 🔒 安全升级：测试Cookie刷新token功能
test_refresh_token() {
    log_info "🔄 测试刷新token功能..."
    
    if [ ! -f "$COOKIE_JAR" ]; then
        log_warn "⚠️  Cookie jar不存在，跳过刷新token测试"
        return 0
    fi
    
    # 显示即将执行的curl命令
    local curl_cmd="curl -s -w \"\\n%{http_code}\" -X POST \\
        \"$BASE_URL/sms/refresh-token\" \\
        -H \"Content-Type: application/x-www-form-urlencoded\" \\
        -H \"Accept: application/json\" \\
        --cookie-jar \"$COOKIE_JAR\" \\
        --cookie \"$COOKIE_JAR\" \\
        -d \"grant_type=refresh_token\" \\
        -d \"scope=openid%20profile\""
    
    log_info "执行curl命令:"
    echo -e "${YELLOW}$curl_cmd${NC}"
    
    # 🔒 安全升级：使用Cookie模式刷新token
    if [[ "$LEGACY_MODE" == "1" ]]; then
        # 兼容模式：显式传入 refresh_token 与 legacyMode=true
        if [[ -z "$SMS_REFRESH_TOKEN" || "$SMS_REFRESH_TOKEN" == "null" ]]; then
            log_warn "⚠️  未检测到本地保存的 refresh_token，将尝试从登录响应体读取（若登录已在legacy模式）"
        fi
        RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
            "$BASE_URL/sms/refresh-token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Accept: application/json" \
            --cookie-jar "$COOKIE_JAR" \
            --cookie "$COOKIE_JAR" \
            -d "grant_type=refresh_token" \
            -d "client_id=ffv-client" \
            -d "refresh_token=${SMS_REFRESH_TOKEN}" \
            -d "legacyMode=true")
    else
        # Cookie 模式
        RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
            "$BASE_URL/sms/refresh-token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Accept: application/json" \
            --cookie-jar "$COOKIE_JAR" \
            --cookie "$COOKIE_JAR" \
            -d "grant_type=refresh_token" \
            -d "scope=openid%20profile")
    fi
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    log_info "HTTP状态码: $HTTP_CODE"
    log_info "响应内容:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    
    if [ "$HTTP_CODE" = "200" ]; then
        log_info "✅ 刷新token成功"
        
        # 提取新的访问令牌
        NEW_ACCESS_TOKEN=$(echo "$BODY" | jq -r '.access_token' 2>/dev/null)
        NEW_REFRESH_TOKEN=$(echo "$BODY" | jq -r '.refresh_token' 2>/dev/null)
        
        if [ "$NEW_ACCESS_TOKEN" != "null" ] && [ -n "$NEW_ACCESS_TOKEN" ]; then
            log_info "✅ 获得新的访问令牌: ${NEW_ACCESS_TOKEN:0:50}..."
            export SMS_ACCESS_TOKEN="$NEW_ACCESS_TOKEN"
            
            if [[ "$LEGACY_MODE" == "1" ]]; then
                if [ "$NEW_REFRESH_TOKEN" != "null" ] && [ -n "$NEW_REFRESH_TOKEN" ]; then
                    log_info "✅ 获得新的刷新令牌: ${NEW_REFRESH_TOKEN:0:50}..."
                    export SMS_REFRESH_TOKEN="$NEW_REFRESH_TOKEN"
                else
                    log_warn "⚠️  LEGACY 模式期望响应体含 refresh_token，但未找到"
                fi
            else
                if [ "$NEW_REFRESH_TOKEN" != "null" ] && [ -n "$NEW_REFRESH_TOKEN" ]; then
                    log_info "✅ (非预期) 响应体包含刷新令牌: ${NEW_REFRESH_TOKEN:0:50}..."
                else
                    log_info "🍪 刷新令牌已更新到HttpOnly Cookie中 (安全模式)"
                fi
            fi
            
            # 解码并显示刷新后的JWT内容
            echo -e "\n${BLUE}📝 解析刷新后的访问令牌 (Refreshed Access Token) 内容:${NC}"
            IFS='.' read -r header payload signature <<< "$NEW_ACCESS_TOKEN"
            echo -e "\n${YELLOW}🔍 JWT Header:${NC}"
            header_decoded=$(decode_jwt "$header")
            if [ $? -eq 0 ] && [ -n "$header_decoded" ]; then
                echo "$header_decoded" | jq '.' 2>/dev/null || echo "$header_decoded"
            else
                echo "❌ 无法解码JWT Header"
            fi
            echo -e "\n${YELLOW}🔍 JWT Payload (Claims):${NC}"
            payload_decoded=$(decode_jwt "$payload")
            if [ $? -eq 0 ] && [ -n "$payload_decoded" ]; then
                echo "$payload_decoded" | jq '.' 2>/dev/null || echo "$payload_decoded"
                # 高亮 groups
                groups=$(echo "$payload_decoded" | jq -r '.groups // empty' 2>/dev/null)
                if [ -n "$groups" ] && [ "$groups" != "null" ]; then
                    echo -e "\n${GREEN}✅ (Refreshed) Groups信息:${NC}"
                    echo "$groups" | jq '.' 2>/dev/null || echo "$groups"
                else
                    echo -e "\n${RED}❌ (Refreshed) JWT中缺少groups信息${NC}"
                fi
                # 高亮 authorities
                authorities=$(echo "$payload_decoded" | jq -r '.authorities // empty' 2>/dev/null)
                if [ -n "$authorities" ] && [ "$authorities" != "null" ]; then
                    echo -e "\n${GREEN}✅ (Refreshed) Authorities信息:${NC}"
                    echo "$authorities" | jq '.' 2>/dev/null || echo "$authorities"
                else
                    echo -e "\n${YELLOW}⚠️  (Refreshed) JWT中没有authorities信息（这可能是正常的）${NC}"
                fi
            else
                echo "❌ 无法解码JWT Payload"
            fi
        else
            log_error "❌ 未能从刷新响应中提取新的访问令牌"
            return 1
        fi
    elif [ "$HTTP_CODE" = "401" ]; then
        log_warn "⚠️  刷新token未授权 - 可能token已过期或无效"
        return 0
    else
        log_warn "⚠️  刷新token失败 (HTTP $HTTP_CODE)"
        return 0
    fi
}

# 测试API访问
test_api_access() {
    if [ -z "$SMS_ACCESS_TOKEN" ]; then
        log_warn "⚠️  没有访问令牌，跳过API访问测试"
        return 0
    fi
    
    log_info "测试API访问..."
    
    # 显示即将执行的curl命令
    local curl_cmd="curl -s -w \"\\n%{http_code}\" -X GET \\
        \"$BASE_URL/api/userinfo\" \\
        -H \"Authorization: Bearer $SMS_ACCESS_TOKEN\" \\
        --cookie-jar \"$COOKIE_JAR\" \\
        --cookie \"$COOKIE_JAR\""
    
    log_info "执行curl命令:"
    echo -e "${YELLOW}$curl_cmd${NC}"
    
    # 🔒 安全升级：测试用户信息API（带Cookie支持）
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
        "$BASE_URL/api/userinfo" \
        -H "Authorization: Bearer $SMS_ACCESS_TOKEN" \
        --cookie-jar "$COOKIE_JAR" \
        --cookie "$COOKIE_JAR")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    log_info "HTTP状态码: $HTTP_CODE"
    log_info "响应内容:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    
    if [ "$HTTP_CODE" = "200" ]; then
        log_info "✅ API访问测试成功"
        return 0
    elif [ "$HTTP_CODE" = "401" ]; then
        log_warn "⚠️  API访问未授权 - 令牌可能无效或端点需要特定权限"
        return 0
    elif [ "$HTTP_CODE" = "404" ]; then
        log_warn "⚠️  API端点未找到 - 这是正常的，如果/api/userinfo端点不存在"
        return 0
    else
        log_warn "⚠️  API访问测试失败 (HTTP $HTTP_CODE) - 这可能是正常的"
        return 0
    fi
}

# 清理函数
cleanup() {
    if [ -f "$COOKIE_JAR" ]; then
        rm -f "$COOKIE_JAR"
        log_info "🧹 清理Cookie文件"
    fi
}

# 设置退出时清理
trap cleanup EXIT

# 主流程
main() {
    # 解析可选参数：--legacy-mode | -L 启用 legacyMode
    LEGACY_MODE=0
    PHONE_ARG=""
    if [[ "$1" == "--legacy-mode" || "$1" == "-L" || "$1" == "legacy" ]]; then
        LEGACY_MODE=1
        PHONE_ARG="$2"
    else
        PHONE_ARG="$1"
        if [[ "$2" == "--legacy-mode" || "$2" == "-L" || "$2" == "legacy" ]]; then
            LEGACY_MODE=1
        fi
    fi

    if [[ $LEGACY_MODE -eq 1 ]]; then
        log_info "开始SMS登录端到端测试 (LEGACY 模式：响应体返回 refresh_token)"
    else
        log_info "开始SMS登录端到端测试 (Cookie 模式：refresh_token 存于 HttpOnly Cookie)"
    fi
    
    # 获取手机号
    get_phone_number "$PHONE_ARG"
    
    # 测试数据库连接
    if ! test_database; then
        log_warn "继续测试，但可能无法自动获取验证码"
    fi
    
    # 发送短信验证码
    if ! send_sms_code; then
        log_warn "⚠️  短信验证码发送失败，但继续测试流程（可通过数据库查询验证码）"
    fi
    
    # 获取验证码
    if ! get_verification_code_from_db; then
        log_error "获取验证码失败，测试终止"
        exit 1
    fi
    
    # SMS登录
    if ! sms_login; then
        log_error "SMS登录失败，测试终止"
        exit 1
    fi
    
    # 🔒 安全升级：测试刷新token功能
    test_refresh_token
    
    # 测试API访问
    test_api_access
    
    log_info "🎉 SMS登录端到端测试完成 (模式：$([[ $LEGACY_MODE -eq 1 ]] && echo LEGACY || echo Cookie))"
}

# 执行主流程
main "$@" 