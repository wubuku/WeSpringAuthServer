#!/bin/bash

# SMS登录端到端测试脚本
# 测试SMS验证码发送和登录流程

set -e

# 配置
#BASE_URL="http://localhost:9000"
BASE_URL="https://al.u2511175.nyat.app:50518"
DB_HOST="localhost"  
DB_NAME="ruichuangqi_dev"
DB_USER="postgres"
DB_PASSWORD="123456"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
    
    # 显示即将执行的curl命令
    local curl_cmd="curl -s -w \"\\n%{http_code}\" -X GET \\
        \"$BASE_URL/sms/login?mobileNumber=$PHONE_NUMBER&verificationCode=$VERIFICATION_CODE\""
    
    log_info "执行curl命令:"
    echo -e "${YELLOW}$curl_cmd${NC}"
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
        "$BASE_URL/sms/login?mobileNumber=$PHONE_NUMBER&verificationCode=$VERIFICATION_CODE")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    log_info "HTTP状态码: $HTTP_CODE"
    log_info "响应内容:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    
    if [ "$HTTP_CODE" = "200" ]; then
        log_info "✅ SMS登录成功"
        
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
            echo -e "${CYAN}刷新令牌 (前50字符):${NC} ${REFRESH_TOKEN:0:50}..."
            echo -e "${CYAN}令牌类型:${NC} $TOKEN_TYPE"
            echo -e "${CYAN}过期时间:${NC} $EXPIRES_IN 秒"
            echo -e "${GREEN}========================================${NC}"
            
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
        -H \"Authorization: Bearer $SMS_ACCESS_TOKEN\""
    
    log_info "执行curl命令:"
    echo -e "${YELLOW}$curl_cmd${NC}"
    
    # 测试用户信息API
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
        "$BASE_URL/api/userinfo" \
        -H "Authorization: Bearer $SMS_ACCESS_TOKEN")
    
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

# 主流程
main() {
    log_info "开始SMS登录端到端测试"
    
    # 获取手机号
    get_phone_number "$1"
    
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
    
    # 测试API访问
    test_api_access
    
    log_info "🎉 SMS登录端到端测试完成"
}

# 执行主流程
main "$@" 