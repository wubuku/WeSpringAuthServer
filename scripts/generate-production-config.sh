#!/bin/bash

# =============================================================================
# WeSpring Auth Server - 生产环境配置生成工具
# =============================================================================
# 这是一个傻瓜化的部署配置工具，引导用户完成生产系统的所有配置项目
# 生成生产环境可用的配置环境变量文件和必要的密钥文件
# =============================================================================

# set -e  # 暂时注释掉，避免静默退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置文件路径
ENV_FILE=".env.prod"
KEYSTORE_DIR="./production-keys"
KEYSTORE_FILE="$KEYSTORE_DIR/jwt-signing-keys.jks"

# 打印带颜色的消息
print_header() {
    echo ""
    echo "=============================================================================="
    echo "$1"
    echo "=============================================================================="
    echo ""
}

print_info() {
    echo "ℹ️  $1"
}

print_success() {
    echo "✅ $1"
}

print_warning() {
    echo "⚠️  $1"
}

print_error() {
    echo "❌ $1"
}


# 读取用户输入的函数
read_input() {
    local prompt="$1"
    local default="$2"
    local is_password="$3"
    local is_required="$4"
    local format_hint="$5"
    
    
    while true; do
        echo "" >&2  # 添加空行增加可读性
        
        if [ "$is_required" = "true" ]; then
            echo "🔴 [必需] $prompt" >&2
        else
            echo "🟡 [可选] $prompt" >&2
        fi
        
        if [ -n "$format_hint" ]; then
            echo "   格式: $format_hint" >&2
        fi
        
        if [ -n "$default" ]; then
            echo "   默认值: $default" >&2
        fi
        
        if [ "$is_password" = "true" ]; then
            echo -n "请输入: " >&2
            read -s value
            echo >&2  # 换行
        else
            echo -n "请输入: " >&2
            read value
        fi
        
        # 如果用户没有输入，使用默认值
        if [ -z "$value" ] && [ -n "$default" ]; then
            value="$default"
        fi
        
        # 检查必需字段
        if [ "$is_required" = "true" ] && [ -z "$value" ]; then
            echo "❌ 此字段为必需项，请输入有效值" >&2
            continue
        fi
        
        # 如果是可选字段且用户没有输入且没有默认值，使用占位符
        if [ "$is_required" = "false" ] && [ -z "$value" ] && [ -z "$default" ]; then
            value="xxx"
        fi
        
        REPLY="$value"
        break
    done
}

# 生成随机密码
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# 生成16进制盐值
generate_hex_salt() {
    openssl rand -hex 8
}

# 验证邮箱格式
validate_email() {
    local email="$1"
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# 验证URL格式
validate_url() {
    local url="$1"
    if [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
        return 0
    else
        return 1
    fi
}

# 生成JWT密钥库
generate_keystore() {
    local keystore_password="$1"
    local key_password="$2"
    local key_alias="$3"
    
    print_info "正在生成JWT签名密钥库..."
    
    # 创建密钥目录
    mkdir -p "$KEYSTORE_DIR"
    
    # 生成密钥对
    keytool -genkeypair \
        -alias "$key_alias" \
        -keyalg RSA \
        -keysize 2048 \
        -validity 3650 \
        -keystore "$KEYSTORE_FILE" \
        -storetype JKS \
        -storepass "$keystore_password" \
        -keypass "$key_password" \
        -dname "CN=WeSpring Auth Server,OU=Auth,O=WeSpring,L=City,ST=State,C=CN" \
        -noprompt
    
    print_success "JWT密钥库已生成: $KEYSTORE_FILE"
}

# 主函数
main() {
    print_header "WeSpring Auth Server 生产环境配置生成工具"
    
    echo "此工具将引导您完成生产环境的所有必要配置。"
    echo "对于不愿意录入的可选项，将使用 'xxx' 作为占位符。"
    echo "请确保在部署前替换所有 'xxx' 占位符！"
    echo ""
    
    read -p "按回车键开始配置..." dummy
    
    # 检查是否已存在配置文件
    if [ -f "$ENV_FILE" ]; then
        print_warning "发现已存在的配置文件: $ENV_FILE"
        read -p "是否覆盖? (y/N): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            print_info "已取消操作"
            exit 0
        fi
    fi
    
    # 开始生成配置文件
    cat > "$ENV_FILE" << 'EOF'
# =============================================================================
# WeSpring Auth Server - 生产环境变量配置
# =============================================================================
# 此文件由 generate-production-config.sh 自动生成
# 请检查所有 'xxx' 占位符并替换为实际值
# =============================================================================

EOF
    
    # =============================================================================
    # 数据库配置
    # =============================================================================
    print_header "数据库配置"
    
    read_input "数据库主机地址" "" false true "例: localhost, db.example.com"
    DB_HOST="$REPLY"
    read_input "数据库端口" "5432" false true "PostgreSQL默认端口: 5432"
    DB_PORT="$REPLY"
    read_input "数据库名称" "" false true "例: authserver_prod"
    DB_NAME="$REPLY"
    read_input "数据库用户名" "" false true "例: authserver_user"
    DB_USERNAME="$REPLY"
    read_input "数据库密码" "" true true "建议使用强密码"
    DB_PASSWORD="$REPLY"
    read_input "最大连接池大小" "20" false false "生产环境建议: 20-50"
    DB_MAX_POOL_SIZE="$REPLY"
    read_input "最小空闲连接数" "10" false false "建议为最大连接池的一半"
    DB_MIN_IDLE="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 数据库配置 [必需]
# =============================================================================
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USERNAME=$DB_USERNAME
DB_PASSWORD=$DB_PASSWORD
DB_MAX_POOL_SIZE=$DB_MAX_POOL_SIZE
DB_MIN_IDLE=$DB_MIN_IDLE

EOF
    
    # =============================================================================
    # 服务器配置
    # =============================================================================
    print_header "服务器配置"
    
    read_input "服务器端口" "9000" false false "默认: 9000"
    SERVER_PORT="$REPLY"
    read_input "授权服务器URL" "" false true "例: https://auth.yourdomain.com"
    AUTH_SERVER_ISSUER="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 服务器配置
# =============================================================================
SERVER_PORT=$SERVER_PORT
SPRING_PROFILES_ACTIVE=prod
AUTH_SERVER_ISSUER=$AUTH_SERVER_ISSUER

EOF
    
    # =============================================================================
    # OAuth2 Cookie安全配置
    # =============================================================================
    print_header "OAuth2 Cookie安全配置"
    
    print_info "Cookie配置用于跨域认证和安全性"
    read_input "Cookie域名" "" false true "例: .yourdomain.com (注意前面的点)"
    OAUTH2_COOKIE_DOMAIN="$REPLY"
    read_input "强制HTTPS Cookie" "true" false false "生产环境建议: true"
    OAUTH2_COOKIE_SECURE="$REPLY"
    read_input "Cookie SameSite策略" "Lax" false false "选项: Lax, Strict, None"
    OAUTH2_COOKIE_SAME_SITE="$REPLY"
    read_input "Cookie有效期(秒)" "2592000" false false "默认30天: 2592000"
    OAUTH2_COOKIE_MAX_AGE="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# OAuth2 Cookie 安全配置 [必需]
# =============================================================================
OAUTH2_COOKIE_DOMAIN=$OAUTH2_COOKIE_DOMAIN
OAUTH2_COOKIE_SECURE=$OAUTH2_COOKIE_SECURE
OAUTH2_COOKIE_SAME_SITE=$OAUTH2_COOKIE_SAME_SITE
OAUTH2_COOKIE_MAX_AGE=$OAUTH2_COOKIE_MAX_AGE

EOF
    
    # =============================================================================
    # CORS跨域配置
    # =============================================================================
    print_header "CORS跨域配置"
    
    print_info "配置允许访问授权服务器的前端应用地址"
    read_input "允许的源地址" "" false true "例: https://app.yourdomain.com,https://admin.yourdomain.com"
    CORS_ALLOWED_ORIGINS="$REPLY"
    read_input "允许的HTTP方法" "GET,POST,PUT,DELETE,OPTIONS" false false
    CORS_ALLOWED_METHODS="$REPLY"
    read_input "允许的请求头" "Authorization,Content-Type,Accept,X-Requested-With,Origin" false false
    CORS_ALLOWED_HEADERS="$REPLY"
    read_input "允许携带凭证" "true" false false
    CORS_ALLOW_CREDENTIALS="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# CORS 跨域配置 [必需]
# =============================================================================
CORS_ALLOWED_ORIGINS=$CORS_ALLOWED_ORIGINS
CORS_ALLOWED_METHODS=$CORS_ALLOWED_METHODS
CORS_ALLOWED_HEADERS=$CORS_ALLOWED_HEADERS
CORS_ALLOW_CREDENTIALS=$CORS_ALLOW_CREDENTIALS

EOF
    
    # =============================================================================
    # Web客户端配置
    # =============================================================================
    print_header "Web客户端配置"
    
    print_info "配置OAuth2客户端信息"
    read_input "Web客户端ID" "" false true "例: web-client,admin-client"
    WEB_CLIENT_IDS="$REPLY"
    read_input "Web客户端密钥" "" true true "与客户端ID对应的密钥，用逗号分隔"
    WEB_CLIENT_SECRETS="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# Web 客户端配置 [必需]
# =============================================================================
WEB_CLIENT_IDS=$WEB_CLIENT_IDS
WEB_CLIENT_SECRETS=$WEB_CLIENT_SECRETS

EOF
    
    # =============================================================================
    # JWT密钥配置
    # =============================================================================
    print_header "JWT密钥配置"
    
    print_info "JWT密钥用于签名和验证访问令牌"
    
    # 生成默认密码
    default_keystore_password=$(generate_password 16)
    default_key_password=$(generate_password 16)
    
    read_input "密钥库密码" "$default_keystore_password" true false "建议使用生成的随机密码"
    JWT_KEYSTORE_PASSWORD="$REPLY"
    read_input "密钥别名" "jwt-signing-key" false false
    JWT_KEY_ALIAS="$REPLY"
    read_input "私钥密码" "$default_key_password" true false "建议使用生成的随机密码"
    JWT_KEY_PASSWORD="$REPLY"
    read_input "密钥库路径" "/app/keys/jwt-signing-keys.jks" false false "容器内路径"
    JWT_KEYSTORE_PATH="$REPLY"
    
    # 生成密钥库
    generate_keystore "$JWT_KEYSTORE_PASSWORD" "$JWT_KEY_PASSWORD" "$JWT_KEY_ALIAS"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# JWT 密钥配置 [必需]
# =============================================================================
JWT_KEYSTORE_PATH=$JWT_KEYSTORE_PATH
JWT_KEYSTORE_PASSWORD=$JWT_KEYSTORE_PASSWORD
JWT_KEY_ALIAS=$JWT_KEY_ALIAS
JWT_KEY_PASSWORD=$JWT_KEY_PASSWORD

EOF
    
    # =============================================================================
    # 邮件服务配置
    # =============================================================================
    print_header "邮件服务配置"
    
    print_info "邮件服务用于发送密码重置邮件"
    read_input "SMTP服务器地址" "" false true "例: smtp.gmail.com, smtp.qq.com"
    MAIL_HOST="$REPLY"
    read_input "SMTP端口" "587" false false "常用端口: 587(STARTTLS), 465(SSL)"
    MAIL_PORT="$REPLY"
    read_input "邮箱用户名" "" false true "完整邮箱地址"
    MAIL_USERNAME="$REPLY"
    read_input "邮箱密码/应用密码" "" true true "Gmail等需要使用应用专用密码"
    MAIL_PASSWORD="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 邮件服务配置 [必需]
# =============================================================================
MAIL_HOST=$MAIL_HOST
MAIL_PORT=$MAIL_PORT
MAIL_USERNAME=$MAIL_USERNAME
MAIL_PASSWORD=$MAIL_PASSWORD

EOF
    
    # =============================================================================
    # 密码重置配置
    # =============================================================================
    print_header "密码重置配置"
    
    read_input "密码重置页面URL" "" false true "例: https://app.yourdomain.com/reset-password"
    PASSWORD_RESET_URL="$REPLY"
    read_input "密码重置令牌有效期(小时)" "24" false false
    PASSWORD_TOKEN_EXPIRE_HOURS="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 密码重置配置 [必需]
# =============================================================================
PASSWORD_RESET_URL=$PASSWORD_RESET_URL
PASSWORD_TOKEN_EXPIRE_HOURS=$PASSWORD_TOKEN_EXPIRE_HOURS

EOF
    
    # =============================================================================
    # 认证状态加密配置
    # =============================================================================
    print_header "认证状态加密配置"
    
    print_info "用于加密认证过程中的状态信息"
    default_auth_password=$(generate_password 32)
    default_auth_salt=$(generate_hex_salt)
    
    read_input "认证状态加密密码" "$default_auth_password" true false "建议使用生成的随机密码"
    AUTH_STATE_PASSWORD="$REPLY"
    read_input "认证状态加密盐值" "$default_auth_salt" false false "16位十六进制字符"
    AUTH_STATE_SALT="$REPLY"
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 认证状态加密配置 [必需]
# =============================================================================
AUTH_STATE_PASSWORD=$AUTH_STATE_PASSWORD
AUTH_STATE_SALT=$AUTH_STATE_SALT

EOF
    
    # =============================================================================
    # 微信登录配置 (可选)
    # =============================================================================
    print_header "微信登录配置 (可选)"
    
    print_info "如果不需要微信登录功能，可以跳过此部分"
    read -p "是否配置微信登录? (y/N): " setup_wechat
    
    if [[ "$setup_wechat" =~ ^[Yy]$ ]]; then
        read_input "微信小程序AppID" "" false false
        WECHAT_APP_ID="$REPLY"
        read_input "微信小程序AppSecret" "" true false
        WECHAT_APP_SECRET="$REPLY"
        read_input "微信消息验证Token" "" false false
        WECHAT_TOKEN="$REPLY"
        read_input "微信消息加解密Key" "" false false
        WECHAT_AES_KEY="$REPLY"
        read_input "微信授权回调地址" "" false false "例: https://auth.yourdomain.com/wechat/callback"
        WECHAT_REDIRECT_URI="$REPLY"
    else
        WECHAT_APP_ID="xxx"
        WECHAT_APP_SECRET="xxx"
        WECHAT_TOKEN="xxx"
        WECHAT_AES_KEY="xxx"
        WECHAT_REDIRECT_URI="xxx"
    fi
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 微信登录配置 [可选]
# =============================================================================
WECHAT_APP_ID=$WECHAT_APP_ID
WECHAT_APP_SECRET=$WECHAT_APP_SECRET
WECHAT_TOKEN=$WECHAT_TOKEN
WECHAT_AES_KEY=$WECHAT_AES_KEY
WECHAT_REDIRECT_URI=$WECHAT_REDIRECT_URI

EOF
    
    # =============================================================================
    # 短信服务配置 (可选)
    # =============================================================================
    print_header "短信服务配置 (可选)"
    
    print_info "支持阿里云和火山引擎短信服务"
    read -p "是否配置短信服务? (y/N): " setup_sms
    
    if [[ "$setup_sms" =~ ^[Yy]$ ]]; then
        echo "请选择短信服务提供商:"
        echo "1) 阿里云"
        echo "2) 火山引擎"
        echo "3) 模拟器(仅用于测试)"
        read -p "请选择 (1-3): " sms_choice
        
        case $sms_choice in
            1)
                SMS_PROVIDER="aliyun"
                read_input "阿里云AccessKeyId" "" false false
                ALIYUN_SMS_ACCESS_KEY_ID="$REPLY"
                read_input "阿里云AccessKeySecret" "" true false
                ALIYUN_SMS_ACCESS_KEY_SECRET="$REPLY"
                read_input "阿里云短信签名" "" false false
                ALIYUN_SMS_SIGN_NAME="$REPLY"
                read_input "阿里云短信模板代码" "" false false
                ALIYUN_SMS_TEMPLATE_CODE="$REPLY"
                read_input "阿里云区域" "cn-hangzhou" false false
                ALIYUN_SMS_REGION="$REPLY"
                # 火山引擎设为占位符
                HUOSHAN_SMS_ACCESS_KEY_ID="xxx"
                HUOSHAN_SMS_SECRET_KEY="xxx"
                HUOSHAN_SMS_ENDPOINT="xxx"
                HUOSHAN_SMS_SIGN_NAME="xxx"
                HUOSHAN_SMS_TEMPLATE_ID="xxx"
                HUOSHAN_SMS_ACCOUNT="xxx"
                HUOSHAN_SMS_REGION="xxx"
                ;;
            2)
                SMS_PROVIDER="huoshan"
                read_input "火山引擎AccessKeyId" "" false false
                HUOSHAN_SMS_ACCESS_KEY_ID="$REPLY"
                read_input "火山引擎SecretKey" "" true false
                HUOSHAN_SMS_SECRET_KEY="$REPLY"
                read_input "火山引擎端点" "https://sms.volcengineapi.com" false false
                HUOSHAN_SMS_ENDPOINT="$REPLY"
                read_input "火山引擎短信签名" "" false false
                HUOSHAN_SMS_SIGN_NAME="$REPLY"
                read_input "火山引擎短信模板ID" "" false false
                HUOSHAN_SMS_TEMPLATE_ID="$REPLY"
                read_input "火山引擎短信账户" "" false false
                HUOSHAN_SMS_ACCOUNT="$REPLY"
                read_input "火山引擎区域" "cn-north-1" false false
                HUOSHAN_SMS_REGION="$REPLY"
                # 阿里云设为占位符
                ALIYUN_SMS_ACCESS_KEY_ID="xxx"
                ALIYUN_SMS_ACCESS_KEY_SECRET="xxx"
                ALIYUN_SMS_SIGN_NAME="xxx"
                ALIYUN_SMS_TEMPLATE_CODE="xxx"
                ALIYUN_SMS_REGION="xxx"
                ;;
            3)
                SMS_PROVIDER="simulator"
                # 所有短信配置设为占位符
                ALIYUN_SMS_ACCESS_KEY_ID="xxx"
                ALIYUN_SMS_ACCESS_KEY_SECRET="xxx"
                ALIYUN_SMS_SIGN_NAME="xxx"
                ALIYUN_SMS_TEMPLATE_CODE="xxx"
                ALIYUN_SMS_REGION="xxx"
                HUOSHAN_SMS_ACCESS_KEY_ID="xxx"
                HUOSHAN_SMS_SECRET_KEY="xxx"
                HUOSHAN_SMS_ENDPOINT="xxx"
                HUOSHAN_SMS_SIGN_NAME="xxx"
                HUOSHAN_SMS_TEMPLATE_ID="xxx"
                HUOSHAN_SMS_ACCOUNT="xxx"
                HUOSHAN_SMS_REGION="xxx"
                ;;
            *)
                print_warning "无效选择，使用模拟器"
                SMS_PROVIDER="simulator"
                ALIYUN_SMS_ACCESS_KEY_ID="xxx"
                ALIYUN_SMS_ACCESS_KEY_SECRET="xxx"
                ALIYUN_SMS_SIGN_NAME="xxx"
                ALIYUN_SMS_TEMPLATE_CODE="xxx"
                ALIYUN_SMS_REGION="xxx"
                HUOSHAN_SMS_ACCESS_KEY_ID="xxx"
                HUOSHAN_SMS_SECRET_KEY="xxx"
                HUOSHAN_SMS_ENDPOINT="xxx"
                HUOSHAN_SMS_SIGN_NAME="xxx"
                HUOSHAN_SMS_TEMPLATE_ID="xxx"
                HUOSHAN_SMS_ACCOUNT="xxx"
                HUOSHAN_SMS_REGION="xxx"
                ;;
        esac
        
        read_input "验证码长度" "6" false false
        SMS_CODE_LENGTH="$REPLY"
        read_input "验证码有效期(分钟)" "5" false false
        SMS_CODE_EXPIRATION="$REPLY"
    else
        SMS_PROVIDER="xxx"
        SMS_CODE_LENGTH="xxx"
        SMS_CODE_EXPIRATION="xxx"
        ALIYUN_SMS_ACCESS_KEY_ID="xxx"
        ALIYUN_SMS_ACCESS_KEY_SECRET="xxx"
        ALIYUN_SMS_SIGN_NAME="xxx"
        ALIYUN_SMS_TEMPLATE_CODE="xxx"
        ALIYUN_SMS_REGION="xxx"
        HUOSHAN_SMS_ACCESS_KEY_ID="xxx"
        HUOSHAN_SMS_SECRET_KEY="xxx"
        HUOSHAN_SMS_ENDPOINT="xxx"
        HUOSHAN_SMS_SIGN_NAME="xxx"
        HUOSHAN_SMS_TEMPLATE_ID="xxx"
        HUOSHAN_SMS_ACCOUNT="xxx"
        HUOSHAN_SMS_REGION="xxx"
    fi
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 短信服务配置 [可选]
# =============================================================================
SMS_PROVIDER=$SMS_PROVIDER
SMS_CODE_LENGTH=$SMS_CODE_LENGTH
SMS_CODE_EXPIRATION=$SMS_CODE_EXPIRATION

# 阿里云短信配置
ALIYUN_SMS_ACCESS_KEY_ID=$ALIYUN_SMS_ACCESS_KEY_ID
ALIYUN_SMS_ACCESS_KEY_SECRET=$ALIYUN_SMS_ACCESS_KEY_SECRET
ALIYUN_SMS_SIGN_NAME=$ALIYUN_SMS_SIGN_NAME
ALIYUN_SMS_TEMPLATE_CODE=$ALIYUN_SMS_TEMPLATE_CODE
ALIYUN_SMS_REGION=$ALIYUN_SMS_REGION

# 火山引擎短信配置
HUOSHAN_SMS_ACCESS_KEY_ID=$HUOSHAN_SMS_ACCESS_KEY_ID
HUOSHAN_SMS_SECRET_KEY=$HUOSHAN_SMS_SECRET_KEY
HUOSHAN_SMS_ENDPOINT=$HUOSHAN_SMS_ENDPOINT
HUOSHAN_SMS_SIGN_NAME=$HUOSHAN_SMS_SIGN_NAME
HUOSHAN_SMS_TEMPLATE_ID=$HUOSHAN_SMS_TEMPLATE_ID
HUOSHAN_SMS_ACCOUNT=$HUOSHAN_SMS_ACCOUNT
HUOSHAN_SMS_REGION=$HUOSHAN_SMS_REGION

EOF
    
    # =============================================================================
    # 日志配置 (可选)
    # =============================================================================
    print_header "日志配置 (可选)"
    
    read -p "是否自定义日志配置? (y/N): " setup_logging
    
    if [[ "$setup_logging" =~ ^[Yy]$ ]]; then
        read_input "根日志级别" "WARN" false false "选项: ERROR, WARN, INFO, DEBUG"
        LOG_LEVEL_ROOT="$REPLY"
        read_input "安全日志级别" "INFO" false false
        LOG_LEVEL_SECURITY="$REPLY"
        read_input "OAuth2日志级别" "INFO" false false
        LOG_LEVEL_OAUTH2="$REPLY"
        read_input "OIDC日志级别" "INFO" false false
        LOG_LEVEL_OIDC="$REPLY"
        read_input "登出日志级别" "INFO" false false
        LOG_LEVEL_LOGOUT="$REPLY"
        read_input "会话日志级别" "INFO" false false
        LOG_LEVEL_SESSION="$REPLY"
        read_input "Web日志级别" "INFO" false false
        LOG_LEVEL_WEB="$REPLY"
        read_input "应用日志级别" "INFO" false false
        LOG_LEVEL_APP="$REPLY"
        read_input "日志文件路径" "/var/log/auth-server/auth-server.log" false false
        LOG_FILE_PATH="$REPLY"
    else
        LOG_LEVEL_ROOT="xxx"
        LOG_LEVEL_SECURITY="xxx"
        LOG_LEVEL_OAUTH2="xxx"
        LOG_LEVEL_OIDC="xxx"
        LOG_LEVEL_LOGOUT="xxx"
        LOG_LEVEL_SESSION="xxx"
        LOG_LEVEL_WEB="xxx"
        LOG_LEVEL_APP="xxx"
        LOG_FILE_PATH="xxx"
    fi
    
    cat >> "$ENV_FILE" << EOF
# =============================================================================
# 日志配置 [可选]
# =============================================================================
LOG_LEVEL_ROOT=$LOG_LEVEL_ROOT
LOG_LEVEL_SECURITY=$LOG_LEVEL_SECURITY
LOG_LEVEL_OAUTH2=$LOG_LEVEL_OAUTH2
LOG_LEVEL_OIDC=$LOG_LEVEL_OIDC
LOG_LEVEL_LOGOUT=$LOG_LEVEL_LOGOUT
LOG_LEVEL_SESSION=$LOG_LEVEL_SESSION
LOG_LEVEL_WEB=$LOG_LEVEL_WEB
LOG_LEVEL_APP=$LOG_LEVEL_APP
LOG_FILE_PATH=$LOG_FILE_PATH
EOF
    
    # =============================================================================
    # 生成完成
    # =============================================================================
    print_header "配置生成完成"
    
    print_success "生产环境配置文件已生成: $ENV_FILE"
    print_success "JWT密钥库已生成: $KEYSTORE_FILE"
    
    echo ""
    echo "📋 部署清单:"
    echo "   1. 配置文件: $ENV_FILE"
    echo "   2. 密钥目录: $KEYSTORE_DIR/"
    echo "   3. 应用JAR包: target/ffvtraceability-auth-server-*.jar"
    
    echo ""
    echo "🚀 Docker部署命令示例:"
    echo "docker run -d \\"
    echo "  --name auth-server \\"
    echo "  --env-file $ENV_FILE \\"
    echo "  -v \$(pwd)/$KEYSTORE_DIR:/app/keys:ro \\"
    echo "  -p 9000:9000 \\"
    echo "  your-registry/auth-server:latest"
    
    echo ""
    echo "⚠️  部署前检查:"
    echo "   1. 检查所有 'xxx' 占位符并替换为实际值"
    echo "   2. 确保数据库已创建并可访问"
    echo "   3. 确保HTTPS证书已配置(如果使用HTTPS)"
    echo "   4. 测试邮件服务配置"
    echo "   5. 验证CORS配置是否包含所有需要的域名"
    
    echo ""
    echo "✅ 配置生成完成！"
}

# 检查依赖
check_dependencies() {
    if ! command -v keytool &> /dev/null; then
        print_error "keytool 未找到，请安装 Java JDK"
        exit 1
    fi
    
    if ! command -v openssl &> /dev/null; then
        print_error "openssl 未找到，请安装 OpenSSL"
        exit 1
    fi
}

# 脚本入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi