#!/bin/bash

# 获取所有测试用户的JWT令牌（支持可选：刷新 与 解码打印）
# 基于 test.sh 脚本的 OAuth2 授权流程
#
# 用法:
#   ./get-test-user-tokens.sh [OPTIONS]
#
# 选项（默认全部关闭，以避免对本地环境造成副作用）:
#   -r, --refresh   在获取后尝试刷新一次，并输出刷新结果（默认：关闭）
#                   实现方式：给 test.sh 传递 TEST_REFRESH_TOKEN=true 环境变量；
#                   不会修改 test.sh 文件本身。
#   -d, --decode    打印最终（刷新后或初次）access token 的解码结果（默认：关闭）
#                   会解码并高亮显示 groups 与 authorities，便于核验权限。
#   -h, --help      显示帮助并退出。
#
# 说明:
# - 本脚本会临时修改 test.sh 中的 USERNAME/PASSWORD 后执行，再恢复备份；
# - 不会修改 test.sh 的 TEST_REFRESH_TOKEN 配置，避免对他处测试产生影响；
# - 若启用 --refresh，则通过 “TEST_REFRESH_TOKEN=true ./test.sh” 的环境变量方式开启刷新测试；
# - 若启用 --decode，则在每个用户成功获取 token 后解码打印 claims。

echo "🚀 获取所有测试用户的 JWT 令牌"
echo "========================================"
echo ""

# 选项默认值（均为关闭）
ENABLE_REFRESH=0
PRINT_DECODED=0

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--refresh)
            ENABLE_REFRESH=1
            shift
            ;;
        -d|--decode)
            PRINT_DECODED=1
            shift
            ;;
        -h|--help)
            sed -n '1,50p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "未知选项: $1" >&2
            sed -n '1,50p' "$0" | sed 's/^# \{0,1\}//'
            exit 1
            ;;
    esac
done

# 字符串重复函数（兼容 macOS/Linux，避免 seq 命令依赖）
repeat_string() {
    local str="$1"
    local count="$2"
    local result=""
    local i=0

    while [ $i -lt $count ]; do
        result="${result}${str}"
        i=$((i + 1))
    done

    echo "$result"
}

# JWT 解码函数（兼容 macOS/Linux）
if [[ "$OSTYPE" == "darwin"* ]]; then
    decode_jwt() {
        local jwt_part=$1
        local pad=$(( 4 - ${#jwt_part} % 4 ))
        if [ $pad -ne 4 ]; then
            jwt_part="${jwt_part}$(repeat_string '=' $pad)"
        fi
        jwt_part=$(echo "$jwt_part" | tr '_-' '/+')
        echo "$jwt_part" | gbase64 -d 2>/dev/null
    }
else
    decode_jwt() {
        local jwt_part=$1
        local pad=$(( 4 - ${#jwt_part} % 4 ))
        if [ $pad -ne 4 ]; then
            jwt_part="${jwt_part}$(repeat_string '=' $pad)"
        fi
        jwt_part=$(echo "$jwt_part" | tr '_-' '/+')
        echo "$jwt_part" | base64 -d 2>/dev/null
    }
fi

# 函数：获取单个用户的令牌
get_user_token() {
    local username=$1
    local password=$2
    
    echo "🔄 正在获取用户 $username 的令牌..."
    
    # 临时修改test.sh的用户配置
    cp test.sh test.sh.backup
    # 兼容 macOS 和 Linux 的 sed 语法
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/USERNAME=\".*\"/USERNAME=\"$username\"/" test.sh
        sed -i '' "s/PASSWORD=\".*\"/PASSWORD=\"$password\"/" test.sh
    else
        sed -i "s/USERNAME=\".*\"/USERNAME=\"$username\"/" test.sh
        sed -i "s/PASSWORD=\".*\"/PASSWORD=\"$password\"/" test.sh
    fi
    
    # 运行 test.sh
    # 若启用 --refresh，则通过环境变量开启刷新测试；否则保持 test.sh 默认逻辑
    if [[ "$ENABLE_REFRESH" == "1" ]]; then
        if TEST_REFRESH_TOKEN=true ./test.sh > /dev/null 2>&1; then
            :
        else
            echo "❌ 获取用户 $username 的令牌失败"
            return 1
        fi
    else
        if ./test.sh > /dev/null 2>&1; then
            :
        else
            echo "❌ 获取用户 $username 的令牌失败"
            return 1
        fi
    fi

    # 检查tokens.env文件是否存在且包含令牌
    if [ -f "tokens.env" ]; then
        local access_token=$(grep "export ACCESS_TOKEN=" tokens.env | cut -d'=' -f2)
        local refresh_token=$(grep "export REFRESH_TOKEN=" tokens.env | cut -d'=' -f2)
        
        if [ -n "$access_token" ] && [ "$access_token" != "" ]; then
            local upper_username=$(echo "$username" | tr '[:lower:]' '[:upper:]')
            echo "✅ 成功获取用户 $username 的令牌"
            echo ""
            echo "export ${upper_username}_ACCESS_TOKEN=$access_token"
            echo "export ${upper_username}_REFRESH_TOKEN=$refresh_token"
            echo ""
            
            # 可选：解码并显示该用户最终访问令牌（刷新后）的Claims
            if [[ "$PRINT_DECODED" == "1" ]]; then
                echo "📝 $username 解码后的 Access Token Claims:"
                local header=$(echo "$access_token" | cut -d'.' -f1)
                local payload=$(echo "$access_token" | cut -d'.' -f2)
                local header_decoded=$(decode_jwt "$header")
                local payload_decoded=$(decode_jwt "$payload")
                if [ -n "$payload_decoded" ]; then
                    echo "$payload_decoded" | jq '.' 2>/dev/null || echo "$payload_decoded"
                    # 高亮 groups/authorities
                    local groups=$(echo "$payload_decoded" | jq -r '.groups // empty' 2>/dev/null)
                    if [ -n "$groups" ] && [ "$groups" != "null" ]; then
                        echo "✅ groups:"; echo "$groups" | jq '.' 2>/dev/null || echo "$groups"
                    else
                        echo "⚠️  groups 缺失"
                    fi
                    local authorities=$(echo "$payload_decoded" | jq -r '.authorities // empty' 2>/dev/null)
                    if [ -n "$authorities" ] && [ "$authorities" != "null" ]; then
                        echo "✅ authorities:"; echo "$authorities" | jq '.' 2>/dev/null || echo "$authorities"
                    else
                        echo "⚠️  authorities 缺失（若用户无直接权限这是正常的）"
                    fi
                else
                    echo "❌ 无法解码 Access Token"
                fi
            fi
            
            # 保存到汇总文件
            echo "# $username 用户的令牌 (已包含刷新后最新token)" >> all-test-tokens.env
            echo "export ${upper_username}_ACCESS_TOKEN=$access_token" >> all-test-tokens.env
            echo "export ${upper_username}_REFRESH_TOKEN=$refresh_token" >> all-test-tokens.env
            echo "" >> all-test-tokens.env
            
            return 0
        fi
    fi
    
    echo "❌ 获取用户 $username 的令牌失败"
    return 1
}

# 清理之前的汇总文件
rm -f all-test-tokens.env
echo "# 所有测试用户的JWT令牌" > all-test-tokens.env
echo "# 生成时间: $(date)" >> all-test-tokens.env
echo "" >> all-test-tokens.env

# 测试用户列表
users=(
    "hq_admin:hq123"
    "distributor_admin:dist123"
    "store_admin:store123"
    "consultant:cons123"
    "distributor_employee:emp123"
)

success_count=0
total_count=${#users[@]}

# 为每个用户获取令牌
for user_info in "${users[@]}"; do
    username=$(echo "$user_info" | cut -d':' -f1)
    password=$(echo "$user_info" | cut -d':' -f2)
    
    if get_user_token "$username" "$password"; then
        ((success_count++))
    fi
    
    # 恢复原始的test.sh
    mv test.sh.backup test.sh
    
    echo "----------------------------------------"
done

echo "🎉 完成！成功获取 $success_count/$total_count 个用户的令牌"
echo ""
echo "📁 所有令牌已保存到: all-test-tokens.env"
echo ""
echo "使用方法:"
echo "  source all-test-tokens.env"
echo "  echo \$HQ_ADMIN_ACCESS_TOKEN"
echo ""
echo "或者直接复制上面显示的export命令使用"