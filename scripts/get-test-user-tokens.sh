#!/bin/bash

# 获取所有测试用户的JWT令牌
# 基于test.sh脚本的OAuth2授权流程

echo "🚀 获取所有测试用户的 JWT 令牌"
echo "========================================"
echo ""

# 函数：获取单个用户的令牌
get_user_token() {
    local username=$1
    local password=$2
    
    echo "🔄 正在获取用户 $username 的令牌..."
    
    # 临时修改test.sh的用户配置
    cp test.sh test.sh.backup
    sed -i '' "s/USERNAME=\".*\"/USERNAME=\"$username\"/" test.sh
    sed -i '' "s/PASSWORD=\".*\"/PASSWORD=\"$password\"/" test.sh
    
    # 运行test.sh并捕获输出
    if ./test.sh > /dev/null 2>&1; then
        # 检查tokens.env文件是否存在且包含令牌
        if [ -f "tokens.env" ]; then
            local access_token=$(grep "export ACCESS_TOKEN=" tokens.env | cut -d'=' -f2)
            local refresh_token=$(grep "export REFRESH_TOKEN=" tokens.env | cut -d'=' -f2)
            
            if [ -n "$access_token" ] && [ "$access_token" != "" ]; then
                local upper_username=$(echo "$username" | tr '[:lower:]' '[:upper:]')
                echo "✅ 成功获取用户 $username 的令牌"
                echo ""
                echo "# $username 用户的令牌"
                echo "export ${upper_username}_ACCESS_TOKEN=$access_token"
                echo "export ${upper_username}_REFRESH_TOKEN=$refresh_token"
                echo ""
                
                # 保存到汇总文件
                echo "# $username 用户的令牌" >> all-test-tokens.env
                echo "export ${upper_username}_ACCESS_TOKEN=$access_token" >> all-test-tokens.env
                echo "export ${upper_username}_REFRESH_TOKEN=$refresh_token" >> all-test-tokens.env
                echo "" >> all-test-tokens.env
                
                return 0
            fi
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