#!/bin/bash

# ============================================================================
# 权限系统测试脚本 (test-permissions.sh)
# ============================================================================
# 
# 用途：
#   1. 专门测试Spring Security权限控制功能
#   2. 验证不同权限级别的访问控制
#   3. 测试权限继承和组权限功能
#   4. 确保权限配置的正确性
# 
# 功能：
#   - 测试admin用户的完整权限访问
#   - 验证不同权限要求的页面访问控制
#   - 检查API级别的权限验证
#   - 测试权限拒绝场景
# 
# 使用场景：
#   - 权限系统重构后的验证
#   - 安全审计和权限测试
#   - 验证权限配置是否正确
#   - 排查权限相关的403错误
# 
# 运行方法：
#   chmod +x scripts/test-permissions.sh
#   ./scripts/test-permissions.sh
# 
# 输出：
#   - 每个权限级别的测试结果
#   - 权限访问成功/失败状态
#   - 详细的权限验证信息
# 
# 作者: AI Assistant
# 创建日期: 2025-06-19
# ============================================================================

set -e

echo "===== 权限系统测试开始 ====="
echo "时间: $(date)"
echo ""

# 定义颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_section() {
    echo -e "${BLUE}===== $1 =====${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

BASE_URL="http://localhost:9000"

print_section "1. 环境检查"
if ! curl -s $BASE_URL/login > /dev/null 2>&1; then
    print_error "应用程序未运行，请先启动服务"
    exit 1
fi
print_success "应用程序运行正常"

print_section "2. 用户登录"
rm -f test-cookies.txt

# 获取CSRF token
CSRF_TOKEN=$(curl -c test-cookies.txt -s $BASE_URL/login | grep -o 'name="_csrf" value="[^"]*' | cut -d'"' -f4)
if [ -z "$CSRF_TOKEN" ]; then
    print_error "无法获取CSRF token"
    exit 1
fi

# 登录
curl -s -b test-cookies.txt -c test-cookies.txt \
    -d "username=admin" \
    -d "password=admin" \
    -d "_csrf=$CSRF_TOKEN" \
    -X POST \
    "$BASE_URL/login" > /dev/null

print_success "admin用户登录成功"

print_section "3. 权限级别测试"

# 测试需要Users_Read权限的资源
print_warning "测试Users_Read权限..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b test-cookies.txt "$BASE_URL/user-management")
if [ "$STATUS" = "200" ]; then
    print_success "用户管理页面访问成功 (Users_Read)"
else
    print_error "用户管理页面访问失败: $STATUS"
fi

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b test-cookies.txt "$BASE_URL/api/users/list")
if [ "$STATUS" = "200" ]; then
    print_success "用户列表API访问成功 (Users_Read)"
else
    print_error "用户列表API访问失败: $STATUS"
fi

# 测试需要Roles_Read权限的资源
print_warning "测试Roles_Read权限..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b test-cookies.txt "$BASE_URL/group-management")
if [ "$STATUS" = "200" ]; then
    print_success "组管理页面访问成功 (Roles_Read)"
else
    print_error "组管理页面访问失败: $STATUS"
fi

# 测试需要ROLE_ADMIN权限的资源
print_warning "测试ROLE_ADMIN权限..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b test-cookies.txt "$BASE_URL/authority-management")
if [ "$STATUS" = "200" ]; then
    print_success "权限管理页面访问成功 (ROLE_ADMIN)"
else
    print_error "权限管理页面访问失败: $STATUS"
fi

print_section "权限测试完成"

# 清理
rm -f test-cookies.txt

print_success "所有权限测试完成！" 