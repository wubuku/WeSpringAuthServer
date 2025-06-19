#!/bin/bash

# ============================================================================
# 权限问题调试脚本 (debug-permissions-issue.sh)
# ============================================================================
# 
# 用途：
#   1. 自动化调试Spring Security权限配置问题
#   2. 测试用户认证流程和权限检查
#   3. 帮助排查403 Forbidden错误
#   4. 验证权限数据是否正确加载
# 
# 功能：
#   - 测试admin用户登录流程
#   - 检查用户权限是否正确加载
#   - 测试各个管理页面的访问权限
#   - 提供详细的调试输出
# 
# 使用场景：
#   - 重构权限系统后验证功能
#   - 排查403权限拒绝问题
#   - 检查数据库权限配置
# 
# 运行方法：
#   chmod +x scripts/debug-permissions-issue.sh
#   ./scripts/debug-permissions-issue.sh
# 
# 输出：
#   - 登录响应状态
#   - 用户权限信息
#   - 页面访问结果
#   - 详细的调试信息
# 
# 作者: AI Assistant
# 创建日期: 2025-06-19
# ============================================================================

set -e  # 遇到错误立即退出

echo "===== 权限问题调试脚本开始 ====="
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

# 清理旧的cookie文件
rm -f cookies.txt

print_section "1. 检查应用程序状态"
if curl -s http://localhost:9000/login > /dev/null 2>&1; then
    print_success "应用程序正在运行"
else
    print_error "应用程序未运行，请先启动应用"
    exit 1
fi

print_section "2. 获取CSRF Token"
CSRF_TOKEN=$(curl -c cookies.txt -b cookies.txt -s http://localhost:9000/login | grep -o 'name="_csrf" value="[^"]*' | cut -d'"' -f4)
if [ -n "$CSRF_TOKEN" ]; then
    print_success "CSRF Token获取成功: ${CSRF_TOKEN:0:20}..."
else
    print_error "无法获取CSRF Token"
    exit 1
fi

print_section "3. 测试admin用户登录"
LOGIN_RESPONSE=$(curl -i -X POST http://localhost:9000/login \
    -b cookies.txt -c cookies.txt \
    -d "username=admin&password=admin&_csrf=$CSRF_TOKEN" \
    -s)

if echo "$LOGIN_RESPONSE" | grep -q "HTTP/1.1 302"; then
    print_success "admin用户登录成功"
else
    print_error "admin用户登录失败"
    echo "响应:"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

print_section "4. 测试用户权限API"
USER_API_RESPONSE=$(curl -b cookies.txt -s http://localhost:9000/api/users/list)
if echo "$USER_API_RESPONSE" | grep -q "admin"; then
    print_success "用户权限API正常工作"
    echo "API响应: ${USER_API_RESPONSE:0:100}..."
else
    print_error "用户权限API失败"
    echo "响应: $USER_API_RESPONSE"
fi

print_section "5. 测试管理页面访问权限"

# 测试用户管理页面
print_warning "测试用户管理页面..."
USER_PAGE_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" http://localhost:9000/user-management)
HTTP_CODE="${USER_PAGE_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "用户管理页面访问成功 (200)"
else
    print_error "用户管理页面访问失败 ($HTTP_CODE)"
fi

# 测试组管理页面
print_warning "测试组管理页面..."
GROUP_PAGE_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" http://localhost:9000/group-management)
HTTP_CODE="${GROUP_PAGE_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "组管理页面访问成功 (200)"
else
    print_error "组管理页面访问失败 ($HTTP_CODE)"
fi

# 测试权限管理页面
print_warning "测试权限管理页面..."
AUTH_PAGE_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" http://localhost:9000/authority-management)
HTTP_CODE="${AUTH_PAGE_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "权限管理页面访问成功 (200)"
else
    print_error "权限管理页面访问失败 ($HTTP_CODE)"
fi

print_section "6. 测试API权限"

# 测试用户列表API
API_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" http://localhost:9000/api/users/list)
HTTP_CODE="${API_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "用户列表API正常 (200)"
else
    print_error "用户列表API失败 ($HTTP_CODE)"
fi

# 测试组列表API
API_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" http://localhost:9000/api/groups/list)
HTTP_CODE="${API_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    print_success "组列表API正常 (200)"
else
    print_error "组列表API失败 ($HTTP_CODE)"
fi

print_section "调试脚本完成"
print_success "权限调试测试完成！"
echo ""
echo "如果发现问题，请检查:"
echo "1. 数据库中admin用户的权限配置"
echo "2. SecurityConfig中的权限映射"
echo "3. UserService中的权限加载逻辑"
echo ""

# 清理
rm -f cookies.txt 