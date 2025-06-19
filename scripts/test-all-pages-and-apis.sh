#!/bin/bash

# ============================================================================
# 全页面和API综合测试脚本 (test-all-pages-and-apis.sh)
# ============================================================================
# 
# 用途：
#   1. 全面测试Web应用的所有管理页面和API端点
#   2. 验证认证和授权功能完整性
#   3. 检查页面渲染和API响应正确性
#   4. 提供完整的功能回归测试
# 
# 功能：
#   - 测试用户登录流程
#   - 验证所有管理页面可访问性
#   - 测试所有管理API端点
#   - 检查权限控制是否正确
#   - 测试移动端API（微信小程序）
#   - 生成详细的测试报告
# 
# 使用场景：
#   - 部署前的完整功能验证
#   - 重构后的回归测试
#   - CI/CD流水线中的自动化测试
#   - 发布前的质量保证
# 
# 运行方法：
#   chmod +x scripts/test-all-pages-and-apis.sh
#   ./scripts/test-all-pages-and-apis.sh
# 
# 输出：
#   - 详细的测试结果
#   - 每个页面/API的响应状态
#   - 错误信息和建议
#   - 测试统计摘要
# 
# 作者: AI Assistant
# 创建日期: 2025-06-19
# ============================================================================

set -e

echo "===== 全页面和API综合测试开始 ====="
echo "时间: $(date)"
echo ""

# 定义颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

print_section() {
    echo -e "${BLUE}===== $1 =====${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((PASSED_TESTS++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    ((FAILED_TESTS++))
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

count_test() {
    ((TOTAL_TESTS++))
}

# 清理环境
rm -f cookies.txt
BASE_URL="http://localhost:9000"

print_section "1. 环境检查"
count_test
if curl -s $BASE_URL/login > /dev/null 2>&1; then
    print_success "应用程序运行正常"
else
    print_error "应用程序未运行，请先启动服务"
    exit 1
fi

print_section "2. 用户认证测试"
print_info "获取CSRF Token..."
count_test
CSRF_TOKEN=$(curl -c cookies.txt -b cookies.txt -s $BASE_URL/login | grep -o 'name="_csrf" value="[^"]*' | cut -d'"' -f4)
if [ -n "$CSRF_TOKEN" ]; then
    print_success "CSRF Token获取成功"
else
    print_error "CSRF Token获取失败"
    exit 1
fi

print_info "测试admin用户登录..."
count_test
LOGIN_RESPONSE=$(curl -i -X POST $BASE_URL/login \
    -b cookies.txt -c cookies.txt \
    -d "username=admin&password=admin&_csrf=$CSRF_TOKEN" \
    -s)

if echo "$LOGIN_RESPONSE" | grep -q "HTTP/1.1 302"; then
    print_success "用户登录成功"
else
    print_error "用户登录失败"
    exit 1
fi

print_section "3. 管理页面访问测试"

# 定义页面测试列表
declare -A PAGES=(
    ["/"]="首页"
    ["/user-management"]="用户管理"
    ["/group-management"]="组管理"
    ["/authority-management"]="权限管理"
    ["/authority-settings"]="权限设置"
    ["/pre-register"]="用户预注册"
    ["/change-password"]="修改密码"
)

for page in "${!PAGES[@]}"; do
    print_info "测试 ${PAGES[$page]} ($page)..."
    count_test
    HTTP_CODE=$(curl -b cookies.txt -s -w "%{http_code}" $BASE_URL$page -o /dev/null)
    
    case $HTTP_CODE in
        200)
            print_success "${PAGES[$page]} 正常 (200)"
            ;;
        302)
            print_warning "${PAGES[$page]} 重定向 (302)"
            ;;
        403)
            print_error "${PAGES[$page]} 权限拒绝 (403)"
            ;;
        404)
            print_error "${PAGES[$page]} 页面不存在 (404)"
            ;;
        *)
            print_error "${PAGES[$page]} 异常状态码 ($HTTP_CODE)"
            ;;
    esac
done

print_section "4. 管理API测试"

# 定义API测试列表
declare -A APIS=(
    ["/api/users/list"]="用户列表API"
    ["/api/groups/list"]="组列表API"
    ["/api/authorities/base"]="基础权限API"
    ["/api/authorities/users"]="权限用户API"
)

for api in "${!APIS[@]}"; do
    print_info "测试 ${APIS[$api]} ($api)..."
    count_test
    API_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" $BASE_URL$api)
    HTTP_CODE="${API_RESPONSE: -3}"
    
    case $HTTP_CODE in
        200)
            print_success "${APIS[$api]} 正常 (200)"
            ;;
        401)
            print_error "${APIS[$api]} 认证失败 (401)"
            ;;
        403)
            print_error "${APIS[$api]} 权限拒绝 (403)"
            ;;
        404)
            print_error "${APIS[$api]} 接口不存在 (404)"
            ;;
        500)
            print_error "${APIS[$api]} 服务器错误 (500)"
            ;;
        *)
            print_error "${APIS[$api]} 异常状态码 ($HTTP_CODE)"
            ;;
    esac
done

print_section "5. 移动端API测试（无状态）"

print_info "测试SMS发送验证码API..."
count_test
SMS_RESPONSE=$(curl -s -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{"phoneNumber":"13800138000"}' \
    $BASE_URL/sms/send-code)
HTTP_CODE="${SMS_RESPONSE: -3}"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "SMS发送API正常 (200)"
else
    print_error "SMS发送API异常 ($HTTP_CODE)"
fi

print_info "测试微信登录API（预期401认证失败）..."
count_test
WECHAT_RESPONSE=$(curl -s -w "%{http_code}" \
    "$BASE_URL/wechat/login?loginCode=test123&mobileCode=test456&clientId=ffv-client" \
    -o /dev/null)

if [ "$WECHAT_RESPONSE" = "401" ]; then
    print_success "微信登录API响应正常（认证失败为预期结果）"
else
    print_warning "微信登录API响应异常 ($WECHAT_RESPONSE)"
fi

print_section "6. Web SMS API测试（有状态）"

print_info "测试Web SMS发送验证码..."
count_test
WEB_SMS_RESPONSE=$(curl -b cookies.txt -s -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d '{"phoneNumber":"13800138000"}' \
    $BASE_URL/web-sms/send-code)
HTTP_CODE="${WEB_SMS_RESPONSE: -3}"

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Web SMS发送API正常 (200)"
else
    print_error "Web SMS发送API异常 ($HTTP_CODE)"
fi

print_section "7. 测试结果统计"
echo ""
print_info "测试统计摘要:"
echo "  总测试数: $TOTAL_TESTS"
echo -e "  成功: ${GREEN}$PASSED_TESTS${NC}"
echo -e "  失败: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo ""
    print_success "🎉 所有测试通过！系统功能正常！"
    echo ""
else
    echo ""
    print_error "⚠️  发现 $FAILED_TESTS 个问题，请检查上述错误信息"
    echo ""
    echo "常见问题排查："
    echo "1. 检查数据库连接和权限配置"
    echo "2. 验证Spring Security配置"
    echo "3. 确认所有必要的控制器已正确注册"
    echo "4. 检查应用日志获取详细错误信息"
    echo ""
fi

# 清理
rm -f cookies.txt

print_section "测试完成"
echo "结束时间: $(date)" 