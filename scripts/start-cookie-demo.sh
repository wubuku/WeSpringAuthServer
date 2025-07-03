#!/bin/bash

# SMS登录Cookie安全模式演示启动脚本
# 版本: 1.0
# 描述: 启动WeSpring Auth Server并提供Cookie安全模式的SMS登录演示
# 特点: 同域部署，通过Spring Boot的/demo端点服务前端页面

echo "🚀 启动SMS登录Cookie安全模式演示"
echo "=================================="

# 项目根目录
PROJECT_ROOT="/Users/yangjiefeng/Documents/wubuku/WeSpringAuthServer"
BACKEND_URL="http://localhost:9000"
DEMO_URL="$BACKEND_URL/demo"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查项目目录
if [ ! -d "$PROJECT_ROOT" ]; then
    echo -e "${RED}❌ 错误: 项目目录不存在: $PROJECT_ROOT${NC}"
    exit 1
fi

# 检查演示文件
if [ ! -f "$PROJECT_ROOT/sms-login-demo/index.html" ]; then
    echo -e "${RED}❌ 错误: SMS登录演示文件不存在: $PROJECT_ROOT/sms-login-demo/index.html${NC}"
    exit 1
fi

echo -e "${BLUE}📁 项目目录: $PROJECT_ROOT${NC}"
echo -e "${BLUE}🎯 演示URL: $DEMO_URL${NC}"
echo ""

# 检查后端服务状态
echo -e "${YELLOW}🔍 检查后端服务状态...${NC}"
if curl -s --connect-timeout 3 "$BACKEND_URL/actuator/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ 后端服务已运行在: $BACKEND_URL${NC}"
    BACKEND_RUNNING=true
else
    echo -e "${YELLOW}⚠️  后端服务未运行，准备启动...${NC}"
    BACKEND_RUNNING=false
fi

# 如果后端未运行，则启动
if [ "$BACKEND_RUNNING" = false ]; then
    echo -e "${YELLOW}🔄 启动后端服务...${NC}"
    cd "$PROJECT_ROOT"
    
    # 检查Maven Wrapper
    if [ ! -f "mvnw" ]; then
        echo -e "${RED}❌ 错误: Maven Wrapper不存在，请确保在正确的项目目录${NC}"
        exit 1
    fi
    
    # 后台启动Spring Boot应用
    echo -e "${BLUE}📋 启动命令: ./mvnw spring-boot:run${NC}"
    nohup ./mvnw spring-boot:run > backend.log 2>&1 &
    BACKEND_PID=$!
    
    echo -e "${YELLOW}⏳ 等待后端服务启动（最多60秒）...${NC}"
    
    # 等待服务启动，最多60秒
    WAIT_TIME=0
    MAX_WAIT=60
    while [ $WAIT_TIME -lt $MAX_WAIT ]; do
        if curl -s --connect-timeout 2 "$BACKEND_URL/actuator/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ 后端服务启动成功！${NC}"
            break
        fi
        
        echo -n "."
        sleep 2
        WAIT_TIME=$((WAIT_TIME + 2))
    done
    
    if [ $WAIT_TIME -ge $MAX_WAIT ]; then
        echo -e "\n${RED}❌ 后端服务启动超时，请检查日志: backend.log${NC}"
        echo -e "${YELLOW}💡 提示: 可以手动运行 './mvnw spring-boot:run' 查看详细错误${NC}"
        exit 1
    fi
    
    echo ""
fi

# 显示服务信息
echo -e "${GREEN}🎉 服务启动完成！${NC}"
echo "=================================="
echo -e "${GREEN}✅ 后端服务: $BACKEND_URL${NC}"
echo -e "${GREEN}✅ 演示页面: $DEMO_URL${NC}"
echo ""

# Cookie安全特性说明
echo -e "${BLUE}🍪 Cookie安全特性：${NC}"
echo "   - HttpOnly Cookie存储refresh_token"
echo "   - 同域部署确保Cookie安全共享"
echo "   - client_secret完全后端化"
echo "   - SameSite=Lax防护CSRF攻击"
echo ""

# 测试步骤
echo -e "${BLUE}🎯 测试步骤：${NC}"
echo "   1. 浏览器访问: $DEMO_URL"
echo "   2. 输入手机号：13800138000"
echo "   3. 发送验证码并登录"
echo "   4. 观察Cookie设置和刷新过程"
echo "   5. 使用开发者工具检查Cookie（Application → Cookies）"
echo ""

# 安全验证点
echo -e "${BLUE}🔒 安全验证点：${NC}"
echo "   - 登录响应不包含refresh_token（已安全存储在Cookie）"
echo "   - Cookie设置了HttpOnly标志（防XSS）"
echo "   - Cookie设置了SameSite=Lax（防CSRF）"
echo "   - 前端代码不再包含client_secret"
echo ""

# 自动打开浏览器
echo -e "${YELLOW}🌐 正在打开浏览器...${NC}"
if command -v open > /dev/null 2>&1; then
    open "$DEMO_URL"
elif command -v xdg-open > /dev/null 2>&1; then
    xdg-open "$DEMO_URL"
elif command -v start > /dev/null 2>&1; then
    start "$DEMO_URL"
else
    echo -e "${YELLOW}⚠️  无法自动打开浏览器，请手动访问: $DEMO_URL${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Cookie安全模式演示启动完成！${NC}"
echo -e "${YELLOW}💡 按 Ctrl+C 可以停止脚本（后端服务会继续运行）${NC}"
echo -e "${YELLOW}💡 如需停止后端服务，请查找进程并手动终止${NC}"

# 整合提示 - 与现有测试脚本协作
echo ""
echo "=================================="
echo -e "${BLUE}🧪 相关测试脚本：${NC}"
echo "=================================="
echo -e "${GREEN}📱 SMS登录端到端测试:${NC}"
echo "   bash scripts/test-sms-login.sh 13800138000"
echo ""
echo -e "${GREEN}🔒 Cookie安全功能测试:${NC}"  
echo "   bash scripts/test-cookie-security.sh"
echo ""
echo -e "${GREEN}🛡️  OAuth2安全验证:${NC}"
echo "   bash scripts/verify-oauth2-security.sh"
echo ""
echo -e "${BLUE}💡 建议测试流程:${NC}"
echo "   1. 先手动测试演示页面功能"
echo "   2. 再运行自动化测试脚本验证"
echo "   3. 最后进行OAuth2安全验证"

# 实时显示后端日志（可选）
echo ""
echo -e "${BLUE}📋 实时日志（可选，按Ctrl+C退出日志查看）：${NC}"
if [ "$BACKEND_RUNNING" = false ] && [ -f "backend.log" ]; then
    echo -e "${YELLOW}⚡ 正在显示后端启动日志...${NC}"
    tail -f backend.log &
    TAIL_PID=$!
    
    # 等待用户输入
    read -p "按回车键停止日志显示并保持服务运行..."
    kill $TAIL_PID 2>/dev/null
fi

echo ""
echo -e "${GREEN}✨ 演示环境就绪！请在浏览器中测试Cookie安全特性${NC}"
echo -e "${BLUE}📖 更多信息请查看: sms-login-demo/README.md${NC}" 