#!/bin/bash

# SMS登录演示启动脚本
# 这个脚本会自动选择最佳的方式来启动web服务器

echo "🚀 启动SMS登录演示..."
echo "================================"

# 检查当前目录
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DEMO_DIR"

echo "📁 Demo目录: $DEMO_DIR"

# 检查后端服务是否运行
echo "🔍 检查后端服务状态..."
if curl -s http://localhost:9000/actuator/health > /dev/null 2>&1; then
    echo "✅ 后端服务运行正常 (http://localhost:9000)"
else
    echo "⚠️  后端服务未运行，请先启动 WeSpring Auth Server"
    echo "   在项目根目录运行: ./start.sh 或 ./mvnw spring-boot:run"
    echo ""
fi

# 选择web服务器
echo "🌐 启动Web服务器..."

# 优先使用 serve (如果安装了Node.js)
if command -v npm > /dev/null 2>&1; then
    echo "📦 检测到Node.js，使用serve启动..."
    if ! command -v serve > /dev/null 2>&1; then
        echo "📥 安装serve..."
        npm install -g serve
    fi
    echo "🎯 启动serve服务器..."
    echo "   访问地址: http://localhost:8080"
    echo "   按 Ctrl+C 停止服务"
    echo ""
    serve -s . -p 8080
    
# 备选方案：使用Python HTTP服务器
elif command -v python3 > /dev/null 2>&1; then
    echo "🐍 使用Python HTTP服务器启动..."
    echo "🎯 启动Python服务器..."
    echo "   访问地址: http://localhost:8080"
    echo "   按 Ctrl+C 停止服务"
    echo ""
    python3 -m http.server 8080
    
elif command -v python > /dev/null 2>&1; then
    echo "🐍 使用Python HTTP服务器启动..."
    echo "🎯 启动Python服务器..."
    echo "   访问地址: http://localhost:8080"
    echo "   按 Ctrl+C 停止服务"
    echo ""
    python -m http.server 8080
    
else
    echo "❌ 未找到合适的web服务器"
    echo "请安装以下任一工具："
    echo "  - Node.js (推荐): https://nodejs.org/"
    echo "  - Python 3: https://python.org/"
    echo ""
    echo "或者手动在浏览器中打开: file://$DEMO_DIR/index.html"
    echo "（注意：直接打开可能遇到CORS问题）"
    exit 1
fi