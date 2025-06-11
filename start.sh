#!/bin/bash

echo "FFV Traceability Auth Server"
echo "============================"

# 检查Java版本
JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | sed '/^1\./s///' | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 17 ]; then
    echo "错误: 需要Java 17或更高版本，当前版本: $JAVA_VERSION"
    exit 1
fi

# 设置认证模式
MODE=${AUTH_MODE:-session}
echo "认证模式: $MODE"

# 设置JVM参数
JAVA_OPTS="-Xmx512m -Xms256m"

# 启动应用
echo "正在启动服务器..."
export AUTH_MODE=$MODE
./mvnw spring-boot:run -Dspring-boot.run.jvmArguments="$JAVA_OPTS" 