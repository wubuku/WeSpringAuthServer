# 构建阶段
FROM eclipse-temurin:17-jdk-jammy as build

WORKDIR /opt/auth-server

# 复制项目文件
COPY pom.xml .
COPY src src

# 构建应用
RUN --mount=type=cache,target=/root/.m2 \
    apt-get update && \
    apt-get install -y maven && \
    mvn clean package -DskipTests

# 运行阶段
FROM eclipse-temurin:17-jre-jammy

# 创建非root用户
RUN groupadd -r authserver && useradd -r -g authserver authserver

# 创建应用目录
RUN mkdir /app && chown authserver:authserver /app

USER authserver
WORKDIR /app

# 复制构建产物
COPY --from=build --chown=authserver:authserver \
    /opt/auth-server/target/ffvtraceability-auth-server-*.jar \
    /app/auth-server.jar

# 暴露端口
EXPOSE 9000

# 启动命令
ENTRYPOINT ["java", "-jar", "/app/auth-server.jar"]