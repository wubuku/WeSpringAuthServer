# 数据文件重构总结

## 🎯 重构目标

解决原始 `data.sql` 文件混合了基础数据和测试数据的问题，实现：
- ✅ 基础数据与测试数据分离
- ✅ 支持多环境配置
- ✅ 生产环境安全性提升
- ✅ 开发测试便利性保持

## 📁 新的文件结构

```
src/main/resources/
├── data-base.sql          # 🔵 纯基础数据（仅权限定义和用户组）
├── data-dev.sql           # 🟡 开发环境数据（admin用户+OAuth2客户端+测试数据）
├── data-prod.sql          # 🟢 生产环境数据（生产特定配置）
├── data.sql               # ⚪ 原文件（已标记重构，保留兼容性）
├── application.yml        # 默认配置（仅基础数据）
├── application-dev.yml    # 开发环境配置
└── application-prod.yml   # 生产环境配置
```

## 🔵 data-base.sql - 纯基础数据

**包含内容**：
- ✅ 基础用户组：`ADMIN_GROUP`, `USER_GROUP`
- ✅ 基础权限定义：`ROLE_ADMIN`, `ROLE_USER`, `Users_Read`, `Roles_Read` 等

**不包含**：
- ❌ 任何用户账户（包括admin）
- ❌ OAuth2客户端配置
- ❌ 测试数据

**设计理念**：生产环境可以安全加载的最小数据集

## 🟡 data-dev.sql - 开发环境数据

**包含内容**：
- ✅ **admin用户**（密码：admin）
- ✅ **OAuth2客户端配置**（开发环境回调地址）
- ✅ **项目特定用户组**：`HQ_ADMIN_GROUP`, `DISTRIBUTOR_ADMIN_GROUP` 等
- ✅ **测试用户**：`hq_admin`, `distributor_admin`, `store_admin` 等
- ✅ **业务权限定义**：`Vendors_Read`, `Items_Read`, `Procurement_Read` 等
- ✅ **用户标识测试数据**

**设计理念**：开发和测试阶段需要的完整数据集

## 🟢 data-prod.sql - 生产环境数据

**包含内容**：
- ✅ 生产环境特定配置（当前为空）
- ✅ 生产环境OAuth2客户端示例（注释状态）

**设计理念**：生产环境特定的安全配置

## ⚙️ 配置文件对应关系

### application.yml（默认）
```yaml
spring:
  sql:
    init:
      data-locations:
        - classpath:data-base.sql  # 仅基础权限定义
```
**适用场景**：最小化启动，仅加载权限框架

### application-dev.yml（开发环境）
```yaml
spring:
  sql:
    init:
      mode: always
      data-locations:
        - classpath:data-base.sql  # 基础数据
        - classpath:data-dev.sql   # + 开发测试数据
```
**适用场景**：开发和测试环境，包含完整的测试用户和权限

### application-prod.yml（生产环境）
```yaml
spring:
  sql:
    init:
      mode: never  # 🔒 安全：不自动执行SQL
      data-locations:
        - classpath:data-base.sql
        - classpath:data-prod.sql
```
**适用场景**：生产环境，需要手动管理用户和客户端

## 🚀 使用方式

### 开发环境启动
```bash
# 方式1：使用profile
export SPRING_PROFILES_ACTIVE=dev
./start.sh

# 方式2：直接指定
./mvnw spring-boot:run -Dspring.profiles.active=dev
```

### 生产环境启动
```bash
export SPRING_PROFILES_ACTIVE=prod
java -jar ffvtraceability-auth-server.jar
```

### 自定义数据加载
```bash
# 如果需要特定的数据组合
export SPRING_PROFILES_ACTIVE=dev
export SQL_INIT_MODE=always
./mvnw spring-boot:run
```

## 🔒 安全改进

### 生产环境安全
- ✅ **无默认用户**：生产环境不会自动创建admin用户
- ✅ **无默认客户端**：避免使用开发环境的OAuth2配置
- ✅ **手动控制**：`mode: never` 要求手动执行数据初始化
- ✅ **密码安全**：生产环境必须手动设置强密码

### 开发环境便利
- ✅ **即开即用**：包含完整的测试用户和权限
- ✅ **测试友好**：包含各种角色的测试用户
- ✅ **OAuth2就绪**：预配置的客户端可直接测试

## 📋 迁移检查清单

### 立即可用
- [x] 新文件结构已创建
- [x] 配置文件已更新
- [x] 向后兼容性保持

### 建议验证
- [ ] 使用 `dev` profile 启动，验证admin用户可登录
- [ ] 使用 `prod` profile 启动，验证无默认用户
- [ ] 运行 `./scripts/test-permissions.sh` 验证权限配置
- [ ] 测试OAuth2授权流程

### 生产部署前
- [ ] 手动创建生产环境管理员用户
- [ ] 配置生产环境OAuth2客户端
- [ ] 设置强密码和安全的client_secret
- [ ] 验证 `mode: never` 配置生效

## 🔄 环境变量覆盖

### 支持的覆盖
```bash
# Profile切换
export SPRING_PROFILES_ACTIVE=dev|prod

# SQL执行模式
export SQL_INIT_MODE=always|never

# 数据库配置
export DB_HOST=localhost
export DB_NAME=ffvtraceability
export DB_USERNAME=postgres
export DB_PASSWORD=your_password
```

### 不支持的覆盖
```bash
# ❌ 数组类型无法直接覆盖
export SPRING_SQL_INIT_DATA_LOCATIONS="classpath:custom.sql"
```

### 解决方案
使用profile机制或创建自定义的application-{profile}.yml文件

## 📝 总结

这次重构彻底解决了数据文件的安全性和可维护性问题：

1. **安全性提升**：生产环境不再包含默认用户和测试配置
2. **开发便利**：开发环境保持完整的测试数据
3. **配置清晰**：每个环境的数据需求明确分离
4. **向后兼容**：现有部署不受影响

现在可以安全地在生产环境部署，同时保持开发环境的便利性！