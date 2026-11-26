# 技术栈与关键机制

> **Purpose**: 认证授权服务器核心机制的文档导航。已有文档保持原位，本页只做链接。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 机制变更时更新对应文档并同步本页索引。

## 事实基线

Java 17 / Spring Boot 3.4.6 / Spring Security 6.2.0 / Spring Authorization Server 1.3.6 / PostgreSQL，详见 [pom.xml](../../pom.xml)。

## 核心机制

| 主题 | 文档 |
|------|------|
| OAuth2 Session vs JWT 深度分析 | [oauth2-session-vs-jwt-comprehensive-analysis.md](../drafts/oauth2-session-vs-jwt-comprehensive-analysis.md) |
| STATELESS 方案研究 | [Spring_Authorization_Server_STATELESS方案研究.md](../drafts/Spring_Authorization_Server_STATELESS方案研究.md) |
| JWT 自定义 Claims 的 Jackson 序列化修复 | [oauth2-jackson-serialization-fix.md](../oauth2-jackson-serialization-fix.md) |
| 层级权限体系与 `authority_definitions` 重构 | [refactoring-permissions-to-authority-definitions.md](../refactoring-permissions-to-authority-definitions.md) |
| 微信登录集成 | [wechat-miniprogram-auth-integration.md](../wechat-miniprogram-auth-integration.md) |
| 阿里云短信服务集成 | [阿里云短信服务_Spring_Boot_集成指南.md](../drafts/阿里云短信服务_Spring_Boot_集成指南.md) |
| 短信供应商切换 | [阿里云短信服务切换指南.md](../drafts/阿里云短信服务切换指南.md) |
| HttpOnly Cookie 安全方案（已实施） | [OAuth2-安全修复短期方案-完成总结与评估.md](../drafts/OAuth2-安全修复短期方案-完成总结与评估.md) |

## 代码位置速查

| 机制 | 位置 |
|------|------|
| 三条安全过滤链 | `src/main/java/org/dddml/ffvtraceability/auth/config/SecurityConfig.java` |
| 授权服务器（JWT/JWKS） | `src/main/java/org/dddml/ffvtraceability/auth/config/AuthorizationServerConfig.java` |
| 认证 Provider / Filter | `src/main/java/org/dddml/ffvtraceability/auth/authentication/` |
| 数据库 Schema | `src/main/resources/schema.sql` |
