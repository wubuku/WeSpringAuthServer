# 文档模板（WeSpringAuthServer 适配版）

> 模板中的 `{占位符}` 需按当前代码与 `pom.xml` 替换。**不要**把模板里的示例命令当成已验证命令直接照抄。
> 已有文件（`README.md`、`CLAUDE.md`、`.agent.md`、`.cursorrules`）保持原位，模板仅用于新建或增量修改。

---

## AGENTS.md 模板（P0，≤120 行）

```markdown
# WeSpringAuthServer — Agent 导航

> **Purpose**: AI Agent 进入项目的统一入口。
> **Updated by**: 人工维护（未记录具体流程）。
> **Update rule**: 新增文档或结构变化时同步更新索引；细节写在对应文档，不写在这里。

## 1. 项目概览
- 类型：独立 Spring Boot OAuth2 认证授权服务器（FFV Traceability 系统）
- 技术栈：Java 17 / Spring Boot 3.4.6 / Spring Security 6.2.0 / Spring Authorization Server 1.3.6 / PostgreSQL（以 `pom.xml` 为准）
- 状态：生产配置与多认证方式已就绪；主端口 9000

## 2. 文档索引
- [README.md](README.md) — 人类落地页
- [CLAUDE.md](CLAUDE.md) — 共享速查手册
- [docs/README.md](docs/README.md) — 文档导航中心
- [.agent.md](.agent.md) / [.cursorrules](.cursorrules) — 开发与安全规则
- [.agents/skills/project-docs/](.agents/skills/project-docs/) — 文档体系技能

## 3. 快速命令

    build:   ./mvnw clean package -DskipTests
    test:    ./mvnw test
    run:     ./dev.sh
    verify:  curl http://localhost:9000/actuator/health

## 4. 模块概览

| 模块 | 路径 | 职责 |
|------|------|------|
| authentication | src/main/java/.../authentication/ | 短信/微信/密码认证 Provider 与 Filter |
| config | src/main/java/.../config/ | 授权服务器、安全过滤链、Cookie、JWT |
| controller | src/main/java/.../controller/ | 用户/组/权限管理与登录接口 |
| service | src/main/java/.../service/ | 业务服务与短信供应商 |
| resources | src/main/resources/ | application*.yml、schema.sql、data*.sql、模板 |

## 5. Agent 约束

- **BEFORE**：改代码前读 `.cursorrules` 与 `CLAUDE.md`；涉及行为变更先在 `docs/drafts/` 写规划并三轮收敛
- **DO NOT**：提交 `.env` / `.env.prod` / `production-keys/`；在日志或文档中写 token、验证码、密码
- **ALWAYS**：改权限/Schema/OAuth2 配置后跑相关测试与 `scripts/verify-oauth2-security.sh`

## 6. 维护规则
- 新增文档 → 同时更新本文件与 `docs/README.md`
- 文档问题 → 修对应文档，不在本文件堆内容
```

---

## CLAUDE.md / 速查模板（已存在文件按需增量修改）

```markdown
# CLAUDE.md - 共享速查手册

> **Purpose**: 跨机器共享的日常开发、测试、排查快速参考。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 事实以 `pom.xml` / 代码为准；版本漂移时修正，不照抄旧值。

## 核心工作流
1. 启动：`./dev.sh`（构建 + 健康检查 + 抓取测试 Token）
2. 验证：`./mvnw test` + `curl` 端点
3. 按主题跑 `scripts/test-*.sh`
4. 改代码前读 `.cursorrules`

## 关键命令

    ./mvnw clean package -DskipTests
    ./mvnw test -Dtest=<TestClass>
    ./dev.sh status | logs | stop | restart

## 服务与端口

| 服务 | 端口 | 启动方式 |
|------|------|----------|
| Auth Server | 9000 | `./dev.sh` 或 `./mvnw spring-boot:run` |
| PostgreSQL | 5432 | 本地/容器，见 `application.yml` |

## 高频注意事项
- `/api/**`、`/auth-srv/**` 需要 `ROLE_ADMIN`
- 敏感信息通过环境变量注入，不写入仓库
- 模板中的 Spring Boot 版本以 `pom.xml` 为准
```

---

## docs/README.md 模板（P1）

```markdown
# 文档导航

> **Purpose**: 全项目文档入口。已有文档保持原位，本页只做归类与链接。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 新增文档即补一行索引；不复制正文。

## 文档目录

| 目录 | 说明 |
|------|------|
| [development-guides/](development-guides/) | 本地搭建、启动、配置 |
| [technology-stack/](technology-stack/) | 技术栈与关键机制 |
| [api-testing/](api-testing/) | API 与 OAuth2 流程测试 |
| [operations-guides/](operations-guides/) | 部署、密钥、运维 |
| [drafts/](drafts/) | 草稿与实施规划 |
| [archive/](archive/) | 归档（按需） |

## 已有文档归类

| 主题 | 文档 |
|------|------|
| 快速开始 / 部署 | [根目录 README.md](../README.md) |
| 共享速查 | [CLAUDE.md](../CLAUDE.md) |
| 开发规则 | [.cursorrules](../.cursorrules)、[.agent.md](../.agent.md) |
| 脚本索引 | [scripts/README.md](../scripts/README.md) |

## 快速导航
- [AGENTS.md](../AGENTS.md) — Agent 入口
- [文档体系技能](../.agents/skills/project-docs/SKILL.md) — 维护规范
```

---

## docs/drafts/README.md 模板

```markdown
# 草稿文档索引

> **Purpose**: 活跃迭代的设计、审计与实施规划索引。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 新增草稿即补一行（文件名 + 一句话说明 + 最后更新）。

## 规划与实施

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [DOCUMENTATION_PLAN.md](DOCUMENTATION_PLAN.md) | 文档体系审计与建设规划 | YYYY-MM-DD |

## 安全与认证

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [xxx.md](xxx.md) | 一句话说明 | YYYY-MM-DD |

## 命名规范
- 设计：` <topic>-design.md`；实施：`<component>-plan.md`；进度：`<component>-progress.md`
- 历史草稿可加 `YYYY-MM-DD_` 前缀
- 完成并稳定 2 周后按归档规则移入 `../archive/`
```

---

## docs/archive/README.md 模板

```markdown
# 归档文档

> **Purpose**: 历史文档索引，仅供参考，不再维护。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 归档时补一行，原文件删除并更新引用。

## 归档规则
1. 功能完全实现 + 设计稳定 2 周以上无变更 → 归档
2. 文件名加最后相关日期前缀：`YYYY-MM-DD_<原名>.md`

## 归档索引

| 日期 | 文件 | 说明 |
|------|------|------|
| YYYY-MM-DD | [YYYY-MM-DD_xxx.md](YYYY-MM-DD_xxx.md) | 说明 |
```

---

## 规则文件模板（.cursorrules 增量维护）

本项目**不使用** `.cursor/rules/*.mdc` 目录；新增规则直接增量写入根目录 `.cursorrules`，避免双源。

```markdown
## 规则标题
- 规则正文（清晰、可执行），必要时给出正反例
```

---

## Architecture 模板

```markdown
# 架构设计

> **Purpose**: 认证授权服务器的架构与关键决策。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 代码/配置变化后同步更新；版本以 `pom.xml` 为准。

## 设计原则

| 原则 | 说明 |
|------|------|
| 单一授权服务器 | 集中认证，资源服务器通过 JWT 校验 |
| 最小权限 | `/api/**`、`/auth-srv/**` 需要 `ROLE_ADMIN` |
| 敏感信息隔离 | 密钥/令牌只在环境与运行时存在 |

## 系统概览

    Client → /oauth2/authorize (PKCE) → login (密码/短信/微信)
          → /oauth2/token → JWT (自定义 claims)
          → Resource Server

## 安全过滤链

| 过滤链 | 路径 | 策略 |
|--------|------|------|
| mobileApiSecurityFilterChain | /sms/**, /wechat/** | STATELESS, permitAll |
| webApiSecurityFilterChain | /api/**, /auth-srv/** | BASIC, ADMIN |
| defaultSecurityFilterChain | 其他 | 表单登录 |

## 数据库关键表

| 表 | 用途 |
|----|------|
| users / authorities | Spring Security 标准用户与权限 |
| authority_definitions | 层级权限定义（树形） |
| oauth2_authorization | 授权与令牌 |
| sms_verification_codes | 短信验证码 |

## 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 权限粒度 | 新增 `authority_definitions` | 不改 Spring Security 原生 schema 支持树形权限 |
| Session | Spring Session JDBC | 支持集群 |
```

---

## Testing Guide 模板

```markdown
# 测试指南

> **Purpose**: 测试命令与分层策略。测试即生产代码。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 命令以实际执行为准；新增测试套件时补录。

## 快速命令

    ./mvnw test
    ./mvnw test -Dtest=<TestClass>
    bash scripts/test.sh
    bash scripts/get-test-user-tokens.sh

## 分层
- 单元：Service / Mapper 逻辑
- 集成：Controller + SecurityFilterChain + 数据库
- 端到端：授权码 + PKCE、短信登录、微信登录、Cookie 安全

## 覆盖目标

| 类型 | 目标 |
|------|------|
| 关键安全路径 | 必须有测试 |
| 变更触及的 Controller/Service | 集成测试覆盖 |
```

---

## Troubleshooting 模板

```markdown
# 故障排查指南

> **Purpose**: 按症状组织的诊断与解决步骤。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 从真实问题迭代添加，解决方案须验证过。

## 启动失败
**症状**：...
**诊断**：`./dev.sh logs`、检查 PostgreSQL 连通性、`application.yml` 配置
**解决**：...

## 权限异常（403）
**症状**：...
**诊断**：检查 `authorities` 表、`ROLE_ADMIN`、`SecurityConfig`
**解决**：...

## OAuth2 / Token 问题
**症状**：...
**诊断**：`curl` 端点、检查 issuer / redirect_uri / PKCE / Cookie
**解决**：...
```

---

## DOCUMENTATION_PLAN.md 模板

```markdown
# 文档体系建设规划

> **Purpose**: 文档审计结果、优先级与本期范围。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 体系调整时更新；完成项标注日期，不写流水账。

## 现状审计
- 已有：...（链接）
- 缺口：...
- 冲突/过时：...

## 本期目标（P0→P3）
- P0：...
- P1：...
- P2/P3：...

## 有意不做的项
- 不移动已有文档 → 用索引链接
- 不新建 `.cursor/rules/` → 规则在单文件 `.cursorrules`
- 不猜测 LICENSE → 待所有者确认

## 验证
- 链接检查：...
- 与代码一致性：...
```
