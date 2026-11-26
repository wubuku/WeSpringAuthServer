# WeSpringAuthServer — Agent 导航

> **Purpose**: AI Agent 进入本项目的统一入口。地图，不是手册。
> **Updated by**: 未记录（人工维护）。
> **Update rule**: 结构或文档增减时同步更新索引；细节写在对应文档，不在此堆积。

## 1. 项目概览

- **类型**：独立 Spring Boot OAuth2 认证授权服务器（FFV Traceability 系统）
- **技术栈**：Java 17 / Spring Boot **3.4.6** / Spring Security 6.2.0 / Spring Authorization Server **1.3.6** / PostgreSQL / JdbcTemplate（**以 `pom.xml` 为准**；`README.md`、`.agent.md` 中 3.2.0、1.5.0 为历史值）
- **状态**：多认证方式（密码/短信/微信）、PKCE、JWT、层级权限与生产部署配置已就绪；服务端口 **9000**
- **主类**：`org.dddml.ffvtraceability.auth.AuthServerApplication`

## 2. 文档索引

- [README.md](README.md) — 人类落地页（特性、部署、测试流程）
- [CLAUDE.md](CLAUDE.md) — 共享速查手册
- [docs/README.md](docs/README.md) — 文档导航中心（全量文档索引）
- [.agent.md](.agent.md) — 项目须知与安全架构
- [.cursorrules](.cursorrules) — 开发与安全规则（**修改代码前必读**）
- [.agents/skills/project-docs/](.agents/skills/project-docs/) — 文档体系建设与维护规范
- [scripts/README.md](scripts/README.md) — 测试/运维脚本索引

## 3. 快速命令

    # 首次：cp .env.example .env（按实际情况填写），需本地 PostgreSQL
    build:   ./mvnw clean package -DskipTests
    test:    ./mvnw test                       # 单类：./mvnw test -Dtest=<TestClass>
    run:     ./dev.sh                          # 构建+启动+健康检查+抓取测试 Token
    verify:  curl http://localhost:9000/actuator/health
    stop:    ./dev.sh stop

## 4. 模块概览

| 模块 | 路径 | 职责 |
|------|------|------|
| 入口 | `src/main/java/.../AuthServerApplication.java` | Spring Boot 启动类 |
| authentication | `src/main/java/.../authentication/` | 密码/短信/微信认证 Provider、Filter、Token |
| config | `src/main/java/.../config/` | 授权服务器、三条 SecurityFilterChain、Cookie、JWT、CORS |
| controller | `src/main/java/.../controller/` | 用户/组/权限管理 API 与登录/测试页面 |
| service | `src/main/java/.../service/` | 用户、微信、OAuth2 辅助与短信供应商 |
| security / dto / mapper / exception | `src/main/java/.../` 同名子包 | 扩展用户详情、DTO、JDBC Mapper、全局异常处理 |
| 资源 | `src/main/resources/` | `application*.yml`、`schema.sql`、`data*.sql`、`keys/`、Thymeleaf 模板 |
| 脚本 | `scripts/` | 授权码流程、Token 获取、安全验证、Docker 构建脚本 |

## 5. Agent 约束

- **BEFORE**：修改代码/配置前读 `.cursorrules` 与 `CLAUDE.md`；涉及代码、数据库、接口、权限、迁移或部署的变更，先在 `docs/drafts/` 写规划并完成三轮收敛（见文档体系技能的"规划先行"）。
- **DO NOT**：提交 `.env` / `.env.prod` / `production-keys/` / `scripts/*.env`；在日志或文档中写 token、验证码、密码、密钥真实值；为"归类"而移动已有文档。
- **ALWAYS**：改权限/Schema/OAuth2 配置后跑相关测试与 `scripts/verify-oauth2-security.sh`；新增文档后立即更新本文件与 `docs/README.md`；事实冲突以 `pom.xml` 和代码为准。

## 6. 维护规则

- 新增文档 → 补 `docs/README.md` 索引，并 `git add` 该文件。
- 文档问题 → 修对应文档，不在本文件堆内容；本文件保持 ≤120 行。
- 已有文档保持原位，只做链接与增量修改；不要新建 `.cursor/rules/`（规则在单文件 `.cursorrules`）。
- 本机缓存（`.workbuddy/memory/` 等）不是共享事实来源，不得作为唯一依据。
