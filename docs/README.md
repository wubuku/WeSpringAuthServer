# 文档导航

> **Purpose**: 全项目文档入口。已有文档保持原位，本页只做归类与链接，不复制正文。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 新增文档即补索引行；细节写在对应文档。

## 文档目录

| 目录 | 说明 |
|------|------|
| [development-guides/](development-guides/) | 本地搭建、启动、配置、数据准备 |
| [technology-stack/](technology-stack/) | 技术栈与关键机制（OAuth2、JWT、权限、第三方登录） |
| [api-testing/](api-testing/) | API 与 OAuth2 流程测试、集成指南 |
| [operations-guides/](operations-guides/) | 部署、密钥、Docker、运维 |
| [drafts/](drafts/) | 活跃草稿、安全审计与实施规划 |
| [archive/](archive/) | 归档文档（按需创建） |

## 已有文档：按主题归类（链接，不移动）

### 入门与规则

| 主题 | 文档 |
|------|------|
| 人类落地页 / 快速开始 | [根目录 README.md](../README.md) |
| Agent 导航入口 | [AGENTS.md](../AGENTS.md) |
| 共享速查手册 | [CLAUDE.md](../CLAUDE.md) |
| 项目须知与安全架构 | [.agent.md](../.agent.md) |
| 开发与安全规则（改代码前必读） | [.cursorrules](../.cursorrules) |
| 文档体系建设规范 | [project-docs SKILL](../.agents/skills/project-docs/SKILL.md) |
| 测试/运维脚本索引 | [scripts/README.md](../scripts/README.md) |

### 开发与技术机制

| 主题 | 文档 |
|------|------|
| 数据库集成 | [database-integration-guide.md](database-integration-guide.md) |
| 配置重构记录 | [configuration-refactoring-summary.md](configuration-refactoring-summary.md) |
| 数据文件重构 | [data-files-restructure-summary.md](data-files-restructure-summary.md) |
| 密码编码器 API | [password-encoder-api-guide.md](password-encoder-api-guide.md) |
| OAuth2 Jackson 序列化修复 | [oauth2-jackson-serialization-fix.md](oauth2-jackson-serialization-fix.md) |
| 权限重构（permissions → authority_definitions） | [refactoring-permissions-to-authority-definitions.md](refactoring-permissions-to-authority-definitions.md) |
| 待办与重构清单 | [TODOs-refactor-list.md](TODOs-refactor-list.md) |
| Chrome DevTools 自动工作区 | [chrome-devtools-automatic-workspace-explained.md](chrome-devtools-automatic-workspace-explained.md) |

### 集成与测试

| 主题 | 文档 |
|------|------|
| OAuth2 客户端集成（含 Web 前端） | [oauth2-client-integration-guide.md](oauth2-client-integration-guide.md) |
| 资源服务器集成 | [resource-server-integration-guide.md](resource-server-integration-guide.md) |
| 微信小程序登录集成 | [wechat-miniprogram-auth-integration.md](wechat-miniprogram-auth-integration.md) |
| 示例资源服务器 | [example-resource-server/README.md](../example-resource-server/README.md) |
| 短信登录 Demo | [sms-login-demo/README.md](../sms-login-demo/README.md) |
| 微信测试脚本说明 | [scripts/README-wechat-test.md](../scripts/README-wechat-test.md) |

### 草稿与规划

- 全部草稿、安全审计与阶段性总结见 [drafts/README.md](drafts/README.md)；文档体系建设规划见 [DOCUMENTATION_PLAN.md](drafts/DOCUMENTATION_PLAN.md)。

## 快速导航

- [AGENTS.md](../AGENTS.md) — Agent 入口与约束
- [CLAUDE.md](../CLAUDE.md) — 日常速查
- [.cursorrules](../.cursorrules) — 修改代码前必读
- [scripts/README.md](../scripts/README.md) — 可执行验证脚本
