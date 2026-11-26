# 开发指南

> **Purpose**: 本地搭建、启动与日常开发文档的导航。已有文档保持原位，本页只做链接。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 新增指南即补一行，正文写在被链接的文档中。

## 环境与启动

| 主题 | 文档 / 入口 |
|------|-------------|
| 环境要求、四种启动方式、生产部署 | [根目录 README.md](../../README.md) |
| 日常速查（命令、端口、注意事项） | [CLAUDE.md](../../CLAUDE.md) |
| 一键开发启动脚本（含参数说明） | `./dev.sh --help`；脚本索引见 [scripts/README.md](../../scripts/README.md) |
| 环境变量样例 | [.env.example](../../.env.example)（首次 `cp .env.example .env`） |

## 数据与配置

| 主题 | 文档 |
|------|------|
| 数据库集成指南 | [database-integration-guide.md](../database-integration-guide.md) |
| 配置重构记录 | [configuration-refactoring-summary.md](../configuration-refactoring-summary.md) |
| 数据文件结构调整 | [data-files-restructure-summary.md](../data-files-restructure-summary.md) |
| 密码编码与生成测试密码 | [password-encoder-api-guide.md](../password-encoder-api-guide.md) |
| 测试数据准备 | [测试数据准备.md](../drafts/测试数据准备.md) |
| 测试用户与权限 SQL | [insert-test-users.sql](../../scripts/insert-test-users.sql) |

## 常用命令

    ./mvnw clean package -DskipTests
    ./mvnw test -Dtest=<TestClass>
    ./dev.sh                      # 默认 dev profile，端口 9000

> 版本、主类与依赖以 [pom.xml](../../pom.xml) 为准；README/.agent.md 中旧版本号为历史记录。
