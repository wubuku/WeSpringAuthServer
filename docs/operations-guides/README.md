# 运维与部署指南

> **Purpose**: 部署、密钥与运维文档的导航。已有文档保持原位，本页只做链接。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 部署方式或密钥流程变更时更新对应文档并同步本页索引。

## 部署入口

| 主题 | 文档 / 位置 |
|------|-------------|
| 生产部署步骤、Docker Compose、健康检查 | [根目录 README.md — 生产环境部署](../../README.md) |
| 生产配置生成工具 | [scripts/generate-production-config.sh](../../scripts/generate-production-config.sh) |
| 本地环境变量样例 | [.env.example](../../.env.example) |
| JWT 密钥库生成 | [scripts/generate-jwt-keystore.sh](../../scripts/generate-jwt-keystore.sh) |
| 本地 Docker 构建 | [scripts/docker-build-local.sh](../../scripts/docker-build-local.sh) |
| CI 构建推送工作流 | [docker-build-push.yml](../../.github/workflows/docker-build-push.yml) |
| 生产密钥目录 | `production-keys/`（**不得提交**） |

## 健康检查与验证

    curl http://localhost:9000/actuator/health
    curl http://localhost:9000/.well-known/oauth-authorization-server
    curl http://localhost:9000/.well-known/openid_configuration

## 历史与安全记录

| 主题 | 文档 |
|------|------|
| 项目独立化状态 | [project-independence-status.md](../drafts/project-independence-status.md) |
| HttpOnly Cookie 安全实施计划 | [oauth2-安全修复短期方案-HttpOnly-Cookie实施计划.md](../drafts/oauth2-安全修复短期方案-HttpOnly-Cookie实施计划.md) |
| 安全修复总结 | [security-fixes-summary.md](../drafts/security-fixes-summary.md) |
| 项目关键检查点 | [.cursorrules](../../.cursorrules) |

> 生产环境强制 HTTPS Cookie、严格 CORS 域名限制；所有敏感值通过环境变量注入。
