# 草稿文档索引

> **Purpose**: 活跃迭代的设计、安全审计与实施规划索引；已有草稿保持原位。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 新增草稿即补一行（文件名 + 说明 + 最后更新）；完成并稳定 2 周后按归档规则处理。

## 文档体系建设

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [DOCUMENTATION_PLAN.md](DOCUMENTATION_PLAN.md) | 文档体系审计、优先级与本期范围 | 2026-11-26 |

## 认证架构与 STATELESS 研究

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [oauth2-session-vs-jwt-comprehensive-analysis.md](oauth2-session-vs-jwt-comprehensive-analysis.md) | Session vs JWT 深度对比与技术验证 | 2025-06-11 |
| [technical-validation-report.md](technical-validation-report.md) | Spring Authorization Server 官方实现与可行性验证 | 2025-06-11 |
| [Spring_Authorization_Server_STATELESS方案研究.md](Spring_Authorization_Server_STATELESS方案研究.md) | STATELESS 架构方案研究 | 2025-06-11 |
| [step1-master-plan.md](step1-master-plan.md) | 第一步主方案（修改清单、验证方案） | 2025-06-11 |
| [step1-detailed-validation-plan.md](step1-detailed-validation-plan.md) | 端到端验证脚本与场景 | 2025-06-11 |
| [STATELESS-migration-progress.md](STATELESS-migration-progress.md) | 实施进度与里程碑 | 2025-06-11 |

## 安全审计与修复

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [oauth2-安全修复短期方案-HttpOnly-Cookie实施计划.md](oauth2-安全修复短期方案-HttpOnly-Cookie实施计划.md) | HttpOnly Cookie 实施计划 | 2025-07-03 |
| [OAuth2-安全修复短期方案-完成总结与评估.md](OAuth2-安全修复短期方案-完成总结与评估.md) | 安全修复完成总结与评估 | 2025-07-03 |
| [Phase1-完成总结与下一步指南.md](Phase1-完成总结与下一步指南.md) | Phase 1 完成总结 | 2025-07-03 |
| [Phase2-OAuth2-Cookie-Security-Implementation-Complete.md](Phase2-OAuth2-Cookie-Security-Implementation-Complete.md) | Phase 2 Cookie 安全实施完成 | 2025-07-03 |
| [api-security-audit-progress.md](api-security-audit-progress.md) | API 安全审计进度 | 2025-06-20 |
| [controller-security-detailed-review.md](controller-security-detailed-review.md) | Controller 安全详细审查 | 2025-06-20 |
| [proactive-security-analysis.md](proactive-security-analysis.md) | 主动安全分析 | 2025-06-20 |
| [remaining-security-assessment.md](remaining-security-assessment.md) | 剩余安全风险评估 | 2025-06-20 |
| [security-fixes-summary.md](security-fixes-summary.md) | 安全修复汇总 | 2025-06-20 |
| [refactoring-verification-checklist.md](refactoring-verification-checklist.md) | 重构验证清单 | 2025-06-19 |
| [template-pages-audit-progress.md](template-pages-audit-progress.md) | 模板页面审计进度 | 2025-06-19 |

## 登录方式与集成

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [sms-login-error-handling-improvement.md](sms-login-error-handling-improvement.md) | 短信登录错误处理改进 | 2025-10-28 |
| [sms-login-demo-Cookie安全模式升级完成总结.md](sms-login-demo-Cookie安全模式升级完成总结.md) | 短信登录 Demo Cookie 模式升级 | 2025-07-03 |
| [阿里云短信服务_Spring_Boot_集成指南.md](阿里云短信服务_Spring_Boot_集成指南.md) | 阿里云短信集成指南 | 2025-06-28 |
| [阿里云短信服务切换指南.md](阿里云短信服务切换指南.md) | 短信供应商切换指南 | 2025-06-28 |
| [partner-portal-client-integration.md](partner-portal-client-integration.md) | 合作伙伴门户客户端接入 | 2025-05-31 |

## 数据与前端方案

| 文件 | 说明 | 最后更新 |
|------|------|----------|
| [测试数据准备.md](测试数据准备.md) | 测试用户与权限数据准备 | 2025-06-25 |
| [测试数据准备-完成报告.md](测试数据准备-完成报告.md) | 测试数据准备完成报告 | 2025-06-25 |
| [user-identifications-display-plan.md](user-identifications-display-plan.md) | 用户标识展示方案 | 2025-06-20 |
| [极简微前端套件方案.md](极简微前端套件方案.md) | 微前端方案研究（历史提案） | 2025-07-15 |
| [project-independence-status.md](project-independence-status.md) | 项目从父模块独立的状态记录 | 2025-06-11 |

其他材料：`oauth2-security-env-config.example`、`test-data-for-user-identifications.sql`、`get_methods_test_summary.txt`。

## 技术概念澄清（保留原有结论）

- ✅ **STATELESS（无状态）认证架构** — 强调架构简化与无状态特性
- ❌ ~~"跨域认证"~~ — 认证本身无法跨域；API 跨域访问本来就支持
- 🔐 认证过程始终在授权服务器同域中安全进行（无论是否 STATELESS）

## 使用指南

1. 架构背景 → [oauth2-session-vs-jwt-comprehensive-analysis.md](oauth2-session-vs-jwt-comprehensive-analysis.md)
2. 安全现状 → [OAuth2-安全修复短期方案-完成总结与评估.md](OAuth2-安全修复短期方案-完成总结与评估.md)
3. 实施验证 → [step1-detailed-validation-plan.md](step1-detailed-validation-plan.md) 与 [scripts/README.md](../../scripts/README.md)
4. 完成并稳定 2 周后 → 移入 `../archive/` 并更新索引
