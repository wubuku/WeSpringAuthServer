# API 与 OAuth2 流程测试

> **Purpose**: API 测试与集成文档的导航。已有文档保持原位，本页只做链接。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 新增测试脚本或集成指南即补一行；不复制正文。

## 起点

- Base URL：`http://localhost:9000`（`SERVER_PORT` 可覆盖）
- 测试页面：`/oauth2-test`（授权码 + PKCE 全流程）
- 认证方式：表单登录（Session）、JWT Bearer、`/api/**` 与 `/auth-srv/**` 需 BASIC + `ROLE_ADMIN`
- 完整说明见 [根目录 README.md](../../README.md)

## 集成指南

| 主题 | 文档 |
|------|------|
| OAuth2 客户端集成（含 Web 前端） | [oauth2-client-integration-guide.md](../oauth2-client-integration-guide.md) |
| 资源服务器集成 | [resource-server-integration-guide.md](../resource-server-integration-guide.md) |
| 合作伙伴门户客户端接入 | [partner-portal-client-integration.md](../drafts/partner-portal-client-integration.md) |
| 测试用户与 Token 准备 | [测试数据准备.md](../drafts/测试数据准备.md) |

## 可执行脚本

完整索引见 [scripts/README.md](../../scripts/README.md)。常用：

    bash scripts/test.sh                        # 授权码流程
    bash scripts/get-test-user-tokens.sh        # 批量获取测试用户 Token
    bash scripts/test-sms-login.sh 13800138000  # 短信登录端到端
    bash scripts/test-wechat-login.sh           # 微信登录
    bash scripts/verify-oauth2-security.sh      # OAuth2 安全配置验证
    bash scripts/test-permissions.sh            # 权限系统测试

`test.sh` 与 `get-test-user-tokens.sh` 已于 2026-11-26 加固：临时产物隔离在 `mktemp` 目录并退出清理；`TEST_OUTPUT_DIR` 控制令牌输出目录；汇总文件默认 `scripts/all-test-tokens.env`、原子写入并 `chmod 600`，支持 `-o/--output`、`-r/--refresh`、`-d/--decode`；任一用户失败返回非零退出码。细节见 [scripts/README.md](../../scripts/README.md)。

> 令牌、验证码等敏感值只存在于运行时环境，不得写入文档或提交的环境文件。
