### WeSpring Auth Server 重构与待办事项清单（持续更新）

面向：维护者与贡献者。目标：减少重复、统一安全策略、优化可维护性与可测试性。

---

## 1. Refresh Token 端点/逻辑去重与统一

- 现状：
  - `SmsLoginController` 暴露：`POST /sms/refresh-token`
  - `SocialLoginController` 暴露：`POST /wechat/refresh-token`
  - `WebTokenController` 在授权码交换时自行处理 Cookie 模式（`handleCookieModeResponse`），方式与上述两处相似但非复用。

- 问题：刷新逻辑与 Cookie 写入存在重复实现，维护成本高，行为不一致风险大。

- 待办：
  - [ ] 抽取统一的 `RefreshTokenController`（建议路径：`POST /oauth2/refresh-token`），内部复用 `OAuth2AuthenticationHelper.processRefreshToken(...)` 与 `CookieSecurityConfig`。
  - [ ] 在 `SmsLoginController` 与 `SocialLoginController` 中保留现有端点但转发到统一控制器（标注弃用计划）。
  - [ ] `WebTokenController` 的 Cookie 模式响应改为复用统一的“写 Cookie + 去除 refresh_token”工具方法（见第 2 节）。

---

## 2. Token 响应 Cookie 模式处理统一化

- 现状：
  - `SmsLoginController` / `SocialLoginController` 登录成功后：设置 HttpOnly Cookie + 调用 `OAuth2AuthenticationHelper.writeTokenResponse(..., cookieMode=true)`。
  - `WebTokenController`：单独实现了 `handleCookieModeResponse(...)` 来写入 Cookie 并移除响应体中的 refresh_token。

- 待办：
  - [ ] 在 `OAuth2AuthenticationHelper` 中新增公共方法：`writeCookieModeRefreshToken(HttpServletResponse, String refreshToken)` 与 `stripRefreshTokenFromBody(String json)` 或直接提供 `buildCookieModeResponse(...)`。
  - [ ] `WebTokenController` 改为调用公共方法，删除重复逻辑。

---

## 3. CookieSecurityConfig 配置与实现对齐

- 现状：
  - `CookieSecurityConfig.CookieHelper` 将 Cookie `maxAge` 写死为 30 天。
  - `CookieSecurityConfigManager` 具备 `oauth2.cookie.max-age`、`same-site` 等配置读取与校验，但 `CookieHelper` 未使用。

- 待办：
  - [ ] 让 `CookieHelper` 通过注入 `CookieSecurityConfigManager` 获取 `domain/secure/sameSite/maxAge`，移除硬编码 30 天。
  - [ ] 统一日志与校验位置，避免重复输出与分散校验逻辑。
  - [ ] 当 `SameSite=None` 时强制 `Secure=true`（运行期保护）。

---

## 4. API 参数命名与路径一致性

- 现状：
  - `/sms/refresh-token` 与 `/wechat/refresh-token` 的请求参数命名存在差异（如 `client_id` vs `clientId`）。
  - 登录端点存在别名 `/sms/auth` 与 `/sms/login`。

- 待办：
  - [ ] 制定统一命名规范（外部公开端点尽量遵循 OAuth 规范：`client_id`、`grant_type` 等）。
  - [ ] 保留别名的同时，在响应 Header 中加 `Deprecation` 与 `Link`（RFC 8594）提示迁移路径与截止期。

---

## 5. 日志安全与降噪

- 现状：
  - 多处日志打印 token 前缀（前 20 个字符）。

- 待办：
  - [ ] 将包含敏感 token 片段的日志降级为 `DEBUG` 并默认关闭；`INFO` 及以上不包含任何 token 片段。
  - [ ] 统一使用掩码工具类（如 `TokenMasker.mask(String)`）。

---

## 6. 安全配置与链路核对（非功能改动）

- 待办：
  - [ ] 核对 `SecurityConfig` 的多 FilterChain 配置：确保 `/sms/**`、`/wechat/**` 走无状态链；管理端 `/auth-srv/**` 要求 `ROLE_ADMIN`。
  - [ ] 确保 CSRF 对无状态 API 关闭，对基于表单的管理界面保留。
  - [ ] 核查新增/重构端点的权限与匹配器，避免“临时 permitAll”。

---

## 7. Token TTL 与 Cookie 过期对齐策略

- 现状：
  - Access/Refresh TTL 配置在 DB 的 `oauth2_registered_client.token_settings`；Cookie `maxAge` 独立配置。

- 待办：
  - [ ] 明确策略：`refresh_token` TTL >= Cookie `maxAge`；否则可能出现 Cookie 存在但服务器端 refresh_token 已失效的错配。
  - [ ] 提供校验或启动告警：当两者不一致时记录 `WARN` 并给出建议值。

---

## 8. 控制器间认证流程复用

- 现状：
  - `SmsLoginController` 与 `SocialLoginController` 登录成功后的 token 持久化与 Cookie 写入逻辑高度相似。

- 待办：
  - [ ] 在 `OAuth2AuthenticationHelper` 中增加统一的“登录后处理”方法（创建 `TokenPair`、保存 `Authorization`、设置 Cookie、写安全响应）。
  - [ ] 控制器仅负责参数校验与调用服务层，减少控制器中业务细节。

---

## 9. 单元与集成测试补齐

- 待办：
  - [ ] 增加 MockMvc 测试：`/sms/auth`、`/wechat/login`、`/oauth2/refresh-token`（Cookie 模式）。
  - [ ] 增加 Cookie 属性断言（`Domain/Secure/SameSite/Max-Age`）。
  - [ ] 增加 TTL 行为测试（access_token 过期 → refresh → 成功续期）。

---

## 10. 文档与脚本同步

- 待办：
  - [ ] 更新 `docs/wechat-miniprogram-auth-integration.md`：引用统一的刷新端点与参数命名规范。
  - [ ] 更新 `scripts/test-sms-login.sh`：增加对统一刷新端点的测试路径，保留旧端点测试作为回归用例（到弃用截止期）。

---

## 11. 配置与 Linter 清单

- 待办：
  - [ ] 清理或注解说明 `application.yml` 中自定义命名空间（如 `oauth2.*`、`auth-server.*`、`sms.*`）的 linter 告警来源，避免误导读者为“未知属性错误”。
  - [ ] 将关键自定义配置提炼为 `@ConfigurationProperties` Bean（如 `CookieProperties`、`SmsProperties`），提升类型安全与自动提示。

---

## 12. 兼容性与弃用计划

- 待办：
  - [ ] 给 `/sms/refresh-token` 与 `/wechat/refresh-token` 添加响应 Header：`Deprecation: true` 与 `Link: <.../oauth2/refresh-token>; rel="successor-version"`。
  - [ ] 在版本发布说明中标注弃用时间与迁移步骤，预留双轨期（例如 2 个小版本）。

---

如需按此清单分阶段实施，可先完成 1、2、3 三项（高价值去重），随后推进 6、7、9（安全与质量），最后同步 10、12（对外沟通）。


