## WeSpring Auth Server 重构与待办事项清单（持续更新）

面向：维护者与贡献者。

目标：
- 减少重复、统一安全策略、优化可维护性与可测试性
- 遵循安全基线（管理端严格 `ROLE_ADMIN`、移动端 API 无状态、默认拒绝的保守策略）

范围：
- 涉及文件：`SecurityConfig.java`、`SmsLoginController`、`SocialLoginController`、`WebTokenController`、`OAuth2AuthenticationHelper`、`CookieSecurityConfig`、数据库表 `oauth2_registered_client`
- 涉及端点：`/sms/**`、`/wechat/**`、`/web-clients/oauth2/**`、计划新增 `/oauth2/refresh-token`

安全基线（必须遵守）：
- 管理 API `/auth-srv/**` 必须 `ROLE_ADMIN`
- 移动端 API 走无状态链，禁用 CSRF；不得使用宽松 `permitAll()` 替代授权控制
- 禁止在日志中输出明文凭证/完整 token；`refresh_token` 仅存储在 HttpOnly Cookie

使用方式：
- 先看“执行优先级总览”把控节奏
- 再按“安全加固工作流”并行推进各主题
- “功能重构与去重统一”与“配置与类型安全”在安全基础上实施
- “附录A”保留了全部细节项，便于逐条跟踪与签收

---

### 🔥 实施优先级（合并安全等级与功能阶段）

**🔴 P0 - 立即修复（安全漏洞）**：
- 23（移除 fallback 硬编码密钥）
- 22（SameSite=None 强制 Secure 检查）
- 26（验证/修正 FilterChain 路径匹配归属）

**🟠 P1 - 本周内修复（数据/信息安全）**：
- 21（为 OAuth2 相关数据库操作加事务与回滚）
- 24（异常信息脱敏与专用安全处理）
- 25（统一日志脱敏策略与等级）

**🟡 P2 - 下迭代修复（配置与一致性）**：
- 22（Cookie 配置动态化与运行时校验）、27（配置类型安全与校验）
- 13、14、15、16、17、18、19、20（其余安全项收束）

**🟢 P3 - 功能重构（去重统一）**：
- 1、2、3、4、5、6、7、8（功能整合、API 一致性、配置优化）

**📄 文档/脚本同步**：
- 9、10、11、12（测试、文档、配置、兼容性）

---

## 附录A：详细条目（完整清单 1–27）

### 1. Refresh Token 端点/逻辑去重与统一

- 现状：
  - `SmsLoginController` 暴露：`POST /sms/refresh-token`
  - `SocialLoginController` 暴露：`POST /wechat/refresh-token`
  - `WebTokenController` 在授权码交换时自行处理 Cookie 模式（`handleCookieModeResponse`），方式与上述两处相似但非复用。

- 问题：刷新逻辑与 Cookie 写入存在重复实现，维护成本高，行为不一致风险大。

- 待办：
  - [ ] 抽取统一的 `RefreshTokenController`（建议路径：`POST /oauth2/refresh-token`），内部复用 `OAuth2AuthenticationHelper.processRefreshToken(...)` 与 `CookieSecurityConfig`。
  - [ ] 在 `SmsLoginController` 与 `SocialLoginController` 中保留现有端点但转发到统一控制器（标注弃用计划）。
  - [ ] `WebTokenController` 的 Cookie 模式响应改为复用统一的“写 Cookie + 去除 refresh_token”工具方法（见第 2 节）。

验收标准：
- [ ] 统一端点具备与原端点一致的功能与返回结构（Cookie 模式）
- [ ] 原端点返回 `Deprecation` 与 `Link` Header，功能由统一端点承接
- [ ] 新老端点均通过集成测试（含 Cookie 与无 Cookie 回退路径）

---

### 2. Token 响应 Cookie 模式处理统一化

- 现状：
  - `SmsLoginController` / `SocialLoginController` 登录成功后：设置 HttpOnly Cookie + 调用 `OAuth2AuthenticationHelper.writeTokenResponse(..., cookieMode=true)`。
  - `WebTokenController`：单独实现了 `handleCookieModeResponse(...)` 来写入 Cookie 并移除响应体中的 refresh_token。

- 待办：
  - [ ] 在 `OAuth2AuthenticationHelper` 中新增公共方法：`writeCookieModeRefreshToken(HttpServletResponse, String refreshToken)` 与 `stripRefreshTokenFromBody(String json)` 或直接提供 `buildCookieModeResponse(...)`。
  - [ ] `WebTokenController` 改为调用公共方法，删除重复逻辑。

验收标准：
- [ ] 统一方法被三处调用（SMS/WeChat/Web），无重复代码
- [ ] 响应体不包含 `refresh_token`；`Set-Cookie` 正确（HttpOnly、Secure、SameSite、Domain、Max-Age）

---

### 3. CookieSecurityConfig 配置与实现对齐

- 现状：
  - `CookieSecurityConfig.CookieHelper` 将 Cookie `maxAge` 写死为 30 天。
  - `CookieSecurityConfigManager` 具备 `oauth2.cookie.max-age`、`same-site` 等配置读取与校验，但 `CookieHelper` 未使用。

- 待办：
  - [ ] 让 `CookieHelper` 通过注入 `CookieSecurityConfigManager` 获取 `domain/secure/sameSite/maxAge`，移除硬编码 30 天。
  - [ ] 统一日志与校验位置，避免重复输出与分散校验逻辑。
  - [ ] 当 `SameSite=None` 时强制 `Secure=true`（运行期保护）。

验收标准：
- [ ] `maxAge` 不再硬编码；来自配置并记录有效配置
- [ ] `SameSite=None` 时若 `Secure=false` 直接拒绝启动（或 ERROR 日志并终止）

---

### 4. API 参数命名与路径一致性

- 现状：
  - `/sms/refresh-token` 与 `/wechat/refresh-token` 的请求参数命名存在差异（如 `client_id` vs `clientId`）。
  - 登录端点存在别名 `/sms/auth` 与 `/sms/login`。

- 待办：
  - [ ] 制定统一命名规范（外部公开端点尽量遵循 OAuth 规范：`client_id`、`grant_type` 等）。
  - [ ] 保留别名的同时，在响应 Header 中加 `Deprecation` 与 `Link`（RFC 8594）提示迁移路径与截止期。

验收标准：
- [ ] 面向外部的刷新端点统一采用 OAuth 规范参数名
- [ ] 旧别名端点在文档与响应中出现废弃提示与迁移路径

---

### 5. 日志安全与降噪

- 现状：
  - 多处日志打印 token 前缀（前 20 个字符）。

- 待办：
  - [ ] 将包含敏感 token 片段的日志降级为 `DEBUG` 并默认关闭；`INFO` 及以上不包含任何 token 片段。
  - [ ] 统一使用掩码工具类（如 `TokenMasker.mask(String)`）。

验收标准：
- [ ] `INFO` 级别不出现任何 token 明文/片段
- [ ] `DEBUG` 日志可控开关，默认关闭；引入统一掩码工具类

---

### 6. 安全配置与链路核对（非功能改动）

- 待办：
  - [ ] 核对 `SecurityConfig` 的多 FilterChain 配置：确保 `/sms/**`、`/wechat/**` 走无状态链；管理端 `/auth-srv/**` 要求 `ROLE_ADMIN`。
  - [ ] 确保 CSRF 对无状态 API 关闭，对基于表单的管理界面保留。
  - [ ] 核查新增/重构端点的权限与匹配器，避免“临时 permitAll”。

验收标准：
- [ ] `SecurityConfig` 中明确 `securityMatcher()` 范围与链路顺序；新增端点落入正确链路
- [ ] 针对 `/oauth2/refresh-token` 的授权与 CSRF 行为有测试覆盖

---

### 7. Token TTL 与 Cookie 过期对齐策略

- 现状：
  - Access/Refresh TTL 配置在 DB 的 `oauth2_registered_client.token_settings`；Cookie `maxAge` 独立配置。

- 待办：
  - [ ] 明确策略：`refresh_token` TTL >= Cookie `maxAge`；否则可能出现 Cookie 存在但服务器端 refresh_token 已失效的错配。
  - [ ] 提供校验或启动告警：当两者不一致时记录 `WARN` 并给出建议值。

验收标准：
- [ ] 启动/运行期输出 TTL 与 `maxAge` 对齐检查结果；不一致时 `WARN` 并提供建议值

---

### 8. 控制器间认证流程复用

- 现状：
  - `SmsLoginController` 与 `SocialLoginController` 登录成功后的 token 持久化与 Cookie 写入逻辑高度相似。

- 待办：
  - [ ] 在 `OAuth2AuthenticationHelper` 中增加统一的“登录后处理”方法（创建 `TokenPair`、保存 `Authorization`、设置 Cookie、写安全响应）。
  - [ ] 控制器仅负责参数校验与调用服务层，减少控制器中业务细节。

验收标准：
- [ ] 登录后处理统一一个入口；控制器精简，测试用例通过

---

### 9. 单元与集成测试补齐

- 待办：
  - [ ] 增加 MockMvc 测试：`/sms/auth`、`/wechat/login`、`/oauth2/refresh-token`（Cookie 模式）。
  - [ ] 增加 Cookie 属性断言（`Domain/Secure/SameSite/Max-Age`）。
  - [ ] 增加 TTL 行为测试（access_token 过期 → refresh → 成功续期）。

验收标准：
- [ ] 新老端点均有集成测试；覆盖 Cookie 与 TTL 行为

---

### 10. 文档与脚本同步

- 待办：
  - [ ] 更新 `docs/wechat-miniprogram-auth-integration.md`：引用统一的刷新端点与参数命名规范。
  - [ ] 更新 `scripts/test-sms-login.sh`：增加对统一刷新端点的测试路径，保留旧端点测试作为回归用例（到弃用截止期）。

验收标准：
- [ ] 文档、脚本与实际端点一致；含迁移说明与示例

---

### 11. 配置与 Linter 清单

- 待办：
  - [ ] 清理或注解说明 `application.yml` 中自定义命名空间（如 `oauth2.*`、`auth-server.*`、`sms.*`）的 linter 告警来源，避免误导读者为“未知属性错误”。
  - [ ] 将关键自定义配置提炼为 `@ConfigurationProperties` Bean（如 `CookieProperties`、`SmsProperties`），提升类型安全与自动提示。

验收标准：
- [ ] Linter 告警可解释或消除；配置具备类型安全与 IDE 提示

---

### 12. 兼容性与弃用计划

- 待办：
  - [ ] 给 `/sms/refresh-token` 与 `/wechat/refresh-token` 添加响应 Header：`Deprecation: true` 与 `Link: <.../oauth2/refresh-token>; rel="successor-version"`。
  - [ ] 在版本发布说明中标注弃用时间与迁移步骤，预留双轨期（例如 2 个小版本）。

验收标准：
- [ ] 旧端点保留至少两个版本周期；监控其调用量下降趋势

> 🚨 以下是安全盲点与风险补充（重要！！！）

### 13. 权限控制与安全链路验证（关键安全盲点）

- **现状风险**：
  - 统一刷新端点 `/oauth2/refresh-token` 可能绕过现有的安全链路配置
  - 当前 `/sms/**` 和 `/wechat/**` 在 `mobileApiSecurityFilterChain` 中配置为 `permitAll()`，但新的统一端点可能落入不同的安全链路

- **待办**：
  - [ ] **关键**：确保新的 `/oauth2/refresh-token` 端点在正确的 SecurityFilterChain 中（Order=1 的移动端链路）
  - [ ] **关键**：验证统一端点不会意外要求 `ROLE_ADMIN` 权限（避免破坏移动端无状态访问）
  - [ ] **关键**：确保 CSRF 保护对新端点正确禁用（移动端 API 不应有 CSRF 要求）
  - [ ] 添加集成测试验证新端点的安全链路配置正确性

验收标准：
- [ ] 针对 `/oauth2/refresh-token` 的链路与授权断言用例通过

### 14. Cookie 安全配置一致性验证（安全风险）

- **现状风险**：
  - `CookieHelper` 硬编码 30 天可能与 refresh_token TTL 不匹配，导致安全窗口期问题
  - `SameSite=None` 时未强制 `Secure=true` 可能导致跨站攻击风险

- **待办**：
  - [ ] **关键**：添加启动时校验：当 `SameSite=None` 时强制 `Secure=true`，否则拒绝启动
  - [ ] **关键**：添加 TTL 一致性检查：Cookie maxAge 不应超过 refresh_token TTL
  - [ ] 在 `CookieSecurityConfigManager` 中添加运行时安全策略验证
  - [ ] 添加配置不当时的明确错误提示和修复建议

验收标准：
- [ ] 启动期安全检查有效；配置不当时失败且给出清晰修复建议

### 15. 向后兼容性安全风险（破坏性变更风险）

- **现状风险**：
  - 移除旧端点可能导致生产环境中的移动端应用无法刷新 token
  - 参数命名变更（`client_id` vs `clientId`）可能破坏现有客户端集成

- **待办**：
  - [ ] **关键**：保留旧端点至少 2 个版本周期，不能立即删除
  - [ ] **关键**：在旧端点添加 `Deprecation` header 和详细的迁移指南
  - [ ] 添加监控和告警：跟踪旧端点的使用情况，确保安全迁移
  - [ ] 制定明确的弃用时间表和客户端通知机制

验收标准：
- [ ] 监控看板具备旧端点使用统计；通知机制与时间表已发布

### 16. 日志安全与审计完整性（合规风险）

- **现状风险**：
  - Token 前缀日志可能仍然暴露敏感信息，不符合安全审计要求
  - 统一后的日志格式可能影响现有的安全监控和告警系统

- **待办**：
  - [ ] **关键**：将所有包含 token 片段的日志降级为 `DEBUG`，生产环境默认关闭
  - [ ] **关键**：确保 `INFO` 级别日志完全不包含任何 token 信息（包括前缀）
  - [ ] 添加安全审计日志：记录刷新操作的用户、时间、客户端等信息（不含 token）
  - [ ] 统一日志格式，确保与现有监控系统兼容

验收标准：
- [ ] 审计日志包含必要上下文但无敏感信息；与监控系统对齐

### 17. 数据库事务与一致性（数据安全）

- **现状风险**：
  - 统一的 token 处理可能涉及多个数据库操作，缺乏事务保护
  - Authorization 保存失败时可能导致 token 泄露或状态不一致

- **待办**：
  - [ ] **关键**：为统一的 token 处理方法添加 `@Transactional` 注解
  - [ ] **关键**：确保 token 生成、Authorization 保存、Cookie 设置的原子性
  - [ ] 添加失败回滚机制：token 处理失败时清理已设置的 Cookie
  - [ ] 添加数据一致性验证：定期检查 Authorization 表与 Cookie 状态的一致性

验收标准：
- [ ] 相关方法具备事务；失败回滚与一致性校验通过

### 18. 客户端凭据管理安全（认证安全）

- **现状风险**：
  - `OAuth2ClientCredentialsManager` 中的异常处理可能掩盖安全问题
  - `getDefaultClientCredentials()` 的 fallback 机制可能被滥用

- **待办**：
  - [ ] **关键**：移除 `getDefaultClientCredentials()` 中的 fallback 机制，失败时应明确拒绝
  - [ ] **关键**：改进异常处理：记录详细错误日志但不暴露给客户端
  - [ ] 添加客户端凭据访问审计：记录所有凭据查询操作
  - [ ] 添加客户端状态验证：确保客户端未被禁用或过期

验收标准：
- [ ] 无隐式 fallback；异常路径安全；新增审计记录

### 19. 测试覆盖与安全验证（质量保证）

- **现状风险**：
  - 缺乏对新统一端点的安全测试，可能存在未发现的安全漏洞
  - 缺乏对 Cookie 安全属性的自动化验证

- **待办**：
  - [ ] **关键**：添加安全测试：验证统一端点的权限控制正确性
  - [ ] **关键**：添加 Cookie 安全测试：验证 HttpOnly、Secure、SameSite 属性
  - [ ] 添加跨域安全测试：验证 CORS 配置不会影响 Cookie 安全
  - [ ] 添加负载测试：确保统一端点在高并发下的安全性

验收标准：
- [ ] 安全、跨域、Cookie 属性、负载等测试达标并纳入 CI

### 20. 生产环境部署安全（运维安全）

- **现状风险**：
  - 重构后的配置变更可能影响生产环境的负载均衡器配置
  - 新的统一端点可能需要额外的防火墙规则或 WAF 配置

- **待办**：
  - [ ] **关键**：制定详细的生产部署计划，包括回滚策略
  - [ ] **关键**：验证新端点与现有基础设施（负载均衡器、WAF）的兼容性
  - [ ] 准备生产环境配置检查清单：Cookie 域名、HTTPS 设置等
  - [ ] 制定监控和告警规则：跟踪新端点的性能和安全指标

验收标准：
- [ ] 部署/回滚脚本完善；监控与告警覆盖关键指标

---

> 以下是🔍 深度代码审查发现的额外安全风险！

### 21. OAuth2AuthenticationHelper 事务安全缺陷（严重数据风险）

- **现状风险**：
  - `createAndSaveAuthorization()` 方法缺乏 `@Transactional` 注解，可能导致数据不一致
  - `processRefreshToken()` 涉及多个数据库操作但无事务保护
  - `updateAuthorizationWithNewToken()` 失败时可能导致 token 泄露

- **待办**：
  - [ ] **关键**：为 `OAuth2AuthenticationHelper` 的所有数据库操作方法添加 `@Transactional`
  - [ ] **关键**：确保 token 生成失败时的回滚机制，避免部分状态保存
  - [ ] 添加数据库操作失败的详细错误处理和审计日志
  - [ ] 实现 token 操作的原子性保证

验收标准：
- [ ] 所有涉及数据库的方法都有事务保护；失败时完整回滚

### 22. Cookie 安全配置硬编码风险（配置安全）

- **现状风险**：
  - `CookieHelper` 中硬编码 30 天过期时间，未使用配置文件中的 `max-age` 设置
  - `SameSite=None` 时未强制验证 `Secure=true`，存在安全漏洞
  - 配置验证仅在 `@PostConstruct` 中进行，运行时配置变更无保护

- **待办**：
  - [ ] **关键**：修复 `CookieHelper` 使用配置文件中的 `max-age` 而非硬编码
  - [ ] **关键**：添加强制安全检查：`SameSite=None` 必须配合 `Secure=true`
  - [ ] 添加运行时配置一致性检查和告警机制
  - [ ] 实现配置热更新的安全验证

验收标准：
- [ ] Cookie 配置完全来自配置文件；安全策略强制执行；有运行时验证

### 23. 客户端凭据验证绕过风险（认证安全）

- **现状风险**：
  - `OAuth2ClientCredentialsManager.validateClient()` 使用简单字符串比较，可能被时序攻击
  - `getDefaultClientCredentials()` 的 fallback 机制 `"fallback-secret"` 是硬编码安全漏洞
  - 异常处理返回 `null` 可能掩盖安全问题

- **待办**：
  - [ ] **关键**：移除 `getDefaultClientCredentials()` 的 fallback 机制，失败时抛出异常
  - [ ] **关键**：使用安全的字符串比较方法防止时序攻击
  - [ ] 改进异常处理：记录详细安全日志但不暴露敏感信息
  - [ ] 添加客户端凭据访问的审计跟踪

验收标准：
- [ ] 无 fallback 机制；使用安全比较；完整审计日志

### 24. 全局异常处理安全信息泄露（信息安全）

- **现状风险**：
  - `GlobalExceptionHandler` 直接将异常消息暴露给客户端
  - API 错误响应可能包含敏感的内部实现细节
  - 缺乏对安全相关异常的特殊处理

- **待办**：
  - [ ] **关键**：过滤敏感异常信息，避免暴露内部实现细节
  - [ ] **关键**：为 OAuth2 相关异常添加专门的安全处理逻辑
  - [ ] 添加异常分类：公开信息 vs 内部调试信息
  - [ ] 实现安全异常的审计日志记录

验收标准：
- [ ] 客户端收到的错误信息安全；内部异常有完整日志记录

### 25. 日志安全策略不一致（审计风险）

- **现状风险**：
  - `OAuth2AuthenticationHelper` 中仍有 token 前缀日志（第512行）
  - `CookieHelper` 中的 DEBUG 日志包含 token 片段
  - 不同组件的日志级别和脱敏策略不统一

- **待办**：
  - [ ] **关键**：统一所有组件的日志脱敏策略，移除所有 token 片段
  - [ ] **关键**：将包含敏感信息的日志降级为 `TRACE`，生产环境禁用
  - [ ] 建立统一的日志安全工具类，强制使用脱敏方法
  - [ ] 添加日志安全扫描工具，自动检测敏感信息泄露

验收标准：
- [ ] 所有日志使用统一脱敏；生产环境无敏感信息输出

### 26. SecurityFilterChain 路径匹配潜在冲突（权限绕过风险）

- **现状风险**：
  - `/oauth2/**` 路径在 `defaultSecurityFilterChain` 中配置为 `permitAll()`
  - 新的统一端点 `/oauth2/refresh-token` 可能意外落入默认链路而非移动端链路
  - 多个 FilterChain 的路径匹配可能存在优先级冲突

- **待办**：
  - [ ] **关键**：明确验证 `/oauth2/refresh-token` 的 FilterChain 归属
  - [ ] **关键**：调整 SecurityFilterChain 的路径匹配，避免意外的权限绕过
  - [ ] 添加 FilterChain 路径匹配的集成测试
  - [ ] 实现路径匹配冲突的启动时检查

验收标准：
- [ ] 新端点在正确的 FilterChain 中；无权限绕过风险；有完整测试覆盖

### 27. 配置属性类型安全缺失（配置风险）

- **现状风险**：
  - Cookie 相关配置使用 `@Value` 注解，缺乏类型安全和验证
  - 配置错误只在运行时发现，可能导致生产环境问题
  - 缺乏配置项的文档和默认值说明

- **待办**：
  - [ ] **关键**：将 Cookie 配置迁移到 `@ConfigurationProperties` 类
  - [ ] **关键**：添加配置验证注解（`@Valid`、`@NotNull` 等）
  - [ ] 提供配置项的完整文档和示例
  - [ ] 实现配置错误的友好提示和修复建议

验收标准：
- [ ] 配置类型安全；启动时验证；有完整文档

### 🔗 任务依赖与对齐关系

- 1 刷新端点统一 → 13（链路校验）、26（路径归属）、17（事务回滚）
- 2 响应 Cookie 模式统一 → 5、16、25（日志安全与审计一致性）
- 3 Cookie 配置对齐 → 14、22、27（安全与类型安全）、7（TTL 对齐）
- 4 API 命名/路径一致性 → 12、15（兼容与弃用）
- 6 安全链路核对 → 13、26（链路/匹配冲突）
- 7 TTL 与 Cookie 对齐 → 14（安全策略）
- 8 登录后处理复用 → 17（事务与原子性）
- 9 测试补齐 → 13、14、16、19、26（安全/跨域/Cookie/负载）
- 11 配置与 Linter → 27（配置类型安全）

如需按此清单分阶段实施，可先完成 1、2、3 三项（高价值去重），随后推进 6、7、9（安全与质量），最后同步 10、12（对外沟通）。


