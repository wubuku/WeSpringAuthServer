---
name: project-docs
description: 为软件项目创建和维护系统化、AI Agent 友好的文档体系。触发词："创建文档"、"完善文档"、"文档体系建设"、"建立文档体系"、"set up docs"、"document this project"、"onboarding agent"。适用于 WeSpringAuthServer 这类已有大量散落文档、需要导航化整理的仓库；文档是一等公民。
---

# Project Documentation System — AI-Agent Friendly（WeSpringAuthServer 适配版）

创建和维护系统的、AI 友好的文档体系。**文档是一等公民**：AI Agent 能够安全地导航、理解并修改代码库。

> 本技能移植自 RuiChuangQi-AI 的 `project-docs`，已按本项目实际删除 DDDML、前端（`admin-console`）、`docs-lint.py` 巡检器、"第 N 轮约定"等不适用内容，改为适配单模块 Maven/Spring Boot 认证授权服务器。

## 核心原则

1. **代码库是唯一真相来源** — 架构、约束、决策都在代码和测试中，不在聊天记录或本机缓存里。
2. **文档首先是给 AI Agent 的** — 面向"需要理解上下文才能安全改代码"的 Agent。
3. **导航 > 内容** — 好的导航体系胜过全面但分散的文档堆。
4. **三层深度**：Hub（入口）→ Guides（指南）→ Reference（参考），渐进式披露。
5. **生命周期意识**：每份文档都有归属阶段（live / draft / archive）。

---

## 本项目事实基线（动手前先确认，不要凭旧文档猜测）

| 项 | 事实 |
|----|------|
| 项目类型 | 单模块 Maven，独立 Spring Boot OAuth2 认证授权服务器（FFV Traceability 系统） |
| 真实版本 | 以 `pom.xml` 为准：Java 17、Spring Boot **3.4.6**、Spring Security 6.2.0、Spring Authorization Server **1.3.6**（README/.agent.md 中 3.2.0、1.5.0 为历史值） |
| 主类 / 端口 | `org.dddml.ffvtraceability.auth.AuthServerApplication` / **9000**（`SERVER_PORT` 可覆盖） |
| 存储 | PostgreSQL + JdbcTemplate（无 JPA/MyBatis）+ Spring Session JDBC |
| 关键安全 | 三条 SecurityFilterChain；授权码 + PKCE；JWT 自定义 claims；HttpOnly refresh_token Cookie；层级权限 `authority_definitions`；短信/微信登录 |
| 已有 Agent 文档 | `CLAUDE.md`（共享速查）、`.agent.md`（须知）、`.cursorrules`（安全与开发规则）— **均保持在原位** |
| 本机缓存 | `.workbuddy/memory/` 已被 `.gitignore` 排除；CodeBuddy 记忆在仓库外。**都不是共享事实来源** |
| 不适用 | 无 DDDML、无前端构建、无 `docs-lint.py`、无 `.cursor/rules/` 目录（规则是单文件 `.cursorrules`） |
| 敏感物 | `.env` / `.env.prod` / `production-keys/` / `scripts/*.env` 不得提交；token、验证码、密码不得写入文档或日志 |

---

## 实施规划先行与收敛检查（强制范围）

本节适用于涉及**代码、数据库、接口、权限、迁移、部署或跨模块行为**的变更。纯文字修订、格式整理和不改变系统行为的索引维护，按普通文档维护规则处理即可。

### 规划先行

在修改代码、SQL、配置或部署脚本前，先在 `docs/drafts/` 完成详尽规划。规划前必须交叉核对：现有 Java 代码、SecurityFilterChain 与 Controller、`schema.sql`/`data*.sql`、`application*.yml`、权限模型、测试与脚本、相关长期文档及已知历史问题（尤其 `docs/drafts/` 中的安全修复记录）。

规划文档须满足：

1. **可实施**：背景、目标、范围、非目标、事实来源、关键数据/接口、实施顺序、测试、发布、迁移、回滚、遗留事项，使中断后另一人可直接接续。
2. **尽量自包含**：关键上下文与决策写在规划里；已有文档用近距离相对链接引用，不复制大段正文，也不要求读者层层搜索。
3. **决策不留空洞**：阻断性决策给推荐默认值；未知项写明推荐默认、理由、验证方式与可逆边界，不得留给"实施时再决定"。
4. **与现实一致**：不以猜测补齐代码或数据事实；无法确认的标注验证方法、影响与降级行为。
5. **可验证**：核心验收能映射到具体测试、SQL 查询、构建、启动检查或 `curl` 证据；数据变更须说明执行顺序与回滚边界。
6. **控制范围**：先冻结规划基线、审查范围与"实质性缺陷"判定标准，不为行号、格式、非穷举文件清单或实施中自然暴露的局部细节扩展范围。

### 严格三轮收敛协议

规划完成后执行固定范围的系统性检查循环，计数器初始为 `0`：

1. 每轮检查代码库与相关文档的必要部分，交叉验证事实准确性、逻辑一致性、可实施性、权限/数据安全、迁移风险与核心验收可验证性。
2. 若发现**实质性问题**（方案不可实施、形成越权路径、数据安全/迁移风险、核心验收无法验证、逻辑矛盾会改变结果），立即修改规划并修复问题；计数器重置为 `0`，从第 1 轮重来。
3. 本轮未发现需修改规划的实质性问题，计数器加 `1`。
4. 只有**连续 3 次完整检查、期间未修改规划文档**，才允许结束循环。

每轮在沟通中输出可追溯摘要：时间、范围、发现、处理、结果。**无问题轮次不写入规划文档**，以免破坏"连续三次无修改"的终止条件；只有影响未来实施的关键决策、踩坑经验、遗留风险和可复用验证结论才沉淀。

不触发计数器重置的观察项：行号偏差、措辞/格式细节、非穷举文件清单、实施中自然暴露的局部细节和不改变方案的次要边界问题。**但凡实际修改了规划文档，一律重置为 `0`。不得在三轮收敛前宣称规划完成。**

### 实施后的回收

实施中发现会改变范围、数据安全、权限、迁移、回滚或核心验收的遗漏事实，先暂停相关动作，更新规划并重跑三轮协议。完成后规划只保留简洁最终方案、关键决策、踩坑经验、验证证据与遗留事项；删除无维护价值的大段预研代码、全量打勾清单和流水账，但保留能帮助未来避坑的内容。

---

## 实施、测试与验收门槛

适用于涉及代码、接口、数据库、权限、构建、部署或跨模块行为的任务。与上面的规划流程连续执行：**先规划，再实施；先通过基本集成验证，再做固定范围的实现代码收敛检查；最后才交给用户手动验收。**

### 基本集成验证是硬门槛

开始三轮实现代码检查前，必须先完成涉及部分的基本集成验证；不得以代码 review 代替测试，也不得未经验证就让用户手动验收。

本项目为**单模块后端**，至少确认：

- 本次修改相关的集成测试已执行，并尽量走端到端路径，覆盖新增/修改的 Controller、Service、Mapper、持久化与权限行为，而非只测孤立单元方法。
- 可编译：`./mvnw clean package -DskipTests`（或至少 `./mvnw clean test-compile`）。
- 测试全部通过：`./mvnw test`；单类用 `./mvnw test -Dtest=<TestClass>`。
- 服务可启动：优先 `./dev.sh`（自动构建、健康检查、加载 `.env` 并抓取测试 Token）；必要时前台 `./dev.sh --foreground` 观察日志。
- 真实端点可用：用 `curl` 验证（如 `/actuator/health`、`/.well-known/oauth-authorization-server`、`/oauth2-test`、`/oauth2/token`），不要只依赖 Mock。
- 敏感数据：从 `.env` 加载环境时直接注入命令环境，不把密钥写进规划、源码或提交的环境文件；日志中不输出 token、验证码、密码。
- 脚本验证：`scripts/test.sh`（授权码流程）、`scripts/get-test-user-tokens.sh`（批量 Token）、`scripts/verify-oauth2-security.sh`、`scripts/test-permissions.sh` 等按主题选用。

### 实现代码三轮收敛检查

相关基本集成验证全部通过后，执行限时、固定范围的三轮检查，计数器初始为 `0`。每轮按需阅读本次涉及的代码、测试、配置与近邻文档，避免无边界探索：

1. 检查行为正确性、回归风险、权限与数据安全（越权/越租户）、错误处理、测试覆盖、构建/启动可行性与 OAuth2 契约（issuer、redirect_uri、scope、claims）。
2. 发现实际问题立即修改代码或测试；至少重新执行 `./mvnw clean package -DskipTests` 与受影响测试，必要时重启服务并重新 `curl` 验证；计数器重置为 `0`，从第 1 轮重来。
3. 本轮未发现需修改的实际问题，计数器加 `1`。
4. 只有连续 3 轮且期间没有代码或测试修改，才可结束检查。修改任一代码/测试/相关配置后必须从第 1 轮重计。

暂停前自问：后端是否有测试证据？服务是否已真实启动并验证端点？修改是否被集成测试覆盖？是否仍有必要联调？是否真有信心交给用户手动验收？汇报必须区分"已测试验证""仅代码检查""未执行"，不得用未经测试的结论报喜。

---

## 本机缓存与共享事实的边界

根目录**没有** `MEMORY.md`。本项目的共享速查是 `CLAUDE.md`（已提交）；`.workbuddy/memory/` 与 CodeBuddy 记忆仅为本机缓存，均不构成跨机器、跨工作区的共享事实来源。

因此，必须共享的规则、架构约束、测试门槛、部署要求和可复用经验，应落在已跟踪的 `AGENTS.md`、`README.md`、`CLAUDE.md`、`.agent.md`、`.cursorrules`、`.agents/skills/` 或 `docs/` 中，并更新相应索引。Agent 可以读取本机缓存作为补充，但不得把它当作唯一依据，也不得仅修改缓存就宣称项目文档已完成同步。

---

## 关键规则：已有文档不移动，新文档链接已有内容

| 规则 | 说明 |
|------|------|
| **不移动文件位置** | 已有文档保持在原目录，不因为"归类"而搬迁 |
| **可重命名文件** | 过期历史文档可加日期前缀，如 `YYYY-MM-DD_<原名>.md` |
| **链接而非重复** | 新文档用相对路径链接到已有文档，不复制已有正文 |
| **保持原位置** | 当前 `docs/` 的扁平结构反映项目历史，索引层负责导航 |

### 文档名冲突处理（新增 vs 已有同名/职责重叠）

❌ 不要：直接覆盖/大幅删改已有文档、移动已有文档。

✅ 正确做法：
1. 保留旧内容，将已有文档重命名为 `YYYY-MM-DD_<描述性名称>.md`；
2. 创建新文档（作为索引/导航）；
3. 双向链接：新文档链接旧文档（"原内容已移至 X"），旧文档头部标注来源。

### 补充策略

需要补充的内容在某处已存在时：在新文档中**链接**，不复制、不重写；需要更新的过期内容直接改原文件。

---

## 文档系统结构

> 下图是**目标规范**（含本技能新建的入口文件）。**不要照图去找尚未创建的目录**；以 `docs/README.md` 为实际索引。已有扁平文档保持原位，由索引层归类。

```text
WeSpringAuthServer/
├── AGENTS.md                       # P0: AI Agent 导航入口（≤120 行）— 本技能新建
├── README.md                       # P0: 人类落地页（已存在，保持原位）
├── CLAUDE.md                       # P0: 共享速查手册（已存在，≈MEMORY 角色）
├── .agent.md / .cursorrules        # P0: 已有开发规则（单文件，不改成 .cursor/rules/）
├── .agents/skills/project-docs/   # P1: 本技能
│   ├── SKILL.md
│   └── references/{checklist,templates}.md
├── docs/                           # P1: 文档导航中心
│   ├── README.md                  # 文档目录索引 — 本技能新建
│   ├── development-guides/        # 开发指南（索引层，链接回已有文档）
│   ├── technology-stack/          # 技术栈文档（索引层）
│   ├── operations-guides/         # 运维/部署指南（索引层）
│   ├── api-testing/               # API 测试文档（索引层）
│   ├── drafts/                    # P2: 草稿与规划（已存在，需更新索引）
│   └── archive/                   # P3: 归档（按需）
├── src/main/java/...               # 源代码（不移动）
└── scripts/                        # 可执行的验证/运维脚本（README.md 为索引）
```

### 根目录白名单

仅以下文档可位于根目录；其他说明性文档放 `docs/`：

| 文件 | 状态 | 说明 |
|------|------|------|
| `README.md` | 必需 | 人类落地页（已存在） |
| `AGENTS.md` | 必需 | AI Agent 导航入口（本技能新建） |
| `CLAUDE.md` | 已存在 | 共享速查手册 |
| `.agent.md` / `.cursorrules` | 已存在 | 开发与安全规则 |
| `.agents/skills/` | 可选 | AI 技能（本技能所在） |
| `LICENSE` | 缺失 | 需项目所有者确认许可证后补充，**不要猜测** |

---

## 优先级

| 优先级 | 文档 | 目标 |
|--------|------|------|
| **P0** | `AGENTS.md` + `README.md` + `CLAUDE.md` + `.agent.md` / `.cursorrules` | 先有入口与规则 |
| **P1** | `docs/README.md` + `development-guides/` + `technology-stack/` + `.agents/skills/` | 核心工程知识可导航 |
| **P2** | `api-testing/` + `operations-guides/` + `drafts/` | 详细操作与规划 |
| **P3** | `archive/` + 源材料 | 按需 |

---

## 核心文档规范

### AGENTS.md — AI Agent 导航入口（P0，≤120 行）

目的：Agent 统一入口，回答"这是什么、文件在哪、如何安全修改"。**地图，不是手册。**

```markdown
# WeSpringAuthServer — Agent 导航

## 1. 项目概览
- 类型 / 技术栈 / 状态（以 pom.xml 为准）

## 2. 文档索引
- README.md / CLAUDE.md / docs/README.md / .cursorrules / .agents/skills/

## 3. 快速命令
    build / test / run / verify

## 4. 模块概览
| 模块 | 路径 | 职责 |

## 5. Agent 约束
- BEFORE / DO NOT / ALWAYS

## 6. 维护规则
- 新增文档 → 立即更新本文件与 docs/README.md
```

### CLAUDE.md — 共享速查手册（已存在）

目的：跨机器共享的日常开发、测试、排查快速参考。更新时保持事实与 `pom.xml`/代码一致，发现版本漂移应修正而不是照抄旧值。新增长期规则时，同步更新 `AGENTS.md` 或 `docs/README.md` 的索引。

### docs/README.md — 文档导航中心（P1）

```markdown
# 文档导航

## 文档目录
| 目录 | 说明 |

## 已有文档归类（链接，不移动）
| 主题 | 文档 |

## 快速导航
- AGENTS.md / CLAUDE.md / .cursorrules / scripts/README.md
```

### 规则文件（已存在，不重构）

`.cursorrules` 是单文件规则（安全原则、Controller/数据库/前端约定、故障排查）。若要新增规则，优先增量修改此文件；**不要**为了效仿模板而新建 `.cursor/rules/` 目录造成双源。

---

## 生命周期管理

| 类型 | 生命周期 | 位置 | 规则 |
|------|----------|------|------|
| **Live** | 定期更新 | 合适目录 | 必须有 Purpose Header |
| **Draft** | 活跃迭代 | `docs/drafts/` | 描述性命名 |
| **Historical** | 一次编写不再改 | `docs/archive/YYYY-MM-DD_<name>.md` | 加入归档索引 |
| **Reference** | 版本发布时稳定 | `docs/` | 版本控制 |
| **组件 README** | 绑定组件 | `<component>/README.md` | 允许在根级（如 `scripts/README.md`） |

### Purpose Header（Live 文档必须）

```markdown
# 文档标题

> **Purpose**: 本文档跟踪什么。
> **Updated by**: 更新者或流程（未记录时如实写"未记录（人工提交）"）。
> **Update rule**: 如何更新（覆盖 / 追加）。
```

### 新建文档的默认动作

写完新文档后，**四步是默认动作**：

1. **入索引** — 在 `docs/README.md`（及所属目录 README）补一行；
2. **`git add` 该文件** — 否则索引链接指向克隆者拿不到的文件；
3. **相对路径从文件自身算起** — `docs/x.md` 链到 `docs/README.md` 写 `README.md`，不是 `../README.md`；锚点不要凭记忆写，先确认标题存在；
4. **表格单元格里的竖线要转义** — 命令里的 `|` 写成 `\|`，或把命令放进代码块（表格外）。

> 这四步都是"看起来没问题、但会让读者拿不到或看不懂"的问题；不要等巡检来报（本项目没有巡检器）。

### 归档规则

1. 复制到 `docs/archive/YYYY-MM-DD_<描述性名称>.md`（日期 = 最后相关日期，不是今天）；
2. 在 `docs/archive/README.md` 添加行；
3. 删除原文件；
4. 更新所有指向它的引用。

**归档时机**：功能完全实现 + 设计稳定 2 周以上无变更。

### 草稿命名规范

| 模式 | 使用时机 | 示例 |
|------|----------|------|
| `<topic>-design.md` | 通用设计/研究 | `oauth2-session-vs-jwt-analysis.md` |
| `<phase>-<N>-<topic>.md` | 分阶段实施 | `phase2-cookie-security.md` |
| `<component>-<topic>.md` | 组件特定 | `sms-provider-switch.md` |

避免 `TASK_PROGRESS.md`、`NOTES.md`、`TEMP.md` 这类无主题命名。历史草稿可加 `YYYY-MM-DD_` 前缀。

---

## 工作流：建立文档系统

### Step 1: 审计现有文档

```bash
find . -name "*.md" \
  -not -path "./target/*" -not -path "./.git/*" \
  -not -path "./reference-submodules/*" \
  -not -path "./.workbuddy/*" -not -path "./.understand-anything/*" \
  | sort
```

评估：已有什么、缺口在哪、是否有孤立或过期文档、根级文档是否需要移动（**不要移动，用链接代替**）。

### Step 2: 制定计划

1. 创建 `docs/drafts/DOCUMENTATION_PLAN.md`；
2. 列出所有需要的文档及优先级（P0→P3）；
3. 识别文档依赖关系；
4. 记录本次有意不做的项及原因（避免后来者误以为是遗漏）。

### Step 3: 按优先级构建

- **P0**：`AGENTS.md`；核对 `README.md` / `CLAUDE.md` / `.agent.md` / `.cursorrules` 在位且索引正确。
- **P1**：`docs/README.md`；建立 `development-guides/`、`technology-stack/` 等索引层；本技能。
- **P2**：`api-testing/`、`operations-guides/`、`drafts/` 索引完善。
- **P3**：`archive/` 按需。

### Step 4: 验证

- 所有相对链接可解析、无死链；
- 所有引用的命令与 `pom.xml` / `dev.sh` / `scripts/` 一致；
- 代码示例与配置片段取自当前代码，不抄旧版本；
- 涉及系统行为的文档修改，按前面的"实施、测试与验收门槛"执行。

---

## 质量检查清单

详见 `references/checklist.md`。每个文档至少：遵循模板结构、命令已验证、无重复正文（用链接）、交叉链接有效。

`AGENTS.md`：≤120 行、P0/P1 已索引、快速命令齐全、Agent 约束清晰。

---

## 常见错误与预防

| 错误 | 预防 |
|------|------|
| 巨型 README 包含一切 | Hub → Guides → Reference 分层 |
| 无导航（到处搜索） | `docs/README.md` 与 `AGENTS.md` 做入口 |
| 重构后文档过时 | 代码变更 = 同一提交中更新文档；以 `pom.xml` 为准核对版本 |
| 把旧文档搬进新目录"归类" | 不移动，用链接；只可重命名 |
| 凭模板创建 `.cursor/rules/` | 本项目规则是单文件 `.cursorrules`，增量修改 |
| 把本机缓存当共享事实 | `.workbuddy/memory/` 被忽略；共享规则写进已跟踪文档 |
| 文档里写死 token/密码/验证码 | 敏感值只存在于环境与脚本运行时 |

---

## 参考模板

`references/templates.md`：README、AGENTS、CLAUDE/速查、docs/README、草稿/归档索引、Architecture、Testing、Troubleshooting、DOCUMENTATION_PLAN 模板。

`references/checklist.md`：创建前、各文档、链接、最终验证清单。

---

## 与 AI Agent 的集成

1. **进入项目时**：先读 `AGENTS.md`，再按需读 `CLAUDE.md`、`.agent.md`、`.cursorrules`。
2. **修改前**：核对 `AGENTS.md` 的 Agent 约束；涉及行为变更先按本技能做规划与三轮收敛。
3. **变更期间**：同步更新相关文档与索引。
4. **变更后**：按门槛验证，区分"已验证/仅检查/未执行"。

**规则**：当变更因"知识缺口"失败时 — 先修复文档，再修复代码。
