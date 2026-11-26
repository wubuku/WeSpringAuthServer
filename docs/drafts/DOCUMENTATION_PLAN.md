# 文档体系建设规划

> **Purpose**: 记录文档审计结果、优先级、范围与有意不做的项（含第二轮整理）。
> **Updated by**: 未记录（变更由人工提交）。
> **Update rule**: 体系调整时更新；完成项标注日期，不写流水账。

## 1. 现状审计（2026-11-26）

- **已有 P0**：`README.md`（人类落地页，803 行）、`CLAUDE.md`（共享速查）、`.agent.md`（项目须知）、`.cursorrules`（安全与开发规则）。四者均在根目录且内容有价值。
- **已有 P1/P2**：`docs/` 下 11 篇扁平文档（OAuth2 客户端/资源服务器/微信登录集成、权限重构、数据库集成、配置重构等）与 `docs/drafts/` 下 27 篇草稿（安全审计、STATELESS 研究、短信/微信登录等）。
- **组件 README**：`scripts/README.md`（脚本索引）、`scripts/README-wechat-test.md`、`example-resource-server/README.md`、`sms-login-demo/README.md`。
- **缺口**：无 `AGENTS.md`（Agent 无统一入口）；无 `docs/README.md`（文档无导航中心）；`docs/drafts/README.md` 仅索引少数 STATELESS 文档，大量草稿孤立；`docs/` 无分类索引层。
- **冲突/过时**：`README.md`、`.agent.md` 写 Spring Boot 3.2.0 / SAS 1.5.0，`pom.xml` 实为 3.4.6 / 1.3.6；根目录无 `MEMORY.md`；无 `LICENSE`、无 `CONTRIBUTING.md`。

## 2. 本期目标（P0 → P2）

| 优先级 | 动作 | 产物 |
|--------|------|------|
| P0 | 新建 Agent 导航入口 | [AGENTS.md](../../AGENTS.md)（≤120 行，索引已有规则文档） |
| P1 | 新建文档导航中心 | [docs/README.md](../README.md)（按主题链接全部已有文档） |
| P1 | 建立分类索引层 | [development-guides/](../development-guides/)、[technology-stack/](../technology-stack/)、[api-testing/](../api-testing/)、[operations-guides/](../operations-guides/) |
| P2 | 修复草稿索引 | 重写 [docs/drafts/README.md](README.md)，覆盖全部草稿 |
| P2 | 补 README 导航 | 根 `README.md` 增加"文档导航"一节 |
| P0 | 技能落地 | [.agents/skills/project-docs/](../../.agents/skills/project-docs/)（SKILL + checklist + templates，已按本项目适配） |

本期为纯文档建设，不改变系统行为，因此未触发技能中的"规划三轮收敛"与"实现代码三轮收敛"流程。

## 3. 有意不做的项（避免被误认为遗漏）

1. **不移动任何已有文档**：`docs/` 的扁平结构反映项目历史，仅通过索引归类。
2. **不新建 `.cursor/rules/`**：本项目规则在单文件 `.cursorrules`，避免双源。
3. **不创建根 `MEMORY.md`**：本机缓存 `.workbuddy/memory/` 已被 `.gitignore` 排除；共享速查角色由 `CLAUDE.md` 承担。
4. **不猜测 `LICENSE` / `CONTRIBUTING.md`**：需项目所有者确认许可证与协作方式后补充。
5. **不批量改写旧文档的版本号**：仅在新文档中注明"以 `pom.xml` 为准"；旧文档内容保持原样，避免大范围正文改动。
6. **不引入 DDDML / 前端 / docs-lint 相关内容**：本项目无 DDDML、无前端构建、无巡检器。

## 4. 验证

- 链接检查：对全部新建/修改文档执行相对链接解析，要求无死链（脚本见 SKILL 的 `references/checklist.md`）。
- 索引覆盖：`docs/README.md` 与 `docs/drafts/README.md` 覆盖全部已有 Markdown 文档（组件 README 除外，已单独索引）。
- 事实一致性：新文档中的命令取自 `dev.sh` / `scripts/`，版本取自 `pom.xml`。
- 结果（2026-11-26）：已检查全部 Markdown 的相对链接，修复了根 README 的 2 处旧仓库路径链接、`docs/drafts/` 中 3 处旧草稿链接；模板文件中的示例链接为占位符，检查脚本已排除代码块；新建 `docs/archive/README.md` 以消除归档目录死链。检查通过。

## 5. 遗留事项

- 根 `README.md` 与 `.agent.md` 中的旧版本号待后续单独修订（需人工确认改动范围）。
- `LICENSE` / `CONTRIBUTING.md` 待项目所有者决策。
- `docs/archive/` 已建立索引（[README.md](../archive/README.md)），暂无归档条目；待首批草稿满足归档条件（功能实现 + 稳定 2 周）后迁入。

---

## 6. 第二轮整理（2026-11-26）

### 触发与审计

第一轮提交 `4f97f9b` 后新增提交 `adad099 refactor(scripts): harden OAuth2 test scripts and isolate token artifacts`，改动 `dev.sh`、`scripts/test.sh`、`scripts/get-test-user-tokens.sh`，改变了脚本接口与产物行为。按技能的"代码变更 = 同一提交中更新文档"与 Step 4 验证要求，复核全部文档，发现：

1. **脚本索引缺失**：`scripts/README.md` 没有 `test.sh` 条目，也遗漏了 `docker-build-local.sh`、`generate-production-config.sh` 等已有脚本。
2. **脚本行为过时**：`scripts/README.md` 把 `cookies.txt` 列为"Cookie测试数据"，但 `test.sh` 现改用 `mktemp` 临时目录并在退出时清理；`get-test-user-tokens.sh` 新增 `-r/--refresh`、`-d/--decode`、`-o/--output`，产物原子写入并 `chmod 600`，任一用户失败即非零退出。
3. **失效的旧父项目路径**：根 `README.md` 仍有 5 处指向 `src/ffvtraceability-*` 或不存在文档的路径（第 368、373、380、464、532 行）。
4. **本规划文档过时**：第 5 节曾写"`docs/archive/` 尚未建立"，与第一步已创建索引的事实不符（本轮已修正）。

### 范围与非目标

- 范围：更新 `scripts/README.md`、根 `README.md` 的失效引用与脚本说明、`docs/api-testing/README.md` 的脚本入口说明。
- 非目标：不改任何脚本代码；不重写 `README.md` 中 PKCE 流程示意代码（仅在章节开头加"当前脚本已隔离临时产物"的说明）；不批量修正旧版本号；不移动任何文档。

### 适用流程

本轮仅为文字修订与索引维护，不改变系统行为，**未触发**技能中的"规划三轮收敛"与"实现代码三轮收敛"；仍执行 Step 4 的链接与事实一致性验证。

---

## 7. 第三轮整理（2026-11-26，空杯审计）

### 触发

第二轮后无新代码提交（`a9f7b2b` 仍为 HEAD）。按用户要求以"空杯心态"重新审视整个文档体系，不沿用前两轮的结论，直接从代码与配置反查文档事实。

### 审计发现

1. **P0 文档事实漂移**：`.agent.md` 两处（Overview 与 Technology Stack）仍写 Spring Boot 3.2.0 / SAS 1.5.0，根 `README.md` 技术栈写 3.2.0 / "最新版本"，与 `pom.xml`（3.4.6 / 1.3.6）冲突。两者都是 Agent/人类的首读入口，比历史草稿更需要准确；`AGENTS.md` / `SKILL.md` 中"旧文档仍写旧版本"的括号说明也随之失效，需一并修正。
2. **`CLAUDE.md` 计数过时**：`config/` 写"25+"（实际 23 个 Java 文件）、`controller/` 写"27"（实际 25 个）。
3. **导航链接不显式**：`docs/README.md` 的分类表只链到目录，`docs/development-guides/README.md`、`docs/technology-stack/README.md`、`docs/operations-guides/README.md` 从 Hub 不可直接点击到达；`SKILL.md` 对 `references/checklist.md`、`references/templates.md` 只用反引号提及，不可点击。可达性审计显示 5 个文件为非 Hub 可达。
4. **前轮决策需修订**：第 3 节"不批量改写旧版本号"与第 6 节"不批量修正旧版本号"的约束，在 P0 文档范围内被本轮推翻；历史草稿仍保持原样。
5. **链接与骨架**：163 条相对链接全部有效；草稿索引 28 篇全覆盖；技能声称的根目录状态（无 `MEMORY.md`、`LICENSE`、`CONTRIBUTING.md`、`.cursor/rules/`）经复核均成立。

### 范围与非目标

- 范围：修正 `.agent.md`、根 `README.md` 的版本号及 `AGENTS.md` / `SKILL.md` 的关联说明；修正 `CLAUDE.md` 的两个计数；把 Hub 与技能中的目录链接/纯文本引用改为显式 Markdown 链接；记录本轮审计。
- 非目标：不改任何代码、脚本或配置；不改写 `docs/drafts/` 下历史草稿的版本描述（它们是当时状态的记录）；不新建文档、不移动文档；不猜测 `LICENSE`。

### 适用流程

同为纯文档修订，不改变系统行为，**未触发**三轮收敛；执行 Step 4 的链接、事实与计数验证。
