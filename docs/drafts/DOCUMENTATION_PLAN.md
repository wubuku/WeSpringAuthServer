# 文档体系建设规划

> **Purpose**: 记录本次文档审计结果、优先级、范围与有意不做的项。
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
- `docs/archive/` 尚未建立，待首批草稿满足归档条件（功能实现 + 稳定 2 周）后创建。
