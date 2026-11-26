# 文档质量检查清单（WeSpringAuthServer 适配版）

> 用法：新建或修改文档时按对应小节自检；最终提交前跑一遍"最终验证"。

## 创建前

- [ ] 评估现状：`find . -name "*.md" ... | sort`（见 SKILL.md Step 1），识别缺口与孤立/过期文档
- [ ] 确认要写的内容在已有文档中是否已有：**有则链接，不复制、不移动**
- [ ] 涉及代码/数据库/接口/权限/迁移/部署 → 先在 `docs/drafts/` 写规划，并执行三轮收敛
- [ ] 确认事实基线：版本以 `pom.xml` 为准，命令以 `dev.sh` / `scripts/` 实际内容为准
- [ ] 若发现 `README.md`/`.agent.md` 中版本与 `pom.xml` 冲突，按 `pom.xml` 写，并标注差异

## README.md（已存在，增量维护）

- [ ] 一句话描述 + 关键词
- [ ] 特性列表（5–8 项）
- [ ] 快速开始 ≤5 步（`./dev.sh` / `./mvnw ...`）
- [ ] 架构图或链接
- [ ] 文档导航链接（指向 `AGENTS.md`、`docs/README.md`）
- [ ] 命令来自当前仓库，未抄旧版本

## AGENTS.md（新建，≤120 行）

- [ ] 项目概览（类型、技术栈、状态）
- [ ] 文档索引使用相对路径
- [ ] 快速命令：`build` / `test` / `run` / `verify`
- [ ] 模块概览表（路径与职责对应真实目录）
- [ ] Agent 约束：`BEFORE` / `DO NOT` / `ALWAYS`
- [ ] 维护规则：新增文档 → 更新 `AGENTS.md` 与 `docs/README.md`
- [ ] P0/P1 文档全部索引

## CLAUDE.md / 速查（已存在，增量维护）

- [ ] 关键命令与端口（9000）
- [ ] 服务与环境变量入口（`.env.example`，不写真实值）
- [ ] 高频注意事项（权限、`ROLE_ADMIN`、敏感信息、CSRF/Cookie）
- [ ] 与 `AGENTS.md`、`docs/README.md` 的链接有效
- [ ] 不把本机缓存（`.workbuddy/memory/`）当作共享依据

## .cursorrules（已存在，增量维护）

- [ ] 规则清晰可执行，有正反例
- [ ] 与新增规则冲突时先改此文件，不新建 `.cursor/rules/`
- [ ] 涉及安全（`ROLE_ADMIN`、敏感日志、Cookie/CSRF）的条款保留

## docs/README.md（新建，≤100 行）

- [ ] 目录结构说明
- [ ] 所有子目录与已有文档按主题列出（相对链接）
- [ ] 指向 `AGENTS.md`、`CLAUDE.md`、`.cursorrules`、`scripts/README.md`
- [ ] 明确"已有文档不移动，仅链接"

## Architecture / 架构文档

- [ ] 设计原则 3–5 条
- [ ] 系统概览图（含三条 SecurityFilterChain、OAuth2 端点）
- [ ] 模块依赖与核心类
- [ ] 数据流（授权码 + PKCE、Token 刷新、短信/微信登录）
- [ ] 数据库关键表（`users`、`authorities`、`authority_definitions`、`oauth2_authorization` 等）
- [ ] 关键设计决策表
- [ ] 200–400 行；代码片段来自当前代码

## Development Guide / 开发指南

- [ ] 前置条件（JDK 17、Maven、PostgreSQL）
- [ ] 分步骤启动（`./dev.sh`、`./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`）
- [ ] 所有命令实测可用
- [ ] 常见问题（端口占用、数据库未就绪、Token 获取失败）
- [ ] 链接已有文档，不重复正文

## API Testing / API 测试

- [ ] Base URL（`http://localhost:9000`，可用 `SERVER_PORT` 覆盖）
- [ ] 认证方式（Session / JWT / BASIC + `ROLE_ADMIN`）
- [ ] 错误响应格式
- [ ] 端点：方法、路径、请求/响应示例、错误码
- [ ] 使用 `scripts/test.sh`、`scripts/get-test-user-tokens.sh` 等实测
- [ ] 不把真实 token 写入文档（用占位符）

## Troubleshooting / 故障排查

- [ ] 按**症状**组织，不按组件
- [ ] 启动失败、运行时错误、权限异常、OAuth2/Cookie 问题分节
- [ ] 每个问题含：症状、诊断步骤、解决方案
- [ ] 命令示例与日志解读来自真实脚本/日志

## 草稿与归档

草稿：
- [ ] 描述性命名（禁止 `TASK_PROGRESS.md`、`NOTES.md`、`TEMP.md`）
- [ ] 放 `docs/drafts/`
- [ ] 内容可实施，目的清晰

归档：
- [ ] 文件名加 `YYYY-MM-DD_` 前缀（最后相关日期）
- [ ] 复制到 `docs/archive/`，更新 `docs/archive/README.md`
- [ ] 更新原引用，删除原文件

## 命名与链接

- [ ] 历史文件用 `YYYY-MM-DD_` 前缀；文件名无空格
- [ ] 所有相对路径从文件自身算起，可解析
- [ ] 无指向已移动/已删除文档的死链
- [ ] 表格单元格内命令的 `|` 已转义或移入代码块

## 最终验证

- [ ] 文档中的命令在当前仓库实际执行过（或明确标注"未执行"）
- [ ] 链接全部可解析（可用脚本批量检查，见下）
- [ ] 无敏感信息（token、密码、验证码、密钥真实值）
- [ ] 索引与目录内容一致（无孤立文档）
- [ ] 变更涉及系统行为时，已按 SKILL 的测试门槛验证
- [ ] 提交中包含所有新建文档的 `git add`（否则索引指向不可达文件）

### 链接批量检查（可选）

```bash
python3 - <<'PY'
import pathlib, re
root = pathlib.Path('.')
bad = []
for f in root.rglob('*.md'):
    if any(p in f.parts for p in ('.git', 'target', 'reference-submodules', '.workbuddy', '.understand-anything')):
        continue
    text = f.read_text(errors='ignore')
    text = re.sub(r'```.*?```', '', text, flags=re.S)  # 模板示例中的链接不是真实引用
    for link in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
        if link.startswith(('http://', 'https://', '#', 'mailto:')):
            continue
        target = (f.parent / link.split('#')[0]).resolve()
        if not target.exists():
            bad.append(f'{f}: {link}')
print('\n'.join(bad) if bad else 'OK: no broken relative links')
PY
```
