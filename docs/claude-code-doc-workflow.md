# Claude Code 文档工作流完整方案

---

## 场景一：全新项目（0 → 1）

### 第一步：初始化项目结构

启动 Claude Code 后，**第一件事**是运行 `/init`，让 Claude 扫描项目并生成基础 CLAUDE.md：

```bash
/init
```

然后手动补充 `/init` 无法自动发现的内容，包括业务背景、团队约定、技术选型原因。

---

### 第二步：建立文档目录结构

约定好文档放在哪里，Claude 才知道去哪里维护。推荐结构：

```
your-project/
├── CLAUDE.md                    # Claude 的项目记忆
├── docs/
│   ├── architecture.md          # 架构决策和整体设计
│   ├── api.md                   # API 接口文档
│   ├── decisions/               # ADR：架构决策记录
│   │   └── 001-use-postgres.md
│   └── project_notes/           # 开发过程追踪
│       ├── key_facts.md         # 项目关键事实
│       ├── decisions.md         # 决策日志
│       └── bugs.md              # Bug 及解决方案
├── .claude/
│   ├── settings.json            # Hooks 配置
│   └── commands/                # 自定义命令
│       ├── doc-sync.md
│       └── feature-done.md
└── src/
```

---

### 第三步：CLAUDE.md 写什么

**原则：写 Claude 不能自己发现的东西，不写代码本身能说明的东西。**

```markdown
# 项目名称

## 技术栈
- Node.js 20 + TypeScript + Fastify
- PostgreSQL 16（不用 ORM，用 raw SQL + parameterized queries）
- 部署在 AWS ECS

## 构建和测试
- `npm run dev`：启动开发服务器
- `npm test`：运行单元测试
- `npm run test:e2e`：运行集成测试（需要本地 DB）

## 项目约定
- 所有 public 函数必须有 JSDoc 注释
- API 接口变更必须更新 docs/api.md
- 错误码统一定义在 src/constants/errors.ts，禁止散落在业务代码里
- 不允许直接 push main，必须通过 PR

## 文档规则
- 完成一个完整功能后，更新 docs/architecture.md 和 docs/project_notes/
- 新增 API 接口后，立即更新 docs/api.md
- 架构级决策写入 docs/decisions/（ADR 格式）
- 日常小修改、重构、bugfix 不需要更新文档

## 参考文档
- API 规范：@docs/api.md
- 架构说明：@docs/architecture.md
```

> **控制在 150 行以内**，越精简遵守率越高。

---

### 第四步：配置 Hooks（git commit 时触发）

在 `.claude/settings.json` 里配置，只在 git commit 时检查文档，而不是每次改文件：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "prompt",
            "prompt": "检查这个 bash 命令是否是 git commit 或 git push。如果是，先检查本次改动：1) 是否新增或修改了 API 接口但没有更新 docs/api.md；2) 是否有重大架构变更但没有记录在 docs/decisions/ 里。有遗漏则拒绝并提示具体要补什么。其他 bash 命令直接放行，不要干扰正常开发。"
          }
        ]
      }
    ]
  }
}
```

---

### 第五步：自定义命令

#### `/project:feature-done` — 功能完成时调用

`.claude/commands/feature-done.md`：

```markdown
当前功能开发完毕。请执行以下步骤：

1. 回顾本次会话中修改的所有文件
2. 判断是否需要更新以下文档（有则更新，没有则跳过）：
   - docs/api.md（如果有 API 变更）
   - docs/architecture.md（如果有架构变更）
   - docs/project_notes/decisions.md（如果有重要决策）
   - docs/project_notes/key_facts.md（如果有值得记录的事实）
3. 生成一条规范的 git commit message（格式：type(scope): description）
4. 等待我确认后再执行 git commit
```

#### `/project:doc-sync` — 手动触发文档同步

`.claude/commands/doc-sync.md`：

```markdown
扫描 src/ 目录下最近修改的文件，对比 docs/ 目录的内容，
找出文档落后于代码的地方并批量补全。
重点检查：API 接口、公共函数签名、配置项变更。
```

---

### 第六步：开发节奏

```
日常开发（不用管文档）
    ↓
功能完成 → 运行 /project:feature-done
    ↓
Claude 自动判断是否需要更新文档 + 生成 commit message
    ↓
你确认 → git commit（此时 Hook 再次校验）
    ↓
push → PR
```

---

---

## 场景二：老项目接手

### 第一步：读懂项目（先别写代码）

进入项目目录，对 Claude 说：

```
请帮我分析这个项目，不要修改任何文件。
按顺序做：
1. 扫描 package.json / go.mod / pyproject.toml，识别技术栈
2. 读 README 和现有文档（如果有）
3. 扫描目录结构，识别核心模块
4. 找出 3-5 个最重要的入口文件读懂主流程
5. 生成一份项目概览，包括：架构、核心数据流、关键约定
```

这对应官方推荐的 **Explore（探索）** 阶段，在写任何代码前先建立完整认知。

---

### 第二步：生成初始文档

探索完成后，运行：

```
/init
```

再补充命令：

```
基于你对项目的理解，帮我生成以下文档（如果不确定某处，标注"待确认"）：
- docs/architecture.md：整体架构和模块说明
- docs/api.md：现有 API 接口清单
- docs/project_notes/key_facts.md：关键事实（DB schema、环境变量、特殊约定）
```

**生成后你要做的事**：过一遍，把"待确认"的地方补全，把明显错误的地方修正。这一步不能省，AI 理解老项目会有偏差。

---

### 第三步：补充 CLAUDE.md

生成文档后，老项目的 CLAUDE.md 需要额外强调历史包袱：

```markdown
# 项目名称（老项目）

## 重要背景
- 项目始于 2019 年，部分模块仍使用旧版写法，不要自动"现代化"它们
- legacy/ 目录只修 bug，不重构
- auth 模块由 A 同学维护，改动前先沟通

## 已知技术债
- UserService 有循环依赖问题，待重构（Issue #234）
- payments 模块暂时没有单测，新功能需补测试

## 文档状态
- docs/api.md：AI 生成，2024-01 校验过，基本准确
- docs/architecture.md：AI 生成，部分模块描述待确认
- legacy/ 目录暂无文档，改动时需先探索再操作

## 当前约定（参考 docs/）
（同新项目规则）
```

---

### 第四步：写新代码时的工作流

老项目写新功能，每次开始前先探索再动手：

```
开始新功能前：
"我要实现 [功能描述]，请先找到相关的现有代码，
理解当前的数据流和约定，然后告诉我你的实现思路，
等我确认后再开始写代码。"
```

功能完成后，同样用 `/project:feature-done` 触发文档更新。

---

### 第五步：渐进式补全文档

老项目文档不用一次全补，按"谁改谁补"原则：

```markdown
# 在 CLAUDE.md 补充这条规则：

## 文档补全规则
- 修改某个模块时，顺手把该模块的注释和文档补到及格线
- 及格线：核心函数有 JSDoc，模块有 README 或在 architecture.md 里有说明
- 不要因为补文档而大范围改动无关代码
```

---

---

## 完整配置速查

### `.claude/settings.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "prompt",
            "prompt": "只在检测到 git commit 或 git push 命令时执行检查：确认 docs/api.md 和 docs/architecture.md 是否与本次改动同步。其余命令直接放行。"
          }
        ]
      }
    ]
  }
}
```

### 目录结构一览

```
.claude/
├── settings.json          # Hooks
└── commands/
    ├── feature-done.md    # /project:feature-done
    └── doc-sync.md        # /project:doc-sync

docs/
├── architecture.md
├── api.md
├── decisions/
│   └── 001-xxx.md
└── project_notes/
    ├── key_facts.md
    ├── decisions.md
    └── bugs.md

CLAUDE.md                  # 提交到 git，团队共享
CLAUDE.local.md            # 加入 .gitignore，个人偏好
```

### 触发时机总结

| 时机 | 动作 | 方式 |
|---|---|---|
| 功能完成 | 更新相关文档 + 生成 commit message | `/project:feature-done` |
| git commit | 校验 API/架构文档是否同步 | PreToolUse Hook 自动触发 |
| 手动触发 | 批量扫描文档落差 | `/project:doc-sync` |
| 接手老项目 | 生成初始文档 | `/init` + 手动探索 |
| 修改某模块 | 顺手补该模块文档 | CLAUDE.md 规则约束 |
