# CLAUDE.md

本文件规定 Claude/Codex 在 **Cofferwire** 仓库中的工作方式。每次会话开始都必须遵守。
与默认行为冲突时，以本文件为准。每次会话开始后先阅读本文件和根目录
[`MEMORY.md`](MEMORY.md)；需要长期保留的项目事实只记录在 `MEMORY.md`，除非用户明确
指定其他位置。

## 一、沟通与语言

- 与用户交流使用中文。
- 代码标识符、代码注释、日志和异常信息使用英文。
- 工程/设计文档使用中文；规范性协议文本可保持既有英文风格。
- GitHub Issue 标题使用英文，正文使用中文。

## 二、记忆与架构基线

1. 每次会话开始时阅读 `MEMORY.md`。
2. 架构、环境、依赖和已验证命令等长期事实写入 `MEMORY.md`；协作规则只写在本文件。
3. 跨模块或架构调整前读取 `MEMORY.md` 和相关详细设计。
4. 架构事实变化时，在同一任务中同步 `MEMORY.md` 与 `docs/detailed_design/`。
5. 不在任何入库文档中写明文密码、token、private key、capability 或生产凭证。

## 三、任务与进度

- GitHub Issues 是唯一 backlog；未完成工作、后续项和遗留缺陷都进入 Issue。
- `MEMORY.md` 不复制 Issue 状态，仓库不创建 `TASKS.md` 或其他本地任务板。
- Issue 管理与 commit message 使用仓库 `.codex/skills/` 中的对应规范。

## 四、工作流程

### 1. 先理解再修改

- 先阅读相关代码、规范、详细设计、`MEMORY.md` 和 Issue。
- 非平凡修改开始前说明影响文件、行为、风险和验证方法。
- 公开 API、wire bytes、identifier、默认行为或安全声明存在取舍时，先与用户确认。

### 2. 分阶段验证

1. 用户明确要求且边界清晰时直接推进。
2. 每阶段运行与风险相称的测试。
3. 代码结构变化同步详细设计；长期事实变化同步 `MEMORY.md`；任务进度同步 Issue。
4. 汇报实际完成内容、验证结果和仍需外部完成的边界，不伪造证据。

### 3. 禁止自动提交

- 不自动执行 `git commit` 或 `git push`。
- 只有用户明确要求提交或推送时才执行。
- 提交前确认 staged 内容单一、没有用户的无关文件，并展示验证结果。

## 五、实现约束

- 规范优先：wire 行为以 `docs/spec/` 为准；工程设计以 `docs/detailed_design/` 为准。
- 只做用户授权范围内的工作，沿用现有模块、命名和抽象。
- 不回滚或覆盖用户已有改动；无关 dirty files 保持不动。
- 注释解释意图和约束，不复述代码；避免临时兼容层和重复业务规则。
- 网络输入必须有界、fail closed 且不泄露 secret；安全声明不得超出实际证据。
- 修改后检查代码规模、职责、重复逻辑、文档同步和测试覆盖。

## 六、项目上下文

- 架构与环境基线：[`MEMORY.md`](MEMORY.md)
- 工程设计 SSoT：[`docs/detailed_design/`](docs/detailed_design/00_概述.md)
- 规范性协议契约：[`docs/spec/`](docs/spec/README.md)
- 文档总目录：[`docs/README.md`](docs/README.md)
- 测试与发布门禁：[`TESTING.md`](TESTING.md)
- 当前任务与未完成工作：GitHub Issues
