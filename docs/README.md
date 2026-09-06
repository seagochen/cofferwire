# docs 目录

Cofferwire 的设计、验证和运维入口。工程总览与快速上手见
仓库根 [README.md](../README.md)；实现设计以
[`detailed_design/`](detailed_design/00_概述.md) 为唯一正源（SSoT），协议线上行为
则以 [`spec/`](spec/README.md) 的规范性文本为准。

## 文档一览

| 文件 / 目录 | 类别 | 内容 |
|---|---|---|
| [`spec/`](spec/README.md) | 协议规范 | 规范性协议文本、CDDL 与 identifier registry |
| [`detailed_design/`](detailed_design/00_概述.md) | 详细设计书 | 按源码边界拆分的系统设计，入口为 `00_概述.md` |
| [`../conformance/evidence/`](../conformance/evidence/README.md) | 验证证据 | 互操作、模糊测试、故障注入与运营限制的机器可读证据 |

## 详细设计书

| 文件 | 内容 |
|---|---|
| [`00_概述.md`](detailed_design/00_概述.md) | 亲文档、系统全貌、模块索引、追溯与移交 |
| [`05_术语表.md`](detailed_design/05_术语表.md) | 项目术语与容易混淆的边界 |
| [`10_通用设计.md`](detailed_design/10_通用设计.md) | 数据、安全、错误、性能、测试与依赖策略 |
| [`20_协议模型与编解码.md`](detailed_design/20_协议模型与编解码.md) | 类型不变量、queue/blob frame 与严格解码 |
| [`30_密码学.md`](detailed_design/30_密码学.md) | 命令认证、端到端加密、blob 与回执密码学 |
| [`40_客户端状态机.md`](detailed_design/40_客户端状态机.md) | 发送、接收、恢复、回执和离线 bundle |
| [`50_Relay与守护进程.md`](detailed_design/50_Relay与守护进程.md) | 内存模型、SQLite 事务、认证和网络适配 |
| [`60_一致性验证与独立实现.md`](detailed_design/60_一致性验证与独立实现.md) | registry、vectors、互操作、fuzz、故障与发布证据 |
| [`70_外部接口.md`](detailed_design/70_外部接口.md) | HTTPS、WebSocket、line transport 与命令接口 |
| [`80_配置参考.md`](detailed_design/80_配置参考.md) | daemon 参数、测试和证据收集配置入口 |
| [`90_部署与运维.md`](detailed_design/90_部署与运维.md) | 构建、部署、备份、保留、安全响应与发布 |

## 文档形式方针

- 对代码以参照为主：以路径和符号名定位实现，不复制函数体、常量值或默认配置。
- 详细设计只在 `detailed_design/` 展开；README 与模块说明只提供摘要和链接。
- 规范性协议要求只在 `docs/spec/` 定义；设计书解释实现如何满足规范，不创建第二套 wire 契约。
- Markdown 版本由 Git commit/tag 管理，文件名不携带版本号。
- 变更历史直接使用 Git commit/tag，不在仓库维护平行的会话 changelog。
- 架构图使用内联 Mermaid，保证可审查、可 diff。
- 未完成工作只进入 GitHub Issues，不在文档目录创建本地任务清单。
- #25/#27/#28 的本地实验产物统一写入被 Git 忽略的 `docs/temp/`，发布完成后删除；
  可复现的空白输入模板保存在 `scripts/fixtures/`。
