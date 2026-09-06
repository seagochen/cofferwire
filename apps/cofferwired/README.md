# cofferwired

提供 Cofferwire reference HTTPS/WebSocket Relay daemon 和 queue-v1 line transport。
daemon 负责 bounded transport、严格解码、命令认证、按凭证限流和 SQLite Relay 调度，
不解析 application content。

- 设计与处理链：[`docs/detailed_design/50_Relay与守护进程.md`](../../docs/detailed_design/50_Relay与守护进程.md)
- 网络接口：[`docs/detailed_design/70_外部接口.md`](../../docs/detailed_design/70_外部接口.md)
- 参数、部署和运维：[`docs/detailed_design/80_配置参考.md`](../../docs/detailed_design/80_配置参考.md)、[`90_部署与运维.md`](../../docs/detailed_design/90_部署与运维.md)

本 daemon 是 reference implementation；当前安全支持边界见 [`SECURITY.md`](../../SECURITY.md)。
