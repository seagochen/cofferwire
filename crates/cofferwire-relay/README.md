# cofferwire-relay

包含传输无关的内存语义参考和 SQLite queue/blob 事务实现。调用方必须在进入该层之前
完成协议解码和认证；payload 对 Relay 保持 opaque。

当前 schema、replay、durability 和 daemon 分层设计见
[`docs/detailed_design/50_Relay与守护进程.md`](../../docs/detailed_design/50_Relay与守护进程.md)。
