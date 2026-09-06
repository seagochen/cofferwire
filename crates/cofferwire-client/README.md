# cofferwire-client

提供 transport-independent sender/recipient、resumable blob、receipt 与 offline recovery
状态机，并通过 trait 把具体 transport 和 durable application store 留给调用方。

设计与持久化顺序见
[`docs/detailed_design/40_客户端状态机.md`](../../docs/detailed_design/40_客户端状态机.md)。
