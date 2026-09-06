# MEMORY.md

记录 Cofferwire 的稳定架构与本地运行环境事实，供后续开发和运维使用。任务状态只进入
GitHub Issues；本文件不保存凭证或临时进度。

## 整体架构

- queue-v1 是冻结的小消息协议 scope；blob、receipt 和 offline bundle 使用独立 profile，
  支持 queue-v1 不隐含支持其他 profile。
- 每台接收设备使用独立 queue。Relay 不建模全局用户，也不负责多设备 fan-out、应用
  冲突或 family-tree 业务语义。
- Relay 位于端到端信任边界之外，只提供 opaque payload 的可用性、授权状态机和持久化；
  client 负责内容认证、解密和应用状态。
- 接收顺序固定为 download → authenticate/decrypt → local durable commit → relay ACK。
  `receipt.applied` 是独立的端到端应用回执，不能与 relay ACK 混用。
- transport 可替换。客户端状态机通过 `Transport` 移动完整 frame，不依赖 HTTPS、
  WebSocket、文件或连接顺序。
- Rust 依赖方向为 types → codec/crypto → client，relay 独立实现语义/SQLite，daemon 在
  最外层组合 codec、crypto、relay 和网络资源控制。
- `cofferwire-relay` 同时包含内存语义参考 `Relay` 和 SQLite 事务实现 `DurableRelay`；
  queue/blob effect 与 replay response 需要原子提交。
- 工程设计 SSoT 位于 `docs/detailed_design/`；规范性 wire 契约位于 `docs/spec/`。

## 存储与安全边界

- Relay 使用 bundled SQLite；schema、迁移和 durability pragma 的一次信息源是
  `crates/cofferwire-relay/src/durable.rs`。
- queue deletion 级联删除 queue message；blob deletion 当前撤销 grant，不保证从
  `blob_objects`/`blob_chunks` 物理擦除 ciphertext。
- daemon 在严格 decode 后验证 queue principal 或 blob capability，认证成功后才进入
  per-credential rate limit 和业务事务。
- Relay 能观察 IP、timing、size、queue/blob access；端到端加密不提供匿名性或流量分析
  抵抗保证。
- 私钥、plaintext、proof、capability 和 production credential 不得进入日志、metrics、
  Debug/Display、公开 evidence 或仓库。

## 本地开发环境

- 工作区：`/home/orlando/projects/cofferwire`
- 已验证平台：Linux x86_64。
- workspace 基线：Rust 1.84、edition 2021、Cargo workspace、`Cargo.lock` 固定依赖。
- 当前本机已验证工具：`rustc 1.84.1`、`cargo 1.84.1`；nightly 仅用于 `cargo-fuzz`。
- 独立实现要求 Python 3.11+；CI 使用 Python 3.11，本地更高版本不能替代最低版本 CI。
- daemon 使用运营者提供的 TLS PEM 文件和本地 SQLite 路径；仓库没有 `.env` 配置层。
- 当前没有记录固定生产部署主机、远程账户、IP、证书路径或云服务依赖。

## 依赖与外部服务

- Rust 密码学使用 Ed25519、RFC 9180 HPKE、HKDF/SHA-256 和 ChaCha20-Poly1305 的现有库。
- 网络 daemon 使用 Axum/Tokio/Tower 与 rustls；不依赖外部 queue 或数据库服务。
- 独立 Python 实现只依赖 `cryptography`，不得 import/link Rust reference implementation。
- GitHub Actions 执行稳定测试和定时 fuzz；具体 action/toolchain 以 workflow 为准。

## 常用命令

- 全量 Rust 测试：`cargo test --workspace`
- 严格 lint：`cargo clippy --workspace --all-targets -- -D warnings`
- 格式检查：`cargo fmt --all -- --check`
- 规范覆盖：`python3 scripts/check_conformance.py --check-report conformance/coverage.json`
- 独立实现：`python3 -m unittest discover -s independent/python/tests -v`
- 四组合互操作：`python3 scripts/run_interop_matrix.py --output /tmp/interop-matrix-v1.json`
- fuzz target 编译：`cargo check --manifest-path fuzz/Cargo.toml --bins`
- 完整发布流程：按 `docs/detailed_design/90_部署与运维.md` 执行；缺真实 pilot、独立 review
  或正式签名时只能称为 rehearsal。

## 已知操作注意事项

- WebSocket 集成测试需要绑定 loopback 临时端口；受限 sandbox 中出现 `EPERM` 时，应在
  获得明确权限后重跑，不能把环境拒绝误判为协议失败。
- 不要并行启动两个完整 Cargo test/interop run；它们会争用 build artifacts、临时网络
  和 SQLite 测试资源。workspace 与 interop 应串行验证。
- fuzz crash reproduction 的最后一个参数必须是实际 artifact 文件；不存在的
  `fuzz/artifacts/<target>/crash-*` 路径会被 libFuzzer 当作缺失目录并立即失败。
- SQLite 文件级备份仅验证过停机冷拷贝；热备份和多个 daemon 进程共享同一文件未经验证。
