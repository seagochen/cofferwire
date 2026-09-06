# cofferwire-codec

在 Cofferwire typed model 与严格 canonical frame bytes 之间作确定性转换，并向认证层暴露
收到的原始 authenticated byte range。它只实现协议使用的 CBOR 子集。

设计见 [`docs/detailed_design/20_协议模型与编解码.md`](../../docs/detailed_design/20_协议模型与编解码.md)；
exact wire 规则见 [`docs/spec/05-wire-format.md`](../../docs/spec/05-wire-format.md) 与
[`docs/spec/07-blobs.md`](../../docs/spec/07-blobs.md)。
