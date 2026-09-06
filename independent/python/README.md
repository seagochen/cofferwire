# Independent Python implementation

这是从公开 specification 与 vectors 编写的 clean-room queue-v1 client/relay，不 import、
link 或生成自 Rust reference implementation。独立性边界见
[`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md)，在整体验证体系中的职责见
[`docs/detailed_design/60_一致性验证与独立实现.md`](../../docs/detailed_design/60_一致性验证与独立实现.md)。

从仓库根运行：

```sh
python3 -m unittest discover -s independent/python/tests -v
python3 scripts/run_interop_matrix.py --output /tmp/interop-matrix-v1.json
```
