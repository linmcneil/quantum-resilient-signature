# v2 评测方法学（METHODOLOGY）

本文固定 E1–E4 的评测协议，作为论文 Methods 部分的来源。所有实验可复现：
随机种子写死；单脚本幂等；`python scripts/run_v2_all.py` 一键重跑。

## 0. 环境与机器信息
- 每份 `eval_v2_*.json` 记录 machine 元数据：platform/processor/release/python/
  numpy/matplotlib/openssl 版本、`perf_counter` 分辨率。
- 计时脚本单线程、无并行负载；计时含 Python/调用开销，跨语言比较一律以
  OpenSSL 等官方基准为准（本仓库 Track A/B 为 Python+numpy 实现）。
- `requirements.txt` 固定依赖版本。

## 1. 成功率类指标（E1/E3）
- 计数结果一律报告 Wilson 95% 置信区间（`qrsv2/stats.py`），不放裸点。
- E1：合法接受率/篡改检出率/盲猜拒绝率基于 1500/1500/300 样本；
- E3：每参数点 8–12 个独立随机实例（LLL 攻击耗时随维度急剧增长，受
  120 s/点上限保护；达到上限的实例记为失败并记录 trials）。

## 2. 耗时时序类指标（E2）
对齐 ePrint 2026/1333 对 ML-DSA 评测的批评：
- 固定消息集（600+ 字节同构负载逐条变化）；
- **逐样本计时**并保存原始样本（`samples_ms`）；统计报
  mean / median / p90 / p99 / max；
- Track B 含拒绝采样：额外记录单次签名重试次数的完整分布（中位数、分位数、
  最大值、直方图）——只报均值会严重低估最坏情形执行时间（WCET）；
- RSA-3072-PSS 采用系统 OpenSSL 3.5 `openssl speed`（in-process、行业标准
  实现），聚合值标记 `distribution=constant`；不采用自写的纯 Python RSA 做
  基准（只做功能自检），避免实现质量差异污染对比。

## 3. 攻击实验（E3）语义
- Track A：Kannan 嵌入（LLL，QR 加速浮点实现），恢复三元私钥 s；
  缩尺参数 q=257、σ≈5 使“目标向量 / GH 界”比值 ≈1，使相变落在
  可达维度内（这是**教学标定**，不是生产参数）；
- 教学级估计器（root-Hermite/core-SVP）用于**趋势对照**，不用于声称具体
  安全位；已知局限：目标向量低于 GH 界时估计退化为维度上界（无法区分 σ）。
  已用 lattice-estimator 完成 uSVP/BDD/core-SVP 复核（`scripts/crosscheck_lattice_estimator.py`、
  `data/lattice_estimator_crosscheck.json`）：n=144 参考估计 12–41 bits（84.4 为饱和上界），
  推荐 n=480 达 ≈90 bits core-SVP；默认 dual 家族与 Track B bit 级建模留作后续。

## 4. 区块链场景（E4）
- 定义：单节点收 1000 笔/块、交易负载 64 B；记账开销 = 每笔签名/凭证字节；
  膨胀系数 = 记账开销 / 负载；验签 TPS = 1000 / 验签耗时中位数。
- NIST 方案（ML-DSA-44/FN-DSA-512/ECDSA）只给出官方规格尺寸（FN-DSA-512 按 FALCON v1.2 草案）+ 文献数量级耗时，
  明确标注“非本机实测”。

## 5. 复现性清单
- 种子：E1=12345/20260908 系；E2=11/22/20260908；E3=20260908；E4 直接读 E2。
- 产物：`data/eval_v2_e1..e4.json`（含 schema 内嵌字段说明）、
  `docs/figures_v2/*.png`（160 dpi）。
- 单元测试 `tests/test_v2_core.py` 覆盖：估计器烟雾、Track A/B 往返与篡改、
  签名序列化、RSA-PSS 功能（纯 Python 小模数）。