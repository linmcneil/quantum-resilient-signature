# 文献调研：LWE/格签名前沿与评测方法（2026-09-08）

> 用途：为省级大创「RSA 加密算法的研究与改进」的抗量子分支确定对标物与实验口径。
> 调研方式：Google Scholar / IACR ePrint / 期刊官网检索，全部为 2023–2026 年文献。

## 1. 一句话结论

前沿 = **以 NIST 标准化的格签名（ML-DSA/FIPS 204、FN-DSA/拟 FIPS 206）为工程基线**，
学术上在 **Lyubashevsky “Fiat–Shamir with Aborts” 框架**上不断压缩签名尺寸、去掉拒绝采样，
区块链落地研究关心的是**签名尺寸导致的交易膨胀与验证开销**。
评测规范上，2026 年已出现专门论文批评“只报平均耗时”的做法——拒绝采样使签名耗时长尾分布，
必须报告**分位数与最坏情形**。我们 v1 的“打稻草人式防御率对比（LWE 100% vs RSA 0%）”
不属于当前主流评测口径，需要重构。

## 2. 算法演进主线

- 2009 Lyubashevsky, *Fiat-Shamir with Aborts*（Asiacrypt）——格签名基础框架。
- 2012 *Lattice Signatures Without Trapdoors*——高斯拒绝采样、无陷门。
- → CRYSTALS-Dilithium → **FIPS 204 (ML-DSA)**，NIST 于 2024-08-13 连同 FIPS 203 (ML-KEM)、FIPS 205 (SLH-DSA) 正式发布；**FN-DSA（FALCON 路线，拟 FIPS 206）** 2025-08 已提交标准草案审批，公开草案与定稿待发布（截至 2026-09 尚未公开）。
- 参考尺寸（NIST Ⅰ级）：ML-DSA-44 pk 1312 B / sk 2560 B / sig 2420 B；FN-DSA-512 pk 897 B / sig 666 B（FALCON v1.2 / FN-DSA 草案值）。

### 最近 2–3 年的学术增量（“前沿在卷什么”）
| 论文 | 年份/会议 | 贡献 |
| --- | --- | --- |
| HAETAE | CHES 2024 | 双峰拒绝采样，签名/验签钥比 Dilithium 小至多 39%/25%，含 AVX2 与 Cortex-M4 实现 |
| G+G | Asiacrypt 2023 | 卷积高斯，**无拒绝采样、无噪声淹没** |
| Compact Lattice Signatures via Iterative Rejection Sampling | CRYPTO 2025 | 迭代拒绝采样，签名更紧 |
| Rhyme (3C sampling) | ePrint 2025/1350（清华/山大等） | 基于 LWE 变体 + 3C 采样，**不用 flooding/拒绝采样/高斯卷积**，ROM/QROM 可证 + 参考实现 |
| Tight Lattice-Based Signatures without Trapdoors from Search LWE | CRYPTO 2026 / ePrint 2026/953 | 首个无陷门、紧归约到 **search LWE** 的格签名 |
| Ringtail | 2025 | 两轮 LWE 门限签名（pk 7.7 KB / sig 5.7 KB） |

注意：Rhyme 的作者含清华/山大/华为等国内团队，说明“LWE 变体 + 新型采样，摆脱拒绝采样”
正是国内活跃方向——我们的 v2 选题若贴近这条线，答辩时好讲且可引用。

## 3. 区块链场景评测口径（我们要“对标”的表格长什么样）

- *Navigating the quantum computing threat landscape for blockchains*（Computer Science Review, 2025）：
  按 key/sig 尺寸 + keygen/sign/verify 相对性能列出各 PQC 方案在链上的适用性。
- *Post-Quantum Transition in Blockchain Architectures*（MDPI Technologies 14(6):367, 2026）：
  实测基线 ECDSA 签名 ~65–73 B；格签名把交易负载放大 **10–30×**，验签开销 **2–5×**。
  核心指标：签名尺寸、区块/交易格式膨胀、带宽、吞吐(TPS)。
- 产业侧（可作 CV 的“意义”素材）：NIST 要求 2030 年前弃用 ECC；CNSA 2.0 规定 2025 起软件/固件签名用 ML-DSA；2026 年已有公链（TRON 等）开放量子抗性签名公测。

## 4. 评测方法论的最新批评（最值得借鉴的一条）

*Apples, Oranges, and Signatures: Pitfalls and Methodology in ML-DSA Benchmarking*
（PQShield + 慕尼黑联邦国防军大学, ePrint 2026/1333）：

- ML-DSA 因**拒绝采样**导致签名耗时高度可变，单次可能达到均值约 **20×**；
- 直接报 mean/min/max 会误导真实系统迁移规划；
- 正确做法：固定标准输入数据集，报告**分位数 + 最坏情形(WCET)**；
- 配套（RP2040/Cortex-M0+ 论文）：每安全级 ≥100 次，mean + 方差分析拒绝采样延迟。

## 5. 安全参数怎么定（不是拍脑袋）

- **lattice-estimator**（Albrecht et al.）是事实标准：对给定 LWE 实例输出 primal/dual 等攻击的
  bit 复杂度与最优 BKZ 块长 β；NIST 安全级别即按 gate-count 估计划分。
- 论文惯例：参数选自满足 `estimator ≥ λ`；再在**缩尺小维度**上跑 LLL/BKZ + Babai，
  验证“实测相变点”与理论估计在同一数量级——两层证据互相印证。
- 我们 v1 的 n=128, q=12289, σ=2, V=8 来自专利旧参数，没有任何 estimator 佐证；v2 应重定。

## 6. 可借鉴 / 应避免（对照 v1）

可借鉴：同安全级对照、尺寸 + 耗时分布双轴、安全级由 estimator 推导、缩尺度攻击验证相变。
应避免：教科书 RSA raw = 0% 的稻草人指标；只报均值；无攻击成本语义的“防御成功率 100%”；
参数无来源；把对称 MAC 语义包装成数字签名。

## 7. 主要来源

- FIPS 204：NIST 官网；FN-DSA-512 尺寸按 FALCON v1.2 规范（FIPS 206 尚未正式发布）。ML-DSA / FN-DSA 尺寸表另见多篇 2025–2026 基准论文。
- ePrint 2025/1350（Rhyme）；ePrint 2026/953（Tight Signatures from Search LWE）；
  ePrint 2026/1333（ML-DSA 评测方法论）；CHES 2024 HAETAE；Asiacrypt 2023 G+G；
  CRYPTO 2025 Iterative Rejection Sampling（slides: iacr.org）。
- Computer Science Review 2025（区块链量子威胁全景综述）；
  MDPI Technologies 14(6):367（后量子区块链迁移系统综述，2026）。