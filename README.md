# Quantum-Resilient Signature：基于 LWE 的格基认证与签名

**论文（独立作者预印本）**：Zhiqian Lin. *Reproducible Design-Space Study of Lightweight Lattice-Based
Authentication and Signatures for Blockchain Transactions*. Cryptology ePrint Archive,
Paper 2026/1925, Sep 2026. https://eprint.iacr.org/2026/1925

在线仓库：https://github.com/linmcneil/quantum-resilient-signature
Zenodo 归档（代码与数据）DOI：https://doi.org/10.5281/zenodo.22659733

这个项目的出发点是量子计算对 RSA/ECC 这类传统公钥密码的威胁：Shor 算法能在多项式
时间内分解大整数、计算离散对数，一旦可扩展的量子计算机落地，RSA 基于整数分解的
安全性就不再成立。顺着 `b = A·s + e` 这条 LWE 构造，我把思路落成了两条轻量方案线，
面向区块链这类“大量短消息 + 高频验签”的场景：

- **Track A：LWE 认证标签。** 用交易哈希逐笔派生矩阵 A（一事一密），凭证
  `b = A·s + e`，验签端校验残差是否在阈值内。语义上属于 MAC，验签需要共享密钥，
  适合联盟链 / 托管这类有信任基础的场景。
- **Track B：公开可验证的格签名原型。** 公钥是 `(A, T = A·S)`，签名端做
  Fiat–Shamir with Aborts，用拒绝采样保证输出的 `z` 不泄露私钥信息。验签不需要
  共享密钥，任何节点都能验。

另外配套两块工作：**I1** 是一套参数实例化方法，先用 root-Hermite / core-SVP 估计器
把参数定到目标安全级，再用缩尺的 LLL 嵌入攻击做交叉验证，看成功率是否和估计的安全
级同步变化；**I2** 是 Track A 里的交易派生矩阵——A 由 `SHA-256(tx)` 展开得到，既不用
传输矩阵本身，也避免不同交易复用同一份凭证。

## 主要结果

实验全部在本机（Windows 11，CPU）跑通，脚本可一键复现。关键结论：

- **正确性（Track A / Track B）**：Track A 合法凭证接受、篡改检出、盲猜凭证
  拒绝三组测试（1500 / 1500 / 300 次）全部 1.0000；Track B 合法签名接受、
  篡改交易拒绝、随机伪造拒绝、单字节篡改签名拒绝四组测试（各 1000 次）也全部 1.0000。
- **性能（同机实测）**：Track A 签发中位 2.34 ms、验签 0.098 ms，凭证 288 B；
  Track B 签发中位 1.36 ms、验签 0.160 ms，签名 544 B；对照组 RSA-3072-PSS
  （OpenSSL 3.5.7 实测）签发 7.39 ms、验签 0.135 ms。
- **安全-性能权衡（缩尺攻击，q=257）**：恢复成功率随维度 n 增大从 ~0.9 降到 ~0.1、
  随噪声 σ 增大从全成功降到 ~0.1，与 I1 估计的安全级变化方向一致；样本越多攻击
  越有利，这恰好说明“一事一密”设计的意义。
- **区块链场景（1000 笔/块，负载 64 B/笔）**：Track A 每笔 288 B（膨胀 4.5×），
  Track B 每笔 544 B（8.5×），验签吞吐量级在几千到一万 TPS 之间。
- **参考工具复核（lattice-estimator）**：用社区 lattice-estimator 对教学参数做独立复核，
  Kyber512 / Dilithium2 官方 doctest 数字逐一验证一致。Track A 的 n=144 原型参考估计为
  约 12–41 bits（教学估计器报的 84.4 bits 是维度饱和上界，非安全估计）；建议 ≥80 bits
  教学参数取 n=m=480（≈90 bits core-SVP / ≈118 bits 默认模型）。Track B 同构核在
  bound<λ1 时“无解”，说明其安全性属植入短解的非齐次实例，且 ∞-范数 MSIS 定参需满足
  2(κ−h) < (q−1)/2。数据见 `data/lattice_estimator_crosscheck.json`，图见 v2_fig7。

完整分项表格和逐实验数据见 `docs/REPORT_v2.md`，论文骨架在 `paper/`。

## 复现

```bash
pip install numpy matplotlib      # 核心实现只用标准库
python scripts/run_v2_all.py      # 一次跑完 E1、E1b、E2、E3、E4 并出图
```

也可以分开跑：`scripts/run_v2_e1.py`（Track A 正确性与阈值曲线）、`run_v2_e1b.py`（Track B 正确性）、
`run_v2_e2.py`（性能对照）、`run_v2_e3.py`（缩尺攻击）、`run_v2_e4.py`（区块链场景）、
`make_figures_v2.py`（绘图）。

lattice-estimator 交叉复核（可选，结果已随库提供）：先 `git clone
https://github.com/malb/lattice-estimator`，再设 `LATTICE_ESTIMATOR_DIR` 后运行
`python scripts/crosscheck_lattice_estimator.py`。Windows 控制台请先设
`$env:PYTHONIOENCODING="utf-8"`（estimator 日志含 Unicode 符号，GBK 控制台会报错）。
无 Sage 环境时脚本自动使用仓库内的
`scripts/sage_shim/`（该层只实现 estimator 用到的 ~28 个 `sage.all` 数值符号，已在
doctest 数字上验证一致）。
单测：`python tests/test_v2_core.py`。

实验数据落在 `data/`，图在 `docs/figures_v2/`，核心代码在 `qrsv2/`。

## 目录结构

```
qrsv2/    核心实现：参数、安全级估计、认证标签/签名、LLL、RSA-PSS、矩阵派生
scripts/  E1–E4、lattice-estimator 交叉复核与绘图脚本（sage_shim/ 为可选 Sage 数值兼容层）
tests/    单测
data/     评测 JSON
docs/     方法学、实验设计、结果报告、文献综述与图表
paper/    LaTeX 论文骨架
qrs/      v1 遗留（已冻结）
```

## 局限与后续

这套实现是研究原型，不是可部署的密码库，有几处明确的边界：

- 安全性结论是参数估计 + 缩尺实验 + 参考工具复核，没有形式化证明；已完成
  lattice-estimator 的 uSVP/BDD/core-SVP 复核（见 `data/lattice_estimator_crosscheck.json`），
  默认 dual 家族与 Track B 的 bit 级建模仍是后续工作。
- Track B 的 ringless 公钥有约 224 KB，远大于 ML-DSA 的 1312 B——这直观说明了
  为什么正式实现需要 module/ring 结构加 NTT，也是下一步的主要工作。
- I2 让矩阵 A 随被签消息变化，对手可能刻意选择消息，需要额外的归约论证。

## v1

`qrs/`、`docs/EXPERIMENT.md` 是第一版存档。v1 用“LWE 100% vs RSA 0%”的防御率做对比，
两种攻击的语义不对等、结论有误导，因此重做了 v2，v1 仅保留作为追溯，不再引用其结论。

## 论文与引用

论文（独立作者预印本，CC BY）：Zhiqian Lin. *Reproducible Design-Space Study of Lightweight
Lattice-Based Authentication and Signatures for Blockchain Transactions*. Cryptology ePrint
Archive, Paper 2026/1925, Sep 2026. https://eprint.iacr.org/2026/1925

```
@misc{cryptoeprint:2026/1925,
  author       = {Zhiqian Lin},
  title        = {Reproducible Design-Space Study of Lightweight Lattice-Based Authentication and Signatures for Blockchain Transactions},
  howpublished = {Cryptology {ePrint} Archive, Paper 2026/1925},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/1925}
}
```

代码与数据的归档版本见 Zenodo：https://doi.org/10.5281/zenodo.22659733（`CITATION.cff` 里同时给出了
论文与软件两条引用）。论文的自我定位是**方法学贡献**——可复现的设计空间研究加上评测方法学，
不声称新的可证明安全方案，也不声称形式化安全证明。

## 说明

本项目在代码编写、文档整理与实验过程中使用了 AI 辅助编程工具（OpenAI Codex），作者对全部代码、实验数据和结论进行了人工核对；仓库与论文内容仅代表作者个人工作。

英文版说明见 `README.en.md`；论文与代码/数据的引用条目见 `CITATION.cff`。
