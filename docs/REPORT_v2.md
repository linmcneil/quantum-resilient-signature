# v2 实验报告（2026-09-08，本机 CPU）

本文件汇总 E1–E4 结果口径与复现方法，配合 README 与 data/*.json 使用。

## E1 · Track A 正确性与阈值
- 参数：n=144, q=12289, σ=2, tail=6, V=8（由 I1 估计器按 ≥80 bits 扫描得到，
  教学估计器报 84.4 bits / BKZ β=289——该值是维度饱和上界，非安全估计，见下节复核）。
- 1500 合法标签全部接受；1500 篡改交易全部检出；300 随机盲猜全部拒绝。
- 残差（max|b−As|_∞）直方图：合法集中于 ≤6，篡改集中在远大于 V 的大残差区；
  误拒率与篡改放行率随 V 的权衡见 v2_fig1。

## E3 · 缩尺攻击（q=257）
见 data/eval_v2_e3.json：
- sweep_a：n=5..20, σ=5；成功率 0.83→0.10，est_bits 3.2→12.0（估计值仅教学级）。
- sweep_b：n=6, M=1..6；成功率 0.75→1.00。
- sweep_c：n=12, σ=1..7；成功率 1.00→0.10。
方法：LLL（QR 加速）Kannan 嵌入恢复三元 s；每点随机实例，含时间上限保护。
与估计器的“成功→困难”方向一致（相变趋势验证）。

## E2 · 性能对照
方法学对齐 ePrint 2026/1333：固定消息集、≥600 次、报 median/p90/p99/max。
- Track A：签发 med 2.34 ms / p99 4.99；验签 med 0.098 ms；凭证 288 B（逐样本 n=1000）。
- Track B：签发 med 1.36 ms / p99 9.66（拒绝采样长尾）；验签 med 0.160 ms；签名 544 B；
  拒绝次数 med 6 / p99 35 / max 61。
- RSA-3072-PSS（OpenSSL 3.5.7 in-process speed，本机）：签名 med 7.39 ms；验签 med 0.135 ms；签名 384 B。纯 Python 仅作功能自检。
- ML-DSA-44 / FN-DSA-512 / ECDSA：官方规格尺寸表（非本机实测；FN-DSA-512 按 FALCON v1.2/FN-DSA 草案值，FIPS 206 尚未发布）。
机器信息记录于 eval_v2_e2.json["machine"]。

## E4 · 区块链场景
见 data/eval_v2_e4.json：1000 笔/块、64 B/笔的记账膨胀与验签 TPS。
结论与 2025–2026 区块链 PQC 迁移综述一致：签名尺寸主导区块膨胀（格方案 4.5–37.8×），
验签吞吐仍在实用区间。

## I1 复核 · lattice-estimator（参考实现）

用社区 lattice-estimator（github.com/malb/lattice-estimator，commit 53da598，2026-08-19）
对教学参数独立复核。估计器攻击代码**原样运行**；无 Sage 环境时用 `scripts/sage_shim/`
提供其 import 的 ~28 个 `sage.all` 数值符号。该数值层先在 Kyber512 uSVP/BDD、
ADPS16 core-SVP、Dilithium2 MSIS lattice 的官方 doctest 数字上逐一验证一致，再出本方案数字。
复现：`python scripts/crosscheck_lattice_estimator.py`；产物：`data/lattice_estimator_crosscheck.json`、
`docs/figures_v2/v2_fig7_reference_bits.png`。

Track A（q=12289，σ=2，三元密钥，m=n）：
- n=144 原型：uSVP(默认)≈41.3 bits、BDD(默认)≈41.1 bits、uSVP(ADPS16 core-SVP)≈12.0 bits、
  dual-hybrid(ADPS16)≈17.7 bits——与教学估计器 84.4 bits 差距显著，教学数字为饱和上界。
- n=480（推荐，≥80 bits 保守口径）：uSVP(默认)≈117.9、BDD≈114.8、uSVP(ADPS16)≈91.4、
  dual-hybrid(ADPS16)≈89.4 bits。E1–E4 基准仍用 n=144 原型，仅作方法学演示。
Track B：
- 同构核 A（224×256）在 Euclidean bound≈13.1（< λ1≈1.5×10^4）下参考工具报“无解”，
  说明其安全性在植入短解的非齐次（preimage）实例，不在通用同构核搜索。
- ∞-范数 MSIS 攻击要求 length_bound < (q−1)/2 = 6144；两签名关系界 2(κ−h)=7848 已超出，
  未来定参需增大 q 或减小 κ−h 使 2(κ−h) < (q−1)/2。

## 复现
python scripts/run_v2_all.py（会依次跑 E1/E3/E2/E4 与图表）。RSA-3072 私钥仅缓存于
本机 TEMP（不入库）。全部随机种子固定写死，JSON 可逐字节复现。