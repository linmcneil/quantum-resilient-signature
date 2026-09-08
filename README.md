# Quantum-Resilient Signature / LWE·格基认证与签名 · v2

省级大创课题「RSA 加密算法的研究与改进」的**可复现实验库（v2）**。
针对量子计算（Shor/格算法）对 RSA/ECC 的威胁，围绕“面向区块链交易的轻量格基
认证与签名”给出：**两条方案线（Track A/B）、参数实例化方法学（I1）、交易派生
矩阵变体（I2）以及一套对齐 2025–2026 学界规范的评测（E1–E4）**。

> 语义声明（重要，防止误解）：
> - **Track A 是对称认证标签（MAC 语义）**，不是公钥签名。验签需要共享私钥 s，
>   对应《技术交底书》`b = A·s + e` 的“一事一密”思想。
> - **Track B 是公开可验证格签名原型**（Lyubashevsky Fiat–Shamir with Aborts 的
>   ringless 教学实现），安全基于（非齐次）SIS。
> - 全部安全性结论为**教学级估计 + 缩尺实验**，不构成形式化证明；正式使用前
>   需用 lattice-estimator 复核并用 module/ring 结构重构（见下）。
> - 仓库内不再出现“LWE 100% vs RSA 0%”这类打稻草人的对比口径（v1 遗留口径已废弃，
>   见 [V1 说明](#v1-legacy)）。

## 1. 方案与创新点

| 编号 | 内容 | 状态 |
| --- | --- | --- |
| Track A | LWE 认证标签：A=SHA-256(tx) 逐笔派生（一事一密），b=A·s+e，阈值校验 | ✅ 已实现 |
| Track B | 公开可验证格签名：pk=(A,T=A·S)，拒绝采样使 z 在盒内均匀（传输不泄露 S） | ✅ 已实现 |
| I1 | 参数方法学：root-Hermite/core-SVP 估计器定参 + 缩尺 LLL 嵌入攻击交叉验证相变 | ✅ 已实现 |
| I2 | 交易派生矩阵：A=Expand(SHA-256(tx)) 免传矩阵种子/防跨交易复用 | ✅ 已在 Track A 使用，边界见文末 |
| I3 | 可复现评测：全部 JSON 入 `data/`，图表入 `docs/figures_v2/`，一键复现 | ✅ 已实现 |

## 2. 快速开始

```bash
python -m pip install numpy matplotlib        # 其余只用标准库

python scripts/run_v2_e1.py      # E1 正确性与阈值曲线
python scripts/run_v2_e3.py      # E3 缩尺格攻击（相变）
python scripts/run_v2_e2.py      # E2 同安全级性能对照（RSA 采用系统 OpenSSL speed）
python scripts/run_v2_e4.py      # E4 区块链场景（膨胀/TPS）
python scripts/make_figures_v2.py

# 或一键全部：
python scripts/run_v2_all.py

# 单测（纯功能，几秒）
python tests/test_v2_core.py
python tests/test_core.py        # v1 遗留单测
```

## 3. 关键结果（2026-09-08，本机 CPU 实测）

### E1 正确性（Track A，n=144/q=12289/σ=2，估计 ~84 bits 教学级）
合法接受率 **1.0000**；篡改检出率 **1.0000**；盲猜凭证拒绝率 **1.0000**。
误拒率/篡改放行率随阈值 V 的权衡曲线见 `v2_fig1`。

### E3 缩尺攻击（I1 交叉验证，q=257）
| 实验 | 结论 |
| --- | --- |
| n 扫描（σ=5） | 恢复成功率 ~0.9（n≤10）→ ~0.3（n≈14）→ ~0.1（n≥19）；估计 bit 安全级同步上升 |
| M 扫描（n=6） | 1 笔样本 ~0.75 → 3–6 笔样本 1.00：**样本越多攻击越有利** |
| σ 扫描（n=12） | σ=1–3 全成功 → σ=7 仅 ~0.1：**噪声越大越难恢复** |

注：教学级估计器在“目标 < GH 界”区退化为维度上界，无法区分 σ——这是简化的已知局限，
完整 lattice-estimator 分析列为 future work（图注已注明）。

### E2 性能对照（同一机器；NIST 项为官方尺寸，非本机）
| 方案 | pk / sk / 签名(字节) | 签发中位(ms) | p99(ms) | 验签中位(ms) |
| --- | --- | --- | --- | --- |
| Track A LWE 标签(对称) | – / 144 / 288 | 2.34 | 4.99 | 0.098 |
| Track B 格签名(ringless) | 229376 / 65536 / 544 | 1.36 | 9.66 | 0.160 |
| RSA-3072-PSS（OpenSSL 3.5.7 实测） | 384 / 384 / 384 | 7.39 | 7.39 | 0.135 |
| ML-DSA-44 (FIPS 204 官方) | 1312 / 2560 / 2420 | 参考 | 参考 | 参考 |
| FN-DSA-512 (FIPS 206 官方) | 897 / 1281 / 666 | 参考 | 参考 | 参考 |

要点：
- Track B 签名**拒绝次数** 中位 6、p99=35、max=61 → 拒绝采样带来显著长尾，
  只报均值会误导（对齐 ePrint 2026/1333 的批评）。见 `v2_fig5`。
- Track B ringless 公钥 ~224 KB ≫ ML-DSA 1312 B：这是“为什么正式方案需要
  module/ring 结构”的直接工程证据（NTT/环结构把公钥压缩三个数量级）。

### E4 区块链场景（1000 笔/块，负载 64 B/笔）
| 方案 | 每笔记账字节 | 区块膨胀 | 验签 TPS(估) |
| --- | --- | --- | --- |
| Track A 标签 | 288 | 4.5× | ~1.0 万 |
| Track B 签名 | 544 | 8.5× | ~6.3 千 |
| RSA-3072-PSS | 384 | 6.0× | ~7.4 千 |
| ML-DSA-44（官方尺寸+文献耗时） | 2420 | 37.8× | ~2.0 万 |
| FN-DSA-512 | 666 | 10.4× | ~1.25 万 |
| ECDSA P-256（基线） | 64 | 1.0× | ~10 万 |

格签名/标签在“吞吐可接受、但交易膨胀明显”的区间——与 2025–2026 区块链 PQC 迁移
综述（10–30× 量级）一致，说明落地关键是签名尺寸与批量验签。

## 4. 图表（docs/figures_v2/）

| 图 | 内容 |
| --- | --- |
| v2_fig0 | Track A / Track B 方案流程示意 |
| v2_fig1 | 残差分布 + 误拒/篡改放行 vs 阈值 V |
| v2_fig2 | E3：成功率 vs n 与估计 bit 安全级（I1 交叉验证） |
| v2_fig3 | E3：成功率 vs 样本数 M / vs 噪声 σ |
| v2_fig4 | 尺寸对照（pk/sk/签名，log 轴） |
| v2_fig5 | 签名耗时 ECDF + 拒绝次数分布（WCET） |
| v2_fig6 | 区块链区块膨胀 + 验签 TPS |

## 5. 目录结构

```
qrsv2/            # v2 核心（params/estimator/tag/signature/lattices/rsa_pss/expand）
scripts/          # run_v2_e1..e4、make_figures_v2、run_v2_all
tests/test_v2_core.py
data/eval_v2_e1..e4.json
docs/             # LITERATURE_REVIEW、EXPERIMENT_v2_design、REPORT_v2、ARXIV_OUTLINE
docs/figures_v2/
qrs/              # v1 遗留（已冻结）
```

## 6. 已知边界与未来工作
- 形式化安全证明（ROM/QROM、SIS/LWE 归约）——教学实现未覆盖；
- 用 module/ring 结构 + NTT 重构 Track B，解决公钥尺寸问题；
- I2 消息派生矩阵会让 A 随被签消息被对手“挑”，需额外的归约论证；
- 完整 lattice-estimator（primal/dual、BKZ-β 预估）复核正式参数。

## 7. V1 legacy
`qrs/`、`scripts/run_eval.py`、`docs/EXPERIMENT.md` 等 v1 内容为历史存档，保留仅为
可追溯性。其“LWE 100% vs RSA 0%”的防御率口径存在“不同攻击语义对比”的缺陷，已被
本 v2 取代，**不再作为结论引用**。