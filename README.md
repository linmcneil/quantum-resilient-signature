# Quantum-Resilient Signature：抗量子 LWE 认证凭证 vs RSA 基线

省级大创课题「RSA 加密算法的研究与改进」的**可复现实验代码库**。
针对量子计算（Shor 算法）对 RSA/ECC 类代数结构的威胁，实现并量化评测一种
**基于 LWE（带误差学习）的轻量级认证凭证方案**，并与教科书 RSA 基线对照。

> 安全声明：本仓库为**研究与教学用途的模拟/原型实现**，不是生产级密码库。
> “防护成功率”均指在**本文明确定义的攻击模型与预算**下的实验结果，
> 不构成形式化安全证明；专利交底书引用的历史数字请以本仓库可复现实验为准，
> 由发明人核对口径后再引用。

## 1. 方案（对应《技术交底书》）

- 参数：格维度 n=128，模数 q=12289，私钥 s ∈ {-1,0,1}^n（短向量）；
- 签名：SHA-256(tx) → 随机种子 → 矩阵 A（一事一密），b = A·s + e (mod q)，
  e ~ 截断离散高斯（σ=2）；
- 验签：持钥方验证 ‖b - A·s‖_∞ <= V（V=8）。
- 关键设计：A 由交易逐笔生成、密钥为短向量、噪声掩盖密钥，
  不再依赖大整数分解，规避 Shor 算法所需的代数周期性。

## 2. 威胁模型与实验设计

统一使用“自适应选择消息预言机 + 有界查询预算”的攻击模型：
攻击者可以索取若干历史样本，但**无法获得私钥 s**，目标是对一笔**新交易**
伪造能通过验证的凭证。

| 方案 | 攻击实现 | 预期 |
| --- | --- | --- |
| LWE（本方案） | 有界历史样本 + 最小二乘/舍入恢复 s | 无 s 时无法构造合法凭证 |
| RSA raw（教科书） | 乘法同态存在性伪造（2 次选择消息） | 可被任意伪造 |
| RSA + SHA-256（对照） | 同种乘法伪造（被哈希破坏） | 该攻击下安全（注：仍受分解威胁） |

实验脚本与《技术交底书》中的 `__init__ / sign_transaction /
run_blockchain_defense_test / blockchain_defense_data.csv` 一一对应。

## 3. 快速开始

```bash
pip install -r requirements.txt

# 防御成功率实验（N=10000，默认与交底书口径对齐）
python scripts/run_eval.py --attempts 10000 --seed 42 --out-dir data

# 生成全套图表（docs/figures/）
python scripts/make_figures.py

# 单测
python tests/test_core.py
```

## 4. 结果（2026-09-08，N=10000 / 方案，seed=42）

| 方案 | 伪造成功 | 防护成功率 |
| --- | --- | --- |
| LWE（本方案） | 0 / 10000 | 100.00% |
| RSA raw（教科书） | 10000 / 10000 | 0.00% |
| RSA + SHA-256（对照） | 0 / 10000 | 100.00% |

延迟与参数敏感性见 `docs/figures/`。

## 5. 图表（数形结合）

| 图 | 内容 | 文件 |
| --- | --- | --- |
| 图 0 | 方案流程 | docs/figures/fig0_scheme_overview.png |
| 图 1 | 三种方案防御成功率 | docs/figures/fig1_defense_rate.png |
| 图 2 | 验证残差分布与阈值 V、检出率 | docs/figures/fig2_verify_residuals.png |
| 图 3 | 成功率随尝试次数的稳定性 | docs/figures/fig3_running_defense.png |
| 图 4 | 攻击预算 M vs 伪造成功率 | docs/figures/fig4_attack_budget_sweep.png |
| 图 5 | 签名/验签延迟对比 | docs/figures/fig5_latency.png |

## 6. 局限与路线

- 攻击面为“线性/舍入恢复 + 存在性伪造”，尚未实现 LLL/BKZ 格基规约攻击与
  基于 Shor 的因数分解模拟；参数安全性需要独立分析（n/q/σ 与错误率关系）；
- 待办：LLL/BKZ 攻击模块与参数敏感度曲线、真实 RSA-PSS 对照、
  实验图表中文化/导出 EPS、GitHub Actions CI 与开源发布。
