# v2 arXiv 论文大纲（M5，草稿定位：技术报告 / 复现性研究）

> 定位声明（写在论文开头）：本文**不是**声称提出“可证明安全的新签名”；
> 而是给出一个可复现的实验框架，研究“面向区块链交易的轻量格基
> 认证/签名设计空间”——含参数实例化方法学（I1）、交易派生矩阵
> 变体（I2）、以及对齐 2025–2026 学界评测规范的基准（E1–E4）。

## 拟定标题（候选）
- 英文： *Reproducible Design-Space Study of Lightweight Lattice-Based
  Authentication and Signatures for Blockchain Transactions*
- 中文副题：面向区块链交易的轻量格基认证与签名：设计空间、参数方法与复现基准

## 结构
1. Introduction
   - 动机：量子威胁下区块链签名迁移（NIST FIPS 204/206；2030 ECC 弃用）
   - 大创项目背景（RSA→格，交底书思想：一事一密）
   - 贡献列表（I1 方法论闭环 / I2 消息派生 / I3 开源基准）
2. Background & Related Work
   - LWE/SIS、Fiat-Shamir with Aborts（Lyubashevsky 2009/2012）
   - NIST 标准（ML-DSA/FN-DSA）与最新学术进展（HAETAE、Rhyme、search-LWE 紧归约）
   - 区块链 PQC 迁移综述（区块膨胀 10–30× 等口径）
3. Threat Model 与语义边界（重要，防止审稿误解）
   - Track A = 对称认证标签（MAC 语义）——不能当公钥签名
   - Track B = 公开验证格签名（SIS 语义，ringless 教学原型）
   - 形式化安全为未来工作（不硬claim）
4. Parameter Methodology (I1)
   - root-Hermite/core-SVP 估计器（教学级，含与 lattice-estimator 的差异声明）
   - 缩尺 LLL/BKZ+Babai 交叉验证协议：成功率 vs n/M/σ，相变对照
5. Transaction-derived Matrix (I2)
   - A = Expand(SHA-256(tx))：免传矩阵种子、防跨交易复用
   - 安全边界讨论：消息相关 A 的 adversary-chosen 问题（未来工作）
6. Benchmark (E2/E4)
   - 方法学对齐 ePrint 2026/1333：分布而非均值；拒绝采样 WCET
   - Track A/B、RSA-3072-PSS（本机）、ML-DSA-44/FN-DSA-512（官方值）
   - 区块链区块膨胀与验签吞吐
7. Results & Discussion
8. Conclusion & Future Work
9. Reproducibility（仓库链接、seed、环境、一键脚本 run_v2_all.py）

## 图表复用
v2_fig0..v2_fig6 → 论文 Figure；data/*.json 为数据附录。

## 提交动作（需要用户）
- arXiv 账号 + 作者名（你本人、指导老师/合作者是否署名）
- 决定 中文 or 英文 初稿；是否挂 D 大学 / 合作机构名
- LaTeX 编译（本地 overleaf）或由本仓库提供 paper/ 目录