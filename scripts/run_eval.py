"""CLI：跑防御成功率模拟实验。

用法：
    python scripts/run_eval.py --attempts 10000 --seed 42 --out-dir data
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qrs.experiment import run_blockchain_defense_test  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="LWE vs RSA 抗伪造防御成功率实验")
    ap.add_argument("--attempts", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--lwe-queries", type=int, default=8)
    ap.add_argument("--rsa-bits", type=int, default=1024)
    ap.add_argument("--out-dir", default="data")
    args = ap.parse_args()
    run_blockchain_defense_test(
        attempts=args.attempts,
        seed=args.seed,
        lwe_queries=args.lwe_queries,
        rsa_bits=args.rsa_bits,
        out_dir=args.out_dir,
    )


if __name__ == "__main__":
    main()
