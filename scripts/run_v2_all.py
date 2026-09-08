"""一键复现 v2 全部实验（E1-E4）+ 图表。"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def run(script: str) -> None:
    t0 = time.perf_counter()
    print(f"\n=== {script} ===", flush=True)
    subprocess.run([PY, str(ROOT / "scripts" / script)], check=True)
    print(f"=== {script} done in {time.perf_counter() - t0:.1f}s ===\n", flush=True)


def main() -> None:
    run("run_v2_e1.py")
    run("run_v2_e3.py")
    run("run_v2_e2.py")
    run("run_v2_e4.py")
    run("make_figures_v2.py")
    print("v2 pipeline complete.")


if __name__ == "__main__":
    main()