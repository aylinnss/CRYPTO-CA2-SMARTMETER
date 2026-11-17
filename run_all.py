"""Run every CA2 demonstration and save the full output to results.txt.

Usage (from the repository root):  py run_all.py      (Windows)
                                   python3 run_all.py (Linux / macOS)
"""

import platform
import subprocess
import sys
from datetime import datetime

import cryptography

STEPS = [
    ("Normal operation", [sys.executable, "-m", "src.run"]),
    ("Attack against FLAWED build", [sys.executable, "-m", "attack.attack", "--build", "flawed"]),
    ("Attack against CORRECT build", [sys.executable, "-m", "attack.attack", "--build", "correct"]),
    ("Test suite", [sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider"]),
]


def main() -> None:
    lines = [
        f"Run at   : {datetime.now():%Y-%m-%d %H:%M}",
        f"OS       : {platform.system()} {platform.release()} ({platform.version()})",
        f"Python   : {platform.python_version()}",
        f"cryptography: {cryptography.__version__}",
    ]
    for title, cmd in STEPS:
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines += ["", "=" * 70, f"{title}   (exit code {result.returncode})",
                  "$ " + " ".join(["python"] + cmd[1:]), "=" * 70,
                  result.stdout.rstrip(), result.stderr.rstrip()]
        print(f"{title:32s} exit code {result.returncode}")
    with open("results.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\nSaved full output to results.txt")


if __name__ == "__main__":
    main()
