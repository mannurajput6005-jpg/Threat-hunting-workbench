"""CLI: score the detection rules against the labeled sample dataset.  python scripts/evaluate_detection.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.config import SAMPLES_DIR  # noqa: E402
from evaluation.evaluate import evaluate_file  # noqa: E402

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else SAMPLES_DIR / "labeled_eval.csv"
    print(json.dumps(evaluate_file(target), indent=2))
