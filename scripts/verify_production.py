from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NLP_DIR = ROOT / "nlp_engine"
MODEL_DIR = NLP_DIR / "models" / "cyberbert-ner-v5-real-aug"
OUTPUT_DIR = NLP_DIR / "outputs"
PREDICTION_FILE = OUTPUT_DIR / "production_check_prediction.json"

PYTHON_CMD = sys.executable
NPM_CMD = "npm.cmd" if sys.platform.startswith("win") else "npm"


REQUIRED_MODEL_FILES = [
    "config.json",
    "label_map.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
]


def run(command: list[str], label: str) -> None:
    print(f"\n[RUN] {label}")
    print(" ".join(command))

    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
    )

    print(result.stdout)

    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")


def check_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing required file: {path}")

    if path.is_file() and path.stat().st_size == 0:
        raise RuntimeError(f"Required file is empty: {path}")


def check_model_files() -> None:
    print("\n[CHECK] NLP model files")

    for filename in REQUIRED_MODEL_FILES:
        path = MODEL_DIR / filename
        check_file(path)
        print(f"OK: {path.relative_to(ROOT)}")


def check_prediction_output() -> None:
    print("\n[CHECK] NLP prediction output")

    check_file(PREDICTION_FILE)

    with PREDICTION_FILE.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    meta = payload.get("meta", {})

    if meta.get("mode") != "model":
        raise RuntimeError(f"Expected mode=model, got: {meta.get('mode')}")

    if meta.get("model_loaded") is not True:
        raise RuntimeError("Expected model_loaded=true")

    if meta.get("fallback_used") is not False:
        raise RuntimeError("Expected fallback_used=false")

    warnings = meta.get("warnings", [])
    if warnings:
        raise RuntimeError(f"Expected no NLP warnings, got: {warnings}")

    print("OK: NLP mode=model")
    print("OK: model_loaded=true")
    print("OK: fallback_used=false")
    print("OK: warnings=[]")


def main() -> int:
    try:
        print("AI CTIX Production Verification")
        print(f"Project root: {ROOT}")
        print(f"Python: {PYTHON_CMD}")
        print(f"NPM: {NPM_CMD}")

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        check_model_files()

        run(
            [PYTHON_CMD, str(Path("nlp_engine") / "self_test.py")],
            "NLP smoke tests",
        )

        run(
            [
                PYTHON_CMD,
                str(Path("nlp_engine") / "inference.py"),
                "--mode",
                "model",
                "--model_dir",
                str(Path("nlp_engine") / "models" / "cyberbert-ner-v5-real-aug"),
                "--report_text_file",
                str(Path("nlp_engine") / "sample_report.txt"),
                "--output_json",
                str(PREDICTION_FILE.relative_to(ROOT)),
            ],
            "NLP model inference",
        )

        check_prediction_output()

        run([NPM_CMD, "test"], "Node test suite")

        run([NPM_CMD, "run", "build"], "Next.js production build")

        print("\n✅ PRODUCTION VERIFICATION PASSED")
        return 0

    except Exception as error:
        print(f"\n❌ PRODUCTION VERIFICATION FAILED: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())