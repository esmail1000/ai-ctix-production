# Fixes Applied

## Runtime blockers fixed

- Fixed invalid inline regex flag in `span_matching.normalize_cve_token()`.
- Added missing `Tuple` import in `regex_extractor.py`.
- Removed hard dependency on `torch`, `numpy`, `transformers`, and `datasets` during lightweight imports.

## Inference improvements

- `inference.py` now supports:
  - `--mode auto` default: use model when available, otherwise fallback safely.
  - `--mode model`: strict model inference.
  - `--mode regex`: deterministic extraction only.
  - `--no_meta`: legacy output shape without diagnostics.
- Added `run_inference_text()` for easier backend integration.
- Added model directory validation before loading Hugging Face weights.
- Added stable `meta` diagnostics.

## Extraction improvements

- CVEs normalize to `CVE-YYYY-NNNN`.
- URL hostnames are included in `domains`.
- Added deterministic keyword/rule extraction for common:
  - severity labels;
  - vulnerability types;
  - impact phrases.

## Training/data improvements

- Training now gives a clear dependency error instead of a confusing import traceback.
- `preprocessing.py` can be imported and used for text alignment checks without installing heavy ML packages.
- Added `self_test.py` for local smoke testing.

## Verified locally

Executed successfully:

```bash
python -m py_compile labels.py utils.py regex_extractor.py span_matching.py text_loader.py preprocessing.py train.py inference.py prepare_data.py self_test.py
python self_test.py
python inference.py --report_text_file /tmp/sample_report.txt --output_json outputs/sample_prediction.json
```

Note: full model training/inference still requires installing `requirements.txt` and providing either real report text/PDFs or a trained model directory.
