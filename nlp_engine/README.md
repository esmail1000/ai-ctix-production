# AI-Powered Cyber Threat Intelligence Extractor

Modular NLP pipeline for cyber threat / pentest report extraction.

It supports two execution modes:

1. **Hybrid model mode**: CyberBERT token-classification NER + deterministic regex/rule extractors.
2. **Safe fallback mode**: deterministic regex/rule extractors only, used automatically when the trained model or ML dependencies are missing.

The stable inference schema is:

```json
{
  "cve_ids": [],
  "vulnerability_types": [],
  "severity": [],
  "impacts": [],
  "ips": [],
  "urls": [],
  "domains": [],
  "ports": [],
  "meta": {
    "engine": "nlp-hybrid",
    "mode": "auto",
    "model_loaded": false,
    "model_dir": "models/cyberbert-ner",
    "fallback_used": true,
    "warnings": []
  }
}
```

## Data layout

- `../processed_reports.json`: structured labels (`vulnerabilities`, `cves`, `impact`, `severity`, etc.).
- Raw report text can come from:
  - a JSON field: `report_text`, `raw_report`, `text`, `content`, or `body`;
  - a matching TXT file: `data/raw/{stem}.txt`, where `{stem}` is the stem of the `file` field;
  - a matching PDF in `data/pdf/`, extracted by `prepare_data.py`;
  - synthetic fallback text from JSON labels, only when explicitly enabled for smoke tests.

## Install

```bash
cd project
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Smoke test without ML dependencies

```bash
python self_test.py
```

This validates the CVE matcher, deterministic extraction fallback, and inference schema.

## Inference

Auto mode is recommended for integration because it never crashes just because the model folder is missing; it falls back to regex/rule extraction.

```bash
python inference.py --report_text_file path/to/report.txt --output_json outputs/prediction.json
```

Strict model mode requires `models/cyberbert-ner/` to contain a trained Hugging Face token-classification model:

```bash
python inference.py --mode model --model_dir models/cyberbert-ner --report_text_file path/to/report.txt
```

Regex/rule-only mode:

```bash
python inference.py --mode regex --report_text_file path/to/report.txt
```

Legacy output without `meta`:

```bash
python inference.py --no_meta --report_text_file path/to/report.txt
```

## Prepare raw text from PDFs

```bash
python prepare_data.py --processed_json ../processed_reports.json --raw_pdf_dir data/pdf --raw_text_dir data/raw
```

## Train

Use real reports when possible:

```bash
python train.py --processed_json ../processed_reports.json --raw_text_dir data/raw --raw_pdf_dir data/pdf --save_dataset
```

Last-resort smoke training using synthetic text from labels:

```bash
python train.py --processed_json ../processed_reports.json --allow_synthetic_fallback
```

Outputs are written to `models/cyberbert-ner/`.

## Syntax check

```bash
python -m py_compile labels.py utils.py regex_extractor.py span_matching.py text_loader.py preprocessing.py train.py inference.py prepare_data.py self_test.py
```
