# Phase 1 — Backend & NLP Reality Check

## Scope

This phase verifies that the analysis backend does not silently present rule-based or heuristic output as trained NLP output. It focuses on `/api/analyze`, the Python NLP engine, upload validation, model readiness, and the minimum NLP fields required by the project PDF.

## Findings before changes

- The project contains a real backend path for report ingestion, persistence, post-analysis processing, and Python NLP execution.
- The uploaded model directory exists at `nlp_engine/models/cyberbert-ner` and includes model weights.
- The runtime quality gate fails because no model metrics file was present (`test_metrics.json` or `training_config.json` final metrics).
- Python inference returned `model_loaded=false`, `fallback_used=true`, and `model_quality_gate_passed=false` on the smoke sample.
- The previous backend logic accepted NLP findings as usable as long as findings existed and no error was returned, even when the engine was using fallback extraction.
- HTML reports were partially supported by the text extractor but blocked by upload validation and not represented as a report type.
- Python `findings` output grouped multiple vulnerabilities into one finding object in a simple smoke sample.
- `exploitation_steps` was missing as a first-class output field.
- Sequential report ID generation could collide under concurrent analysis requests.
- `.env.local` was included in the submitted project copy and should not be distributed.

## Changes applied

### Backend strict NLP handling

- Added strict NLP readiness checks to `lib/server/analysis-build.ts`.
- In strict mode, analysis is blocked if the trained model is not loaded, if fallback is used, or if the quality gate fails.
- Added support for:
  - `NLP_STRICT_MODEL=true`
  - `NLP_REQUIRE_QUALITY_GATE=true`

### NLP health endpoint

- Added `GET /api/nlp/health`.
- The endpoint checks model directory, config file, weights, metrics, and quality gate readiness.
- It returns HTTP `503` when the NLP model is not production-ready.

### Exploitation steps

- Added `exploitation_steps` to Python NLP output.
- Added extraction from labels such as `Exploitation Steps`, `Steps to Reproduce`, `Proof of Concept`, `PoC`, and numbered steps.
- Added TypeScript mapping to expose/persist exploitation steps through reported finding metadata and the public API finding object.

### Per-finding grouping

- Updated Python `build_findings` to split explicit finding sections before building finding objects.
- The smoke sample now returns two finding objects instead of one aggregated object.

### HTML upload support

- Allowed `.html` and `.htm` in upload validation.
- Added `text/html` MIME support.
- Added basic HTML-to-text cleaning in `text-extraction.ts`.
- Added `HTML` as a valid report type.

### Safer report IDs

- Replaced sequential DB-scan report ID generation with timestamp + random nonce IDs.
- This avoids race-condition collisions during concurrent report ingestion.

### Environment hygiene

- Updated `.env.example` to use PostgreSQL instead of SQLite, matching Prisma's provider.
- Updated default `NLP_MODEL_DIR` to the actual model path.
- Added strict NLP environment flags to `.env.example`.
- Removed `.env.local` from the working project copy.

## Smoke test result

Command used:

```bash
python nlp_engine/inference.py \
  --report_text_file /tmp/ctix_sample_report.txt \
  --output_json /tmp/ctix_out.json \
  --model_dir nlp_engine/models/cyberbert-ner \
  --mode auto \
  --min_model_f1 0.3 \
  --min_entity_confidence 0.75
```

Result after changes:

- `findings`: 2
- `exploitation_steps`: extracted
- `CVE-2024-12345`: extracted
- `CVE-2017-5638`: extracted
- severity: extracted
- impact/remediation: extracted
- `model_loaded`: still `false`
- `fallback_used`: still `true`
- `model_quality_gate_passed`: still `false`

The fallback output is now better structured, but strict backend mode will not accept it as production NLP.

## Remaining blockers

1. Add real model evaluation metrics into `nlp_engine/models/cyberbert-ner/test_metrics.json` by running the evaluation pipeline on a real test set.
2. Install/verify ML dependencies from `nlp_engine/requirements.txt`, especially `transformers`.
3. Re-run `/api/nlp/health` and require `ok=true` before calling the backend production-ready.
4. Re-run `/api/analyze` end-to-end with database and authentication enabled.
5. Rotate any secrets that were present in `.env.local` before sharing or deploying the project.
