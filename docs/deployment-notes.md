# Deployment Notes

## Requirements

- Node.js compatible with Next.js 16.
- PostgreSQL database.
- Neo4j database when graph features are enabled.
- Python runtime for NLP and text extraction helpers.
- Trained NLP model directory with config, weights and metrics.
- Optional Tesseract OCR for scanned PDFs.
- Optional NVD API key for higher-rate CVE lookups.
- Optional MISP URL/API key for MISP enrichment.

## Environment setup

1. Copy `.env.example` to `.env.local`.
2. Replace all placeholder secrets.
3. Set `DATABASE_URL` for PostgreSQL.
4. Set Neo4j connection values.
5. Set `NLP_MODEL_DIR` to the trained model path.
6. Keep `NLP_STRICT_MODEL=true` and `NLP_REQUIRE_QUALITY_GATE=true` for production-like testing.
7. Configure email provider credentials for registration and password reset emails.

## Database setup

Run Prisma generation/build commands from the project root:

```bash
npm install
npm run prisma:generate
npm run build
```

Apply migrations according to your deployment process if migrations are present.

## Running locally

```bash
npm run dev
```

Open:

```text
http://localhost:3000
```

## Production start

```bash
npm run build
npm run start
```

## Operational checks

After deployment:

1. Visit `/api/nlp/health` while authenticated or from a trusted test environment.
2. Analyze a small known-good report.
3. Confirm PostgreSQL report/finding persistence.
4. Confirm Neo4j graph generation if graph features are enabled.
5. Confirm threat-intel positive and negative CVE behavior.
6. Confirm export output for one report.

## Known operational warnings

- Next.js may warn that the `middleware` file convention is deprecated in favor of `proxy` in newer versions. This is non-blocking for the current implementation but should be tracked for future framework upgrades.
- If MISP is not configured, MISP output should show `disabled`, not an error and not fake matches.
- If OCR dependencies are missing, scanned PDFs may return extraction warnings. Text-based PDFs should still parse normally.
