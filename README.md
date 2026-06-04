# AI CTIX Extractor

AI CTIX Extractor is an analyst-centered prototype for cyber threat intelligence extraction from pentesting and security reports. It supports report upload, finding extraction, risk review, report summaries, graph visualization, and export-ready HTML/PDF pages.

## What was improved in this version

This update focuses on frontend and UX improvements only. Existing backend routes, request payloads, database structures, NLP/risk logic, and export endpoints were left unchanged.

### UI/UX upgrades

- Added reusable UI components for badges, status labels, confidence labels, empty states, alerts, page headers, evidence blocks, and statistic cards.
- Added mobile-friendly navigation with a hamburger menu and a secondary More menu.
- Improved the Analyzer workflow with drag-and-drop upload, file validation, pre-analysis checklist, staged processing feedback, and richer generated-output review.
- Improved Findings with filters for extraction method, confidence, CVE availability, review state, missing evidence, and missing remediation.
- Added confidence, method, evidence preview, and frontend-only review badges to findings tables.
- Reworked Finding Details into an evidence-first analyst review page with warnings for missing evidence, missing remediation, low confidence, and fallback extraction.
- Added dashboard workspace-health metrics, including needs-review findings, fallback findings, missing evidence, missing remediation, and export-ready reports.
- Added report-level quality and readiness indicators to Report Details.
- Added graph node filters and clearer graph inspection controls.
- Added export readiness checklist and print-friendly styles.

## Safety and backend compatibility

The Analyzer still submits the same `FormData` keys:

```ts
formData.append('text', pastedText)
formData.append('file', selectedFile)
fetch('/api/analyze', { method: 'POST', body: formData })
```

No backend API contracts were changed. Quality labels such as `Needs Review`, `Missing Evidence`, and `Low Confidence` are derived in the frontend from existing finding fields and are not persisted.

## Run locally

```bash
npm install
npm run dev
```

Then open the local Next.js URL shown in the terminal.

## Test and build

```bash
npm run test
npm run build
```

## Environment

Do not commit real secrets. Use `.env.example` as a template and create a local `.env.local` file only on your machine.

## Known limitations

- Model files are not included in this package.
- Dataset task values and benchmark labels still need confirmation.
- Attack-path prediction remains a prototype unless supported by real asset relationships and validated graph data.
- Analyst approve/edit/reject actions are not persisted because no backend workflow endpoint was added.
