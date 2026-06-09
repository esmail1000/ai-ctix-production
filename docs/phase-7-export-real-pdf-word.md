# Phase 7 Export Real PDF and Word Files

This patch updates the Export Center so downloadable files are generated directly from saved backend report data.

## Changes

- `PDF` now downloads a real `.pdf` file from `GET /api/export?reportId=<id>&format=pdf`.
- `WORD` now downloads a Word-compatible `.doc` report from `GET /api/export?reportId=<id>&format=word`.
- The old browser-print-only PDF workflow is no longer the primary PDF export.
- The previous PowerPoint-compatible HTML `.ppt` option is replaced in the UI by a Word-compatible report option.
- JSON, CSV, and HTML exports are unchanged.

## Backend behavior

- The API uses the authenticated user's saved report, findings, latest summary, and latest risk score.
- No mock data, hardcoded findings, fake intelligence, or simulated counts are added.
- Unsupported file formats return a `400` response.
- Missing or unauthorized reports still return `404` through the existing user-scoped lookup.

## Files changed

- `app/api/export/route.ts`
- `app/export/page.tsx`

## Verification

Run:

```bash
npm run build
```

Then open:

```text
/export?reportId=<REPORT_ID>
```

Expected downloads:

- PDF button -> `<report-id>-ai-ctix-final-report.pdf`
- WORD button -> `<report-id>-ai-ctix-final-report.doc`
