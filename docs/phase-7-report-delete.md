# Phase 7 Report Delete

Added a real delete workflow to the Reports page.

## Scope

- Frontend only on `/reports` plus the authenticated report API.
- No mock data.
- No backend analysis changes.
- No NLP/risk/graph/threat-intel/recommendation logic changes.

## Behavior

Each report card now includes a **Delete** button. The button opens a confirmation dialog showing:

- report name
- report ID
- linked finding count

After confirmation, the client calls:

```http
DELETE /api/reports/:id
```

The API checks the authenticated user and deletes only reports owned by that user.

## Data cleanup

The delete flow removes the report and linked PostgreSQL records:

- analysis findings
- analysis runs
- summaries
- risk scores
- report record

Neo4j report-scoped graph cleanup is attempted after the PostgreSQL deletion. If Neo4j is unavailable, the report remains deleted from the primary database and the API returns a warning instead of failing the whole delete operation.
