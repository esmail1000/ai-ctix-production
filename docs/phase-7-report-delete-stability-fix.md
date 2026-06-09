# Phase 7 Report Delete Stability Fix

This patch stabilizes the Reports page delete flow after the initial delete feature was added.

## Problem

After confirming deletion, the Reports page could flicker or rapidly remount while the modal and animated cards refreshed in-place.

## Fix

- The delete button now prevents repeated/double delete submissions.
- Click propagation is stopped for delete controls and the modal.
- The UI uses a hard navigation back to `/reports?deleted=1` after a successful delete instead of `router.refresh()`.
- PostgreSQL deletion remains the source-of-truth deletion path.
- Neo4j cleanup is still attempted, but it is started as a best-effort background task so slow graph cleanup cannot freeze the Reports UI.

## Backend Scope

No analysis, NLP, risk scoring, recommendation, or graph generation logic was changed.
