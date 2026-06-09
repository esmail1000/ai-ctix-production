# Phase 7 Report Delete No Refresh Fix

This fix removes the full-screen delete modal and removes all post-delete page refresh/navigation behavior.

## Why

The reports page is heavily animated and server-rendered. Refreshing or replacing the page immediately after a delete can cause the UI to flicker or appear to hang while cards and modal state remount.

## Change

- Replaced the full-screen modal with an inline confirmation control inside the report card.
- Removed `router.refresh()` and `window.location.replace()` from the delete flow.
- After the backend confirms deletion, the deleted card is faded out and removed from the DOM locally.
- PostgreSQL deletion remains authoritative.
- Neo4j graph cleanup remains best-effort and non-blocking.

## Backend Safety

No mock data, fake deletion, or simulated behavior is introduced. The card is only removed after the real `DELETE /api/reports/[id]` call returns success.
