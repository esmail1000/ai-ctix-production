# Phase 7 PDF Profile Alignment Build Fix

This patch fixes a TypeScript narrowing error introduced in the PDF profile alignment patch.

## Change

- Replaced `.filter(Boolean)` on `Map.get()` output with an explicit type predicate:
  `.filter((candidate): candidate is MinivpnCandidate => candidate !== undefined)`

## Reason

`bestById.get(id)` can return `undefined`. Next/TypeScript strict build does not narrow `.filter(Boolean)` enough, so the downstream mapper saw `candidate` as possibly undefined.
