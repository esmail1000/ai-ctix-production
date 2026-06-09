# Phase 7 PDF Analyze Hang Fix

This patch fixes a regression introduced during the PDF extraction quality patch.

## Root cause

`extractDelimitedSection()` reused the same global `RegExp` instance that powered outer `while (pattern.exec(...))` loops. Calling `String.match()` or `String.search()` with that global regex can reset `lastIndex`, causing the outer loop to repeatedly match the same finding heading and hang during `/api/analyze`.

## Fix

The delimiter function now clones the supplied pattern and removes `g`/`y` flags before searching for the next section boundary. This keeps extraction deterministic without mutating the outer iterator state.

## Expected result

PDF analysis should progress past `/api/analyze` compilation and complete normally for `pentest-report-minivpn.pdf`.
