# watch-state

Working memory for the bulletin watcher (`.github/workflows/watch.yml` on `main`):
which vulnerability ids it has already seen, and how far into the official CVE
list it has read. The watcher updates `seen.json` after each run.

This branch is never published and never merged. To make the watcher forget an
item (so it drafts it again), remove its id from `seen.json`.
