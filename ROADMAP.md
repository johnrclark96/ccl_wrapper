CCL Wrapper Roadmap (Source of Truth)

Chunk 0+1+2 (first PR):
- --self-check => self_check.json with environment + library provenance
- Fix stage_wrap() call sites (keyword-only args) so run proceeds
- Top-level fatal capture => fatal.txt + flushed traceback

Then sequential PRs:
Chunk 3: stage_wrap catches BaseException (except Ctrl+C) + stage summary skeleton
Chunk 4: SafeJsonlWriter + centralize error emission
Chunk 5: manifest/report environment certainty
Chunk 6: stream sqlite reads (remove fetchall in high-volume queries)
Chunk 7: IndexedDB external blob resolver + counters + bounded search flags
Chunk 8: cache body_status per entry + resilience
Chunk 9: root_tag uniqueness + roots/index.json mapping
Chunk 10+: optional expansions behind flags
