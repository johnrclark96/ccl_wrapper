# Agent Instructions (CCL Wrapper)

This repository is code-only. Never add private data, exports, logs, databases, or decoded artifacts.

Development rules:
- One roadmap chunk per PR. Do not mix chunks unless explicitly instructed.
- Keep diffs minimal: no formatting churn, no unrelated refactors, no renames unless required.
- Preserve existing behavior unless the chunk explicitly changes it.
- Prefer adding/adjusting targeted tests over broad refactors.

PR requirements:
- PR title must include the chunk number(s).
- PR description must include: scope, files changed, and acceptance checks.
- If a change affects CLI or output artifacts, update ROADMAP.md notes only as needed.

Safety:
- Do not add any secrets or tokens.
- Do not add workflow automation that touches external systems unless explicitly requested.