# Claude Code Instructions

## Commits

- Never add `Co-Authored-By` trailers to any commit message.
- Never create or push git tags automatically. Tags are only created when the user explicitly asks to cut a release.

## Releases

When the user asks to release / tag / publish a version:

1. Ask the user what tag they want (e.g. `v2.0.3`).
2. Prepare everything locally: stage files, write the commit message, create the tag.
3. Show the user a summary of exactly what will be pushed (commit message, tag, branches).
4. Ask for explicit confirmation before running any `git push` commands.
5. Only push after the user confirms.
