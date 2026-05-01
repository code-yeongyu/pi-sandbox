# Repository Conventions

Conventions for human contributors and AI agents working on this repository.

## Style

- Terse technical prose. No emojis in commits, issues, PR comments, or code.
- TypeScript strict mode. No `any`, no `unknown` casts, no suppressions, no enums.
- ESM modules with `.js` suffix in import paths under Node16 resolution.
- Tabs for indentation. Double quotes for strings.
- Tests use vitest with `#given <X> #when <Y> #then <Z>` descriptions.

## Commands

- `npm install` — install dependencies.
- `npm run typecheck` — run `tsgo --noEmit`.
- `npm run lint` — run Biome.
- `npm run lint:forbidden` — run AST-based forbidden-pattern checks.
- `npm test` — run vitest once.
- `pi -e ./src/index.ts` — load the extension into a local pi session for manual smoke testing.

## Constraints

- Runtime is Node only; do not introduce Bun APIs.
- No dependency on pi-coding-agent internal modules outside the public root API.
- No `git add -A` or `git add .`. Stage only explicit files.
- No `git commit --no-verify`. No force pushes. No history rewriting on shared branches.
