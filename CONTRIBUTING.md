# Contributing

## Branch model

- **`dev`** is the **primary / default** branch.
- **`main`** is the secondary branch.
- All work happens on a **feature branch off `dev`** and lands via a **Pull
  Request into `dev`**. Never push directly to `dev`.

## Workflow

1. Sync and branch off `dev`:
   ```bash
   git checkout dev && git pull origin dev
   git checkout -b feat/short-description
   ```
2. Implement + test locally:
   ```bash
   go test ./...
   go vet ./...
   gofmt -w ./...
   ```
3. Commit (conventional style) and push:
   ```bash
   git add -A && git commit -m "feat: add X"
   git push -u origin feat/short-description
   ```
4. Open a PR into `dev`:
   ```bash
   gh pr create --base dev --head feat/short-description \
     --title "feat: add X" --body "..."
   ```

## Conventions

- **Commit messages:** [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:', `docs:`, `chore:`, `test:`, `refactor:`).
- **One logical change per PR**, with tests.
- **Go:** `gofmt` + `go vet` must be clean. Prefer small, well-tested packages.
- **Protocol changes** must update `docs/PROTOCOL.md`.

## CI

GitHub Actions runs `go build`, `go vet`, and `go test` on every PR into `dev`.
