# Contributing to r0zscope

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/) to automate versioning and releases.

### Format

```
<type>(<optional scope>): <description>
```

### Types

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | Minor (0.X.0) |
| `fix` | Bug fix | Patch (0.0.X) |
| `perf` | Performance improvement | Patch (0.0.X) |
| `refactor` | Code refactor (no behavior change) | Patch (0.0.X) |
| `feat!` | Breaking change | Major (X.0.0) |
| `docs` | Documentation only | No release |
| `test` | Tests only | No release |
| `ci` | CI/CD changes | No release |
| `chore` | Maintenance | No release |

### Examples

```bash
git commit -m "feat: add nuclei template support"
git commit -m "fix: handle empty subdomain list"
git commit -m "feat(ctf): add vhost brute-force mode"
git commit -m "feat!: change output directory structure"
```

## How Releases Work

Releases are fully automated:

1. You push commits to `main` using conventional commit messages
2. The CI analyzes commit prefixes since the last tag
3. A new semver tag is created automatically (e.g., `v1.6.0`)
4. GoReleaser builds binaries for all platforms and publishes a GitHub Release

**You don't need to manually create tags or releases.** Just follow the commit convention.

### Manual Tags Still Work

If you prefer to tag manually (`git tag v1.x.x && git push origin v1.x.x`), the release pipeline will still trigger normally. The auto-tag workflow simply skips if no conventional commit prefixes are found.

## Development

```bash
git clone https://github.com/renansj/r0zscope.git
cd r0zscope
go build -o r0zscope .
```

## Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Use conventional commits
4. Open a PR against `main`
5. Use a conventional commit prefix in the PR title (e.g., `feat: add nuclei support`)

**Important:** Use **squash merge** so the PR title becomes the commit message on `main`. This is what triggers the version bump. Regular merge commits (`Merge pull request #N...`) don't have a conventional prefix and won't generate a release.
