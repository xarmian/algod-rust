# Docker Image CI/CD

`.github/workflows/docker-image.yml` builds `docker/Dockerfile` and, on
`main` / version tags, publishes it to GHCR
(`ghcr.io/xarmian/algod-rust`). See that workflow's header comment for the
full trigger/tagging rationale (mirroring the `algorand/algod` Docker Hub
image's port/data-dir/tag-naming conventions for drop-in compatibility).

## Required GitHub repository secrets

**None.** The workflow authenticates to GHCR with the automatically
provisioned `secrets.GITHUB_TOKEN` — nothing needs to be created or
rotated under *Settings → Secrets and variables → Actions*.

This differs from `coverage.yml`, which **does** need a manually configured
secret:

| Secret            | Used by         | Required for                                    |
| ------------------ | --------------- | ------------------------------------------------ |
| `CODECOV_TOKEN`    | `coverage.yml`  | Uploading LCOV reports to Codecov                 |

`docker-image.yml` needs no equivalent entry.

## Required repository *settings* (not secrets)

Two one-time, non-secret settings gate whether the workflow can actually
push:

1. **Workflow permissions.** The `build` and `merge` jobs each declare
   `permissions: packages: write` themselves, which is sufficient regardless
   of the repo-wide default under *Settings → Actions → General → Workflow
   permissions* — an explicit `permissions:` block in a workflow always
   takes precedence over that default (it can only be *restricted* further
   by an org-level policy, not loosened). No change needed unless your org
   enforces a stricter ceiling that blocks `packages: write` outright.
2. **Package visibility.** The first successful push creates the
   `ghcr.io/xarmian/algod-rust` package **private** by default, linked to
   this repository. If the image should be publicly pullable (e.g. for
   `docker pull` without `docker login`), set it to public once under the
   package's own *Package settings* page (`https://github.com/users/<owner>/packages/container/algod-rust/settings`
   or the org equivalent) — this is a package setting, not a repo secret,
   and only needs doing once after the first publish. Equivalently, via
   `gh`/the API once the package exists:

   ```bash
   gh api -X PATCH users/xarmian/packages/container/algod-rust --field visibility=public
   ```

   This requires a token with `write:packages` + `delete:packages` scope
   (`gh auth login --scopes write:packages,delete:packages` if the default
   `gh` token lacks it) — the workflow's own `secrets.GITHUB_TOKEN` does
   **not** have enough permission to flip visibility itself (that's an
   owner/admin-level action), so this step can't be automated into
   `docker-image.yml` and stays a manual one-time action after the first
   publish.

## If you fork this repo or push to a different owner

`env.IMAGE_NAME` in the workflow is `${{ github.repository }}`, so a fork
publishes to `ghcr.io/<your-username>/algod-rust` automatically — no
workflow edit or secret needed, since `GITHUB_TOKEN` is scoped to whichever
repository the workflow runs in.

One caveat: the `build` job's arm64 leg runs on `ubuntu-24.04-arm`, GitHub's
native ARM64 hosted runner. That label is free only for **public**
repositories (GitHub Changelog, 2025-01-16). If you fork to a **private**
repo, that job either fails to find a runner or bills against your paid
minutes depending on your plan — drop the `arm64` entry from the `build`
job's `platform`/`include` matrix (and the corresponding digest in `merge`'s
`imagetools create` invocation) to publish amd64-only instead.

## If you later want to also push to Docker Hub

Not currently done (GHCR only, to match how `docker/docker-compose.yml`
already pulls `algorand/algod` from Docker Hub for the *Go* side while
staying registry-agnostic for the *Rust* side). If this is added later, it
would need two new secrets — `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (a
Docker Hub access token, not the account password) — plus an additional
`docker/login-action` step. Skipped for now to keep the required-secrets
list empty.
