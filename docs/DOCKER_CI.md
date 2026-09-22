# Docker Image CI/CD

`.github/workflows/docker-image.yml` builds `docker/Dockerfile` and, on
`main` / version tags / a daily schedule, publishes it to GHCR
(`ghcr.io/xarmian/algod-rust`) and, optionally, to Docker Hub
(`docker.io/<DOCKERHUB_USERNAME>/algod-rust`). See that workflow's header
comment for the full trigger/tagging rationale (mirroring the
`algorand/algod` Docker Hub image's port/data-dir/tag-naming conventions for
drop-in compatibility).

## Required GitHub repository secrets

| Secret               | Required?   | Used by                | Required for                                                             |
| --------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------- |
| *(none)*               | —           | `docker-image.yml`      | GHCR publishing — authenticates with the automatically provisioned `secrets.GITHUB_TOKEN`, nothing to create |
| `DOCKERHUB_USERNAME`   | Optional    | `docker-image.yml`      | Docker Hub publishing — the namespace images are pushed under            |
| `DOCKERHUB_TOKEN`      | Optional    | `docker-image.yml`      | Docker Hub publishing — the access token used to authenticate            |
| `CODECOV_TOKEN`        | Required    | `coverage.yml`          | Uploading LCOV reports to Codecov (unrelated to this workflow)           |

GHCR publishing needs **no secret setup at all** — it always runs. Docker
Hub publishing is **entirely opt-in**: the workflow's `prepare` job checks
whether both `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` are set and, if
either is missing, every Docker Hub step (login, build output, manifest
push, smoke test) is skipped automatically and only GHCR gets published —
this is the default state for a fresh fork or clone, and is not an error.

### Setting up Docker Hub publishing

1. **Create a Docker Hub access token** (not your account password — Docker
   Hub deprecated password-based API auth):
   - Log in to [hub.docker.com](https://hub.docker.com) as the account/org
     that should own the `algod-rust` repository.
   - *Account Settings → Personal access tokens → Generate new token.*
   - Give it a description (e.g. `algod-rust GitHub Actions`) and the
     **Read & Write** permission scope (Read-only can't push; Admin is more
     than this workflow needs).
   - Copy the token immediately — Docker Hub only shows it once.
2. **Add both secrets to the GitHub repository**
   (*Settings → Secrets and variables → Actions → New repository secret*,
   or `gh secret set NAME` from the CLI):

   ```bash
   gh secret set DOCKERHUB_USERNAME --body "<your-dockerhub-username-or-org>"
   gh secret set DOCKERHUB_TOKEN    --body "<the-access-token-from-step-1>"
   ```

   `DOCKERHUB_USERNAME` is the Docker Hub namespace images publish under
   (`docker.io/<DOCKERHUB_USERNAME>/algod-rust`) — it does not need to match
   the GitHub org/user (`xarmian`).
3. **Create the Docker Hub repository once**, if it doesn't already exist:
   either push manually once (`docker login`, then let the first workflow
   run create it — Docker Hub auto-creates a repo on first push from a
   token with Write access) or create `<DOCKERHUB_USERNAME>/algod-rust`
   ahead of time via the Docker Hub UI (*Create Repository*). Either way,
   set its visibility (public/private) directly on Docker Hub — this
   workflow doesn't manage that.
4. **That's it.** The next `main`/tag/scheduled push publishes to both
   registries with identical tags and digests — no workflow edit needed.

To stop publishing to Docker Hub again, delete either secret
(*Settings → Secrets and variables → Actions*, or
`gh secret delete DOCKERHUB_USERNAME`) — the workflow falls back to
GHCR-only on the next run, same as a fork that never configured them.

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
job's `platform`/`include` matrix to publish amd64-only instead. `merge`'s
`imagetools create` step needs no edit: it globs whatever digest files
`download-artifact` fetched, so it already adapts to however many platforms
`build` actually produced.

## Pushing to Docker Hub

See "Setting up Docker Hub publishing" above — it's optional and
secret-gated, not a separate mode to enable in the workflow itself.
