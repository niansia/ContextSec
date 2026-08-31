# Releasing ContextSec

ContextSec releases fail closed. A tag is not sufficient authorization to publish.

## Repository preconditions

1. GitHub Immutable Releases is enabled for the repository. The release job proves this before building by calling `GET /repos/{owner}/{repo}/immutable-releases`; a missing credential, 404, or `enabled != true` stops the release.
2. The `release` environment requires a manual reviewer and accepts only `v*` tags. Its environment secret `RELEASE_ADMIN_TOKEN` must have repository Administration **read** permission only, because GitHub's immutable-release status endpoint requires admin read access and `GITHUB_TOKEN` cannot request that permission.
3. `main` protection and the `v*` tag ruleset remain active.
4. The release tag is an annotated or signed tag whose peeled commit is exactly the current remote `main` HEAD. An ancestor of `main` is not releasable.

## Workflow trust closure

After approval, the job has 30 minutes. It reuses the same complete security proof as pull requests, verifies the immutable-release precondition, verifies exact-main identity, builds the archive twice, and emits `release-evidence.json`. That evidence binds the source commit, tool/detector/checker versions and semantic digests, verification-coverage summary, workflow run, and release archive digest.

The archive, evidence, and checksum manifest are covered by GitHub artifact attestations. Local and re-downloaded verification pins the release workflow identity, exact source commit, and GitHub-hosted runner before publication. The final step verifies GitHub's immutable Release attestation, which binds the published tag and all assets.

The attestation-availability loop can wait up to 10 minutes. The 30-minute job timeout intentionally leaves room for checkout, builds, attestations, draft verification, and service latency.
