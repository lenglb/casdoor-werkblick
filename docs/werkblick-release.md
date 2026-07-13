# Werkblick Casdoor release process

The production artifact is `ghcr.io/lenglb/casdoor-werkblick`. Deployments must
always use the immutable digest emitted by the release workflow. Version and
source-SHA tags are discovery aids, not deployment identifiers. No `latest` tag
is published.

## Repository controls required before the first release

1. Create the fork as `lenglb/casdoor-werkblick` and protect its default branch.
2. Require the complete **Werkblick CI** workflow before changes can merge.
3. Add a tag ruleset covering `werkblick-v*`. Restrict tag creation and deletion
   to the release maintainers. The release job refuses unprotected tags.
4. Create the `ghcr-production` environment with a required reviewer and block
   self-review.
5. Keep the workflow token default at read-only. The publish job alone receives
   `packages: write`, `id-token: write`, and `attestations: write`.
6. Keep the GHCR package linked only to this repository. Do not add a PAT or a
   long-lived signing key. GHCR login uses the job-scoped `GITHUB_TOKEN`; Cosign
   and GitHub provenance use short-lived GitHub OIDC identities.
7. After the first publish, make the package public when the public fork is the
   source of truth. If it must remain private, store a read-only server pull
   credential in 1Password and keep it out of Compose files and host shells.

The fork can be created without cloning or publishing local changes with:

```bash
gh repo fork casdoor/casdoor --clone=false --fork-name casdoor-werkblick
```

## Release

Release tags have exactly this form:

```text
werkblick-v<upstream-major>.<upstream-minor>.<upstream-patch>-r<werkblick-revision>
```

For example, the first Werkblick build based on Casdoor 3.115.0 is
`werkblick-v3.115.0-r1`. Create releases only from a commit contained in the
protected default branch. A signed annotated Git tag is recommended in addition
to the enforced image signature:

```bash
git tag -s werkblick-v3.115.0-r1 <reviewed-commit>
git push fork werkblick-v3.115.0-r1
```

The tag runs the full backend, frontend, and container build first. Publication
then creates Linux AMD64 and ARM64 images, an SPDX JSON SBOM, GitHub build
provenance, and keyless Cosign signatures. The workflow summary contains the
only reference that may be deployed:

```text
ghcr.io/lenglb/casdoor-werkblick@sha256:<digest>
```

## Runtime contract

The hardened image is distroless and runs as UID/GID `65532`. It contains no
shell, package manager, application configuration, or private key. Mount
`/conf/app.conf` read-only and inject every credential from the deployment's
1Password-backed secret flow. Writable storage must be limited to the paths the
deployment actually uses, normally `/logs`, `/tmp`, and `/files`.

The Werkblick fork generates a fresh built-in JWT key for a new installation
and loads SAML signing material from the environment's database certificate.
The image still excludes all PEM and key files as defense in depth. Existing
environments must rotate any built-in JWT or SAML key matching the known public
upstream fixture fingerprint
`e9750c7433124b38d6d3c7aee87a65b64e80c3b6ec2cade26a9a9fadad061b4a`.

## Verification and rollback

Verify the exact digest before promotion:

```bash
IMAGE=ghcr.io/lenglb/casdoor-werkblick@sha256:<digest>
IDENTITY='https://github.com/lenglb/casdoor-werkblick/.github/workflows/werkblick-release.yml@refs/tags/werkblick-v3.115.0-r1'

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"

cosign verify-attestation \
  --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE"

gh attestation verify "oci://$IMAGE" --repo lenglb/casdoor-werkblick
```

Rollback is a configuration-only change to the last verified digest. Never
rebuild an old tag and never roll back to a mutable version tag. Keep the prior
digest, its signature verification result, database migration compatibility,
and the deployment recovery check together in the rollout record.

## Updating pinned dependencies

Base-image digests and every GitHub Action are pinned to immutable SHAs. Review
and update them deliberately, including changelogs and generated SBOM changes.
Do not replace the pins with floating major tags. Rebuilding the same source and
`SOURCE_DATE_EPOCH` should reproduce the runtime image; SBOM and provenance are
attached as external registry attestations so they do not perturb its digest.
