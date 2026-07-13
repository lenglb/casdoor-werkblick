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

### Authentication migration invariants

Schema synchronization adds `applications.enable_saml` with a database default
of `false`. Therefore every existing application, including `app-built-in`,
browser clients, and machine-to-machine clients, remains unable to issue SAML
assertions after upgrade. Enabling SAML requires a tenant-bound application and
an absolute HTTPS reply URL (HTTP is accepted only for a loopback development
URL). The request's `AssertionConsumerServiceURL` must then match that registered
reply URL byte-for-byte. Shared applications cannot act as a SAML IdP.

Password login requests with a non-empty password must declare exactly
`signinMethod: "Password"` or `signinMethod: "LDAP"`, and that method must be
enabled on the application. Empty and unknown methods fail before the local or
LDAP password checker. A `Password` method with the `Non-LDAP` rule continues to
authenticate local users without enabling LDAP fallback.

The generic `/api/update-user` endpoint projects request bodies through separate
self-service and admin field allowlists. Authentication credentials, MFA and
WebAuthn material, verification flags, LDAP/provider links, and other
system-maintained fields require purpose-built APIs. Explicit `columns` values
outside the caller's allowlist are rejected. Updating an email address clears
`email_verified` in the same database statement; only the verification flow may
set it again.

OAuth clients must explicitly list every permitted grant type, including
`authorization_code`. An empty `grantTypes` list rejects every grant. Likewise,
an empty application scope allowlist accepts only a request with no scope;
browser clients must explicitly allow the scopes they use. The Werkblick
migration sets browser clients to `authorization_code` plus
`openid profile email`, and workload clients to their exact machine grant and
scope set before this image is promoted.

OIDC UserInfo now emits `email_verified` from the persisted user record. An
unverified email is never upgraded to verified merely because the `email`
scope was granted; downstream account linking must continue to require the
claim to be true.

Authorization codes are bound to the exact `redirect_uri`, explicit
`authorization_code` grant, application, resource, scope and immutable user
ID. The token request must repeat the same `redirect_uri`. Code redemption
reloads the user and current application policy before atomically consuming the
code. Human token issuance and refresh require AAL2 whenever the user has MFA
enabled; a missing required-MFA enrollment also fails closed. Ordinary OIDC
users without MFA remain AAL1-compatible, including users whose truthful
`email_verified` claim is `false`.

### Schema-only migration

Run the new image once with the exact environment value
`WERKBLICK_SCHEMA_MIGRATION_ONLY=true` before starting the service normally.
This mode reads configuration, initializes the database adapter, runs Xorm
`Sync2` through `CreateTables`, logs successful completion, and exits with code
zero. It exits before `InitDb`, storage or log providers, LDAP, authorization,
the user manager, import/sync jobs, webhook workers, and every HTTP, LDAP, or
RADIUS listener. Values such as `TRUE`, `1`, or whitespace-padded `true` do not
enable migration-only mode and therefore take the normal boot path.

This step is required for the Werkblick r2 upgrade because the live schema has
`expire_in_hours` as an integer while the fork now stores it as a floating-point
value. Take and verify the database backup before running the schema-only job,
then inspect the resulting column type before starting the new digest.

The r2 schema also adds `token.subject varchar(100)` and
`token.redirect_uri varchar(500)`. Existing token rows have no immutable
subject or redirect binding and therefore cannot be refreshed or redeemed by
the hardened paths. Plan the cutover as a forced reauthentication and do not
promote the new digest while an authorization callback is in flight.

Werkblick CI builds and loads the actual AMD64 image, creates a starting schema
with the digest-pinned stock Casdoor 3.97.0 image on a digest-pinned PostgreSQL
16 container, reproduces the observed integer TTL columns, and runs that image
in migration-only mode on an isolated internal Docker network. Release is
blocked unless the job exits zero, leaves no container running, converts both
TTL columns to `double precision`, and creates every Werkblick OAuth/SAML token
column. The executable contract lives in
`scripts/verify-postgres-migration.sh` so the same proof can be invoked by an
external deployment pipeline with its locally built candidate image.

For an intentionally empty database, use the separate exact environment value
`WERKBLICK_BOOTSTRAP_DATA_ONLY=true` with a versioned `initDataFile` mounted at
the configured path. This mode initializes routes, flags, the database adapter
and schema, then runs only `InitDb` and the required init-data import before
exiting successfully. A missing configured init-data file is fatal. It does not
initialize storage or log providers, LDAP, authorization, the user manager,
cleanup or sync jobs, site monitoring, webhook delivery, or any listener.

Schema-only and bootstrap-data-only are mutually exclusive. Setting both exact
values to `true` fails before any initialization or database access.

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
