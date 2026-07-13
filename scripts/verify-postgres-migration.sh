#!/usr/bin/env bash

# Copyright 2026 The Casdoor Authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License").

set -euo pipefail

readonly CURRENT_IMAGE="${1:?usage: verify-postgres-migration.sh <current-image>}"
readonly STOCK_IMAGE="casbin/casdoor@sha256:2bac6b4abd3945ab838e9a9b8ecef82a0a12bc500a09ae50f53bbd7a21b39d6b" # 3.97.0
readonly POSTGRES_IMAGE="postgres@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297" # 16.10-alpine3.22
readonly RUN_SUFFIX="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
readonly NETWORK="casdoor-migration-${RUN_SUFFIX}"
readonly POSTGRES_CONTAINER="casdoor-postgres-${RUN_SUFFIX}"
readonly STOCK_CONTAINER="casdoor-stock-${RUN_SUFFIX}"
readonly MIGRATION_CONTAINER="casdoor-migration-job-${RUN_SUFFIX}"
readonly DB_USER="casdoor"
readonly DB_PASSWORD="casdoor-ci-only"
readonly DB_NAME="casdoor"
readonly DSN="user=${DB_USER} password=${DB_PASSWORD} host=postgres port=5432 sslmode=disable dbname=${DB_NAME}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
  docker rm -f \
    "$MIGRATION_CONTAINER" \
    "$STOCK_CONTAINER" \
    "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

query_scalar() {
  docker exec "$POSTGRES_CONTAINER" \
    psql --set ON_ERROR_STOP=1 --username "$DB_USER" --dbname "$DB_NAME" \
    --tuples-only --no-align --command "$1"
}

assert_equal() {
  local actual="$1"
  local expected="$2"
  local message="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "${message}: got '${actual}', want '${expected}'" >&2
    exit 1
  fi
}

docker pull --platform linux/amd64 "$STOCK_IMAGE"
docker pull --platform linux/amd64 "$POSTGRES_IMAGE"
docker image inspect "$CURRENT_IMAGE" >/dev/null

docker network create --internal "$NETWORK" >/dev/null
docker run --detach \
  --name "$POSTGRES_CONTAINER" \
  --network "$NETWORK" \
  --network-alias postgres \
  --env "POSTGRES_USER=${DB_USER}" \
  --env "POSTGRES_PASSWORD=${DB_PASSWORD}" \
  --env "POSTGRES_DB=${DB_NAME}" \
  --health-cmd="pg_isready -U ${DB_USER} -d ${DB_NAME}" \
  --health-interval=2s \
  --health-timeout=3s \
  --health-retries=30 \
  "$POSTGRES_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if [[ "$(docker inspect --format '{{.State.Health.Status}}' "$POSTGRES_CONTAINER")" == "healthy" ]]; then
    break
  fi
  sleep 1
done
assert_equal \
  "$(docker inspect --format '{{.State.Health.Status}}' "$POSTGRES_CONTAINER")" \
  "healthy" \
  "PostgreSQL did not become healthy"

# The pinned upstream 3.97.0 image owns creation of the starting schema. Its
# export mode exits before listeners, giving this test a real stock schema
# without carrying a hand-maintained SQL approximation.
docker run \
  --name "$STOCK_CONTAINER" \
  --network "$NETWORK" \
  --env driverName=postgres \
  --env "dataSourceName=${DSN}" \
  --env "dbName=${DB_NAME}" \
  "$STOCK_IMAGE" \
  -export -exportPath=/tmp/stock-init-data.json

application_table="$(query_scalar "SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'expire_in_hours' ORDER BY table_name LIMIT 1;")"
token_table="$(query_scalar "SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'refresh_token_hash' ORDER BY table_name LIMIT 1;")"
assert_equal "$application_table" "application" "unexpected stock application table"
assert_equal "$token_table" "token" "unexpected stock token table"

# The three Werkblick servers currently carry these two TTL columns as integer.
# Reproduce that observed drift on top of the genuine 3.97 schema so Sync2 must
# prove the exact live integer-to-double-precision upgrade.
query_scalar "ALTER TABLE application ALTER COLUMN expire_in_hours TYPE integer USING round(expire_in_hours)::integer; ALTER TABLE application ALTER COLUMN refresh_expire_in_hours TYPE integer USING round(refresh_expire_in_hours)::integer;" >/dev/null
assert_equal \
  "$(query_scalar "SELECT string_agg(column_name || ':' || data_type, ',' ORDER BY column_name) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'application' AND column_name IN ('expire_in_hours', 'refresh_expire_in_hours');")" \
  "expire_in_hours:integer,refresh_expire_in_hours:integer" \
  "failed to reproduce the live TTL schema"

set +e
docker run \
  --name "$MIGRATION_CONTAINER" \
  --network "$NETWORK" \
  --env driverName=postgres \
  --env "dataSourceName=${DSN}" \
  --env "dbName=${DB_NAME}" \
  --env WERKBLICK_SCHEMA_MIGRATION_ONLY=true \
  --volume "${repo_root}/conf/app.conf:/conf/app.conf:ro" \
  "$CURRENT_IMAGE"
migration_exit=$?
set -e

docker logs "$MIGRATION_CONTAINER"
assert_equal "$migration_exit" "0" "migration-only container exit code"
assert_equal \
  "$(docker inspect --format '{{.State.Status}}' "$MIGRATION_CONTAINER")" \
  "exited" \
  "migration-only container kept a listener or job alive"
if ! docker logs "$MIGRATION_CONTAINER" 2>&1 | grep -Fq "schema migration completed"; then
  echo "migration-only completion log is missing" >&2
  exit 1
fi

assert_equal \
  "$(query_scalar "SELECT string_agg(column_name || ':' || data_type, ',' ORDER BY column_name) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'application' AND column_name IN ('expire_in_hours', 'refresh_expire_in_hours');")" \
  "expire_in_hours:double precision,refresh_expire_in_hours:double precision" \
  "TTL columns were not migrated to double precision"

missing_columns="$(query_scalar "WITH expected(table_name, column_name) AS (VALUES ('application', 'token_endpoint_auth_method'), ('application', 'enable_saml'), ('token', 'refresh_token_family'), ('token', 'refresh_token_consumed'), ('token', 'nonce'), ('token', 'auth_time'), ('token', 'authentication_methods'), ('token', 'authentication_provider')) SELECT count(*) FROM expected LEFT JOIN information_schema.columns c ON c.table_schema = 'public' AND c.table_name = expected.table_name AND c.column_name = expected.column_name WHERE c.column_name IS NULL;")"
assert_equal "$missing_columns" "0" "one or more Werkblick schema columns are missing"

assert_equal \
  "$(query_scalar "SELECT data_type || ':' || lower(column_default) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'application' AND column_name = 'enable_saml';")" \
  "boolean:false" \
  "enable_saml must be a boolean defaulting to false"

echo "Verified stock Casdoor 3.97.0 to Werkblick r2 migration on PostgreSQL 16."
