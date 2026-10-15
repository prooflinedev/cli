#!/usr/bin/env bash
# Upload the reserved CLI version through R2's bucket-scoped S3 API.
# Credentials arrive only in the publish step and travel to curl on stdin.
set -euo pipefail

version=${1:-}
dist=${2:-}
refuse() { printf 'cli publish: %s\n' "$*" >&2; exit 1; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || refuse 'expected an x.y.z version'
[ -d "$dist" ] || refuse 'the release directory is missing'
: "${CLOUDFLARE_ACCOUNT_ID:?the Cloudflare account is required}"
: "${CLI_RELEASE_R2_CREDENTIALS:?the bucket-scoped S3 credentials are required}"
[[ "$CLOUDFLARE_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] || refuse 'invalid Cloudflare account ID'
access_key=$(printf '%s' "$CLI_RELEASE_R2_CREDENTIALS" | jq -er '.access_key_id')
secret_key=$(printf '%s' "$CLI_RELEASE_R2_CREDENTIALS" | jq -er '.secret_access_key')
[[ "$access_key" =~ ^[0-9a-f]{32}$ ]] || refuse 'invalid R2 access key ID'
[[ "$secret_key" =~ ^[0-9a-f]{64}$ ]] || refuse 'invalid R2 secret access key'
unset CLI_RELEASE_R2_CREDENTIALS

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
targets='aarch64-apple-darwin aarch64-unknown-linux-musl x86_64-apple-darwin x86_64-unknown-linux-musl'
# Verify every archive before the first upload. The manifest names exactly
# the four files the installer can download, with their actual digests.
for target in $targets; do
  archive="proofline-$target.tar.gz"
  [ -f "$dist/$archive" ] || refuse "missing $archive"
  digest=$(sha256sum "$dist/$archive" | cut -d ' ' -f 1)
  printf '%s  %s\n' "$digest" "$archive" >> "$temporary/SHA256SUMS"
done
cmp -s "$temporary/SHA256SUMS" "$dist/SHA256SUMS" || refuse 'SHA256SUMS does not match the four release archives'

put() {
  local key=$1 source=$2 content_type=$3 cache_control=$4 condition=${5:-} digest
  digest=$(sha256sum "$source" | cut -d ' ' -f 1)
  # Object Read & Write tokens support the S3 API only. curl signs the exact
  # payload and metadata; credentials stay out of command arguments and logs.
  printf 'user = "%s:%s"\n' "$access_key" "$secret_key" |
    curl --config - --aws-sigv4 'aws:amz:auto:s3' \
      --proto '=https' --tlsv1.2 --fail --silent --show-error \
      --connect-timeout 15 --max-time 120 --retry 2 \
      --request PUT --upload-file "$source" \
      --header "Content-Type: $content_type" \
      --header "Cache-Control: $cache_control" \
      --header "x-amz-content-sha256: $digest" \
      --header "If-None-Match: $condition" \
      "https://$CLOUDFLARE_ACCOUNT_ID.r2.cloudflarestorage.com/proofline-cli-releases/$key"
}

# Old releases predate R2 reservations. Refuse those too, and never replace
# latest with an older version. An unavailable origin is not an empty registry.
status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --location \
  --connect-timeout 15 --max-time 30 --output "$temporary/probe" --write-out '%{http_code}' \
  "https://proofline.sh/cli/download/$version/SHA256SUMS")
[ "$status" = 404 ] || refuse "version $version is already published or its status is unavailable ($status)"
status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --location \
  --connect-timeout 15 --max-time 30 --output "$temporary/latest" --write-out '%{http_code}' \
  'https://proofline.sh/cli/latest')
case "$status" in
  200)
    latest=$(cat "$temporary/latest")
    [[ "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || refuse 'latest is not a version'
    [ "$latest" != "$version" ] && [ "$(printf '%s\n%s\n' "$latest" "$version" | sort -V | tail -1)" = "$version" ] \
      || refuse "$version is not newer than $latest"
    ;;
  404) ;;
  *) refuse "could not read latest ($status)" ;;
esac

# Reserve the version before any release object is written. A failed upload
# retains the claim, so another run cannot overwrite a partial publication.
printf '{"version":"%s","commit":"%s"}\n' "$version" "${GITHUB_SHA:?missing release commit}" > "$temporary/reservation.json"
put "$version/RELEASE.json" "$temporary/reservation.json" application/json 'public, max-age=31536000, immutable' '*'
immutable='public, max-age=31536000, immutable'
for target in $targets; do
  archive="proofline-$target.tar.gz"
  put "$version/$archive" "$dist/$archive" application/gzip "$immutable"
done
put "$version/SHA256SUMS" "$dist/SHA256SUMS" 'text/plain; charset=utf-8' "$immutable"
# Installers see the version only after all five release objects exist.
printf '%s\n' "$version" > "$temporary/latest"
put latest "$temporary/latest" 'text/plain; charset=utf-8' 'public, max-age=60'
printf 'cli publish: uploaded CLI %s\n' "$version"
