#!/usr/bin/env bash
# Upload the reserved CLI version through R2's bucket-scoped S3 API.
# Credentials arrive only in the publish step and travel to curl on stdin.
set -euo pipefail

version=${1:-}
dist=${2:-}
refuse() {
  printf 'cli publish: %s\n' "$*" >&2
  exit 1
}
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
targets='aarch64-apple-darwin aarch64-unknown-linux-musl x86_64-apple-darwin x86_64-pc-windows-msvc x86_64-unknown-linux-musl'
# Verify every archive before the first upload. The manifest names exactly
# the five files the installer can download, with their actual digests.
for target in $targets; do
  archive="proofline-$target.tar.gz"
  [ -f "$dist/$archive" ] || refuse "missing $archive"
  digest=$(sha256sum "$dist/$archive" | cut -d ' ' -f 1)
  printf '%s  %s\n' "$digest" "$archive" >>"$temporary/SHA256SUMS"
done
cmp -s "$temporary/SHA256SUMS" "$dist/SHA256SUMS" || refuse 'SHA256SUMS does not match the five release archives'

origin="https://$CLOUDFLARE_ACCOUNT_ID.r2.cloudflarestorage.com/proofline-cli-releases"
signed() {
  printf 'user = "%s:%s"\n' "$access_key" "$secret_key" |
    curl --config - --aws-sigv4 'aws:amz:auto:s3' --proto '=https' --tlsv1.2 \
      --silent --show-error --connect-timeout 15 --max-time 120 "$@"
}

# Read from the bucket. The installer's edge cache may still hold an older pointer.
read_key() {
  signed --dump-header "$temporary/headers" --output "$temporary/remote" \
    --write-out '%{http_code}' "$origin/$1"
}

put() {
  local key=$1 source=$2 content_type=$3 cache_control=$4 condition=$5 digest
  digest=$(sha256sum "$source" | cut -d ' ' -f 1)
  signed --fail --output /dev/null --request PUT --upload-file "$source" \
    --header "Content-Type: $content_type" --header "Cache-Control: $cache_control" \
    --header "x-amz-content-sha256: $digest" --header "$condition" "$origin/$key"
}

immutable() {
  local key=$1 source=$2 content_type=$3 status
  status=$(read_key "$key")
  case "$status" in
    200) cmp -s "$source" "$temporary/remote" || refuse "existing content differs for $key" ;;
    404) put "$key" "$source" "$content_type" 'public, max-age=31536000, immutable' 'If-None-Match: *' ;;
    *) refuse "could not read $key ($status)" ;;
  esac
}

latest=''
status=$(read_key latest)
case "$status" in
  200)
    latest=$(cat "$temporary/remote")
    [[ "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || refuse 'latest is not a version'
    [ "$(printf '%s\n%s\n' "$latest" "$version" | sort -V | tail -1)" = "$version" ] || refuse "latest is newer than $version"
    etag=$(awk 'tolower($1) == "etag:" {gsub(/\r/, "", $2); print $2}' "$temporary/headers")
    [[ "$etag" =~ ^\"[a-fA-F0-9-]+\"$ ]] || refuse 'latest has no usable entity tag'
    condition="If-Match: $etag"
    ;;
  404) condition='If-None-Match: *' ;;
  *) refuse "could not read latest ($status)" ;;
esac

[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || refuse 'missing release commit'
printf '{"version":"%s","commit":"%s"}\n' "$version" "$GITHUB_SHA" >"$temporary/reservation.json"
status=$(read_key "$version/RELEASE.json")
case "$status" in
  200) cmp -s "$temporary/reservation.json" "$temporary/remote" || refuse 'version reserved for a different commit' ;;
  404)
    status=$(read_key "$version/SHA256SUMS")
    if [ "$status" != 404 ] || [ "$latest" = "$version" ]; then
      refuse 'version is already published or unavailable'
    fi
    put "$version/RELEASE.json" "$temporary/reservation.json" application/json 'public, max-age=31536000, immutable' 'If-None-Match: *'
    ;;
  *) refuse "could not read version reservation ($status)" ;;
esac

for target in $targets; do
  archive="proofline-$target.tar.gz"
  immutable "$version/$archive" "$dist/$archive" application/gzip
done
immutable "$version/SHA256SUMS" "$dist/SHA256SUMS" 'text/plain; charset=utf-8'
if [ -f "$dist/install.sh" ]; then
  immutable "$version/install.sh" "$dist/install.sh" 'text/plain; charset=utf-8'
fi
if [ "$latest" != "$version" ]; then
  printf '%s\n' "$version" >"$temporary/latest"
  put latest "$temporary/latest" 'text/plain; charset=utf-8' 'public, max-age=60' "$condition"
fi
printf 'cli publish: verified CLI %s\n' "$version"
