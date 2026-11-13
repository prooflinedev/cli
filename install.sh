#!/bin/sh
# Installs the Proofline command-line client.
#
#   curl -fsSL https://proofline.sh/cli | sh
#   curl -fsSL https://proofline.sh/cli | sh -s -- --setup
#
# It downloads its matching release for this machine from proofline.sh over
# HTTPS, checks it against the release's SHA256SUMS, and puts `proofline` in
# ~/.local/bin, or in PROOFLINE_INSTALL_DIR when that is set. PROOFLINE_VERSION
# selects another release.
#
# Every statement is inside a function and the last line calls it, so a
# download cut short runs nothing.

set -eu

PROOFLINE_CLI=https://proofline.sh/cli
PROOFLINE_INSTALLER_VERSION=0.2.1
PROOFLINE_SETUP_MIN_VERSION=0.1.8

say() {
  printf 'proofline install: %s\n' "$*" >&2
}

refuse() {
  say "$*"
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || refuse "this installer needs $1, which is not on PATH"
}

# curl refuses any address that is not HTTPS, a redirect included, and any TLS
# older than 1.2.
fetch() {
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "$@"
}

# The release target for this machine, one of the four a release publishes.
target() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Linux) os=unknown-linux-musl ;;
    Darwin)
      os=apple-darwin
      # A shell under Rosetta reports x86_64 on Apple silicon. The native
      # build is the one to install there.
      if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
        arch=arm64
      fi
      ;;
    *) refuse "no Proofline release is built for $os; set PROOFLINE_TOKEN and call the API, or build https://github.com/prooflinedev/cli from source" ;;
  esac
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) refuse "no Proofline release is built for $arch on $(uname -s)" ;;
  esac
  printf '%s-%s\n' "$arch" "$os"
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    refuse "this installer needs sha256sum or shasum to check the download"
  fi
}

main() {
  setup=false
  case "$#:$*" in
    0:) ;;
    1:--setup) setup=true ;;
    1:--help)
      say "usage: curl -fsSL https://proofline.sh/cli | sh -s -- [--setup]"
      say "--setup registers MCP in Claude Code, Cursor and Codex, then opens GitHub setup and CLI sign-in"
      return
      ;;
    *) refuse "unknown arguments; use --setup for coding-agent installation or --help for usage" ;;
  esac

  need curl
  need tar
  need uname
  need mktemp

  target=$(target)
  if [ -n "${PROOFLINE_VERSION:-}" ]; then
    version=${PROOFLINE_VERSION#v}
  else
    version=$PROOFLINE_INSTALLER_VERSION
  fi
  printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' ||
    refuse "the release version is not a version number: $version"

  directory=${PROOFLINE_INSTALL_DIR:-${HOME:?set HOME or PROOFLINE_INSTALL_DIR}/.local/bin}
  archive=proofline-$target.tar.gz
  release=$PROOFLINE_CLI/download/$version

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  trap 'exit 130' INT TERM

  say "downloading proofline $version for $target"
  fetch --output "$work/$archive" "$release/$archive" ||
    refuse "could not download $release/$archive"
  fetch --output "$work/SHA256SUMS" "$release/SHA256SUMS" ||
    refuse "could not download $release/SHA256SUMS"

  expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1 }' "$work/SHA256SUMS")
  [ -n "$expected" ] || refuse "SHA256SUMS for $version lists no $archive"
  actual=$(sha256 "$work/$archive")
  [ "$actual" = "$expected" ] ||
    refuse "the download does not match SHA256SUMS ($actual, expected $expected); nothing was installed"

  tar -xzf "$work/$archive" -C "$work" proofline ||
    refuse "$archive does not contain proofline"
  chmod 755 "$work/proofline"
  if [ "$setup" = true ]; then
    "$work/proofline" agent install claude-code --print >/dev/null ||
      refuse "release $version does not support one-command setup; install release $PROOFLINE_SETUP_MIN_VERSION or later"
  fi

  mkdir -p "$directory" || refuse "could not create $directory"
  # Copy beside the destination and rename over it, so a running proofline
  # is never overwritten in place and an interrupted copy leaves the old one.
  cp "$work/proofline" "$directory/.proofline.$$" || refuse "could not write to $directory"
  mv -f "$directory/.proofline.$$" "$directory/proofline"

  say "installed $("$directory/proofline" --version) at $directory/proofline"
  case ":${PATH:-}:" in
    *":$directory:"*) ;;
    *) say "$directory is not on PATH; add it to run proofline by name" ;;
  esac
  if [ "$setup" = true ]; then
    for client in claude-code cursor codex; do
      "$directory/proofline" agent install "$client" --yes ||
        refuse "could not configure $client; earlier steps remain installed; fix the reported configuration and rerun this command"
    done
    say "opening Proofline setup; sign in with GitHub and install the GitHub App for your team"
    "$directory/proofline" setup ||
      refuse "could not open setup; visit https://proofline.sh/orgs and rerun this command after installing the GitHub App"
    "$directory/proofline" login --scope reviews:read --scope findings:read --scope guidance:read --scope reviews:request --scope setup:write --scope org:configure ||
      refuse "CLI sign-in did not finish; the CLI and MCP entries remain installed; rerun this command to sign in"
    say "restart your coding agent or reload its MCP servers, then ask it to set up Proofline"
  else
    say "run 'proofline login' to sign in"
  fi
}

main "$@"
