#!/bin/sh
set -eu
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
for copy in first second; do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$build_dir/$copy" ./cmd/gateway
done
cmp "$build_dir/first" "$build_dir/second"
shasum -a 256 "$build_dir/first"
