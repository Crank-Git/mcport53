#!/usr/bin/env bash
# Builds release archives of mcp53-server and mcp53-client for every supported
# platform, plus a SHA256SUMS file.
#
#   scripts/build-release.sh <version> <outdir>
#
# Run it from the root of the source tree to build (the release workflow runs
# it inside a checkout of the release tag). Binaries are static
# (CGO_ENABLED=0) and built with -trimpath.
set -euo pipefail

version=${1:?usage: build-release.sh <version> <outdir>}
out=${2:?usage: build-release.sh <version> <outdir>}

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
export COPYFILE_DISABLE=1 # no macOS resource-fork entries in tar archives

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in $targets; do
	os=${target%/*}
	arch=${target#*/}
	name="mcport53_${version}_${os}_${arch}"
	dir="$work/$name"
	mkdir -p "$dir"
	ext=""
	[ "$os" = windows ] && ext=.exe
	for cmd in mcp53-server mcp53-client; do
		CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
			go build -trimpath -ldflags "-s -w" -o "$dir/$cmd$ext" "./cmd/$cmd"
	done
	cp LICENSE README.md "$dir/"
	if [ "$os" = windows ]; then
		(cd "$work" && zip -qr "$out/$name.zip" "$name")
	else
		tar -C "$work" -czf "$out/$name.tar.gz" "$name"
	fi
	echo "built $name"
done

cd "$out"
if command -v sha256sum >/dev/null; then
	sha256sum mcport53_* >SHA256SUMS
else
	shasum -a 256 mcport53_* >SHA256SUMS
fi
echo "wrote $out/SHA256SUMS"
