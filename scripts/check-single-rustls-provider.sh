#!/usr/bin/env sh
# Fail if more than one rustls cryptographic provider is linked into the
# console binary for a given build flavour.
#
# mcp-gateway-crypto selects exactly one provider (`ring` or
# `aws-lc-rs`) at build time so rustls never has to disambiguate two,
# which would panic. Feature unification makes it easy to reintroduce a
# second provider by accident (a dependency slipping back to its default
# rustls features), so this check is meant to run in CI for each flavour.
#
# Usage:
#   scripts/check-single-rustls-provider.sh
#   scripts/check-single-rustls-provider.sh --no-default-features --features "self-signed,aws-lc-rs"
#
# Any arguments are passed through to `cargo tree`, so the same script
# checks every flavour.
set -eu

providers=$(
	cargo tree -p mcp-gateway-console -e features -f '{p} {f}' "$@" \
		| grep 'rustls v0.23' \
		| tr ' ,' '\n\n' \
		| grep -E '^(ring|aws_lc_rs)$' \
		| sort -u
)

count=$(printf '%s' "$providers" | grep -c . || true)

if [ "$count" -ne 1 ]; then
	echo "FAIL: expected exactly one rustls provider, found: ${providers:-none}" >&2
	echo "      (mcp-gateway-crypto must select exactly one; see issue #64)" >&2
	exit 1
fi

echo "OK: single rustls provider ($providers)"
