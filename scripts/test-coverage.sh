#!/usr/bin/env bash
# test-coverage.sh — fail unless every package with statements has 100% coverage
#
# Writes the combined profile to $COVER_PROFILE (default coverage.out) so
# `go tool cover` can show what is missing. Used by CI and `make coverage-check`.
set -euo pipefail

profile="${COVER_PROFILE:-coverage.out}"
output="$(mktemp)"
trap 'rm -f "${output}"' EXIT

go test -covermode=atomic -coverprofile="${profile}" ./cmd/... ./internal/... | tee "${output}"

fail=0
while IFS= read -r line; do
  [[ "${line}" == *"coverage:"* ]] || continue
  [[ "${line}" == *"[no statements]"* ]] && continue
  pct="$(sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p' <<<"${line}")"
  [[ -z "${pct}" ]] && continue
  if awk -v p="${pct}" 'BEGIN { exit !(p < 100.0) }'; then
    echo "coverage shortfall: ${line}"
    fail=1
  fi
done < "${output}"

if [[ "${fail}" -ne 0 ]]; then
  echo "coverage check failed"
  exit 1
fi
echo "coverage check passed"
