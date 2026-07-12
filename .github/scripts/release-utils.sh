#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  release-utils.sh extract-notes VERSION CHANGELOG OUTPUT
  release-utils.sh select-image-tags EVENT REF CURRENT PREVIOUS SHA
  release-utils.sh self-test
EOF
}

extract_notes() {
    if [ "$#" -ne 3 ]; then
        usage
        return 2
    fi

    local version=$1
    local changelog=$2
    local output=$3
    local header="## [${version}]"
    local tmp="${output}.tmp"

    if [ ! -f "${changelog}" ]; then
        echo "Changelog not found: ${changelog}" >&2
        return 1
    fi

    rm -f "${tmp}"
    if ! awk -v header="${header}" '
        BEGIN { found = 0 }
        {
            is_header = (substr($0, 1, length(header)) == header)
            boundary = substr($0, length(header) + 1, 1)
        }
        !found && is_header && (boundary == "" || boundary ~ /[[:space:]]/) {
            found = 1
            next
        }
        found && /^## \[/ { exit }
        found { print }
        END { if (!found) exit 42 }
    ' "${changelog}" > "${tmp}"; then
        rm -f "${tmp}"
        echo "No literal changelog section found for ${header}" >&2
        return 1
    fi

    if ! grep -q '[^[:space:]]' "${tmp}"; then
        rm -f "${tmp}"
        echo "Changelog section ${header} is empty" >&2
        return 1
    fi

    mv "${tmp}" "${output}"
}

select_image_tags() {
    if [ "$#" -ne 5 ]; then
        usage
        return 2
    fi

    local event_name=$1
    local ref=$2
    local current_version=$3
    local previous_version=$4
    local sha=$5

    if [[ ! "${sha}" =~ ^[0-9a-fA-F]{12,40}$ ]]; then
        echo "Invalid commit SHA: ${sha}" >&2
        return 1
    fi

    # Only a version change on a push to main may move the user-facing
    # version and latest tags. PR and manual builds are immutable snapshots.
    if [ "${event_name}" = "push" ] \
        && [ "${ref}" = "refs/heads/main" ] \
        && [ "${current_version}" != "${previous_version}" ]; then
        printf '%s\nlatest\n' "${current_version}"
    else
        printf 'sha-%s\n' "${sha}"
    fi
}

self_test() {
    local script_path=$1
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "${tmpdir}"' RETURN

    cat > "${tmpdir}/CHANGELOG.md" <<'EOF'
# Changelog

## [1.5.20] - 2026-07-13

- Wrong section.

## [1.5.2] - 2026-07-12

- Correct section.

## [1.5.1] - 2026-07-11

- Older section.
EOF

    bash "${script_path}" extract-notes \
        1.5.2 "${tmpdir}/CHANGELOG.md" "${tmpdir}/notes.md"
    grep -q -- '- Correct section\.' "${tmpdir}/notes.md"
    if grep -q -- 'Wrong\|Older' "${tmpdir}/notes.md"; then
        echo "extract-notes crossed an exact-version boundary" >&2
        return 1
    fi
    if bash "${script_path}" extract-notes \
        9.9.9 "${tmpdir}/CHANGELOG.md" "${tmpdir}/missing.md" \
        >/dev/null 2>&1; then
        echo "extract-notes accepted a missing version" >&2
        return 1
    fi

    local sha=0123456789abcdef0123456789abcdef01234567
    local actual
    actual=$(bash "${script_path}" select-image-tags \
        push refs/heads/main 1.5.2 1.5.1 "${sha}")
    if [ "${actual}" != $'1.5.2\nlatest' ]; then
        echo "Version-bump tag selection failed: ${actual}" >&2
        return 1
    fi

    actual=$(bash "${script_path}" select-image-tags \
        push refs/heads/main 1.5.2 1.5.2 "${sha}")
    if [ "${actual}" != "sha-${sha}" ]; then
        echo "Ordinary-main tag selection failed: ${actual}" >&2
        return 1
    fi

    actual=$(bash "${script_path}" select-image-tags \
        workflow_dispatch refs/heads/main 1.5.2 1.5.1 "${sha}")
    if [ "${actual}" != "sha-${sha}" ]; then
        echo "Manual-build tag selection failed: ${actual}" >&2
        return 1
    fi

    actual=$(bash "${script_path}" select-image-tags \
        pull_request refs/pull/1/merge 1.5.2 1.5.1 "${sha}")
    if [ "${actual}" != "sha-${sha}" ]; then
        echo "PR tag selection failed: ${actual}" >&2
        return 1
    fi

    echo "release-utils self-test passed"
}

command=${1:-}
if [ -z "${command}" ]; then
    usage
    exit 2
fi
shift

case "${command}" in
    extract-notes)
        extract_notes "$@"
        ;;
    select-image-tags)
        select_image_tags "$@"
        ;;
    self-test)
        if [ "$#" -ne 0 ]; then
            usage
            exit 2
        fi
        self_test "$0"
        ;;
    *)
        usage
        exit 2
        ;;
esac
