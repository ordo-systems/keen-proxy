#!/usr/bin/env bash
# Publish exactly the retained payload to the release ID resolved before the build.
set -euo pipefail

cd "$1"
[[ "$RELEASE_ID" =~ ^[0-9]+$ ]]
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]
[[ "$RELEASE_REVISION" =~ ^[0-9a-f]{40}$ ]]
[[ "$RELEASE_NATIVE" == true || "$RELEASE_NATIVE" == false ]]
[[ "$RELEASE_ENTWARE_CONTROLLER" == true || "$RELEASE_ENTWARE_CONTROLLER" == false ]]
[[ "$RELEASE_BOOTSTRAP" == true || "$RELEASE_BOOTSTRAP" == false ]]
[[ "$RELEASE_RECOVERY" == true || "$RELEASE_RECOVERY" == false ]]
endpoint="repos/$GH_REPO/releases/$RELEASE_ID"

fail() { echo "Release $RELEASE_TAG: $*" >&2; exit 1; }

check_identity() {
    local release revision
    release=$(gh api "$endpoint")
    jq -e --arg tag "$RELEASE_TAG" --arg sha "$RELEASE_REVISION" \
        --argjson recovery "$RELEASE_RECOVERY" '
        .tag_name == $tag and .draft == ($recovery | not) and
        ($recovery or (.target_commitish == $sha and (.prerelease | not)))' \
        <<< "$release" >/dev/null || fail 'release identity or publication state changed'
    revision=$(gh api "repos/$GH_REPO/commits/refs/tags/$RELEASE_TAG" --jq .sha)
    [[ "$revision" == "$RELEASE_REVISION" ]] || fail 'tag no longer points to the built commit'
}

assets=(keenproxy-source.tar.gz keenproxy-notices.tar.gz install.sh BUILD_INFO.txt)
if [[ "$RELEASE_BOOTSTRAP" == true ]]; then assets+=(bootstrap.sh); fi
if [[ "$RELEASE_ENTWARE_CONTROLLER" == true ]]; then assets+=(S99keenproxy); fi
read -ra architectures <<< "$RELEASE_ARCHITECTURES"
for arch in "${architectures[@]}"; do
    [[ "$arch" =~ ^(amd64|386|armv5|arm64|mipsle|mipsbe)$ ]]
    assets+=("keenproxy-linux-$arch" "keenproxy-lite-linux-$arch")
done
if [[ "$RELEASE_NATIVE" == true ]]; then assets+=(keenproxy.openwrt); fi
[[ "$(awk '{ print $2 }' SHA256SUMS | LC_ALL=C sort)" == "$(printf '%s\n' "${assets[@]}" | LC_ALL=C sort)" ]] ||
    fail 'checksum manifest does not list exactly the expected files'
sha256sum --check --strict SHA256SUMS
[[ "$(head -n 2 BUILD_INFO.txt)" == "$(printf 'Version: %s\nCommit: %s' "$RELEASE_TAG" "$RELEASE_REVISION")" ]] ||
    fail 'build identity does not match the release'
assets+=(SHA256SUMS)

list_assets() {
    gh api --paginate --slurp "$endpoint/assets?per_page=100" | jq -c 'add'
}

asset_entry() {
    jq -c --arg name "$1" '
        [.[] | select(.name == $name)]
        | if length == 1 then .[0] elif length == 0 then empty else error("duplicate asset") end
    ' <<< "$remote"
}

verify_asset() {
    local name=$1 entry=$2 expected digest id
    jq -e '.state == "uploaded"' <<< "$entry" >/dev/null || fail "$name did not finish uploading"
    expected=$(sha256sum "$name")
    digest=$(jq -r '.digest // empty' <<< "$entry")
    if [[ -n "$digest" ]]; then
        [[ "$digest" == "sha256:${expected%% *}" ]] || fail "$name differs from the retained payload"
    else
        # Older assets may not have a server-side digest.
        id=$(jq -er .id <<< "$entry")
        digest=$(gh api -H 'Accept: application/octet-stream' "repos/$GH_REPO/releases/assets/$id" | sha256sum)
        [[ "${digest%% *}" == "${expected%% *}" ]] || fail "$name differs from the retained payload"
    fi
}

check_identity
remote=$(list_assets)
missing=()
for name in "${assets[@]}"; do
    entry=$(asset_entry "$name")
    if [[ -z "$entry" ]]; then
        missing+=("$name")
    elif [[ "$RELEASE_RECOVERY" == false ]] && jq -e '.state == "starter"' <<< "$entry" >/dev/null; then
        # Recover abandoned uploads in the draft, never touch published assets.
        id=$(jq -er .id <<< "$entry")
        gh api --method DELETE "repos/$GH_REPO/releases/assets/$id"
        missing+=("$name")
    else
        verify_asset "$name" "$entry"
    fi
done
for name in "${missing[@]}"; do
    curl --fail-with-body --silent --show-error --connect-timeout 20 --max-time 180 \
        -H "Authorization: Bearer $GH_TOKEN" -H 'Content-Type: application/octet-stream' \
        --data-binary "@$name" "https://uploads.github.com/$endpoint/assets?name=$name" >/dev/null
done

remote=$(list_assets)
for name in "${assets[@]}"; do
    entry=$(asset_entry "$name")
    [[ -n "$entry" ]] || fail "$name is missing after upload"
    verify_asset "$name" "$entry"
done
if [[ "$RELEASE_RECOVERY" == false ]]; then
    [[ "$(jq length <<< "$remote")" == "${#assets[@]}" ]] || fail 'draft contains unexpected assets'
    check_identity
    # Resuming an older draft must not displace a newer public stable release.
    newest=$(gh api --paginate --slurp "repos/$GH_REPO/releases?per_page=100" |
        jq -r '.[][] | select((.draft or .prerelease) | not) |
            .tag_name | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' |
        { cat; printf '%s\n' "$RELEASE_TAG"; } | LC_ALL=C sort -V | tail -n 1)
    latest=false
    if [[ "$newest" == "$RELEASE_TAG" ]]; then latest=true; fi
    gh api --method PATCH "$endpoint" -F draft=false -f "make_latest=$latest" \
        --jq '.html_url'
fi
