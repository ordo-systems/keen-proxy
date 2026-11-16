#!/bin/sh
# Compare complete daemons in uniquely owned containers, never on a live router.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BASELINE=9d398fb3754036cbe35df1cf07098164ff62a9d5
BASE_TAGS=with_quic,with_utls,with_wireguard,with_gvisor
CANDIDATE_TAGS=with_quic,with_utls,with_wireguard,with_awg,with_gvisor
mkdir -p "$ROOT/.agents-work/memory-regression"
OUT=$(mktemp -d "$ROOT/.agents-work/memory-regression/run.XXXXXX")
OWNER="$(basename "$OUT" | tr '[:upper:]' '[:lower:]')-$$"
IMAGE=keenproxy-memory-${OWNER}
CONTAINER=keenproxy-memory-${OWNER}
IMAGE_OWNED=0
CONTAINER_OWNED=0

# Register cleanup before creating any Docker resource. Preserve all evidence.
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$CONTAINER_OWNED" = 1 ]; then
        if owner=$(docker container inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$CONTAINER" 2>/dev/null); then
            if [ "$owner" = "$OWNER" ]; then
                docker stop --time 20 "$CONTAINER" >>"$OUT/cleanup.log" 2>&1 || true
                if docker cp "$CONTAINER:/tmp/." "$OUT/container-tmp" >>"$OUT/cleanup.log" 2>&1; then
                    docker rm -f "$CONTAINER" >>"$OUT/cleanup.log" 2>&1 || result=1
                    if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
                        echo "ERROR: owned container remains: $CONTAINER" >&2
                        result=1
                    fi
                else
                    echo "ERROR: artifact rescue failed; retaining owned container: $CONTAINER" >&2
                    result=1
                fi
            else
                echo "ERROR: refusing to remove container owned by another run: $CONTAINER" >&2
                result=1
            fi
        fi
    fi
    if [ "$IMAGE_OWNED" = 1 ]; then
        docker image rm "$IMAGE" >>"$OUT/cleanup.log" 2>&1 || result=1
        if docker image inspect "$IMAGE" >/dev/null 2>&1; then
            echo "ERROR: owned image tag remains: $IMAGE" >&2
            result=1
        fi
    fi
    printf '%s\n' "$result" >"$OUT/exit-code"
    printf 'Memory gate evidence: %s\n' "$OUT"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

for tool in docker go git python3; do
    command -v "$tool" >/dev/null || { echo "ERROR: required tool unavailable: $tool" >&2; exit 1; }
done
ARCH=$(docker info --format '{{.Architecture}}')
case "$ARCH" in
    aarch64|arm64) GOARCH=arm64 ;;
    x86_64|amd64) GOARCH=amd64 ;;
    *) echo "ERROR: unsupported Docker architecture: $ARCH" >&2; exit 1 ;;
esac
TOOLCHAIN=$(go env GOVERSION)
git -C "$ROOT" cat-file -e "$BASELINE^{commit}" || {
    echo "ERROR: fixed baseline missing; fetch repository history before running the gate" >&2
    exit 1
}
mkdir -p "$OUT/source" "$OUT/bin" "$OUT/results/baseline" "$OUT/results/candidate"
git -C "$ROOT" archive "$BASELINE" >"$OUT/baseline.tar"
tar -xf "$OUT/baseline.tar" -C "$OUT/source"
rm "$OUT/baseline.tar"
# All seven scenarios and comparison use one immutable fixture revision.
cp -R "$ROOT/test/memory" "$OUT/fixture"
{
    printf 'baseline=%s\ncandidate=%s\n' "$BASELINE" "$(git -C "$ROOT" rev-parse HEAD)"
    printf 'toolchain=%s\nGOOS=linux\nGOARCH=%s\n' "$TOOLCHAIN" "$GOARCH"
    printf 'baseline_tags=%s\ncandidate_tags=%s\n' "$BASE_TAGS" "$CANDIDATE_TAGS"
    printf 'ui_assets=excluded\nrepetitions=3\n'
} >"$OUT/manifest.txt"

build() {
    source=$1
    tags=$2
    output=$3
    (cd "$source" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOTOOLCHAIN="$TOOLCHAIN" \
        go build -buildvcs=false -trimpath -tags "$tags" -ldflags '-s -w -buildid=' \
        -o "$output" ./cmd/keenproxy)
}
build "$OUT/source" "$BASE_TAGS" "$OUT/bin/baseline" >"$OUT/baseline-build.log" 2>&1
build "$ROOT" "$CANDIDATE_TAGS" "$OUT/bin/candidate" >"$OUT/candidate-build.log" 2>&1
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOTOOLCHAIN="$TOOLCHAIN" \
    go build -buildvcs=false -trimpath -tags "$CANDIDATE_TAGS" \
    -o "$OUT/bin/sbserver" ./test/netns/sbserver) >"$OUT/server-build.log" 2>&1
for binary in baseline candidate sbserver; do
    go version -m "$OUT/bin/$binary" >"$OUT/$binary-build-info.txt"
done
python3 - "$OUT" <<'PY'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
with (root / 'manifest.txt').open('a') as manifest:
    for binary in ('baseline', 'candidate', 'sbserver'):
        digest = hashlib.sha256((root / 'bin' / binary).read_bytes()).hexdigest()
        manifest.write(f'{binary}_sha256={digest}\n')
    for path in sorted((root / 'fixture').iterdir()):
        if path.is_file():
            manifest.write(f'fixture_{path.name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}\n')
PY

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "ERROR: image tag collision: $IMAGE" >&2
    exit 1
fi
# The unique tag is ours even if a build fails after tagging its final layer.
IMAGE_OWNED=1
docker build -t "$IMAGE" "$OUT/fixture" >"$OUT/image-build.log" 2>&1
docker image inspect "$IMAGE" --format '{{.Id}}' >>"$OUT/manifest.txt"

scenario() {
    variant=$1
    protocol=$2
    run=$3
    filename=$protocol-$run
    # A collision must not give cleanup ownership of somebody else's container.
    if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
        echo "ERROR: container name collision: $CONTAINER" >&2
        exit 1
    fi
    CONTAINER_OWNED=1
    docker create --name "$CONTAINER" --label "keenproxy.memory.owner=$OWNER" \
        --network none --privileged --memory 1g --cpus 2 \
        -e GOMAXPROCS=2 -e GOGC=100 -e GOMEMLIMIT=off \
        -v "$OUT/bin:/binaries:ro" -v "$OUT/fixture:/fixture:ro" \
        -v "$OUT/results/$variant:/results" "$IMAGE" \
        --binary "/binaries/$variant" --server /binaries/sbserver \
        --scenario "$protocol" --variant "$variant" --run "$run" \
        --output "/results/$filename.json" >"$OUT/create.log"
    docker start -a "$CONTAINER" >"$OUT/results/$variant/$filename.log" 2>&1
    status=$(docker inspect --format '{{.State.ExitCode}}' "$CONTAINER")
    [ "$status" = 0 ] || { echo "ERROR: $variant $protocol run $run failed; see $OUT" >&2; exit 1; }
    docker rm "$CONTAINER" >>"$OUT/cleanup.log"
    CONTAINER_OWNED=0
    if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
        echo "ERROR: owned container remains: $CONTAINER" >&2
        exit 1
    fi
}

# Alternate pair order so warm caches cannot consistently favor the candidate.
for run in 1 2 3; do
    if [ "$run" = 2 ]; then
        scenario candidate wireguard "$run"
        scenario baseline wireguard "$run"
    else
        scenario baseline wireguard "$run"
        scenario candidate wireguard "$run"
    fi
done
scenario candidate amneziawg 1
python3 -B "$OUT/fixture/compare.py" --baseline "$OUT/results/baseline" \
    --candidate "$OUT/results/candidate" --output "$OUT/results/report.json"
