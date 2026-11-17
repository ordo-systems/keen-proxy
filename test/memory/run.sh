#!/bin/sh
# Compare complete daemons, or stress the current daemon, in a uniquely owned container.
# Never run either mode on a live router.
set -eu

MODE=compare
if [ "$#" -gt 0 ]; then
    case "$1" in
        --stress) MODE=stress; shift ;;
        *) echo "ERROR: unknown argument: $1" >&2; echo "usage: sh test/memory/run.sh [--stress]" >&2; exit 1 ;;
    esac
fi
if [ "$#" -ne 0 ]; then
    echo "ERROR: unexpected arguments: $*" >&2
    exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
# Accepted full-feature main checkpoint; matches the accepted 37d196c application.
BASELINE=e6a1a1df2730418cf9edc2a71df4cec3e99be255
BASE_TAGS=with_quic,with_utls,with_wireguard,with_awg,with_gvisor,with_xhttp,with_trusttunnel
# 2 GiB with swap disabled. The 320 MiB Go limit belongs only to the measured daemon.
STRESS_MEMORY=2147483648
mkdir -p "$ROOT/.agents-work/memory-regression"
OUT=$(mktemp -d "$ROOT/.agents-work/memory-regression/run.XXXXXX")
OWNER="$(basename "$OUT" | tr '[:upper:]' '[:lower:]')-$$"
IMAGE=keenproxy-memory-${OWNER}
CONTAINER=keenproxy-memory-${OWNER}
IMAGE_OWNED=0
CONTAINER_OWNED=0
IMAGE_ID=
HOST_UID=$(id -u)
HOST_GID=$(id -g)
HANDOFF_CONTAINER=${CONTAINER}-handoff
HANDOFF_OWNED=0
EVIDENCE_DIRTY=0
EVIDENCE_QUIESCENT=1

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

# A failed inspect is not proof of absence. Require a successful list API response.
confirm_absent() {
    resource=$1
    shift
    if ! remaining=$(docker "$@" --format '{{.ID}}'); then
        echo "ERROR: cannot verify resource removal; Docker API unavailable: $resource" >&2
        return 1
    fi
    if [ -n "$remaining" ]; then
        echo "ERROR: owned resource remains: $resource" >&2
        return 1
    fi
}

# Walk only the mounted output trees, without following links or changing modes.
# Descriptor-relative operations keep symlinks from redirecting ownership changes.
evidence_handoff_script() {
    cat <<'PY'
import os
import signal
import stat
import sys

def deadline(signum, frame):
    raise TimeoutError("evidence ownership handoff exceeded 60 seconds")

signal.signal(signal.SIGALRM, deadline)
signal.alarm(60)
uid, gid = map(int, sys.argv[1:3])
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

def handoff(directory):
    with os.scandir(directory) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name, flags, dir_fd=directory)
                try:
                    handoff(child)
                finally:
                    os.close(child)
            else:
                if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                    raise RuntimeError("refusing special-file evidence: " + entry.name)
                if info.st_nlink != 1:
                    raise RuntimeError("refusing hard-linked evidence: " + entry.name)
                os.chown(entry.name, uid, gid, dir_fd=directory, follow_symlinks=False)
    os.fchown(directory, uid, gid)

for root in sys.argv[3:]:
    directory = os.open(root, flags)
    try:
        handoff(directory)
    finally:
        os.close(directory)
PY
}

# A helper is necessary after an exited/OOMKilled workload: docker exec cannot run.
# It has no source/binary mount and is tracked before creation, including failures.
remove_owned_handoff() {
    if [ "$HANDOFF_OWNED" != 1 ]; then
        return 0
    fi
    if ! handoff_owner=$(docker container inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$HANDOFF_CONTAINER" 2>/dev/null); then
        confirm_absent "$HANDOFF_CONTAINER" container ls -a --filter "name=^/$HANDOFF_CONTAINER$" || return 1
    else
        if [ "$handoff_owner" != "$OWNER" ]; then
            echo "ERROR: refusing to remove handoff container owned by another run: $HANDOFF_CONTAINER" >&2
            return 1
        fi
        docker rm -f "$HANDOFF_CONTAINER" >>"$OUT/cleanup.log" 2>&1 || return 1
        confirm_absent "$HANDOFF_CONTAINER" container ls -a --filter "name=^/$HANDOFF_CONTAINER$" || return 1
    fi
    HANDOFF_OWNED=0
}

normalize_evidence() {
    if [ "$EVIDENCE_DIRTY" != 1 ]; then
        return 0
    fi
    if [ "$EVIDENCE_QUIESCENT" != 1 ]; then
        echo "ERROR: refusing evidence handoff without proof the workload exited or was removed" >&2
        return 1
    fi
    if [ "$HANDOFF_OWNED" = 1 ]; then
        echo "ERROR: previous evidence handoff container was not removed" >&2
        return 1
    fi
    if docker container inspect "$HANDOFF_CONTAINER" >/dev/null 2>&1; then
        echo "ERROR: handoff container name collision: $HANDOFF_CONTAINER" >&2
        return 1
    fi
    set --
    for tree in results container-tmp; do
        if [ -L "$OUT/$tree" ]; then
            echo "ERROR: refusing symlink evidence root: $OUT/$tree" >&2
            return 1
        fi
        if [ -d "$OUT/$tree" ]; then
            set -- "$@" --mount "type=bind,src=$OUT/$tree,dst=/evidence/$tree"
        fi
    done
    HANDOFF_OWNED=1
    handoff_status=0
    docker create --name "$HANDOFF_CONTAINER" --label "keenproxy.memory.owner=$OWNER" \
        --network none --read-only --user 0:0 --pids-limit 32 --memory 128m --memory-swap 128m \
        --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE \
        --security-opt no-new-privileges --entrypoint python3 \
        "$@" "$IMAGE_ID" -B -c "$(evidence_handoff_script)" "$HOST_UID" "$HOST_GID" \
        /evidence/results /evidence/container-tmp >>"$OUT/cleanup.log" 2>&1 || handoff_status=$?
    if [ "$handoff_status" = 0 ]; then
        docker start -a "$HANDOFF_CONTAINER" >>"$OUT/cleanup.log" 2>&1 || handoff_status=$?
    fi
    if [ "$handoff_status" = 0 ]; then
        docker inspect --format '{{json .State}}' "$HANDOFF_CONTAINER" \
            >"$OUT/handoff.state.json" 2>>"$OUT/cleanup.log" || handoff_status=$?
    fi
    if [ "$handoff_status" = 0 ]; then
        python3 - "$OUT/handoff.state.json" >>"$OUT/cleanup.log" 2>&1 <<'PY' || handoff_status=$?
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text())
if (state.get("Status") != "exited" or state.get("OOMKilled") is not False
        or type(state.get("ExitCode")) is not int or state["ExitCode"] != 0):
    raise SystemExit("evidence handoff did not exit successfully: " + repr(state))
PY
    fi
    if ! remove_owned_handoff; then
        handoff_status=1
    fi
    if [ "$handoff_status" != 0 ]; then
        echo "ERROR: evidence ownership handoff failed; see $OUT/cleanup.log" >&2
        return 1
    fi
    EVIDENCE_DIRTY=0
}

# Register cleanup before creating any Docker resource.
# Host evidence is kept. An owned container and image are always removed;
# a failed /tmp copy is reported and does not keep the container alive.
remove_owned_container() {
    EVIDENCE_QUIESCENT=0
    if ! owner=$(docker container inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$CONTAINER" 2>/dev/null); then
        if confirm_absent "$CONTAINER" container ls -a --filter "name=^/$CONTAINER$"; then
            CONTAINER_OWNED=0
            EVIDENCE_QUIESCENT=1
        else
            cleanup_status=1
        fi
        return 0
    fi
    if [ "$owner" != "$OWNER" ]; then
        echo "ERROR: refusing to remove container owned by another run: $CONTAINER" >&2
        cleanup_status=1
        return 0
    fi
    docker stop --time 20 "$CONTAINER" >>"$OUT/cleanup.log" 2>&1 || cleanup_status=1
    EVIDENCE_DIRTY=1
    mkdir -p "$OUT/container-tmp" || cleanup_status=1
    if ! docker cp "$CONTAINER:/tmp/." "$OUT/container-tmp" >>"$OUT/cleanup.log" 2>&1; then
        echo "ERROR: artifact rescue failed for $CONTAINER; in-container /tmp was not copied. Host evidence remains at $OUT. Removing the owned container." >&2
        echo "artifact rescue failed; removing owned container without /tmp copy" >>"$OUT/cleanup.log" || true
        cleanup_status=1
    fi
    docker rm -f "$CONTAINER" >>"$OUT/cleanup.log" 2>&1 || cleanup_status=1
    if confirm_absent "$CONTAINER" container ls -a --filter "name=^/$CONTAINER$"; then
        CONTAINER_OWNED=0
        EVIDENCE_QUIESCENT=1
    else
        cleanup_status=1
    fi
}

remove_owned_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        confirm_absent "$IMAGE" image ls --filter "reference=$IMAGE:latest" || cleanup_status=1
        return 0
    fi
    owner=$(docker image inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$IMAGE" 2>/dev/null) || owner=
    id=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null) || id=
    if [ "$owner" != "$OWNER" ]; then
        echo "ERROR: refusing to remove image without our owner label: $IMAGE" >&2
        cleanup_status=1
        return 0
    fi
    if [ -n "$IMAGE_ID" ] && [ "$id" != "$IMAGE_ID" ]; then
        echo "ERROR: refusing to remove retagged image: $IMAGE" >&2
        cleanup_status=1
        return 0
    fi
    docker image rm "$IMAGE" >>"$OUT/cleanup.log" 2>&1 || cleanup_status=1
    confirm_absent "$IMAGE" image ls --filter "reference=$IMAGE:latest" || cleanup_status=1
}

cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    cleanup_status=0
    if [ "$CONTAINER_OWNED" = 1 ]; then
        remove_owned_container
    fi
    remove_owned_handoff || cleanup_status=1
    normalize_evidence || cleanup_status=1
    if [ "$IMAGE_OWNED" = 1 ]; then
        remove_owned_image
    fi
    if [ "$result" = 0 ] && [ "$cleanup_status" != 0 ]; then
        result=$cleanup_status
    fi
    printf '%s\n' "$result" >"$OUT/exit-code"
    if [ "$MODE" = stress ]; then
        printf 'AWG stress evidence: %s\n' "$OUT"
    else
        printf 'Memory gate evidence: %s\n' "$OUT"
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

build() {
    source=$1
    tags=$2
    output=$3
    (cd "$source" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOTOOLCHAIN="$TOOLCHAIN" \
        go build -buildvcs=false -trimpath -tags "$tags" -ldflags '-s -w -buildid=' \
        -o "$output" ./cmd/keenproxy)
}

claim_container() {
    if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
        fail "container name collision: $CONTAINER"
    fi
    CONTAINER_OWNED=1
    EVIDENCE_QUIESCENT=0
}

# Saved success from docker start is insufficient: recheck immediately before handoff.
# Cleanup instead requires positive removal proof, even if stop or rm failed.
confirm_workload_exited() {
    EVIDENCE_QUIESCENT=0
    if ! workload_state=$(docker container inspect --format '{{.State.Status}} {{.State.Running}}' "$CONTAINER"); then
        echo "ERROR: cannot confirm workload quiescence: $CONTAINER" >&2
        return 1
    fi
    if [ "$workload_state" != 'exited false' ]; then
        echo "ERROR: refusing evidence handoff for unconfirmed exited workload: $workload_state" >&2
        return 1
    fi
    EVIDENCE_QUIESCENT=1
}

release_container() {
    if ! owner=$(docker container inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$CONTAINER" 2>/dev/null); then
        echo "ERROR: cannot confirm owner before removal: $CONTAINER" >&2
        exit 1
    fi
    if [ "$owner" != "$OWNER" ]; then
        echo "ERROR: refusing to remove container owned by another run: $CONTAINER" >&2
        exit 1
    fi
    confirm_workload_exited || fail "cannot release container without workload quiescence proof"
    normalize_evidence || fail "cannot release container before evidence ownership handoff"
    docker rm "$CONTAINER" >>"$OUT/cleanup.log" 2>&1 || fail "container removal failed: $CONTAINER"
    confirm_absent "$CONTAINER" container ls -a --filter "name=^/$CONTAINER$" || exit 1
    CONTAINER_OWNED=0
}

# Saved State is the finish proof. A zero docker start status is not success.
prove_container_finished() {
    proof=$1
    label=$2
    cli_status=$3
    mkdir -p "$(dirname "$proof")"
    if ! docker inspect --format '{{json .State}}' "$CONTAINER" >"$proof"; then
        echo "ERROR: cannot read container state for $label: $CONTAINER" >&2
        exit 1
    fi
    parsed=$(python3 - "$proof" <<'PY'
import json
import sys
from pathlib import Path
try:
    state = json.loads(Path(sys.argv[1]).read_text())
except json.JSONDecodeError:
    raise SystemExit(2)
exit_code = state.get("ExitCode")
oom = state.get("OOMKilled")
status = state.get("Status")
if not isinstance(exit_code, int) or isinstance(exit_code, bool) or not isinstance(oom, bool) or not isinstance(status, str):
    raise SystemExit(3)
print("%s %s %s" % (exit_code, "true" if oom else "false", status))
PY
    ) || {
        echo "ERROR: container state proof is unusable for $label: $proof" >&2
        exit 1
    }
    exit_code=${parsed%% *}
    rest=${parsed#* }
    oom=${rest%% *}
    run_status=${rest#* }
    if [ "$oom" = true ]; then
        echo "ERROR: $label was OOMKilled (docker start status $cli_status); see $proof" >&2
        exit 1
    fi
    if [ "$run_status" != exited ]; then
        echo "ERROR: $label did not finish (Status=$run_status, docker start status $cli_status); see $proof" >&2
        exit 1
    fi
    if [ "$exit_code" != 0 ]; then
        echo "ERROR: $label ExitCode=$exit_code (docker start status $cli_status); see $proof" >&2
        exit 1
    fi
    if [ "$cli_status" != 0 ]; then
        echo "ERROR: $label docker start returned $cli_status while State.ExitCode=0; see $proof" >&2
        exit 1
    fi
}

for tool in docker go git python3 make; do
    command -v "$tool" >/dev/null || fail "required tool unavailable: $tool"
done
ARCH=$(docker info --format '{{.Architecture}}')
case "$ARCH" in
    aarch64|arm64) GOARCH=arm64 ;;
    x86_64|amd64) GOARCH=amd64 ;;
    *) fail "unsupported Docker architecture: $ARCH" ;;
esac
make --no-print-directory -s -C "$ROOT" memory-build-settings >"$OUT/build-settings.txt"
{
    IFS= read -r CANDIDATE_TAGS || fail "candidate build tags are missing"
    IFS= read -r TOOLCHAIN || fail "candidate Go version is missing"
    if IFS= read -r extra || [ -n "${extra:-}" ]; then
        fail "unexpected memory build settings output"
    fi
} <"$OUT/build-settings.txt"
[ -n "$CANDIDATE_TAGS" ] || fail "candidate build tags are empty"
case "$TOOLCHAIN" in
    go[0-9]*) ;;
    *) fail "invalid candidate Go version: $TOOLCHAIN" ;;
esac
if [ "$MODE" = compare ]; then
    git -C "$ROOT" cat-file -e "$BASELINE^{commit}" || fail "fixed baseline missing; fetch repository history before running the gate"
fi

mkdir -p "$OUT/bin"
if [ "$MODE" = compare ]; then
    mkdir -p "$OUT/source" "$OUT/results/baseline" "$OUT/results/candidate"
    git -C "$ROOT" archive "$BASELINE" >"$OUT/baseline.tar"
    tar -xf "$OUT/baseline.tar" -C "$OUT/source"
    rm "$OUT/baseline.tar"
else
    mkdir -p "$OUT/results/stress"
    # Fail before weakening affinity. Do not drop --cpus or --cpuset-cpus.
    NCPU=$(docker info --format '{{.NCPU}}')
    case "$NCPU" in
        ''|*[!0-9]*) fail "Docker engine CPU count is not a number: ${NCPU:-empty}" ;;
    esac
    if [ "$NCPU" -lt 2 ]; then
        fail "AWG stress requires a Docker engine with at least 2 CPUs, got $NCPU; refusing to weaken affinity or quota"
    fi
fi
# One immutable fixture revision for every scenario in this run.
cp -R "$ROOT/test/memory" "$OUT/fixture"
if [ "$MODE" = stress ] && [ ! -f "$OUT/fixture/stress.py" ]; then
    fail "immutable fixture is missing stress.py"
fi

if [ "$MODE" = compare ]; then
    {
        printf 'baseline=%s\ncandidate=%s\n' "$BASELINE" "$(git -C "$ROOT" rev-parse HEAD)"
        printf 'toolchain=%s\nGOOS=linux\nGOARCH=%s\n' "$TOOLCHAIN" "$GOARCH"
        printf 'baseline_tags=%s\ncandidate_tags=%s\n' "$BASE_TAGS" "$CANDIDATE_TAGS"
        printf 'ui_assets=excluded\nrepetitions=3\n'
    } >"$OUT/manifest.txt"
    binary_names="baseline candidate sbserver"
else
    {
        printf 'mode=stress\nbaseline=not_built\ncandidate=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
        printf 'toolchain=%s\nGOOS=linux\nGOARCH=%s\n' "$TOOLCHAIN" "$GOARCH"
        printf 'candidate_tags=%s\nui_assets=excluded\n' "$CANDIDATE_TAGS"
        printf 'engine_ncpu=%s\nmemory_bytes=%s\nmemory_swap_bytes=%s\n' "$NCPU" "$STRESS_MEMORY" "$STRESS_MEMORY"
        printf 'cpus=2\ncpuset_cpus=0-1\nparent_gomaxprocs=2\nparent_gogc=100\nparent_gomemlimit=off\n'
    } >"$OUT/manifest.txt"
    binary_names="candidate sbserver"
fi

if [ "$MODE" = compare ]; then
    build "$OUT/source" "$BASE_TAGS" "$OUT/bin/baseline" >"$OUT/baseline-build.log" 2>&1
fi
build "$ROOT" "$CANDIDATE_TAGS" "$OUT/bin/candidate" >"$OUT/candidate-build.log" 2>&1
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOTOOLCHAIN="$TOOLCHAIN" \
    go build -buildvcs=false -trimpath -tags "$CANDIDATE_TAGS" \
    -o "$OUT/bin/sbserver" ./test/netns/sbserver) >"$OUT/server-build.log" 2>&1
for binary in $binary_names; do
    go version -m "$OUT/bin/$binary" >"$OUT/$binary-build-info.txt"
done
python3 - "$OUT" $binary_names <<'PY'
import hashlib
import sys
from pathlib import Path
root = Path(sys.argv[1])
with (root / 'manifest.txt').open('a') as manifest:
    for binary in sys.argv[2:]:
        digest = hashlib.sha256((root / 'bin' / binary).read_bytes()).hexdigest()
        manifest.write(f'{binary}_sha256={digest}\n')
    for path in sorted((root / 'fixture').iterdir()):
        if path.is_file():
            manifest.write(f'fixture_{path.name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}\n')
PY

if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    fail "image tag collision: $IMAGE"
fi
# The unique tag is ours even if a build fails after tagging its final layer.
IMAGE_OWNED=1
docker build --label "keenproxy.memory.owner=$OWNER" -t "$IMAGE" "$OUT/fixture" >"$OUT/image-build.log" 2>&1
IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE") || fail "built image is not inspectable: $IMAGE"
image_owner=$(docker image inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$IMAGE") || fail "built image label is not inspectable: $IMAGE"
if [ "$image_owner" != "$OWNER" ]; then
    fail "built image owner label mismatch: $IMAGE"
fi
printf '%s\nimage_owner=%s\n' "$IMAGE_ID" "$image_owner" >>"$OUT/manifest.txt"

verify_stress_container() {
    mem=$(docker inspect --format '{{.HostConfig.Memory}}' "$CONTAINER")
    swap=$(docker inspect --format '{{.HostConfig.MemorySwap}}' "$CONTAINER")
    nano=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$CONTAINER")
    cpuset=$(docker inspect --format '{{.HostConfig.CpusetCpus}}' "$CONTAINER")
    network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$CONTAINER")
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$CONTAINER")
    entry=$(docker inspect --format '{{.Config.Entrypoint}}' "$CONTAINER")
    cmd=$(docker inspect --format '{{.Config.Cmd}}' "$CONTAINER")
    owner=$(docker inspect --format '{{ index .Config.Labels "keenproxy.memory.owner" }}' "$CONTAINER")
    env_dump=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER")
    if [ "$mem" != "$STRESS_MEMORY" ] || [ "$swap" != "$STRESS_MEMORY" ]; then
        fail "stress memory limits were not applied: memory=$mem swap=$swap expected=$STRESS_MEMORY"
    fi
    if [ "$nano" != 2000000000 ] || [ "$cpuset" != "0-1" ]; then
        fail "stress CPU quota or affinity was not applied: nanocpus=$nano cpuset=$cpuset"
    fi
    if [ "$network" != none ] || [ "$privileged" != true ]; then
        fail "stress network or privilege was not applied: network=$network privileged=$privileged"
    fi
    if [ "$owner" != "$OWNER" ]; then
        fail "stress container owner label mismatch"
    fi
    case "$entry" in
        *python3*) ;;
        *) fail "stress entrypoint was not applied: $entry" ;;
    esac
    case "$cmd" in
        *'/fixture/stress.py'*'/binaries/candidate'*'/binaries/sbserver'*'/results/stress.json'*) ;;
        *) fail "stress command was not applied: $cmd" ;;
    esac
    printf '%s\n' "$env_dump" | grep -Fx 'GOMAXPROCS=2' >/dev/null || fail "parent GOMAXPROCS=2 was not applied"
    printf '%s\n' "$env_dump" | grep -Fx 'GOGC=100' >/dev/null || fail "parent GOGC=100 was not applied"
    printf '%s\n' "$env_dump" | grep -Fx 'GOMEMLIMIT=off' >/dev/null || fail "parent GOMEMLIMIT=off was not applied"
    if printf '%s\n' "$env_dump" | grep -F 'GOMEMLIMIT=320' >/dev/null; then
        fail "parent GOMEMLIMIT must stay off; 320MiB is only for the measured daemon"
    fi
    {
        printf 'actual_memory=%s\nactual_memory_swap=%s\n' "$mem" "$swap"
        printf 'actual_nanocpus=%s\nactual_cpuset=%s\n' "$nano" "$cpuset"
        printf 'actual_network=%s\nactual_privileged=%s\n' "$network" "$privileged"
    } >>"$OUT/manifest.txt"
}

run_stress() {
    claim_container
    EVIDENCE_DIRTY=1
    mkdir -p "$OUT/container-tmp"
    # Image entrypoint is scenario.py; this mode must not run the comparison fixture.
    docker create --name "$CONTAINER" --label "keenproxy.memory.owner=$OWNER" \
        --network none --privileged \
        --memory "$STRESS_MEMORY" --memory-swap "$STRESS_MEMORY" \
        --cpus 2 --cpuset-cpus 0-1 \
        -e GOMAXPROCS=2 -e GOGC=100 -e GOMEMLIMIT=off \
        --entrypoint python3 \
        -v "$OUT/bin:/binaries:ro" -v "$OUT/fixture:/fixture:ro" \
        -v "$OUT/results/stress:/results" "$IMAGE" \
        -B /fixture/stress.py \
        --binary /binaries/candidate --server /binaries/sbserver \
        --output /results/stress.json >"$OUT/create.log"
    verify_stress_container
    status=0
    docker start -a "$CONTAINER" >"$OUT/results/stress/stress.log" 2>&1 || status=$?
    prove_container_finished "$OUT/results/stress/stress.state.json" "AWG stress" "$status"
    if [ ! -s "$OUT/results/stress/stress.json" ]; then
        echo "ERROR: AWG stress exited 0 without a result file; see $OUT" >&2
        exit 1
    fi
    release_container
}

scenario() {
    variant=$1
    protocol=$2
    run=$3
    filename=$protocol-$run
    claim_container
    EVIDENCE_DIRTY=1
    mkdir -p "$OUT/container-tmp"
    docker create --name "$CONTAINER" --label "keenproxy.memory.owner=$OWNER" \
        --network none --privileged --memory 1g --cpus 2 \
        -e GOMAXPROCS=2 -e GOGC=100 -e GOMEMLIMIT=off \
        -v "$OUT/bin:/binaries:ro" -v "$OUT/fixture:/fixture:ro" \
        -v "$OUT/results/$variant:/results" "$IMAGE" \
        --binary "/binaries/$variant" --server /binaries/sbserver \
        --scenario "$protocol" --variant "$variant" --run "$run" \
        --output "/results/$filename.json" >"$OUT/create.log"
    status=0
    docker start -a "$CONTAINER" >"$OUT/results/$variant/$filename.log" 2>&1 || status=$?
    prove_container_finished "$OUT/results/container-state/$variant/$filename.state.json" "$variant $protocol run $run" "$status"
    release_container
}

if [ "$MODE" = stress ]; then
    run_stress
    exit 0
fi

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
