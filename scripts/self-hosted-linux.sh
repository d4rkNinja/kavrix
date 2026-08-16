#!/usr/bin/env bash
#
# Kavrix self-hosted Linux pipeline.
#
# One script for a Linux machine that acts as the project's CI box: it installs
# whatever is missing, fast-forwards the checkout, builds, runs the full gate,
# and — only when every gate passed and only when asked — pushes the branch.
#
# The pinned versions are read out of the repository, never retyped here:
#   Node        .nvmrc
#   pnpm        package.json "packageManager"
#   MongoDB     .github/workflows/ci.yml (image digest and connection URI)
# A pin that exists in two places drifts. If a parse below fails the script
# stops rather than guessing a version, because a gate that runs on the wrong
# runtime is worse than a gate that refuses to run.
#
# Usage:
#   scripts/self-hosted-linux.sh [command] [options]
#
# Commands:
#   all        bootstrap, then pipeline   (default)
#   bootstrap  install missing prerequisites only
#   pipeline   pull, install, build, and run the full gate
#   runner     register this machine as a GitHub Actions self-hosted runner
#
# Options:
#   --push          push the current branch after every gate passes
#   --allow-main    permit --push while on main (default: refuse)
#   --no-pull       build the working tree as-is, without fast-forwarding
#   --skip-mongo    skip the MongoDB replica-set integration and coverage stage
#   --branch NAME   check out NAME before building
#   --labels LIST   extra runner labels, comma separated (runner command)
#   -h, --help      print this help
#
# Why --push is opt-in: a script that pushes every time it succeeds will one day
# push something you did not mean to publish. One flag is cheap; an unintended
# push to a shared branch is not.

set -euo pipefail

readonly SCRIPT_NAME="${0##*/}"

COMMAND='all'
DO_PUSH=0
ALLOW_MAIN=0
DO_PULL=1
SKIP_MONGO=0
TARGET_BRANCH=''
EXTRA_LABELS=''

# Populated by resolve_pins.
NODE_VERSION=''
PNPM_VERSION=''
MONGO_IMAGE=''
MONGO_URI=''
NODE_ARCH=''
RUNNER_ARCH=''

REPO_ROOT=''
LOG_FILE=''
MONGO_CONTAINER='kavrix-mongodb'
declare -a STAGE_REPORT=()

# ---------------------------------------------------------------------------
# Output helpers. Never `set -x`: this script handles a runner registration
# token, and tracing would put it in the log.
# ---------------------------------------------------------------------------

log() { printf '\n== %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '   warning: %s\n' "$*" >&2; }

die() {
  printf '\n%s: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

# Print the header comment, stopping at the first line that is not one, so the
# help text cannot drift out of sync with a line number.
usage() {
  awk 'NR > 2 && /^#/ { sub(/^#[[:space:]]?/, ""); print; next } NR > 2 { exit }' "$0"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Run a command with root privileges, or explain precisely what is missing.
as_root() {
  if [[ "$(id -u)" == '0' ]]; then
    "$@"
  elif have sudo; then
    sudo --non-interactive true 2>/dev/null || info "sudo password required for: $*"
    sudo "$@"
  else
    die "need root to run '$*' but neither root nor sudo is available"
  fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_arguments() {
  if [[ $# -gt 0 ]]; then
    case "$1" in
      all | bootstrap | pipeline | runner)
        COMMAND="$1"
        shift
        ;;
      -* | '') ;;
      *) die "unknown command '$1' (try --help)" ;;
    esac
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --push) DO_PUSH=1 ;;
      --allow-main) ALLOW_MAIN=1 ;;
      --no-pull) DO_PULL=0 ;;
      --skip-mongo) SKIP_MONGO=1 ;;
      --branch)
        [[ $# -ge 2 ]] || die '--branch requires a name'
        TARGET_BRANCH="$2"
        shift
        ;;
      --labels)
        [[ $# -ge 2 ]] || die '--labels requires a comma separated list'
        EXTRA_LABELS="$2"
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown option '$1' (try --help)" ;;
    esac
    shift
  done
}

# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------

require_linux() {
  [[ "$(uname -s)" == 'Linux' ]] || die "this script targets Linux; found $(uname -s)"

  case "$(uname -m)" in
    x86_64 | amd64)
      NODE_ARCH='x64'
      RUNNER_ARCH='x64'
      ;;
    aarch64 | arm64)
      NODE_ARCH='arm64'
      RUNNER_ARCH='arm64'
      ;;
    *) die "unsupported architecture $(uname -m); CI covers x64 and arm64" ;;
  esac
}

locate_repository() {
  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd -- "$script_dir/.." && pwd)"

  [[ -f "$REPO_ROOT/package.json" ]] || die "no package.json at $REPO_ROOT"
  [[ -d "$REPO_ROOT/.git" ]] || die "$REPO_ROOT is not a git checkout"
  cd -- "$REPO_ROOT"
}

start_logging() {
  local log_dir="$REPO_ROOT/logs"
  mkdir -p -- "$log_dir"
  LOG_FILE="$log_dir/$(date -u '+%Y%m%dT%H%M%SZ')-$COMMAND.log"
  # *.log is already ignored by .gitignore, so nothing here can be committed.
  exec > >(tee -a -- "$LOG_FILE") 2>&1
  log "Kavrix self-hosted Linux pipeline: $COMMAND"
  info "repository $REPO_ROOT"
  info "log        $LOG_FILE"
}

# Read one pinned value out of the repository, failing closed on no match.
read_pin() {
  local description="$1" file="$2" expression="$3" value
  [[ -f "$file" ]] || die "cannot read $description: $file is missing"
  value="$(sed -n -e "$expression" -- "$file" | head -n 1)"
  [[ -n "$value" ]] || die "cannot parse $description out of $file"
  printf '%s' "$value"
}

resolve_pins() {
  NODE_VERSION="$(read_pin 'the Node version' '.nvmrc' 's/^[[:space:]]*\([0-9][0-9.]*\)[[:space:]]*$/\1/p')"
  PNPM_VERSION="$(read_pin 'the pnpm version' 'package.json' \
    's/.*"packageManager"[[:space:]]*:[[:space:]]*"pnpm@\([^"]*\)".*/\1/p')"
  MONGO_IMAGE="$(read_pin 'the MongoDB image' '.github/workflows/ci.yml' \
    "s|.*image='\\(docker\\.io/library/mongo@sha256:[0-9a-f]\\{64\\}\\)'.*|\\1|p")"
  MONGO_URI="$(read_pin 'the MongoDB URI' '.github/workflows/ci.yml' \
    's|^[[:space:]]*KAVRIX_MONGODB_URI:[[:space:]]*\(mongodb://.*\)$|\1|p')"

  info "Node   $NODE_VERSION ($NODE_ARCH)"
  info "pnpm   $PNPM_VERSION"
  info "Mongo  ${MONGO_IMAGE##*@}"
}

# ---------------------------------------------------------------------------
# bootstrap: install what is missing, and only what is missing
# ---------------------------------------------------------------------------

detect_package_manager() {
  if have apt-get; then
    printf 'apt'
  elif have dnf; then
    printf 'dnf'
  elif have pacman; then
    printf 'pacman'
  elif have zypper; then
    printf 'zypper'
  else
    printf 'unknown'
  fi
}

install_system_packages() {
  local manager="$1"
  shift
  [[ $# -gt 0 ]] || return 0

  info "installing: $*"
  case "$manager" in
    apt)
      as_root env DEBIAN_FRONTEND=noninteractive apt-get update
      as_root env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$@"
      ;;
    dnf) as_root dnf install --assumeyes "$@" ;;
    pacman) as_root pacman -Sy --needed --noconfirm "$@" ;;
    zypper) as_root zypper --non-interactive install "$@" ;;
    *) die "no supported package manager found; install these by hand: $*" ;;
  esac
}

ensure_base_tools() {
  log 'Base tools'
  local manager missing=()
  manager="$(detect_package_manager)"

  # command -> package name, per manager where the names differ.
  have git || missing+=('git')
  have curl || missing+=('curl')
  have tar || missing+=('tar')
  have sha256sum || missing+=('coreutils')

  if ! have xz; then
    case "$manager" in
      apt) missing+=('xz-utils') ;;
      *) missing+=('xz') ;;
    esac
  fi

  if [[ "$manager" == 'apt' ]]; then
    # Every download below pins --proto '=https', which needs a trust store.
    # The runner's own .NET dependencies (ICU and friends) are installed by its
    # bundled bin/installdependencies.sh, not from here.
    dpkg-query --show ca-certificates >/dev/null 2>&1 || missing+=('ca-certificates')
  fi

  if [[ ${#missing[@]} -eq 0 ]]; then
    info 'already present: git, curl, tar, xz, sha256sum'
  else
    install_system_packages "$manager" "${missing[@]}"
  fi
}

node_prefix() {
  printf '%s/.local/opt/node-v%s-linux-%s' "$HOME" "$NODE_VERSION" "$NODE_ARCH"
}

ensure_node() {
  log "Node $NODE_VERSION"
  local prefix
  prefix="$(node_prefix)"

  if [[ -x "$prefix/bin/node" ]]; then
    info "already installed at $prefix"
  elif have node && [[ "$(node --version)" == "v$NODE_VERSION" ]]; then
    info "system Node is already v$NODE_VERSION ($(command -v node))"
    return 0
  else
    local tarball="node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz"
    local base="https://nodejs.org/dist/v$NODE_VERSION"
    local work
    work="$(mktemp -d)"
    # shellcheck disable=SC2064 # expand work now, not at trap time
    trap "rm -rf -- '$work'" RETURN

    info "downloading $tarball"
    curl --fail --silent --show-error --location \
      --proto '=https' --tlsv1.2 \
      --output "$work/$tarball" "$base/$tarball"
    curl --fail --silent --show-error --location \
      --proto '=https' --tlsv1.2 \
      --output "$work/SHASUMS256.txt" "$base/SHASUMS256.txt"

    # This checks the archive against the checksum list the same origin served.
    # It proves the download was not corrupted or swapped in transit; it does
    # not prove authorship, which would need a named signing key and a
    # rotation policy this project has not decided on.
    info 'verifying SHA-256'
    (cd -- "$work" && grep -F -- " $tarball" SHASUMS256.txt | sha256sum --check --strict -) \
      || die "checksum verification failed for $tarball"

    mkdir -p -- "$(dirname -- "$prefix")"
    rm -rf -- "$prefix.partial"
    mkdir -p -- "$prefix.partial"
    tar -xJf "$work/$tarball" -C "$prefix.partial" --strip-components=1
    rm -rf -- "$prefix"
    mv -- "$prefix.partial" "$prefix"
    info "installed at $prefix"
  fi

  export PATH="$prefix/bin:$PATH"
  [[ "$(node --version)" == "v$NODE_VERSION" ]] \
    || die "expected Node v$NODE_VERSION on PATH, found $(node --version)"
}

ensure_pnpm() {
  log "pnpm $PNPM_VERSION"

  if have pnpm && [[ "$(pnpm --version)" == "$PNPM_VERSION" ]]; then
    info "already active ($(command -v pnpm))"
    return 0
  fi

  if have corepack; then
    corepack enable pnpm
    corepack prepare "pnpm@$PNPM_VERSION" --activate
  else
    # Corepack is unbundled from newer Node majors. Install into the Node
    # prefix this script owns, so nothing needs root.
    warn 'corepack is unavailable; installing pnpm with npm instead'
    npm install --global "pnpm@$PNPM_VERSION"
  fi

  have pnpm || die 'pnpm is still not on PATH after installation'
  [[ "$(pnpm --version)" == "$PNPM_VERSION" ]] \
    || die "expected pnpm $PNPM_VERSION, found $(pnpm --version)"
  info "active ($(command -v pnpm))"
}

# Docker is only needed for the MongoDB stage. Returns non-zero when the stage
# cannot run, so the caller can skip it loudly instead of failing the build.
ensure_docker() {
  log 'Docker (for the MongoDB replica set)'

  if ! have docker; then
    local manager package
    manager="$(detect_package_manager)"
    case "$manager" in
      apt) package='docker.io' ;;
      dnf | pacman | zypper) package='docker' ;;
      *)
        warn 'cannot install Docker automatically on this distribution'
        return 1
        ;;
    esac
    install_system_packages "$manager" "$package"
    as_root systemctl enable --now docker || warn 'could not enable the docker service'
  fi

  if ! docker info >/dev/null 2>&1; then
    if id -nG "$(id -un)" 2>/dev/null | tr ' ' '\n' | grep -qx 'docker'; then
      warn 'the docker daemon is not responding; is the service running?'
    else
      info "adding $(id -un) to the docker group"
      as_root usermod --append --groups docker "$(id -un)" \
        || warn 'could not modify group membership'
      warn 'group membership applies to new logins only'
      warn 'log out and back in (or run: newgrp docker), then re-run this script'
    fi
    return 1
  fi

  info "ready ($(docker --version))"
}

cmd_bootstrap() {
  ensure_base_tools
  ensure_node
  ensure_pnpm
  if [[ "$SKIP_MONGO" == '1' ]]; then
    info 'skipping Docker: --skip-mongo was given'
  elif ! ensure_docker; then
    SKIP_MONGO=1
    warn 'the MongoDB stage will be skipped this run'
  fi
}

# ---------------------------------------------------------------------------
# pipeline stages
# ---------------------------------------------------------------------------

record_stage() {
  STAGE_REPORT+=("$1|$2|$3")
}

# Run one named stage, timing it and reporting failure with its own name.
run_stage() {
  local name="$1"
  shift
  log "$name"
  local started elapsed
  started="$(date '+%s')"
  if "$@"; then
    elapsed="$(($(date '+%s') - started))"
    record_stage "$name" 'passed' "$elapsed"
    info "$name passed in ${elapsed}s"
  else
    elapsed="$(($(date '+%s') - started))"
    record_stage "$name" 'FAILED' "$elapsed"
    print_summary
    die "$name failed after ${elapsed}s (log: $LOG_FILE)"
  fi
}

stage_pull() {
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" != 'HEAD' ]] || die 'the checkout is detached; check out a branch first'

  if [[ -n "$TARGET_BRANCH" && "$TARGET_BRANCH" != "$branch" ]]; then
    git diff --quiet && git diff --cached --quiet \
      || die "refusing to switch to $TARGET_BRANCH with uncommitted changes"
    git fetch --prune origin
    # `switch` only ever resolves a branch, so a branch named like a path
    # cannot be mistaken for one.
    git switch "$TARGET_BRANCH"
    branch="$TARGET_BRANCH"
  fi

  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn 'the working tree has uncommitted changes; building them as they are'
    DO_PULL=0
  fi

  if [[ "$DO_PULL" == '0' ]]; then
    info "not pulling; building $branch at $(git rev-parse --short HEAD)"
    return 0
  fi

  git fetch --prune origin
  # --ff-only: a CI box must never invent a merge commit. If the branch has
  # diverged, that is a decision for a person to make.
  git pull --ff-only origin "$branch"
  info "$branch at $(git rev-parse --short HEAD)"
}

stage_install() { pnpm install --frozen-lockfile; }

stage_verify() {
  # pnpm verify is build + format:check + lint + typecheck + test, in that
  # order — the same gate CI runs. Expect roughly 10-15 minutes.
  pnpm verify
}

stage_package_smoke() { pnpm --filter kavrix --fail-if-no-match package:smoke; }

mongo_shell() {
  docker exec "$MONGO_CONTAINER" mongosh --quiet --eval "$1"
}

# Wait for a mongosh predicate, printing container logs when it never comes.
await_mongo() {
  local description="$1" expression="$2" attempt
  for attempt in $(seq 1 60); do
    if mongo_shell "$expression" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$attempt" == '60' ]]; then
      docker logs "$MONGO_CONTAINER" || true
      die "MongoDB never became $description"
    fi
    sleep 1
  done
}

stop_mongo() {
  docker rm --force "$MONGO_CONTAINER" >/dev/null 2>&1 || true
}

stage_mongo() {
  # Mirrors the mongo-integration job in ci.yml, including the pinned digest.
  # This is the only place repository coverage thresholds are enforced against
  # real adapters, so skipping it means coverage went unchecked — not that it
  # passed.
  info "pulling ${MONGO_IMAGE##*@}"
  docker pull "$MONGO_IMAGE"

  stop_mongo
  trap stop_mongo EXIT
  docker run --detach --name "$MONGO_CONTAINER" \
    --publish 127.0.0.1:27017:27017 \
    "$MONGO_IMAGE" --replSet rs0 --bind_ip_all >/dev/null

  await_mongo 'reachable' 'db.adminCommand({ping: 1}).ok'
  mongo_shell 'rs.initiate({_id:"rs0",members:[{_id:0,host:"127.0.0.1:27017"}]})' >/dev/null
  await_mongo 'a writable primary' 'if (!db.hello().isWritablePrimary) quit(1)'
  info 'replica set rs0 is primary'

  export KAVRIX_MONGODB_URI="$MONGO_URI"
  pnpm --filter @kavrix/storage --fail-if-no-match test:integration
  pnpm --filter @kavrix/api --fail-if-no-match test:integration
  pnpm operational:acceptance
  pnpm test:coverage

  stop_mongo
  trap - EXIT
}

stage_push() {
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"

  git diff --quiet && git diff --cached --quiet \
    || die 'refusing to push with uncommitted changes in the tree'

  if [[ "$branch" == 'main' && "$ALLOW_MAIN" != '1' ]]; then
    die 'refusing to push directly to main; open a pull request, or pass --allow-main'
  fi

  if git rev-parse --verify --quiet "origin/$branch" >/dev/null \
    && [[ -z "$(git log "origin/$branch..HEAD" --oneline)" ]]; then
    info "origin/$branch is already up to date; nothing to push"
    return 0
  fi

  # No --force, ever: this machine is not the authority on what the remote holds.
  git push origin "HEAD:refs/heads/$branch"
  info "pushed $branch ($(git rev-parse --short HEAD))"
}

print_summary() {
  log 'Summary'
  local entry name status seconds
  for entry in "${STAGE_REPORT[@]}"; do
    IFS='|' read -r name status seconds <<<"$entry"
    printf '   %-8s %5ss  %s\n' "$status" "$seconds" "$name"
  done
  info "log: $LOG_FILE"
}

cmd_pipeline() {
  run_stage 'Pull' stage_pull
  run_stage 'Install dependencies' stage_install
  run_stage 'Verify (build, format, lint, typecheck, test)' stage_verify
  run_stage 'Package smoke test' stage_package_smoke

  if [[ "$SKIP_MONGO" == '1' ]]; then
    record_stage 'MongoDB integration and coverage' 'SKIPPED' '0'
    warn 'MongoDB integration and coverage thresholds were not checked'
  else
    run_stage 'MongoDB integration and coverage' stage_mongo
  fi

  if [[ "$DO_PUSH" == '1' ]]; then
    run_stage 'Push' stage_push
  else
    record_stage 'Push' 'skipped' '0'
    info 'not pushing; pass --push to publish this branch'
  fi

  print_summary
}

# ---------------------------------------------------------------------------
# runner: register this machine with GitHub Actions
# ---------------------------------------------------------------------------

repository_slug() {
  local url
  url="$(git remote get-url origin)"
  url="${url%.git}"
  case "$url" in
    git@github.com:*) printf '%s' "${url#git@github.com:}" ;;
    https://github.com/*) printf '%s' "${url#https://github.com/}" ;;
    *) die "cannot derive a GitHub repository from origin: $url" ;;
  esac
}

cmd_runner() {
  log 'GitHub Actions self-hosted runner'

  # The runner refuses to configure itself as root, and running CI as root on a
  # machine that also holds your vault is not a trade worth making.
  [[ "$(id -u)" != '0' ]] || die 'do not register the runner as root; use an ordinary user'

  local slug labels runner_dir host
  slug="$(repository_slug)"
  labels="kavrix-linux"
  [[ -z "$EXTRA_LABELS" ]] || labels="$labels,$EXTRA_LABELS"
  runner_dir="$HOME/actions-runner"
  # `hostname --short` is GNU-only and absent from minimal images.
  host="${HOSTNAME:-$(uname -n)}"
  host="${host%%.*}"

  info "repository $slug"
  info "labels     self-hosted, Linux, $RUNNER_ARCH, $labels"
  info "directory  $runner_dir"

  if [[ -f "$runner_dir/.runner" ]]; then
    info 'this machine is already configured as a runner'
    info "to re-register: cd $runner_dir && sudo ./svc.sh uninstall && ./config.sh remove"
    return 0
  fi

  have gh || die 'the GitHub CLI (gh) is required to mint a registration token'
  gh auth status >/dev/null 2>&1 || die 'run: gh auth login'

  local version tarball url expected
  version="$(gh api 'repos/actions/runner/releases/latest' --jq '.tag_name')"
  version="${version#v}"
  [[ -n "$version" ]] || die 'could not determine the latest runner release'
  tarball="actions-runner-linux-$RUNNER_ARCH-$version.tar.gz"
  url="https://github.com/actions/runner/releases/download/v$version/$tarball"

  # GitHub publishes each asset's SHA-256 in the release notes. Fail closed if
  # it cannot be found rather than installing an unverified archive; the hash
  # can be supplied out of band with RUNNER_SHA256 if the notes change shape.
  expected="${RUNNER_SHA256:-}"
  if [[ -z "$expected" ]]; then
    expected="$(gh api "repos/actions/runner/releases/tags/v$version" --jq '.body' \
      | grep -F -- "$tarball" \
      | grep -o -E '[0-9a-f]{64}' \
      | head -n 1)"
  fi
  [[ -n "$expected" ]] \
    || die "no published SHA-256 for $tarball; re-run with RUNNER_SHA256=<hash>"

  mkdir -p -- "$runner_dir"
  if [[ ! -x "$runner_dir/config.sh" ]]; then
    info "downloading runner $version"
    curl --fail --silent --show-error --location \
      --proto '=https' --tlsv1.2 \
      --output "$runner_dir/$tarball" "$url"
    info 'verifying SHA-256'
    (cd -- "$runner_dir" && printf '%s  %s\n' "$expected" "$tarball" \
      | sha256sum --check --strict -) \
      || die "checksum verification failed for $tarball"
    tar -xzf "$runner_dir/$tarball" -C "$runner_dir"
    rm -f -- "$runner_dir/$tarball"
  fi

  if [[ -x "$runner_dir/bin/installdependencies.sh" ]]; then
    as_root "$runner_dir/bin/installdependencies.sh"
  fi

  # A registration token is a short-lived, single-use credential. It is minted
  # here and passed straight to config.sh, which accepts it only as an
  # argument — so it is briefly visible to `ps` on this machine. That is the
  # vendor's interface, not a choice; it expires in about an hour and cannot be
  # reused. Nothing writes it to the log.
  local token
  token="$(gh api --method POST "repos/$slug/actions/runners/registration-token" --jq '.token')"
  [[ -n "$token" ]] || die 'could not mint a runner registration token'

  (
    cd -- "$runner_dir"
    ./config.sh \
      --url "https://github.com/$slug" \
      --token "$token" \
      --name "$host-linux-$RUNNER_ARCH" \
      --labels "$labels" \
      --work '_work' \
      --unattended \
      --replace
  )
  unset token

  info 'installing the runner as a systemd service'
  (
    cd -- "$runner_dir"
    as_root ./svc.sh install "$(id -un)"
    as_root ./svc.sh start
    as_root ./svc.sh status || true
  )

  log 'Registered'
  info "confirm it reports Idle at https://github.com/$slug/settings/actions/runners"
  info 'then switch ci.yml to: runs-on: [self-hosted, linux, x64]'
}

# ---------------------------------------------------------------------------

main() {
  parse_arguments "$@"
  require_linux
  locate_repository
  start_logging
  resolve_pins

  case "$COMMAND" in
    bootstrap) cmd_bootstrap ;;
    pipeline) cmd_pipeline ;;
    runner) cmd_runner ;;
    all)
      cmd_bootstrap
      cmd_pipeline
      ;;
    *) die "unhandled command '$COMMAND'" ;;
  esac
}

main "$@"
