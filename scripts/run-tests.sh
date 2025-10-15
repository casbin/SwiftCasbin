#!/usr/bin/env bash

# Portable SwiftPM test runner with a hard timeout.
#
# Usage:
#   ./scripts/run-tests.sh [swift test args]
#
# Behavior:
# - Runs `swift test` in a fresh, unique build directory to avoid SwiftPM lockups.
# - Kills the entire test process group if it exceeds TIMEOUT_SECONDS (default 20s).
# - Works on macOS and Linux without requiring GNU timeout.
# - Pass-through of any additional `swift test` flags (e.g. `--filter`).
#
# Config (env vars):
#   TIMEOUT_SECONDS  Timeout in seconds (default: 20)
#   BUILD_ROOT       Directory for temp build dirs (default: project root)
#   BUILD_PATH       If set, use this exact build dir (reuses existing .build)
#   KEEP_BUILD_DIR   If set to 1, keep the temp build dir after run (debugging)

set -Eeuo pipefail

TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-20}"
KEEP_BUILD_DIR="${KEEP_BUILD_DIR:-0}"

# Resolve repository root (fallback to CWD if not a git repo)
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
else
  REPO_ROOT="$(pwd)"
fi

BUILD_ROOT="${BUILD_ROOT:-${REPO_ROOT}}"

# Decide build directory strategy.
# If BUILD_PATH is provided by caller, reuse it (often ".build").
# Otherwise create a unique path to avoid SwiftPM server lockups.
USER_BUILD_PATH="${BUILD_PATH:-}"
if [[ -n "${USER_BUILD_PATH}" ]]; then
  BUILD_PATH="${USER_BUILD_PATH%/}"
  mkdir -p "${BUILD_PATH}"
  CREATED_TEMP_BUILD_DIR=0
else
  BUILD_PATH="${BUILD_ROOT%/}/.build-tests-$(date +%s)-$$"
  mkdir -p "${BUILD_PATH}"
  CREATED_TEMP_BUILD_DIR=1
fi

cleanup() {
  # Best-effort cleanup of temp build artifacts unless explicitly kept
  # or when the user provided BUILD_PATH (we should not delete it).
  if [[ ${CREATED_TEMP_BUILD_DIR:-0} -eq 1 ]]; then
    if [[ "${KEEP_BUILD_DIR}" != "1" ]]; then
      rm -rf "${BUILD_PATH}" 2>/dev/null || true
    else
      echo "[run-tests] Keeping build dir at: ${BUILD_PATH}" >&2
    fi
  fi
}
trap cleanup EXIT INT TERM

CMD=(swift test --build-path "${BUILD_PATH}" --parallel)

# Pass-through any arguments given to this script to `swift test`.
if [[ $# -gt 0 ]]; then
  CMD+=("$@")
fi

echo "[run-tests] Running: ${CMD[*]}" >&2
echo "[run-tests] Timeout: ${TIMEOUT_SECONDS}s" >&2

# Prefer a Python-based timeout to reliably kill the whole process group.
run_with_python_timeout() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "$TIMEOUT_SECONDS" "${CMD[@]}" <<'PY'
import os, sys, subprocess, signal

timeout = int(sys.argv[1])
cmd = sys.argv[2:]

# Start in a new process group so we can kill children too.
proc = subprocess.Popen(cmd, preexec_fn=os.setsid)
try:
    rc = proc.wait(timeout=timeout)
    sys.exit(rc)
except subprocess.TimeoutExpired:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    print(f"[run-tests] Timeout after {timeout}s; terminated test run.", file=sys.stderr)
    sys.exit(124)
PY
}

# Fallback to GNU/BSD timeout if available.
run_with_coreutils_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 5 "${TIMEOUT_SECONDS}" "${CMD[@]}"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout -k 5 "${TIMEOUT_SECONDS}" "${CMD[@]}"
  else
    return 1
  fi
}

# Final fallback: pure Bash watchdog using process groups.
run_with_bash_watchdog() {
  set +e
  # Ensure background job gets its own process group (non-interactive bash needs `set -m`).
  # Turn it on just for spawning, then restore.
  set -m
  "${CMD[@]}" &
  child_pid=$!
  set +m

  # Discover process group id of the child; kill the whole group on timeout only.
  pgid="$(ps -o pgid= -p "$child_pid" | tr -d ' ')"

  # Flag file to detect whether timeout path executed; ensures exit 124 on timeout.
  timeout_flag="$(mktemp 2>/dev/null || echo "/tmp/run-tests.$$.$RANDOM.flag")"
  rm -f "$timeout_flag" 2>/dev/null || true

  (
    sleep "${TIMEOUT_SECONDS}"
    if kill -0 "$child_pid" 2>/dev/null; then
      echo "[run-tests] Timeout after ${TIMEOUT_SECONDS}s; terminating (pgid ${pgid:-?})..." >&2
      : > "$timeout_flag"
      if [[ -n "$pgid" ]]; then
        kill -TERM "-$(printf %d "$pgid")" 2>/dev/null || true
      else
        kill -TERM "$child_pid" 2>/dev/null || true
      fi
      sleep 5
      if kill -0 "$child_pid" 2>/dev/null; then
        echo "[run-tests] Forcing kill..." >&2
        if [[ -n "$pgid" ]]; then
          kill -KILL "-$(printf %d "$pgid")" 2>/dev/null || true
        else
          kill -KILL "$child_pid" 2>/dev/null || true
        fi
      fi
    fi
  ) &
  watchdog_pid=$!

  # Wait for the child; propagate its exit code.
  wait "$child_pid"
  rc=$?
  kill "$watchdog_pid" 2>/dev/null || true
  set -e
  if [[ -s "$timeout_flag" ]]; then
    rm -f "$timeout_flag" 2>/dev/null || true
    return 124
  fi
  rm -f "$timeout_flag" 2>/dev/null || true
  return "$rc"
}

# Choose a single strategy and run once; propagate its exit status.
if command -v python3 >/dev/null 2>&1; then
  run_with_python_timeout
  exit $?
elif command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1; then
  run_with_coreutils_timeout
  exit $?
else
  run_with_bash_watchdog
  exit $?
fi
