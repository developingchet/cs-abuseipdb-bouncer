#!/usr/bin/env bash
# validate-seccomp.sh — static validation for security/seccomp-bouncer.json
#
# Verifies that:
#   1. The file is valid JSON.
#   2. defaultAction is a deny-by-default action (not SCMP_ACT_ALLOW).
#   3. Every syscall known to be required by runc, the Go runtime, bbolt,
#      and the bouncer's network I/O is present in an SCMP_ACT_ALLOW rule.
#
# Usage:
#   bash scripts/validate-seccomp.sh [path/to/seccomp.json]
#
# Requires: jq

set -euo pipefail

PROFILE="${1:-./security/seccomp-bouncer.json}"

# ── Required syscalls ──────────────────────────────────────────────────────
# Keep this list in sync with the profile. Every entry here is a MUST-HAVE.
# Mark critical ones (would block container startup before the Go binary runs)
# with a comment so reviewers understand the blast radius of a removal.

REQUIRED_SYSCALLS=(
  # ── runc startup (CRITICAL — missing any of these crashes the container
  #    before the Go binary ever runs, producing "reopen exec fifo" errors)
  "statx"          # exec fifo magiclink safety check (mount ID)
  "prctl"          # runc process setup + Go runtime

  # ── File I/O
  "read"
  "write"
  "pread64"        # bbolt random-access page reads
  "pwrite64"       # bbolt random-access page writes
  "readv"          # Go runtime scatter I/O
  "writev"         # Go runtime scatter I/O
  "open"
  "openat"
  "openat2"
  "close"
  "stat"
  "fstat"
  "lstat"
  "fstatfs"
  "lseek"
  "fsync"          # bbolt write barrier
  "fdatasync"      # bbolt write barrier
  "ftruncate"      # bbolt file sizing
  "rename"
  "unlink"
  "mkdir"
  "access"
  "faccessat"
  "newfstatat"
  "getcwd"
  "fcntl"          # Go net + file descriptor ops
  "ioctl"          # Go net socket ioctls
  "flock"          # bbolt advisory file lock

  # ── Memory management
  "mmap"           # bbolt memory-mapped pages
  "mprotect"
  "munmap"
  "mremap"
  "madvise"
  "msync"          # bbolt mmap sync to disk
  "brk"

  # ── Network (TCP)
  "socket"
  "connect"
  "bind"
  "listen"
  "accept"
  "accept4"
  "getsockname"
  "getpeername"
  "setsockopt"
  "getsockopt"
  "sendto"
  "recvfrom"
  "sendmsg"
  "recvmsg"
  "shutdown"

  # ── I/O multiplexing
  "poll"
  "epoll_create1"
  "epoll_ctl"
  "epoll_pwait"
  "select"
  "pselect6"
  "pipe2"
  "eventfd2"

  # ── Threading and synchronisation
  "clone3"         # Go goroutine creation
  "futex"          # Go sync primitives
  "set_robust_list"
  "get_robust_list"
  "sched_yield"
  "sched_getaffinity"  # Go runtime GOMAXPROCS detection
  "tgkill"
  "rt_sigaction"
  "rt_sigprocmask"
  "rt_sigreturn"
  "sigaltstack"

  # ── Clock and time
  "clock_gettime"
  "clock_getres"
  "nanosleep"
  "clock_nanosleep"
  "gettimeofday"

  # ── Process
  "exit_group"
  "getpid"
  "gettid"
  "dup2"
  "dup3"
  "getrandom"      # Go crypto/rand
  "arch_prctl"     # Go runtime TLS setup (x86_64)
)

# ── Validation ─────────────────────────────────────────────────────────────

fail=0
missing=()

echo "Profile : $PROFILE"
echo "Syscalls: ${#REQUIRED_SYSCALLS[@]} required"
echo ""

# 1. Valid JSON
if ! jq empty "$PROFILE" 2>/dev/null; then
  echo "FAIL  invalid JSON"
  exit 1
fi
echo "OK    valid JSON"

# 2. defaultAction must be deny-by-default
default_action=$(jq -r '.defaultAction' "$PROFILE")
case "$default_action" in
  SCMP_ACT_ERRNO|SCMP_ACT_KILL|SCMP_ACT_KILL_PROCESS|SCMP_ACT_KILL_THREAD)
    echo "OK    defaultAction = $default_action"
    ;;
  *)
    echo "FAIL  defaultAction is '$default_action' — must be SCMP_ACT_ERRNO or SCMP_ACT_KILL*"
    fail=1
    ;;
esac

# 3. Every required syscall must be present in an SCMP_ACT_ALLOW rule
allowed_syscalls=$(jq -r '
  .syscalls[]
  | select(.action == "SCMP_ACT_ALLOW")
  | .names[]
' "$PROFILE")

for syscall in "${REQUIRED_SYSCALLS[@]}"; do
  if ! echo "$allowed_syscalls" | grep -qx "$syscall"; then
    missing+=("$syscall")
    fail=1
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "FAIL  missing ${#missing[@]} required syscall(s):"
  for s in "${missing[@]}"; do
    echo "        - $s"
  done
else
  echo "OK    all ${#REQUIRED_SYSCALLS[@]} required syscalls present"
fi

echo ""
if [[ $fail -eq 0 ]]; then
  echo "PASS"
  exit 0
else
  echo "FAIL"
  exit 1
fi
