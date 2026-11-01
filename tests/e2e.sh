#!/bin/bash
# End-to-end tests against real binaries on this machine (Linux, macOS, WSL or
# Git Bash). Needs Go and Python 3. Run from anywhere:
#
#   tests/e2e.sh
#
# It builds the client, the relay, and a hostile test relay from a scratch copy
# of the repo, then checks:
#   A  an honest transfer works, and the relay never sees the password or
#      readable file data
#   B  a relay that flips a bit in transit is caught
#   C  a relay that flips a bit AND forges a matching checksum is caught
#   D  a wrong password delivers nothing
#   E  packs of small files, an empty file and resuming a killed download work
#
# Everything runs on 127.0.0.1 in a temporary folder that is removed at the end.
# Exit status is non-zero if any check fails.

set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
FAILED=0
PW="e2e-test-pass-123"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT

strip() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g'; }
ok()    { echo "  ok    $*"; }
fail()  { echo "  FAIL  $*"; FAILED=1; }

echo "building..."
mkdir -p "$WORK/bin" "$WORK/spy"
( cd "$REPO" && tar cf - --exclude=.git --exclude=dist . ) | ( cd "$WORK/spy" && tar xf - )
python3 "$REPO/tests/spy_patch.py" "$WORK/spy" > /dev/null || exit 1
export CGO_ENABLED=0
( cd "$REPO" && go build -o "$WORK/bin/strs" ./cmd/transfer && go build -o "$WORK/bin/relay" ./cmd/transferserver ) || exit 1
( cd "$WORK/spy" && go build -o "$WORK/bin/spyrelay" ./cmd/transferserver ) || exit 1

port=18600
# run <name> <relay> <spy-mode> <receiver-password> <with-small-files:1|0>
# leaves the test folder in $T and the receiver's exit code in $RC
run() {
  local name=$1 relay=$2 mode=$3 rpw=$4 small=$5
  port=$((port + 1))
  T="$WORK/$name"; mkdir -p "$T/src/sub" "$T/out" "$T/relay" "$T/h1" "$T/h2" "$T/spy"
  head -c 16777216 /dev/urandom > "$T/src/big.bin"
  if [ "$small" = 1 ]; then
    echo hello > "$T/src/a.txt"; head -c 5000 /dev/urandom > "$T/src/sub/b.dat"
  fi
  ( cd "$T/src" && find . -type f | sort | xargs sha256sum ) > "$T/src.sha"
  SPY_MODE=$mode SPY_PLAIN="$T/src/big.bin" SPY_DIR="$T/spy" \
    "$relay" -listen 127.0.0.1:$port -advertise 127.0.0.1:$port -state "$T/relay" -ttl 1h > "$T/relay.log" 2>&1 &
  RP=$!; sleep 1.5
  HOME="$T/h1" "$WORK/bin/strs" send -server 127.0.0.1:$port -dir "$T/src" -all -password "$PW" < /dev/null > "$T/send.log" 2>&1 &
  SP=$!
  for _ in $(seq 1 60); do strip < "$T/send.log" | grep -q -E '^ +pin ' && break; sleep 0.5; done
  PIN=$(strip < "$T/send.log" | grep -m1 -E '^ +pin ' | sed 's/.*: //')
  HOME="$T/h2" timeout 120 "$WORK/bin/strs" receive -server 127.0.0.1:$port -password "$rpw" -pin "$PIN" -out "$T/out" -all > "$T/recv.log" 2>&1
  RC=$?
  sleep 1
  ( cd "$T/out" && find . -type f -not -name '.strs*' -not -name '*receipt*' -not -name '*.part' | sort | xargs sha256sum 2>/dev/null ) > "$T/out.sha"
  kill $SP $RP 2>/dev/null; wait $SP $RP 2>/dev/null
}

echo "A. honest transfer through a recording relay"
run A "$WORK/bin/spyrelay" spy "$PW" 1
[ $RC -eq 0 ] && diff -q "$T/src.sha" "$T/out.sha" > /dev/null && ok "all files arrived intact" || fail "files did not arrive intact"
grep -q "$PW" "$T/spy/token.txt" && fail "the relay received the password" || ok "the relay never received the password"
first=$(head -c 32 "$T/src/big.bin" | od -An -tx1 | tr -d ' \n')
grep -q "$first" "$T/spy/payload.hex" && fail "file data was readable on the relay" || ok "the relay saw only ciphertext"

echo "B. relay flips one bit in transit"
run B "$WORK/bin/spyrelay" flip "$PW" 0
[ $RC -ne 0 ] && strip < "$T/recv.log" | grep -q digest_mismatch && ok "caught by the checksum" || fail "tampering was not caught"
[ -f "$T/out/big.bin" ] && fail "the tampered file was kept" || ok "nothing was finalised"

echo "C. relay flips a bit and forges a matching checksum"
run C "$WORK/bin/spyrelay" forge "$PW" 0
[ $RC -ne 0 ] && strip < "$T/recv.log" | grep -q integrity_failed && ok "caught by the signature" || fail "forgery was not caught"
[ -f "$T/out/big.bin" ] && fail "the forged file was kept" || ok "nothing was finalised"

echo "D. wrong password"
run D "$WORK/bin/relay" none "wrong-password-999" 0
[ $RC -ne 0 ] && strip < "$T/recv.log" | grep -q bad_password && ok "rejected" || fail "a wrong password was not rejected"
[ -f "$T/out/big.bin" ] && fail "data was delivered" || ok "nothing was delivered"

echo "E. packs, an empty file, and resume after a hard kill"
port=$((port + 1)); T="$WORK/E"; mkdir -p "$T/src/docs" "$T/out" "$T/relay" "$T/h1" "$T/h2"
for i in $(seq 1 200); do head -c $(( (i % 30 + 1) * 1024 )) /dev/urandom > "$T/src/docs/f_$(printf %03d $i).dat"; done
: > "$T/src/docs/empty.dat"
dd if=/dev/urandom of="$T/src/huge.bin" bs=1M count=600 status=none
( cd "$T/src" && find . -type f | sort | xargs sha256sum ) > "$T/src.sha"
"$WORK/bin/relay" -listen 127.0.0.1:$port -advertise 127.0.0.1:$port -state "$T/relay" -ttl 1h > "$T/relay.log" 2>&1 &
RP=$!; sleep 1.5
HOME="$T/h1" "$WORK/bin/strs" send -server 127.0.0.1:$port -dir "$T/src" -all -password "$PW" < /dev/null > "$T/send.log" 2>&1 &
SP=$!
for _ in $(seq 1 60); do strip < "$T/send.log" | grep -q -E '^ +pin ' && break; sleep 0.5; done
PIN=$(strip < "$T/send.log" | grep -m1 -E '^ +pin ' | sed 's/.*: //')
HOME="$T/h2" "$WORK/bin/strs" receive -server 127.0.0.1:$port -password "$PW" -pin "$PIN" -out "$T/out" -all > "$T/recv1.log" 2>&1 &
R1=$!; sleep 1.2; kill -9 $R1 2>/dev/null; wait $R1 2>/dev/null; sleep 1
HOME="$T/h2" timeout 200 "$WORK/bin/strs" receive -server 127.0.0.1:$port -password "$PW" -pin "$PIN" -out "$T/out" -all > "$T/recv2.log" 2>&1
RC=$?
( cd "$T/out" && find . -type f -not -name '.strs*' -not -name '*receipt*' -not -name '*.part' | sort | xargs sha256sum ) > "$T/out.sha"
[ $RC -eq 0 ] && diff -q "$T/src.sha" "$T/out.sha" > /dev/null && ok "all $(wc -l < "$T/src.sha") files identical after a killed download was resumed" || fail "resume did not produce identical files"
kill $SP $RP 2>/dev/null; wait $SP $RP 2>/dev/null

echo
[ $FAILED -eq 0 ] && echo "all checks passed" || echo "SOME CHECKS FAILED"
exit $FAILED
