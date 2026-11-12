#!/bin/sh
# End-to-end test of serveHTTPS that needs no tailnet and no Let's Encrypt.
#
# It runs examples/https-node under `wrangler dev` against fake services
# from Tailscale's test packages (control server, DERP relay, ACME CA; see
# fake/main.go), and calls it from a second tailnet device (client/main.go)
# that verifies the certificate against the fake CA. Checked: first
# issuance, HTTP and HTTPS answers, reuse of the stored certificate after a
# restart, renewal, and the error when the tailnet has HTTPS disabled.
#
# Needs Go, Node, a built src/tailnet.wasm, and loopback ports 8610-8612
# and 8799. Logs are left in .run/.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
run="$here/.run"
status_url=http://localhost:8799/
wrangler="$root/examples/https-node/node_modules/.bin/wrangler"

rm -rf "$run"
mkdir -p "$run"
[ -x "$wrangler" ] || (cd "$root/examples/https-node" && npm install >/dev/null)
(cd "$here" && go build -o "$run/fake" ./fake && go build -o "$run/client" ./client)

fake_pid=
node_pid=
stop() {
  [ -z "$1" ] && return 0
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
trap 'stop "$node_pid"; stop "$fake_pid"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

start_fake() { # [fake flags]
  "$run/fake" -root "$run/acme-root.pem" "$@" >>"$run/fake.log" 2>&1 &
  fake_pid=$!
}

start_node() { # <state dir>
  (cd "$here/worker" && exec "$wrangler" dev --port 8799 --persist-to "$1") >>"$run/node.log" 2>&1 &
  node_pid=$!
}

wait_status() { # <substring of the node's status JSON>
  i=0
  while [ $i -lt 300 ]; do
    if curl -s -m 5 "$status_url" 2>/dev/null | grep -q "$1"; then return 0; fi
    sleep 0.2
    i=$((i + 1))
  done
  fail "node status never had $1: $(curl -s -m 5 "$status_url" || true)"
}

call() { # runs the client, leaves its output in $out
  out=$("$run/client" -root "$run/acme-root.pem" -n 2 2>&1) || fail "client: $out"
  echo "$out" | grep GET
}

serial() { echo "$out" | sed -n 's/.*serial \([0-9]*\).*/\1/p' | head -1; }
orders() { grep -c 'acme: POST /new-order' "$run/fake.log" || true; }

echo "== first start: issue a certificate"
start_fake
start_node "$run/state"
wait_status certExpiry
call
echo "$out" | grep -q 'GET http://.*: 200 "hello ' || fail "no answer over HTTP"
echo "$out" | grep -q 'GET https://.*: 200 "hello .*verified chains 1' || fail "no verified answer over HTTPS"
[ "$(orders)" = 1 ] || fail "expected 1 ACME order, got $(orders)"
first=$(serial)

echo "== restart: reuse the stored certificate"
stop "$node_pid"
start_node "$run/state"
wait_status certExpiry
grep -q 'https: using the stored certificate' "$run/node.log" || fail "log does not say the stored certificate was used"
call
[ "$(orders)" = 1 ] || fail "a certificate was issued again after the restart"
[ "$(serial)" = "$first" ] || fail "certificate changed across the restart"

echo "== renew"
curl -s -m 120 -X POST "${status_url}renew" | grep -q expiry || fail "renew failed"
call
[ "$(orders)" = 2 ] || fail "expected 2 ACME orders after renewal, got $(orders)"
[ "$(serial)" != "$first" ] || fail "certificate did not change on renewal"

echo "== tailnet with HTTPS disabled"
stop "$node_pid"
stop "$fake_pid"
start_fake -no-https
start_node "$run/state-no-https"
wait_status 'certError":"HTTPS certificates are not enabled'
call
echo "$out" | grep -q 'GET http://.*: 200 "hello ' || fail "no answer over HTTP with HTTPS disabled"
echo "$out" | grep -q 'GET https://.*: ERROR' || fail "HTTPS answered on a tailnet without certificates"

echo "PASS"
