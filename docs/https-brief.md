# Brief: HTTPS for tailnet-do nodes

Fork-only document (aihumin/tailnet-do). Written 2026-11-12 for the agents doing this work.

## Goal

A tailnet-do node serves **HTTPS on its MagicDNS name** with a certificate Tailscale issues
(Let's Encrypt), so `https://<hostname>.<tailnet>.ts.net/` works from browsers, curl and MCP
clients with no certificate warnings and no `-k`.

The first consumer is pagent's scannr: a Cloudflare Worker reachable only from the tailnet,
through a gateway Durable Object that serves the tailnet and forwards to the app over a
service binding (`aihumin/scannr`, `cloudflare/gateway/`). Today it serves plain HTTP on port
80 because this library can't do HTTPS. Some clients (browsers, Claude Desktop's MCP bridge)
refuse or warn on `http://`, and the team requires HTTPS.

The change is general-purpose, so build it **upstream-quality**: the intent is to offer it
to littledivy/tailnet-do as a pull request, so we don't maintain a patched Tailscale alone.

## How things work today (verified against the pinned commits)

- tailnet-do `295ad50`, Tailscale `b31eb1c` (submodule), Go 1.27.3. Two patches in
  `patches/tailscale/`; `scripts/build-wasm.sh` builds `src/tailnet.wasm` (27.6 MB raw,
  6.4 MB gzip) with the build tags in `go/tags.txt`.
- `go/tags.txt` omits, among others, `ts_omit_acme` (certificate issuance) and
  `ts_omit_serve` (Tailscale's serve config). We need ACME back; we do **not** need serve
  config, Funnel or tls-alpn-01.
- Node state goes through `jsStateStore` (`go/main.go`, around line 698), backed by the
  Durable Object's storage (`getState`/`setState` in `src/index.js`).
- **Certificate storage is the blocker.** `feature/acme/certstore.go` `getCertStore()` only
  uses the state store (`certStateStore`) when it detects Kubernetes; otherwise it writes
  files under `TailscaleVarRoot()`, which doesn't exist in wasm/Workers. Certificates and the
  ACME account key must live in the state store here, so they survive Durable Object
  restarts and deploys.
- Issuance for `*.ts.net` names uses **dns-01 through the control server** (control sets the
  TXT record), so a node with no public address can get a certificate. Outbound HTTPS from
  Go on js/wasm goes through the runtime's `fetch`.
- Let's Encrypt's staging directory can be selected with the envknob
  `TS_DEBUG_ACME_DIRECTORY_URL` (`certstore.go` ~line 402). Check how env vars reach Go in
  wasm (`wasm_exec.js` `go.env`) and expose it as a node option.
- `serveHTTP` (`go/main.go` ~line 581) already does HTTP over a netstack listener with
  `whois` per connection; HTTPS should reuse that path with a TLS listener in front.

## Work

1. **Build:** remove `ts_omit_acme` from `go/tags.txt`; make sure the ACME feature is linked
   (feature packages register in `init`, check whether `go/main.go` needs a blank import of
   `tailscale.com/feature/acme`). Keep everything else omitted.
2. **Cert store patch** (`patches/tailscale/0003-…`): let hosts with a custom `StateStore`
   keep certificates in it, in a form Tailscale upstream could accept (for example a
   package-level hook or a capability on the store, not a `GOOS == "js"` special case if
   avoidable). Regenerate patches with `scripts/update-patches.sh`.
3. **Engine:** `serveHTTPS(port, handler)` in `go/main.go`: a TLS listener on the node's
   tailnet address, `GetCertificate` backed by `LocalBackend.GetCertPEM` for the node's
   cert domain (from the netmap's `DNS.CertDomains`), cached in memory and renewed through
   Tailscale's own refresh logic. Same request/`whois` handling as `serveHTTP`. If the
   tailnet has HTTPS disabled, fail with a clear error.
4. **JS API:** `tailnet.serveHTTPS(port, handler)` next to `serve()`, a node option for the
   ACME directory URL (staging), and the cert domain plus certificate expiry in `status()`.
   Update the README.
5. **Example:** `examples/https-node/`: serves `hello <loginName>` over HTTPS on 443.
6. **Measure and record** in the PR description: wasm size before/after (raw and gzip;
   scannr's gateway budget is ≤ 7.5 MB gzip), time to first certificate, time to serve
   after a restart with a stored certificate, CPU per TLS handshake.

## Done when

- `curl https://<host>.<tailnet>.ts.net/` from a tailnet device succeeds **without `-k`**,
  and a browser shows a valid certificate.
- Restarting the object (redeploy or `wrangler dev` restart) serves HTTPS again **without
  a new issuance** (logs show the stored certificate was used).
- Renewal path exercised at least once (force it via `TS_DEBUG_ACME_FORCE_RENEWAL` against
  staging).
- HTTP `serve()` still works, both on the same node.
- Go unit tests for the cert-store change pass; the example runs under `wrangler dev`.
- A PR in **aihumin/tailnet-do** from branch `https` with the measurements, ready for review.
  A clean branch for upstream (no fork-only docs) is prepared but **not opened** upstream
  until the user says so.

## Constraints

- **Let's Encrypt limits:** about 5 identical certificates per name per week. Use the
  **staging** directory for every development loop. Use production only for the final
  acceptance, on one hostname (`tailnet-do-https-dev`), and only a couple of times.
- Certificates are logged publicly (Certificate Transparency): every hostname you issue for
  becomes public. Use only the agreed hostname.
- Credentials only through `bb secret request` into git-ignored files (`.dev.vars`); never
  print, log or commit keys, and never paste them in chat.
- Minimal changes to Tailscale, each as its own patch with a clear message.
- Out of scope: Funnel, tls-alpn-01, wildcard certificates, Tailscale serve config, exit
  nodes.

## What the user provides (ask when you reach live testing, not before)

1. In the Tailscale admin console → DNS: **HTTPS Certificates enabled** for the tailnet.
2. Policy: a tag for the test node, `"tag:tailnet-do-dev": ["autogroup:admin"]` under
   `tagOwners`, and a grant
   `{ "src": ["group:developers"], "dst": ["tag:tailnet-do-dev"], "ip": ["tcp:80", "tcp:443"] }`.
3. An auth key: Reusable, Ephemeral, 7-day expiry, tag `tag:tailnet-do-dev`, pre-approved.
   Request it as `TS_AUTHKEY` with `bb secret request` into `examples/https-node/.dev.vars`.
