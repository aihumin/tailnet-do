# Working in aihumin/tailnet-do

This is pagent's fork of littledivy/tailnet-do. Current work: HTTPS for tailnet nodes, see
`docs/https-brief.md` (read it first; it has the verified starting facts, the plan and the
acceptance criteria).

- **Toolchain:** Go 1.27.3 via `mise exec go@1.27.3 -- …` (not installed globally).
  `git submodule update --init --depth 1`, then `npm run build` (applies patches, builds
  `src/tailnet.wasm`). Examples run with `npx wrangler dev` in their folder.
- **Branches:** work on `https`; open PRs inside aihumin/tailnet-do. Never push to the
  `upstream` remote and never open a PR on littledivy/tailnet-do without the user's go-ahead.
  `AGENTS.md` and `docs/https-brief.md` are fork-only and must not be in an upstream PR.
- **Tailscale changes:** only as patches in `patches/tailscale/` (regenerate with
  `scripts/update-patches.sh tailscale`), small and upstream-quality.
- **Secrets:** only through `bb secret request … --write-env <git-ignored file>`. Never print,
  log, commit or paste a key. Don't open `.env*` / `.dev.vars` files to read them.
- **Let's Encrypt:** staging for all development; production only for final acceptance on
  the hostname `tailnet-do-https-dev`. Every issued name is public (CT logs).
- **Commits:** end messages with `Co-Authored-By: Claude <noreply@anthropic.com>` lines as
  your harness instructs.
