# SANITIZE-CHECK — padlocke-lab

Prepared 2026-11-08 (JST) before outbound push. Method: full-tree `grep`
over everything a solver touches (app source, decoys, Dockerfile/compose,
docs), excluding `SANITIZE-CHECK.md` itself.

```
== [1] flag values on challenge surface ==   ZERO-HIT  (scoped, see exceptions)
== [2] demo credential literal ==            ZERO-HIT  (split at build/app.py:DEMO_PASS, rendered at request time)
== [3] informed-run mask literal ==          ZERO-HIT
== [4] host paths (/Users/..., workspace) == ZERO-HIT
== [5] internal IPs (192.168.x etc.) ==      ZERO-HIT
== bonus: tracker ids / bot aliases / internal tooling ==  ZERO-HIT
```

## Known scoped exceptions (deliberate)

- **Decoy flag** `FLAG{padl0cke_l3gacy_...}` appears verbatim in
  `build/decoys/legacy-report.chk` (it is the trap itself — it must ship
  inside the image) and in `tools/solve.py` (the reference solver asserts the
  trap is reachable). Neither real flag value appears outside
  `SOLUTION.md`/`flags/` — flags are published with the walkthrough by
  design.
- The vendor fiction "Padlocke **Ledger** Systems" shares a word with an
  internal tracking file name; no relation, no leak.
- `docker-compose.yml` pins an isolated RFC1918 bridge subnet
  (`172.30.92.0/24`) — an intentional compose isolation choice, not a
  home/office LAN address.

## Live self-test (this package, not the factory copy)

`docker compose up -d --build` from this directory → health gate green →
`python3 tools/solve.py` full chain **12/12 PASS** (padding-oracle decrypt,
seal flip, pickle RCE, SUID privesc, traversal gate, both decoys, both flags
byte-exact against `flags/`) → `./RESET.sh` → `RESET-OK`, solve artifacts
wiped, chain reproducible post-reset.
