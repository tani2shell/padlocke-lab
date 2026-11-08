# padlocke-lab

![battle-tested](https://img.shields.io/badge/battle_tested-full_chain_verified_by_an_AI_pentest_agent-brightgreen)
Difficulty: **3.5/5 (calibrated)** · Docker Compose · single container

A crypto-first chain in one target: break a sealed session cookie with a
padding oracle, promote yourself by flipping one ciphertext byte, turn a
"snapshot restore" endpoint into RCE with raw pickle, then walk a SUID helper
into root. No easy wins, no wildcards — every rung is earned from the
protocol's own error messages.

**EN** (this file) · [日本語](README.ja.md) · [中文](README.zh.md)

## The story

Padlocke Ledger Systems sells "integrity services for sealed records". Every
portal request carries a signed *session envelope* issued at login — the ops
wiki promises it is tamper-proof. It is even honest about the cipher. But
tamper with the envelope and watch closely: the API answers differently when
the padding fails than when the JSON fails. That difference is a door.

## Quick start

```bash
docker compose up -d --build
# portal: http://127.0.0.1:18962   (bind is 0.0.0.0; 18962 is the only published port)
# reset any time:
./RESET.sh
```

Requirements: Docker with Compose v2. Single container, 1 CPU / 512 MB cap,
isolated bridge subnet — it will not touch your LAN.

## What's in the box

| path | role |
|---|---|
| `build/` | app source, SUID helper C source, decoy payloads |
| `flags/` | two fixed lab flags (bind-mounted into the container) |
| `CHALLENGE.md` | black-box brief — read this first, zero spoilers |
| `SOLUTION.md` | full walkthrough (flags included) — after you give up or win |
| `DIFFICULTY.md` | nominal vs field-calibrated difficulty |
| `tools/solve.py` | reference end-to-end solver (stdlib-only Python) |

## Two flags

- `local.txt` — sits inside the container, readable by the service user once
  you can run a command as it.
- `proof.txt` — readable only by **root**. The service user is not root, and
  there is exactly one root-owned helper on the box.

## Battle-tested status

Full chain (cookie break → privilege flip → RCE → root) verified by a local
AI pentest agent on the calibrated environment (Apple M5 Ultra host, local
Qwen3.8-Flash-Next model). Both flags recovered byte-exact. Timing and
calibration notes: `DIFFICULTY.md`.

## Reset

`./RESET.sh` — tears down, rebuilds, rotates the seal key, wipes solve
artifacts, and gates on health. Deterministic: the target is fully
reproducible from this repo.

## License / series

MIT. Part of the `<target>-lab` pentest series — targets built by a human
forge-master and field-calibrated by an AI pentest agent (calibration data in
`DIFFICULTY.md`).
