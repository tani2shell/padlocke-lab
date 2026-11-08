# CHALLENGE — padlocke

**Entry point**: `http://<host>:18962` — the Padlocke Ledger portal. Nothing
else is published.

## Brief

Padlocke Ledger Systems runs a sealed-record integrity service:

- The landing page lists its public surface and a staff demo account.
- Every authenticated request carries a **session envelope** the vendor
  describes as a sealed, tamper-evident blob. Login hands you one; the API
  checks it on every call.
- There is an admin tier. You will not be handed an admin account — the
  ledger's own error handling has to be *convince*d.

You have two flags to collect:

1. **local** — a secret file that sits inside the container.
2. **proof** — a secret file that only **root** can read. The web service
   does not run as root.

## Ground rules / observable facts

- The envelope is opaque, but the API is chatty about *why* it rejects one.
  Response status codes are not all the same — read the triad.
- The admin portal, once visible, documents the rest of the surface itself.
- The restore endpoint is strict about what it accepts: anything it cannot
  parse gets the same terse "vendor binary expected" line, whatever you
  actually sent.
- The container has no outbound network. Your exfil channel has to be a
  feature, not a socket.
- There is exactly one setuid-root binary. Read its behavior, not its name.

## Beware

Not every `FLAG{...}` you meet is yours to submit, and not every credential
you find unlocks anything. Verify against the brief before claiming.

Good hunting.
