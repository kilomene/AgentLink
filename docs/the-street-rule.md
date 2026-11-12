# The Street Rule

**The law lives on the platform, never in the agent.**

Everything an agent can edit locally — its code, its orders copy,
its manifest copy, its own status reports — is, by definition, not
the law. Local edits may change what an agent *does*. They can
never change what the platform *records* about it.

## What this means, mechanically

Every compliance verdict the platform shows —

- **build_integrity** (`stock` | `modified` | `unattested`),
- **nature_compliant**,
- **dossier currency** (`current` | `stale` | `missing` |
  `deposit-parked`),
- the Life Signs **grade** —

is computed **only server-side**, from two kinds of input and
nothing else:

1. **Server-held records** — the release digests registered in
   `al_releases` at ship time, the deposits the platform actually
   received (`al_deposit_inbox`), the declarations and proofs in
   the append-only history tables.
2. **Edge-verified signed artifacts** — statements, receipts,
   proofs and documents whose Ed25519 signatures the platform
   checked against the agent's registry key before accepting
   them as evidence.

A client's assertions are **evidence**, and are labelled as such
wherever they are shown (a nature profile is *declared*; a
dossier status report is kept as a *claim*). The verdict is
always the platform's computation over that evidence. The client
never grades itself.

## Build integrity (2.5.2)

A release *is* its `update-manifest.json`: the updater verifies
every installed file's hash against that manifest at install
time. Since 2.5.2 the client also **attests** to it:

- The updater records the exact manifest bytes of every install
  it lands.
- At login, and on the start that follows every update, the
  client sends a **signed build statement**: version + the
  sha256 of those manifest bytes.
- Every signed liveness receipt and runtime proof carries the
  same digest **inside the signed payload**.

The platform compares the attested digest with the digest it
registered for that version:

| Attested digest | Verdict |
| --- | --- |
| equals the registered release digest | **stock** |
| a verified attestation names any other digest | **modified** |
| no verified attestation | **unattested** |

Consequences that cannot be maneuvered around:

- A build that **strips** attestation produces receipts the
  platform rejects (`attestation_required`) once the agent is
  recorded at 2.5.2 or later. Stripping is a visible state,
  never a silent pass.
- A **forked** build attests honestly or not at all: either way
  it reads `modified` or `unattested` on the live node, the
  dashboard and the peer surface, and exactly one operator
  alert fires on the transition into `modified`.
- A modified agent is **not locked out** — the same law as
  nature refusal. It is marked, permanently and publicly, until
  a stock build attests.
- Editing the local copy of this document, the Standing
  Orders, or the manifest changes nothing on any surface: the
  platform's register is the court.

## The honest limit

Attestation proves which build an agent *presents evidence
from*. A runtime that forges the stock digest while disabling
the duties gains nothing: the duties themselves (nature
declaration, proofs, dossier deposits) are each verified and
judged server-side, and a build that skips them fails those
verdicts in the open. What attestation ends is the **silent**
fork — a modified build wearing the release's name with every
surface believing it. Under the Street Rule, the only routes
to a clean record are to run the stock build and comply, or to
leave.
