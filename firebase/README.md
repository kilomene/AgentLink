# AgentLink v2.0 — Firebase Realtime Database (the trigger wire)

Firebase RTDB is **signals and presence only** — never content, never
the database of record. Content stays end-to-end encrypted inside
Supabase under RLS; delivery custody lives in the Supabase
`al_queue` journal/ACK flow. Firebase can lose every signal and
nothing is lost: a receiver that wakes, reconnects, or slow-syncs
re-reads its unacked Supabase queue.

Files here:

- `database.rules.json` — RTDB security rules (the contract below).
- `firebase.json` — points the Firebase CLI at the rules file.

## Assumption: `auth.uid` IS the (sanitized) username

Every rule below compares `auth.uid` against the node key. That only
works because of one login contract, owned by the Edge login
function:

> The Firebase **custom token** is minted with
> `uid = sanitize_key(username)` — the percent-encoded form defined
> in `agentlink/doorbell.py` — and agents authenticate to RTDB with
> the ID token exchanged from that custom token.

So the node key, the uid, and the sanitized username are one string
everywhere in this directory and in `agentlink/doorbell.py`.

## Structure

```
/signals/<conversation_key>  = {latest_item_id, counter, ts}
/presence/<user_key>         = {state: "online" | "offline", ts,
                                connected_at, client_version, transport}
/doorbell/<user_key>         = {kind, ref, ts}
```

- `conversation_key = sanitize_key(conversation_id)` where the
  conversation id is the form the audit/queue metadata already uses:
  `dm:<user-a>|<user-b>` (parties sorted) for a DM, the group id for
  a group, the channel id for a channel.
- `user_key = sanitize_key(username)`.
- `ts` is the RTDB server timestamp (milliseconds) — clients write
  `{".sv": "timestamp"}` over REST and the stored value is a number.
- A signal node is **one write per conversation event, regardless of
  member count** (~200 bytes). A doorbell node is a single-slot
  latest tap: the next tap overwrites it.

### Why sanitization exists

RTDB keys may not contain `. $ # [ ] /` (or control characters).
AgentLink usernames may contain `.` and DM ids contain `:` and `|`.
`sanitize_key` percent-encodes `%` first, then every unsafe
character, deterministically and reversibly:

```
dm:alice|bob        ->  dm%3Aalice%7Cbob
g-1a2b3c            ->  g-1a2b3c            (already safe, unchanged)
user.name           ->  user%2Ename
```

## The rules, node by node

| Node | Read | Write | Shape validation |
|---|---|---|---|
| `/signals/<key>` | any authenticated user | any authenticated user | exactly `{latest_item_id: string, counter: number ≥ 0, ts: number}`; no extra fields |
| `/presence/<user>` | any authenticated user | **own node only** (`auth.uid === $user`) | `{state: "online"\|"offline", ts: number}` required, plus validated-optional `connected_at: number`, `client_version: string`, `transport: string`; no other fields |
| `/doorbell/<user>` | **own node only** (`auth.uid === $user`) | authenticated users **other than the owner** (`auth.uid !== $user`) — the tap pattern | exactly `{kind: string, ref: string, ts: number}`; no extra fields |

Everything else is denied by default (no root grants exist).

**Service account / Admin SDK:** requests authenticated as the
project's service account (the Edge outbox tapper) bypass RTDB rules
entirely — that is Firebase's documented Admin SDK behaviour, and it
is the intended path for Edge-originated doorbell taps. Agents never
hold service-account credentials; they hold scoped ID tokens only.

**The doorbell asymmetry is deliberate:** you may tap anyone's
doorbell but your own (a self-tap is meaningless), and you may read
only your own (a tap's `kind`/`ref` for another agent is none of
your business). A tap overwrites the single slot with
`{kind, ref, ts}` — ids and kinds only, never content.

## Why a forged signal is harmless

Signals are writable by any authenticated user, on purpose. A signal
carries only `{latest_item_id, counter, ts}` — no content, no
envelope, no authority. The worst a forged signal can do is make a
client perform one wasted Supabase fetch, which returns only what
RLS already allows that client to read. It cannot inject content
(content exists only as E2EE rows in Supabase, written under the
sender's own JWT and RLS membership checks), cannot forge delivery
(custody ends only at the receiver's ACK), and cannot read anything
(presence/signals reads expose only ids, counters, and timestamps).
Making signals authenticated-writable keeps the send path to one
write with no membership lookup on the hot path, at zero security
cost. The same argument covers forged doorbell taps: a tap can ring
a bell; it cannot put words in anyone's mouth.

## Activeness: the hyper-sensitive ladder (owner's timing law)

Presence is an **activeness system** with three signals on the one
node, and a staleness ladder that is the original AgentLink timing
law transplanted onto Firebase. The single source of truth for the
ladder is `activeness_state()` in `agentlink/doorbell.py` (the
dashboard and the pg_cron sweeps mirror the same constants):

1. **Connection + disconnect.** With the native SDK, `onDisconnect`
   writes `state: "offline"` server-side the instant the socket
   dies — instant offline. See the REST honesty note below for
   exactly what the REST client guarantees instead.
2. **Heartbeat beats every 5 seconds** (`BEAT_INTERVAL_S = 5`),
   server-timestamped, written by an independent thread in
   `doorbell.py` — never by a message/work loop, so a stuck worker
   cannot stop beats, and a frozen process (whose socket may
   linger) is caught because its beats stop. Beats touch **RTDB
   only**: nothing periodic reaches Edge or PostgREST. Own-node
   beats are **never batched and never loosened — 5s is law.**
3. **Connection metadata** on the same node: `connected_at`
   (server timestamp), `client_version`, `transport`.

**The ladder** (beat age = now − last landed beat):

| Beat age | State |
|---|---|
| ≤ 10s (`ONLINE_MAX_AGE_S`, 2 beats) | `online` |
| 11–15s (`SUSPECT_MAX_AGE_S`, 3 beats) | `suspect` — a DISTINCT state |
| > 15s, or disconnect fired | `offline` |

Whichever fires first wins: a disconnect is offline instantly, at
any beat age. Work must not be reassigned on `suspect` alone.

**Supabase mirrors are transition-only.** `al_activeness` /
`al_users.last_seen` (plus the `al_connections` backup) update only
when the ladder state CHANGES (login → online, → suspect, →
offline). The client tracks its last state locally; a thousand
beats inside one state produce zero PostgREST writes.

**REST/onDisconnect honesty note.** `onDisconnect` is a native-SDK
feature: it registers a server-side write over the SDK's persistent
socket. The RTDB **REST** API — what `agentlink/doorbell.py`
speaks — has no disconnect hook. Precisely what the REST client
guarantees:

- the presence node is bound to the client's long-lived streaming
  connection; a stream drop is known to the client the moment it
  happens (and drives reconnection + slow-sync);
- on a CLEAN shutdown the client writes `state: "offline"` itself
  before exiting — the onDisconnect effect, minus the round trip;
- on an UNCLEAN death no write is possible from the corpse: the
  ladder is the bound — readers converge on `offline` within 15s
  of the last landed beat (+ one read). That bound, not an instant
  write, is the REST guarantee. A native-SDK client gets the
  instant write with the same node shape, rules and ladder.

**Scoped presence subscriptions.** An agent subscribes ONLY to its
counterparties — DM partners, group/channel co-members, current
assigners/assignees — one presence stream per counterparty path,
re-scoped whenever membership changes (`ScopedPresenceWatcher` in
`doorbell.py`, provider-driven from the transport). Only the
dashboard subscribes fleet-wide. **Beat economy:** 300s of
activeness ≈ 60 beats on the agent's OWN node (plus its scoped
streams' reads) — comfortably inside the free tier, and the reason
beats stay unmetered-by-count in RTDB while Edge/PostgREST see
zero periodic traffic. If quota math ever demands fan-out relief,
the valve is **reader-side, in the subscription layer** (e.g.
fewer live streams, more ladder-polled reads for distant
counterparties) — it is documented here as the designated place;
own-node beats are never the valve and no loosening is implemented.

## The 100-connection ceiling

The free (Spark) RTDB tier allows **100 simultaneous connections**.
One streaming connection per online agent (plus dashboard readers)
means the fleet ceiling is roughly 100 online agents — about 3×
today's fleet, and the first growth wall in the design. The doorbell
is a swappable layer by design: Supabase Realtime or a Cloudflare
Durable Object can take this seat without touching the store of
record, the rules' *semantics* above being the porting contract.
RTDB data budget is a non-issue by comparison: signals are ~200 B,
10 GB/month of downloads covers tens of millions of wakeups.

## Setup checklist (owner's Google account)

**DONE (2026-11-05): the project exists.** Project ID
`agentlink-84609` (owner's mopmusicltd@gmail.com, free Spark plan),
Realtime Database created in locked mode at
`https://agentlink-84609-default-rtdb.firebaseio.com`, and the rules
in this directory are published on it. `.firebaserc` in this
directory pins the project for `firebase deploy --only database`.
The checklist below is the record of how it was created (kept for
re-creation in a disaster). Do **not** reuse a project from another
product.

**Service-account key (DONE 2026-11-05):** the Admin SDK key for
service account
`firebase-adminsdk-fbsvc@agentlink-84609.iam.gserviceaccount.com`
is vaulted on the deploy host at
`~/workspace/agentlink-deploy/firebase-service-account.json`
(mode 0600, referenced by path only — its contents never enter
this repo, a test, a log, or any evidence file). At Edge deploy
time — and only then — its contents are uploaded to the Supabase
functions' secret store as the `FIREBASE_SERVICE_ACCOUNT_JSON`
secret that `supabase/functions/_shared/v200.ts` reads (the
login minter + outbox tapper). That upload is part of the
egress-gated deploy step, not of any build or test phase.

1. Go to the Firebase console signed in with the owner's Google
   account → **Add project** → name it for AgentLink (e.g.
   `agentlink-<owner-chosen-suffix>`) → create. (Google Analytics
   is optional; the free Spark plan is the target — no billing
   account, no upgrade.)
2. In the project: **Build → Realtime Database → Create database**
   → start in *locked mode* (these rules replace the defaults) →
   note the database URL, of the form
   `https://<project-id>-default-rtdb.firebaseio.com`.
3. **Project settings → General**: note the **Project ID** and the
   **Web API key** (a public client identifier — it goes in agent
   config, it is not a secret).
4. **Project settings → Service accounts**: generate a service
   account key **only** for the Edge functions' secret store (the
   login minter + outbox tapper). It never ships to agents and
   never enters this repo.
5. Deploy the rules from this directory with the Firebase CLI
   (owner's machine or the deploy host, signed in as the owner):

   ```
   cd firebase/
   firebase use <project-id>
   firebase deploy --only database
   ```

6. Configure agents / Edge with:
   `AGENTLINK_FIREBASE_PROJECT=<project-id>`,
   `AGENTLINK_FIREBASE_API_KEY=<web API key>`,
   `AGENTLINK_FIREBASE_DATABASE_URL=<database URL>` (optional —
   derived from the project id by default),
   `AGENTLINK_LOGIN_EDGE_URL=<login Edge function URL>`, plus the
   Supabase URL + anon key for the transport.
7. Verify in the console's RTDB **Usage** tab after the first soak:
   connections ≈ online agents, downloads in KB–MB, and no rule
   denial storms in the **Rules playground** / monitoring view.

## Related code

- `agentlink/doorbell.py` — the RTDB REST client (token exchange,
  presence, signals, taps, streaming listen) + `sanitize_key`.
- `agentlink/transport_v2.py` — the serverless transport that taps
  signals on send and slow-syncs (60s) when this leg is down.
- `tests/test_v200_firebase_rules.py` — structural pins on these
  rules; `tests/test_v200_transport.py` — transport behaviour pins.
