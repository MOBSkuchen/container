# Project audit — `container`

A remote process-supervisor / lightweight "container" manager: a **server** that
clones/downloads/receives sources, runs and supervises them as instances, and
exposes shell/attach/file-transfer side channels; a Ratatui **client** that
manages a fleet of such servers; and a shared **protocol** crate, all layered on
a hand-rolled RPC library (`bierpc`, out-of-tree at `../rpc`).

This document audits the workspace against five criteria: **Security**,
**Usability**, **Code quality & readability**, **Bugs**, and **Migration**. It is
based on a full read of `protocol/`, `server/`, `client/`, and the `bierpc` /
`bier_derive` crates the wire format depends on.

**Severity legend** — `Critical` (remote crash / total compromise), `High`
(serious, likely to bite), `Medium` (real but bounded or requires conditions),
`Low` (polish / latent). Each finding has one home and a `file:line` anchor;
sections cross-reference rather than repeat.

## Executive summary

The codebase is, at the application layer, **well above average**: a clean
crate split, doc comments that explain *why* rather than *what*, atomic file
writes, careful async/terminal handling, and genuinely good tests (the Windows
ConPTY probes are exceptional). The authentication design (HMAC-SHA256 over
`nonce ‖ timestamp ‖ payload`, constant-time verify, nonce replay guard,
replies bound to the request nonce) is correct and thoughtfully documented.

The weaknesses are concentrated in **one layer** — the `bierpc` transport and
its positional serialization — and in **one architectural gap** — the wire and
on-disk formats have no length bounds, no version tag, and no framing, even
though the mechanism to add type-checking (`SerializeVerified` / `TYPE_HASH`)
is already written and simply left unwired.

| # | Finding | Criterion | Severity |
|---|---------|-----------|----------|
| S1 | Pre-auth unbounded allocation → remote memory exhaustion / process abort | Security | **Critical** |
| S2 | No read timeout + 4-permit cap → trivial slowloris / connection exhaustion | Security | **High** |
| S3 | No transport encryption → cleartext session tokens are hijackable on-path | Security | **Medium–High** |
| B1 | `server init` prints **inverted** pairing instructions | Bugs | **High** |
| M1 | Positional format, declaration-order tags, unwired type-hash → lockstep upgrades only | Migration | **High** |
| B2 | `server start -b/--bootstrap` flag is silently ignored | Bugs | Low |
| B3 | `ServerStg::save` truncates in place (non-atomic), unlike every other writer | Bugs | Low |
| Q1 | `RpcError` collapses all I/O detail to a bare `IoError` | Code quality | Medium |
| S4 | Untrusted archive extraction (zip-slip / symlink) — post-auth, bounded | Security | Medium |

---

## 1. Security

### The trust boundary (read this first)

This is a remote-code-execution tool *by design*. An authenticated client can
`CreateInstance { command: "cmd.exe", args, env }`, open a shell in any
checkout, or upload files anywhere under the configured roots. **The security
model therefore rests on exactly two things:**

1. **The pre-shared key** — the sole gate between the network and full control
   of the host.
2. **Network exposure + the absence of encryption** — the channel authenticates
   but does not encrypt or protect side-channel setup.

Everything an authenticated caller can do to the host (run arbitrary programs,
fetch arbitrary URLs, read/write within the roots) is **the capability, not a
vulnerability**. The findings that matter are therefore those reachable
*before* the key check, plus what an on-path attacker gets for free from the
lack of encryption. Post-auth items are covered last and deliberately
down-weighted.

The authentication implementation itself (`protocol/src/auth.rs`) is a bright
spot and worth preserving as-is:

- HMAC-SHA256 via `Mac::verify_slice` (constant-time), key length-checked at
  load (`storage.rs:93`).
- The action travels as an **opaque blob**, decoded only *after* the MAC
  verifies (`server/src/api.rs:257-273`) — untrusted bytes never reach the
  `Action` decoder, and the MAC does not depend on canonical encoding.
- Replies are signed against the **request nonce**, so a reply cannot be lifted
  into another exchange (`auth.rs:177-200`).
- Verification order is shape → MAC → freshness → replay (`auth.rs:155-173`), so
  a nonce is only "burned" once the request is proven authentic — the replay map
  can't be inflated by unauthenticated traffic.
- Nonces and tokens come from `getrandom` / `rand`'s CSPRNG.

### S1 — Pre-auth unbounded allocation (Critical)

**Where:** `rpc/bierpc/src/serialize.rs` — `Vec::deserialize` (`:248`),
`String::deserialize` (`:193`), `HashMap::deserialize` (`:400`); reached via
`RpcServer::incoming_handle` (`rpc/bierpc/src/lib.rs:91`).

The server reads a whole `auth::Request` off the raw socket **before**
`handler.handle` runs `verify_request`. `Request`'s first field is
`nonce: Vec<u8>` (`auth.rs:88`), so deserialization reads an attacker-supplied
`u64` length and calls `Vec::with_capacity(len)` — **no key, no valid
structure, just the first 8 bytes on the wire**. `String::deserialize` is worse:
it does `vec![0u8; len]`, which zero-fills and forces the pages to commit.

Behavior splits by the chosen length, and the precise phrasing matters:

- A length `> isize::MAX` triggers a `"capacity overflow"` **panic**, which a
  `tokio::spawn`ed task *catches* — only that connection dies.
- A large-but-plausible length (e.g. `2^40`, ~1 TiB) reaches the allocator,
  fails, and calls `handle_alloc_error` → **whole-process abort**.

So the accurate claim is: *attacker-controlled pre-auth allocation → memory
exhaustion; on Windows (no memory overcommit, and the primary target here) an
oversized length reliably aborts the entire server with a single unauthenticated
packet.* Even where it does not abort, a handful of `String` requests with
`len ≈ u32::MAX` will thrash the host.

**The fix already exists in this repo.** `protocol/src/term.rs` bounds its
length prefix with `MAX_FRAME` (64 KiB) and returns `Decoded::Invalid` past it
(`term.rs:27,70`). The RPC serialization simply never applies the same
discipline. Fix direction: give every length-prefixed decoder in
`serialize.rs` a sane cap (reject, don't `with_capacity`, on oversize), and/or
frame the RPC with a bounded outer length prefix the server validates before
reading the body. This is the single most important change in the audit.

### S2 — No read timeout + tiny concurrency cap (High)

**Where:** `rpc/bierpc/src/lib.rs:91-105` (`incoming_handle`, no timeout on
`A::deserialize`) and `server/src/main.rs:128` (`server.run(4)`).

The main RPC path has **no read timeout**. `A::deserialize` blocks on
`read_exact` until the bytes arrive or the peer disconnects. The server runs
with a 4-permit semaphore (`run(4)`), so **four** connections that complete the
TCP handshake and then send one byte (or nothing) hold all four permits
indefinitely — a textbook slowloris. Legitimate clients then see
`RPC_TIMEOUT` (5 s, `client/src/net.rs:17`) and the fleet shows the server as
unreachable, though it is merely wedged.

There is also an **unbounded-accept** angle: the accept loop `tokio::spawn`s a
task per connection and acquires the permit *inside* the task
(`lib.rs:133-143`), so thousands of connections become thousands of parked
tasks each holding a file descriptor, regardless of the semaphore.

The contrast is instructive: the side-channel listener *does* wrap its token
read in a 5 s timeout (`server/src/session.rs:46-49`). The pattern exists in
the codebase; the main path just omits it. Fix direction: wrap the request read
in a timeout, raise/parameterize the connection cap, and consider a per-IP
accept rate limit.

### S3 — No transport encryption; session tokens travel in cleartext (Medium–High)

**Where:** whole transport; token minting at `session.rs:33`, delivery in
`Response::SessionOpened` (`protocol/src/api.rs:146-152`), client handshake at
`client/src/net.rs:209-233`.

The channel authenticates but does **not** encrypt (documented candidly in
`auth.rs:14-16` and the design doc §8). Consequences on a hostile/shared
network:

- Instance names, repo URLs, console output, **and file-transfer contents** are
  readable on the wire.
- The 32-byte side-channel **token is sent in cleartext** inside the (signed but
  unencrypted) reply. The listener hands the session to the *first* connection
  presenting the correct token (`session.rs:51`), so an on-path attacker who
  reads the token can race the legitimate client and **hijack a shell or file
  transfer** within the TTL (default 30 s).
- `Reply::Rejected` is inherently unsigned (`auth.rs:102-106`); a MITM can
  inject one to make the client display the misleading "key rejected — run
  keygen" hint (`net.rs:55`). This is acknowledged as "never a basis for a
  security decision," and the impact is confined to a confusing message, but it
  is the one place the channel's lack of integrity is user-visible.

Fix direction: the honest framing is "run this only on a trusted network or
inside a tunnel (WireGuard/SSH)". If the threat model ever includes hostile
networks, wrapping the socket in TLS (rustls is already a dependency via
`reqwest`) or a Noise handshake is the real fix; short of that, at minimum
document the requirement prominently and consider binding to `127.0.0.1` by
default instead of `0.0.0.0` (`server init` currently defaults to
`0.0.0.0:5000`, `server/src/main.rs:16` — all interfaces).

### S4 — Post-auth surface (Medium, and mostly inherent)

These are reachable **only after authentication**, and an authenticated caller
already has arbitrary code execution on the host, so most are a rounding error
against the capability they hold. Listed for completeness, not alarm:

- **Untrusted archive extraction.** Upload/URL sources are unpacked with
  `tar::Archive::unpack` and `zip::ZipArchive::extract`
  (`server/src/transfer.rs:186-191`, `server/src/sourceops.rs:116-128`). Modern
  `tar`/`zip` guard against `..` traversal, but zip-slip and symlink-in-archive
  escapes have a long history; this is the one post-auth item genuinely worth a
  hardening pass, because the extraction target (an instance dir) is more
  constrained than "run any command" and a traversal escapes *that* containment.
  Fix direction: extract into a staging dir and reject entries whose canonical
  path leaves it; confirm the `zip` crate version sanitizes names.
- **Lexical-only path jail.** `resolve_path` rejects `..` and checks
  `starts_with(root)` without resolving symlinks (`transfer.rs:19-49`) — an
  instance that plants a symlink in its own checkout can have an operator's
  transfer follow it out. Documented as "the operator's choice"
  (`transfer.rs:18`); acceptable under the trust model.
- **SSRF via `fetch_url`.** `reqwest::get(url)` follows redirects to any host,
  including cloud metadata endpoints (`sourceops.rs:79`). Post-auth and
  strictly weaker than the command execution already on offer.

None of these change the security posture, which is entirely determined by S1–S3.

---

## 2. Usability

**Strong overall**, especially the client. The design invests in ergonomics in
ways that show real care:

- **Actionable errors.** `NetError::short` names the *fix*, not just the symptom
  ("no key — run `client keygen <phrase>`", `net.rs:49-59`). `keygen` prints the
  exact command to paste on the other side and explains why a random key must be
  copied (`client/src/main.rs:141-145`).
- **A polished TUI**: flattened server/instance tree with inline vitals, text
  meters that turn yellow/red past thresholds (`ui.rs:353-367`), toasts with
  TTL, confirmation modals with inline toggles (delete-files, overwrite),
  per-screen help overlay and keybar, a dual-pane file browser with transfer
  progress and "ghost" rows for in-flight copies.
- **Resilience to unreachable servers**: the poller never blocks the UI; a down
  server stays listed, dimmed, with a last-seen time; rates reset to 0 rather
  than spiking on a counter reset (`app.rs:82-108`).
- **Terminal safety**: a panic hook + `Drop` guard restore the console, so a
  crash never leaves a raw-mode terminal (`main.rs:158`, `console.rs:122-134`).
- **Target resolution**: `server/instance` or a bare name searched across the
  fleet, with ambiguity reported (never a silent pick) and unreachable servers
  skipped-and-mentioned (`client/src/target.rs`).
- **Self-management / bootstrapping** is a genuinely nice touch — restart the
  server itself from the TUI, and a one-time toast pointing out that a freshly
  added server supports it (`app.rs:1028-1038`).

Friction points:

- **First-run pairing is broken** for `server init` — see **B1**. This is the
  worst usability bug because it hits every new operator at the exact moment
  they are trying to connect a client.
- **A dead CLI flag.** `server start -b/--bootstrap` is documented ("Starts as a
  daemon") but ignored — see **B2**. A user who tries it gets silence.
- **Interactive `init` is fragile.** `gather_value_routine` drives the prompt by
  emitting raw cursor moves through the `console` crate and re-prompts by
  recursion on bad input (`server/src/cli.rs:44-96`); it works but is
  terminal-dependent and harder to script than the `mkconfig` example, which is
  the more robust path for automation.
- **Clock coupling.** The 60 s skew window (`auth.rs:32`) means two hosts more
  than a minute apart silently fail to talk; the error does say "check the
  clocks," which softens it.
- **No CLI listing.** Instances are only visible via the TUI or by
  shell/attach/browse; there is no `client ls`-style command for scripts.
- **Rotating a key locks out every client**, by design and clearly messaged
  (`main.rs:96`), but there is no staged rotation.

---

## 3. Code quality & readability

**Application code: high quality.** Adding a feature to the client or a handler
to the server is straightforward, and the code is pleasant to read.

- **Clean separation.** `protocol` holds only wire types so the client never
  pulls `gix`/`processkit`/`sysinfo` (`protocol/src/lib.rs:1-10`). `server`
  re-exports the moved types so paths keep working. The client is a library plus
  a thin `main`, which is *why* the UI is testable headless.
- **Comments explain intent.** Nearly every non-obvious decision has a "why"
  next to it — the biased `select!` to flush output before exit
  (`server/src/terminal.rs:125-129`), why Windows reads events not bytes
  (`client/src/terminal.rs:126-130`), why `stat` keeps a persistent `System`
  (`server/src/api.rs:26-33`). This is the difference between code you can
  modify and code you can only rewrite.
- **Tests that earn their keep.** Unit tests for framing (`term.rs`), the line
  editor (`editor.rs`), and PATHEXT resolution (`manager.rs:833-857`); and
  integration `smoke` / `tui_smoke` that assert on rendered text against a live
  server, including every auth-rejection path built via `auth::request_mac`
  (not a reimplemented HMAC). The ConPTY probes (`evt_probe`, `shell_probe`)
  test the genuinely-hard Windows console paths that "looked untestable."
- **Robustness idioms** are consistent: atomic temp-then-rename for the instance
  index and both client/server books (`storage.rs:123-138`, `book.rs:78-94`),
  `.part` files for downloads, poisoned-mutex recovery via
  `unwrap_or_else(|e| e.into_inner())`.

**The `bierpc` / `bier_derive` layer is the weak spot**, and it is where the two
Critical/High security findings and the migration fragility all originate:

- **`RpcError` discards all detail** — every I/O failure collapses to a bare
  `IoError` (`rpc/bierpc/src/error.rs:8-16`). Debugging a connection problem
  means guessing; this is significant enough to call out (**Q1**, Medium) and
  matches the project's own recorded pain ("bare IoError = server not running").
- **Latent panics.** `Target::to_socket_addr` does `.parse().unwrap()`
  (`lib.rs:20`) and `Into<SocketAddr>` is impl'd instead of `From`. `Target`
  appears unused by `container` (the client passes a real `SocketAddr`), so
  it's latent, but it's a landmine for the next caller.
- **Odd/again-latent bits.** `Vec::deserialize` uses `out.insert(i, …)` in a
  loop where a `push` is meant (`serialize.rs:254`) — correct but confusing; the
  `generic_array_parse` array impl uses `transmute_copy` + `mem::forget` and
  would leak on a mid-deserialize error (feature-gated, unused here).
- **Suppressed signal.** `#![allow(dead_code)]` across the client lib
  (`client/src/lib.rs:8`) hides genuinely dead code; a couple of `map_err`
  closures bind and ignore the error (`storage.rs:76`, `serialize.rs:311`).

None of these are hard to fix, and none touch the well-structured application
code — but the RPC crate is load-bearing for the whole system and currently the
least trustworthy part of it.

---

## 4. Bugs

### B1 — `server init` prints inverted pairing instructions (High)

**Where:** `server/src/main.rs:46`.

```rust
term.write_line(&pairing_advice(
    if !phrase.trim().is_empty() { EitherOr::A(&server_stg.key) } else { EitherOr::B(phrase) }
))?;
```

`pairing_advice` treats `EitherOr::A` as "random key → print the hex" and
`EitherOr::B` as "phrase-derived → re-derive with the phrase"
(`main.rs:58-67`). The condition is **backwards**, provably so by diffing
against `_keygen`, which gets it right (`main.rs:94`: `B(phrase)` when a phrase
exists, `A(hex)` otherwise):

- Operator **gives a passphrase** → hits `EitherOr::A` → told *"This key is
  random, so nothing can re-derive it. Pair with `client keygen --key <hex>`"* —
  false; the key is phrase-derived and the phrase would pair it.
- Operator **takes a random key** (blank phrase) → hits `EitherOr::B("")` →
  printed literally `Pair a client with: client keygen ` **with an empty
  phrase** — and the actual hex they need is never shown.

Every fresh install gets wrong pairing instructions. Fix: invert the condition
(mirror `_keygen`).

### B2 — `server start --bootstrap` is a dead flag (Low)

**Where:** `server/src/cli.rs:19-22` defines `Start { bootstrap: bool }` with
`long_help = "Starts as a daemon"`; `server/src/main.rs:145` matches
`Commands::Start { .. }` and drops it. Whether the server may hand itself over
is governed solely by the `bootstrap` field in the config
(`storage.rs:26`, checked at `api.rs:316`). The flag does nothing. Fix: either
wire it (override the config value for this run) or remove it and its help text.

### B3 — `ServerStg::save` is non-atomic (Low)

**Where:** `server/src/storage.rs:80-88`. It opens the config with
`.truncate(true).write(true)` and serializes in place. Every *other* persistence
path in the project uses temp-then-rename (`save_instances` at `storage.rs:123`,
client `book::save` at `book.rs:78`). A crash or power loss mid-write leaves a
truncated `config.chld` — which, given the positional format (§5), is
unrecoverable without `keygen`/re-`init`. Fix: adopt the same temp-then-rename
here.

### Minor / worth a glance

- **`ServerStg::new` swallows the fetch error** and always emits a generic
  message (`storage.rs:76`, `|e|` unused); harmless today because a fresh
  storage dir has no instances file, so the branch is effectively dead.
- **Console scroll drift.** When the server's ring buffer evicts lines, the
  scroll-retention math (`app.rs:496-499`) can drift because it compares raw
  lengths rather than tracking a stable anchor — a cosmetic jump while scrolled
  back, never a panic.
- **`stat` refreshes disks/networks synchronously** while holding `tokio::sync`
  mutexes on the async runtime (`api.rs:76-92`); sysinfo is blocking, so a slow
  disk enumeration can stall a worker. Low impact at `run(4)` but a latent
  scaling snag.

The UI slicing and modular-arithmetic paths I checked (`draw_console`
`console[start..end]`, `step_instance`, `browse_move`, form cursor `split_at` on
char boundaries) are correctly bounded and do **not** panic on the edge cases
(empty lists, shrunk buffers, multibyte input).

---

## 5. Migration

This is the project's **structural weak point**, and the concern in the prompt
("changes often break the protocol or storage") is well-founded and diagnosable.

**Root cause: the format is positional, tagged by declaration order, and
unversioned — on the wire *and* on disk.**

- **Wire types are hand-positional.** `bier_derive` serializes struct fields in
  source order and enum variants by `i as u16` — the **declaration index**
  (`bier_derive/src/lib.rs:55-58,128-131`). So:
  - Inserting an `Action`/`Response` variant anywhere but the **end** shifts
    every later tag; a client and server on different revisions then silently
    map one variant onto another. The design doc records this exact hazard when
    `DirListing` was "inserted before `Error`, shifting variant indices … Client
    and server must be built from the same revision" (`docs/client-design.md`
    §1.3).
  - Adding/removing/reordering a struct field changes the byte layout with no
    detection → an `"early eof"` or a confident misparse.
- **On-disk files share the identical format.** `config.chld` (`ServerStg`),
  `instances.chld` (`Vec<InstanceConfig>`), and the client's `servers.chld`
  (`Book`) are written with the same `serialize`/`deserialize`
  (`storage.rs`, `book.rs`). There is **no magic number, no version field, no
  schema tag** — `config.chld` begins directly with a `SocketAddr`. Any change
  to `ServerStg` or `InstanceConfig` breaks reading existing files; the only
  recovery tools are `purge-instances` (drops all instances) and re-`keygen` /
  re-`init`.
- **Unknown variant tags hard-error** (`bier_derive/src/lib.rs:166`), so there
  is no forward compatibility — an older binary cannot skip a newer field.

**The sharp observation:** the fix is *already built and simply not connected.*
`SerializeVerified` / `DeserializeVerified` prepend a `TYPE_HASH` and refuse a
mismatch (`serialize.rs:48-72`), and `bier_derive` derives that hash from the
whole type definition (`bier_derive/src/lib.rs:14-26`). Wired into the RPC path
(`RpcClient::call` / `RpcServer::incoming_handle` use plain `serialize`, not the
`_verified` variants — `bierpc/src/lib.rs:53-59,91-100`) and into the file
loaders, this would turn today's silent corruption and `"early eof"` into a
clear *"version mismatch — rebuild both binaries"* at the first byte. The
migration story is not "there is no versioning mechanism"; it is **"the
versioning mechanism exists and is unengaged."**

For contrast, `protocol::term` shows the mature pattern the rest of the wire
format lacks: a bounded length prefix *and* forward-compatible `Frame::Unknown`
skipping so "the format can grow without breaking old servers"
(`term.rs:50-53,131-139`). That discipline applied to `Action`/`Response` and
the `.chld` files would fix migration outright.

**Concrete migration hardening, in priority order:**

1. Wire `deserialize_verified` (or an explicit `u32` schema-version prefix) into
   both the RPC path and the file loaders, so a mismatch is a clean, actionable
   error instead of a misparse. *(Also closes the "must rebuild both sides"
   surprise.)*
2. Add a magic-number + version header to each `.chld` file and a
   read-old-write-new migration shim, so config/instances survive an upgrade
   instead of needing `purge`.
3. Adopt a rule (and enforce it in review) that `Action`/`Response` variants and
   struct fields are **append-only**; document it in code next to the enums, not
   only in the design doc and operator memory.
4. Fold in the S1 length bounds while touching the decoders — the migration fix
   and the DoS fix live in the same file.

---

## Appendix — prioritized fix list

1. **S1** — Bound every length-prefixed decoder in `serialize.rs` (mirror
   `term::MAX_FRAME`); reject oversize instead of `with_capacity`. *(Critical,
   pre-auth remote crash.)*
2. **S2** — Add a read timeout to `incoming_handle`; raise/parameterize the
   connection cap; acquire the permit before spawning. *(High.)*
3. **B1** — Invert the `server init` pairing-advice condition
   (`main.rs:46`). *(High, breaks first-run pairing.)*
4. **M1** — Engage `deserialize_verified` / a version prefix on the RPC and
   file paths; add `.chld` headers + a migration shim. *(High, structural.)*
5. **S3** — Document the trusted-network requirement prominently; default the
   bind to loopback; consider TLS/Noise if hostile networks are in scope.
   *(Medium–High.)*
6. **Q1** — Give `RpcError` real variants / an inner message. *(Medium,
   debuggability.)*
7. **S4** — Harden archive extraction against zip-slip/symlink escape.
   *(Medium.)*
8. **B3 / B2** — Atomic `ServerStg::save`; wire or remove `start --bootstrap`.
   *(Low.)*

**What to keep exactly as it is:** the `protocol::auth` design, the crate split,
the doc-comment culture, the atomic-write idiom, and the headless/ConPTY test
strategy. The system is close to solid; the work is concentrated in one crate
and one format decision.
