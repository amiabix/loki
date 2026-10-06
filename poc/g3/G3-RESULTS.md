# Loki G3: standalone nonce safety prototype, 2-of-3 receipt gate

## G3 PARTIAL. Chromium and Playwright WebKit drilled; Firefox would not launch; no device case tested.

Date 2026-10-03. Standalone: no FROST, no PCZTs, no chain, no G1 state. The subject is the
nonce store and what a browser plus three relays can and cannot promise about it.

**G3 stays PARTIAL.** No physical device case has been run: no power loss, no OS backup
restore, no device transfer. A renderer crash and a `SIGKILL` on a desktop browser are not
device crashes. Every unrun case is listed under
[Device cases: NOT TESTED](#device-cases-not-tested), with a manual procedure for the two
that matter most. G3 does not close until those pass.

**Full G1 remains BLOCKED (ZIP 2005).** Nothing here changes that. G3 neither needs nor
advances it.

```
chromium 153.0.8010.12   full suite       29 passed, 2 failed, 1 inconclusive, of 32
webkit   26.6            portable suite    6 passed, 1 failed, 1 inconclusive, of 8
firefox  not-run         portable suite    NOT RUN: the browser would not launch
```

## Per-engine results

Driven by `playwright-core` 1.63.0 on macOS 27.0.1 (Darwin 27.0), arm64. Every cell comes
from a recorded run; `summarise.mjs` builds this table from the JSON each run writes.

| | chromium 153.0.8010.12 | webkit 26.6 | firefox |
|---|---|---|---|
| suite | full (32 drills) | portable (8) | **NOT RUN** |
| receipt gate | 2 pass | 2 pass | NOT RUN |
| two-tab race | 2 pass | 2 pass | NOT RUN |
| crash recovery | 1 pass | 1 pass | NOT RUN |
| profile restore | 1 pass, 1 expected fail | 1 pass, 1 expected fail | NOT RUN |
| strict durability | 1 inconclusive | 1 inconclusive | NOT RUN |
| renderer-crash URL | `chrome://crash` | **none** | NOT RUN |
| `durability` attribute present | true | true | not measured |
| options bag accepted | true | true | not measured |
| `transaction.durability` reads back | `strict` | `strict` | not measured |
| strict durability supported | **true** | **true** | not measured |

The portable suite is the five categories that are meaningful on every engine:
`gate-three-honest`, `gate-only-one-reachable`, `two-tabs-no-lock`,
`two-tabs-same-package-no-lock`, `hard-kill-after-consume`, `restore-three-honest`,
`restore-all-acknowledgers-lying`, `durability-unsupported-is-not-a-pass`. Chromium also
runs the other 24 drills (relay outage matrix, receipt binding, forgery, impersonation,
the renderer-crash boundaries, and the one-relay baseline).

**The `strict durability` row is `inconclusive` on both engines by construction, not by
failure.** Both engines *do* support strict durability, which is the separate measured row
below it. The drill in that category is the fail-closed path, and it is never counted as a
platform pass. See [Strict IndexedDB durability](#strict-indexeddb-durability).

### Playwright WebKit is not Safari

`webkit 26.6` is the WebKit build Playwright ships (`playwright webkit v2359`, installed to
`~/Library/Caches/ms-playwright/webkit-2359`). **It is not Safari.** It differs in its
networking stack, its process model, its storage backend configuration and its ITP and
storage-eviction policies, all of which bear directly on whether IndexedDB survives. No
result in the `webkit` column is a Safari result, and the harness prints that line itself
on every run:

```
### Playwright WebKit is NOT Safari. This is not a Safari result.
```

Safari 27.0.1 is installed on this machine and was **not tested**. See
[Native Safari](#native-safari-not-tested).

### firefox: NOT RUN, exactly as it failed

The engine is marked NOT RUN and no drill result is claimed for it. Recorded verbatim:

```
### engine: firefox   NOT RUN: the browser would not launch
###   playwright call: browserType.launchPersistentContext: Failed to launch the browser process.
###   engine stderr: [err] *** You are running in headless mode.
###   engine stderr: [err] Could not find profile folder.
###   no drill was run, and no result is claimed for this engine
```

What was tried, in order, and the exact result of each:

| attempt | command | result |
|---|---|---|
| Firefox 142.0.1 (build 1495), `playwright-core` 1.56.1 | `firefox.launch({})` | `sandbox_extension_issue_file_to_process failed for .../plugin-container.app: 1 (Operation not permitted)` |
| content sandbox off | `firefox.launch({ firefoxUserPrefs: { 'security.sandbox.content.level': 0 } })` | same error |
| headed | `firefox.launch({ headless: false })` | same error |
| env override | `MOZ_DISABLE_CONTENT_SANDBOX=1 node ff-probe.mjs` | same error |
| outside my own sandbox | same, unsandboxed | **same error**, so it is not my execution environment |
| upgrade | `npm i playwright-core@1.63.0` then `cli.js install firefox` → Firefox 155.0 (build 1543) | sandbox error gone, new error: `Could not find profile folder.` |
| `launch()` | `firefox.launch({ timeout: 60000 })` | `Could not find profile folder.` |
| persistent, dir absent | `firefox.launchPersistentContext('/tmp/ffp-dirabsent', {})` | `Could not find profile folder.` |
| persistent, dir pre-created | `mkdirSync(dir); firefox.launchPersistentContext(dir, {})` | `Could not find profile folder.` |
| the binary directly | `.../firefox-1543/firefox/Nightly.app/Contents/MacOS/firefox -headless -profile /tmp/ffdirect2 -no-remote -silent` | `*** You are running in headless mode.` then `Could not find profile folder.` |
| profile creation | `... firefox -headless -CreateProfile "g3test /tmp/ffdirect3"` | `Could not find profile folder.` |

`firefox --version` reports `Mozilla Firefox 155.0`, so the binary runs. The 142.0.1 build's
helper was **adhoc, linker-signed** (`codesign -dv` on
`Nightly.app/Contents/MacOS/plugin-container.app` reports
`flags=0x20002(adhoc,linker-signed)`), and macOS 27 refused to issue it a sandbox extension.
I did not re-sign, disable SIP, or otherwise weaken the platform to force a launch.

**Consequence, stated plainly: Firefox's real `durability` behaviour is unmeasured.** Firefox
is the engine most likely to differ here, and the one engine whose behaviour would have been
most worth knowing. It is a gap, not a pass.

## The three relays are SIMULATED OPERATORS

They are three local Node processes on loopback, ports 18765 to 18767, with three Ed25519
keypairs. **Three processes on one machine are not three independent operators.** They share
a kernel, a disk, a clock, a filesystem, and whoever can run `kill`. A 2-of-3 threshold rests
entirely on "at least one of the three is honest", and that is precisely the assumption local
processes cannot demonstrate.

Every result below is about the **store's** behaviour given stipulated operator behaviour. No
result is evidence that real operators would fail independently, and the drills are not
capable of producing such evidence.

Relay identity is derived from the relay id rather than generated per process, so a restarted
operator keeps its pinned key. That is needed to isolate one drill honestly: without it,
"honest but never acknowledged" would have been indistinguishable from "unpinned key", and
`restore-stopped-by-sole-honest-acknowledger` would have passed for the wrong reason. A real
operator would not hold a key this way.

## Run

```
cd poc/g3 && ./run-g3.sh
```

That runs the full suite on Chromium, then the portable suite on WebKit and Firefox, then
prints the per-engine table. Also:

```
cd poc/g3 && ./run-g3.sh gate-three-honest        # one drill, on $G3_ENGINE
cd poc/g3 && G3_ENGINE=webkit ./run-g3.sh --full  # the full suite on one engine
cd poc/g3 && G3_INSTALL=1 ./run-g3.sh             # force a browser (re)install
```

Exits nonzero only on an *unexpected* failure; an engine that will not launch is recorded
and the run continues. The only npm dependency is `playwright-core`; browsers come from
`node_modules/playwright-core/cli.js install chromium webkit firefox`, which is run
automatically when the cache is absent. Checks ports 18764 (page) and 18765 to 18767
(relays) before starting; override with `G3_WEB_PORT`, `RELAY_PORT`, `RELAY_PORT_B`,
`RELAY_PORT_C`. `G3_EXECUTABLE` overrides the browser binary for the selected engine.

## The oracle

A "share" is the scalar half of a Schnorr signature, `s = k + e*x mod q` over the Pallas
scalar field, with the commitment stood in by a hash of `k`. That is enough for the drills to
mean something, because reusing `k` really is catastrophic: two shares over one `k` with
different `e` give `x = (s1-s2)/(e1-e2)`, and `extractOnReuse` computes it. **Every drill ends
by running that oracle over the counterparty's view. A drill passes because no key could be
recovered, not because nothing printed an error.** None of this is a signature scheme.

## The protocol under test

`nonce-store.js`, seven steps. Every write requests `durability: 'strict'`, and each durable
step is its own transaction awaited to `complete`, so a crash always lands on a boundary.

```
0. refuse outright if strict durability is unsupported
1. WAL intent, carrying the package digest                     durable, strict
2. signed receipts from 2 DISTINCT pinned relays               network
3. WAL receipted, every receipt persisted                      durable, strict
4. consume: Spent + secret DELETED + phase consumed            ONE strict transaction
5. compute the share in memory
6. save the share: THE SHARE IS RELEASED HERE                  durable, strict
```

## Strict IndexedDB durability

Every `readwrite` transaction requests `durability: 'strict'`, which asks the browser to flush
to the operating system before reporting `complete` rather than the default `'relaxed'`, which
may report success while the write is still buffered.

**The probe is a real measurement per engine, in three parts**, because an engine can fail this
in two different ways:

| | chromium 153.0.8010.12 | webkit 26.6 | firefox |
|---|---|---|---|
| `'durability' in IDBTransaction.prototype` | true | true | not measured |
| options bag accepted (did it throw) | accepted | accepted | not measured |
| `transaction.durability` reads back | `strict` | `strict` | not measured |
| → treated as supported | **yes** | **yes** | not measured |

The middle row matters on its own. **An engine that accepts the options bag and then does not
reflect `strict` has silently ignored the request**, which is the most dangerous of the three
outcomes because it looks like success. The store treats that as unsupported, exactly as it
treats a throw.

What a page still cannot do: **verify the flush.** `strict` is the browser's own word for it,
not evidence about the disk.

### When it is unsupported, the platform is not counted as passing

```
durability-unsupported-is-not-a-pass   INCONCLUSIVE
    spend: refused durability_unsupported
           {"requested":"strict","optionsAccepted":false,"reflected":"threw: TypeError",
            "attrPresent":true,"supported":false,"policy":"fail_closed","simulated":true}
    acknowledgers: []
    shares released: 0
```

The store **fails closed**: `spend` refuses before touching a nonce and releases no share,
because every crash drill's conclusion rests on a committed transaction actually being on disk.

The suite reports this as **INCONCLUSIVE**, a status separate from pass and fail, excluded from
the pass count and named in the summary. The table's `cell()` gives `inconclusive` priority over
`ok` precisely so this drill cannot be counted as a pass even though its own assertion holds.

**`"simulated": true` is the important field.** That `TypeError` is produced by
`simulateNoStrictDurability()` inside this store. It exercises **this store's fail-closed path
and nothing else.** It is **not** evidence about Chromium, about WebKit, about Firefox, or about
any engine that genuinely lacks the option. No engine actually lacking `durability` has been
run: the one candidate, Firefox, would not launch, so its behaviour is unmeasured rather than
assumed.

Fail-closed also means a platform without strict durability **cannot sign at all**. That is the
safe answer and also an unsolved product problem.

## The receipt gate

```
gate-three-honest        PASS  share_saved, acknowledgers
                               ["relay-18765","relay-18766","relay-18767"], 1 released
gate-only-one-reachable  PASS  refused receipts_required
                               {"need":2,"got":["relay-18765"],
                                "errors":["Failed to fetch","Failed to fetch"]}
                               0 shares released
gate-relay-not-pinned    PASS  refused receipts_required
                               {"need":2,"got":["relay-18765"],
                                "errors":["receipt from an unpinned relay: relay-18766",
                                          "receipt from an unpinned relay: relay-18767"]}
                               0 shares released
```

**`gate-only-one-reachable` is the "no share with only one reachable relay" requirement.** One
reachable operator, a valid signed receipt from it, and nothing is released.

**`gate-relay-not-pinned` leaves all three relays healthy** and withholds only the pin. Still
refused: reachability is not trust.

## Approval succeeds with any one operator down

```
one-down-A  PASS  acknowledgers ["relay-18766","relay-18767"], 1 share released
one-down-B  PASS  acknowledgers ["relay-18765","relay-18767"], 1 share released
one-down-C  PASS  acknowledgers ["relay-18765","relay-18766"], 1 share released
```

Each of the three is taken out in turn, so the result does not depend on which one. The
threshold is met by the remaining two and the share is released.

## An operator going down between startup and receipt collection

```
down-after-startup-one  PASS  startup contacted 3 relay(s):
                              [{"relay-18765",0},{"relay-18766",0},{"relay-18767",0}]
                              THEN taken down: relay-18767
                              spend: share_saved, acknowledgers
                              ["relay-18765","relay-18766"], 1 released

down-after-startup-two  PASS  startup contacted 3 relay(s)
                              THEN taken down: relay-18766, relay-18767
                              refused receipts_required
                              {"need":2,"got":["relay-18765"],
                               "errors":["Failed to fetch","Failed to fetch"]}
                              0 shares released
```

**A first attempt at this drill was not testing anything.** It reported
`startup contacted 0 relay(s): {"decision":"fresh"}`, because the first startup on a brand new
profile returns `fresh` without contacting anybody, so the window the drill claimed to test did
not exist. The drill now runs startup a second time and **asserts** that it contacted every
live relay before taking any away; if it did not, the drill throws rather than passing.

**Finding: the startup check is advisory, and the receipt collection is the gate.** State
observed at startup is already stale by the time receipts are collected, and the store does not
depend on it: `down-after-startup-two` passes startup with three relays reported and then still
refuses, because the threshold is enforced where it matters.

## Duplicate and forged receipts never count as two

```
duplicate-same-relay-listed-twice  PASS  refused receipts_required
                                         {"need":2,"got":["relay-18765"],...}
impersonated-receipt-counts-once   PASS  refused receipts_required
                                         errors: ["bad receipt signature for
                                                   claimed id relay-18765", ...]
forged-signature-rejected          PASS  refused receipts_required
                                         errors: ["bad receipt signature for
                                                   claimed id relay-18766", ...]
tolerates-one-bad-operator         PASS  A honest, B forging, C honest
                                         share_saved by the other two
```

- **Duplicate:** the relay list contains the same operator twice. Distinctness is keyed on the
  relay id the signature verified under, so `got` collapses to one and the threshold is not met.
- **Impersonation:** relay B signs with its own key while claiming to be relay A. Verification
  runs against the key pinned for the *claimed* id, so it fails, and A's genuine receipt is the
  only one that counts.
- **Forgery:** relay B returns a well-formed receipt with a random signature. Rejected.
- **`tolerates-one-bad-operator` is the complement**, and it matters: a gate that is strict but
  unusable is not a design. With a third honest operator available, one forger is tolerated and
  the share is released by the other two.

## Receipts bind the exact commitment, epoch and package digest

Each case has a relay that signs a *valid* receipt naming something other than what was asked
for. All three are rejected and the error names the field:

```
receipt-binds-commitment  PASS  "receipt commitment_id does not bind this record:
                                 got 3b20afa994b24c0e-0-b, wanted 3b20afa994b24c0e-0"
receipt-binds-epoch       PASS  "receipt epoch_id does not bind this record:
                                 got not-the-epoch-you-as, wanted 7298292bb177b879"
receipt-binds-package     PASS  "receipt package_hash does not bind this record:
                                 got dbae87ad8c2412af822c, wanted 0ad2b3510857a2ae2f1c"
```

`rid` is checked the same way, so a receipt cannot be moved between records. The store checks
four things in order: the claimed id is pinned, the signature verifies under *that* key, and
`epoch_id`, `commitment_id`, `rid` and `package_hash` all equal what was requested. A valid
signature over something else is not an acknowledgement of this spend.

## Two tabs racing for one commitment

```
two-tabs-web-lock              PASS  A: share_saved / B: refused receipts_required
two-tabs-no-lock               PASS  A: share_saved / B: refused receipts_required
two-tabs-same-package-lock     PASS  A: share_saved / B: refused nonce_not_available
two-tabs-same-package-no-lock  PASS  A: refused nonce_not_available / B: share_saved
```

A wall-clock barrier puts both tabs inside the consume transaction at the same moment; without
it `Promise.all` only proves both renderers were busy, not that their transactions overlapped.

**With different messages the relays stop the race before the local check is reached**, because
an honest operator refuses a second receipt for a commitment it already acknowledged under a
different package. Those two drills therefore do not test the local check. The `same-package`
variants exist for that: both tabs sign the *same* message, the relays issue both receipts
because it is not a replay from their point of view, and the local compare-and-set is the only
thing left. It holds, and the refusal code changes to `nonce_not_available` to prove which check
fired.

**The Web Lock is still not what makes this safe.** `two-tabs-same-package-no-lock` removes
`navigator.locks` entirely and the outcome is unchanged, because the state check sits inside the
same `readwrite` transaction that performs the update and IndexedDB serializes those over one
store.

## Crashes around the write-ahead record and the share save

```
crash-after-wal           PASS  restart saw Generated/secret, wal=retired
                                retry refused nonce_not_available, 0 shares
crash-after-receipts      PASS  startup continue local=1, wal=retired
                                retry refused receipts_required, 0 shares
crash-after-receipt-save  PASS  startup continue, wal=retired
                                retry refused receipts_required, 0 shares
crash-after-consume       PASS  restart saw Spent/nosecret, wal=lost, 0 shares
crash-before-share-save   PASS  restart saw Spent/nosecret, wal=lost, 0 shares
hard-kill-after-consume   PASS  SIGKILL to 8 browser processes at the same boundary
                                restart saw Spent/nosecret, wal=lost, 0 shares
```

**A false positive was measured and fixed, not argued away.** An earlier run reported
`crash-after-receipts` as `rollback_detected` and burned a healthy epoch: receipts had been
issued but the record was still at `intent`, so the device's accounting did not include it while
the relays did. Safety was preserved, liveness was not. The fix is that **every** WAL record
counts toward what the device can account for, `intent` included, because a relay only ever
acknowledges a record the device wrote an intent for first.

**Detection compares sets, not counts.** A count can be inflated by the device itself; a named
commitment the device has no record of is positive evidence. The `unaccounted` field below names
them.

**A crash after consume loses the slot, and that is correct.** The secret is gone, no share was
saved, the WAL record ends `lost`. A store that kept the secret until the share was safely
written, to be helpful, would be the dangerous design.

**IndexedDB survived `SIGKILL` at that boundary.** One observation on one platform, not a
durability guarantee; the recovery pass does not rely on it.

## Restoration of old browser storage

A profile with two unspent nonces is copied out, both are spent (recording *which* relays
acknowledged), the shares are emitted, then the profile is copied back.

```
restore-three-honest                        PASS
    acknowledgers ["relay-18765","relay-18766","relay-18767"]
    startup: new_epoch, cause=rollback_detected, local=0
    all three reported acked=2, 4 unaccounted commitments named
    replay refused nonce_not_available, no reuse

restore-one-honest-one-lying                PASS
    acknowledgers ["relay-18765","relay-18766"]
    relay-18765 honest reported 2; relay-18766 lying reported 0, really acknowledged 2
    startup: new_epoch, cause=rollback_detected
    replay refused nonce_not_available, no reuse

restore-stopped-by-sole-honest-acknowledger PASS
    relay-18767 down during the spend, so acknowledgers = {18765 honest, 18766 lying}
    then 18766 taken down, and 18767 brought up honest with an EMPTY record
    acknowledgers still honest AND reachable: ["relay-18765"]
    startup: new_epoch, cause=rollback_detected,
             reported [{18765, acked 2}, {18767, acked 0}]
    replay refused nonce_not_available, no reuse

restore-no-acknowledger-reachable           PASS
    both acknowledgers taken down; 18767 up, honest, pinned, EMPTY record
    acknowledgers still honest AND reachable: []
    startup: degraded, cause=insufficient_relays
    replay refused receipts_required {"need":2,"got":["relay-18767"],...}
    no reuse

restore-all-acknowledgers-lying             EXPECTED FAILURE
    acknowledgers {18765 lying, 18766 lying}; 18767 honest, up, EMPTY record
    both liars reported acked=0 while really having acknowledged 2
    startup: continue
    replay: share_saved
    NONCE REUSE, signing key recovered: faad68c612fdd5f8d124b53640223a7a...
```

**The detection condition, stated precisely because the drills now isolate it: at least one
relay that ACKNOWLEDGED the original record must be honest and reachable now.**
`restore-stopped-by-sole-honest-acknowledger` reduces that to exactly one such relay and it is
enough.

**"One honest relay" is NOT the condition, and `restore-all-acknowledgers-lying` proves it.**
In that drill relay-18767 is honest, reachable and correctly pinned throughout the restart. It
cannot help, because it never acknowledged the record and so has nothing to report. The
acknowledgers are the only witnesses, and both are lying. The share is released and the key is
recovered.

**An earlier version of these two drills was not testing that.** The third relay was taken down
before the spend and never brought back, so the log showed it unreachable while the comment
claimed it had returned. It is now brought up with its pinned identity intact and an empty
record, which is what makes the isolation real.

**An outage no longer burns the epoch.** The earlier one-relay prototype started a new epoch on
every unreachable relay, discarding good inventory. With a threshold the device cannot spend
without the relays anyway, so `restore-no-acknowledger-reachable` returns `degraded`, keeps the
epoch, and refuses the replay for lack of receipts. Same safety outcome, inventory survives.

**A relay over-reports rather than under-reports.** In `restore-no-acknowledger-reachable`,
relay-18767 ends up having "really acknowledged 1": it recorded the replay attempt before the
threshold failed. Over-reporting is the safe direction for rollback detection, and it means a
relay's record includes attempts that never became shares.

## The one-relay baseline, kept because it fails

```
restore-one-relay-baseline   EXPECTED FAILURE
    threshold set back to 1, one lying operator
    spend 0: share_saved, acknowledgers ["relay-18765"]
    startup: continue, relay reported acked=0 while really having acknowledged 2
    replay: share_saved
    NONCE REUSE, signing key recovered: b4fa30ca222ea96dc94ca58237027cb2...
```

The threshold is a parameter, so this is the *same* drill at threshold 1. Keeping the one-relay
design runnable is the only thing that makes the 2-of-3 results above mean anything: without it,
a pass could be coming from any other change in this pass rather than from the threshold.

## Native Safari: NOT TESTED

Safari **27.0.1** is installed at `/Applications/Safari.app`. It was not automated, and no
Safari result is claimed anywhere in this document. Two independent reasons, both verified
rather than assumed:

**1. `safaridriver` has no profile isolation.** Its complete option set, from
`safaridriver --help` on this machine:

```
-h, --help        -p, --port        -b, --bidi
--enable          --diagnose        --mcp
```

There is no `--profile`, no `--user-data-dir`, and no equivalent. A WebDriver session
therefore runs against the user's **normal Safari profile**, which these drills must not
touch: they write an IndexedDB database, copy the profile directory out, and copy a stale
snapshot back over it. Running that against a real browsing profile is not an acceptable
test, so it was not run.

**2. Enabling it is a security-settings change.** `safaridriver --enable` "applies
configuration changes so that subsequent WebDriver sessions will run without further
authentication". That is a security setting on the user's machine and requires
authentication; I did not run it. `defaults read com.apple.Safari AllowRemoteAutomation`
returns `Domain 'com.apple.Safari' not found`, so remote automation is not currently
configured.

**Safari Technology Preview is not installed** (`/Applications/Safari Technology Preview.app`
absent). STP would be the honest route, since it keeps its own separate profile, so
automating it would not touch the normal Safari profile.

### To run it yourself

```sh
# Option A, preferred: Safari Technology Preview, which has its own profile
#   install from https://developer.apple.com/safari/technology-preview/
/Applications/Safari\ Technology\ Preview.app/Contents/MacOS/safaridriver --enable
/Applications/Safari\ Technology\ Preview.app/Contents/MacOS/safaridriver -p 18770

# Option B: native Safari. This USES YOUR NORMAL PROFILE. Do not do this on a profile
# you care about; use a separate macOS user account.
safaridriver --enable          # security-settings change, requires authentication
safaridriver -p 18770
```

Then drive it over plain WebDriver against `http://127.0.0.1:18764`; `playwright-core`
cannot drive native Safari. Note what still will not be testable that way: the
profile-restore drill needs the profile directory, and Safari's is under
`~/Library/Safari` and `~/Library/WebKit` with SIP and TCC protections, so a copy-out and
copy-back is not a simple `cp -R`. **Treat Safari as entirely untested until someone runs
it on a throwaway macOS user account.**

## Device cases: NOT TESTED

**Every case in this section is NOT TESTED.** None of them can be driven from this harness:
they need physical hardware, an OS-level backup, or a second device.

| device case | status | why it is not automatable here |
|---|---|---|
| physical power loss mid-write | **NOT TESTED** | needs the power actually cut; `SIGKILL` leaves the kernel page cache and the filesystem journal intact, which is the opposite of the case that matters |
| kernel panic | **NOT TESTED** | cannot be induced without weakening the machine |
| OS backup and restore (Time Machine / Finder) | **NOT TESTED** | needs a real backup target and a restore cycle |
| iCloud backup restore | **NOT TESTED** | needs an iOS device and an Apple ID |
| Quick Start / device transfer | **NOT TESTED** | needs two iOS devices |
| Android cloud backup restore | **NOT TESTED** | needs an Android device and a Google account |
| Android device transfer | **NOT TESTED** | needs two Android devices |
| app reinstall | **NOT TESTED** | no app; this prototype is a page |
| same-device restore | **NOT TESTED** | needs an OS restore path |
| low-memory tab discard | **NOT TESTED** | not inducible reliably from Playwright |
| browser storage eviction under pressure | **NOT TESTED** | needs the engine's quota manager driven to eviction |
| Safari ITP / 7-day storage eviction | **NOT TESTED** | needs native Safari over elapsed wall-clock time |

The two that decide whether the design is viable are power loss and backup restore. Both have
a short manual procedure below. Both are **reproducible by hand and have not been run.**

### Manual procedure A: physical power loss mid-write

What it decides: whether a transaction that IndexedDB reported `complete` under
`durability: 'strict'` is actually on the disk. Every crash drill in this document assumes it
is. `hard-kill-after-consume` cannot test it, because killing a process leaves the kernel's
page cache and the filesystem journal intact.

Needs: the test machine, and the ability to cut its power. A desktop on a switched outlet, or
a laptop with the battery removed, or a VM whose host can be hard-reset. Do not use a laptop
on battery: the OS will shut down cleanly.

```sh
# 1. On the test machine, in poc/g3:
#    start the relays and the page, and leave a browser open on a persistent profile.
G3_TMP=/tmp/g3-power G3_ENGINE=chromium node drills.mjs gate-three-honest
#    ^ confirms the toolchain works, then do the manual part:

# 2. Start the three relays by hand so they survive the browser.
RELAY_ID=relay-18765 RELAY_PORT=18765 RELAY_MODE=honest node relay.mjs &
RELAY_ID=relay-18766 RELAY_PORT=18766 RELAY_MODE=honest node relay.mjs &
RELAY_ID=relay-18767 RELAY_PORT=18767 RELAY_MODE=honest node relay.mjs &
#    and a static server for page.html on 18764 (python3 -m http.server 18764 works).

# 3. Open the page in a REAL browser on a throwaway profile, with the relay list and
#    pinned keys injected. Fetch each relay's key first:
curl -s localhost:18765/pubkey; curl -s localhost:18766/pubkey; curl -s localhost:18767/pubkey
#    then in the page console:
#      window.__RELAYS = [{relay_id:'relay-18765',base:'http://127.0.0.1:18765'}, ...]
#      window.__PINNED = [{relay_id:'relay-18765',spki:'<from /pubkey>'}, ...]
#    reload, then:
#      await __store.startup(); const g = await __store.generate(1);
#      await __store.spend('rid-1', g.ids[0], 'pay alice 1');
#      await __store.sharesOut()        // confirm one share exists

# 4. CUT THE POWER. Not a shutdown, not a reset button that signals the OS: the power.
#    Do it within a second or two of step 3 completing.

# 5. Power on, reopen the same profile, and read the store back:
#      await __store.states()           // expect the nonce Spent, has_secret false
#      await __store.walOut()           // expect phase 'saved'
#      await __store.sharesOut()        // expect the one share still present
#      await __store.startup()          // expect 'continue', NOT 'rollback_detected'
```

**PASS** means the nonce is still `Spent` with no secret, the WAL record still reads `saved`,
and the share is still there. **FAIL, and the important failure, is the nonce reading
`Generated` with its secret intact** while the relays still hold their acknowledgements: the
write was reported complete and did not survive, so `durability: 'strict'` did not mean what
the whole protocol assumes. Record the exact state and the engine version either way.

Repeat at least ten times, and separately with the cut placed between step 1 and step 2 of
the spend protocol, since that is where a lost write converts into a reusable nonce.

### Manual procedure B: OS backup and restore

What it decides: whether an OS-level restore reinstates the IndexedDB directory the way the
`restore-*` drills simulate with `cp -R`. The drills copy the profile directory; a real backup
may restore more, less, or differently, and may not restore IndexedDB at all.

Needs: a Time Machine target (or an iOS/Android device with its platform backup).

```sh
# 1. Fresh throwaway profile, three relays up, as in procedure A steps 2 and 3.
#    Generate two nonces and DO NOT spend them:
#      await __store.startup(); const g = await __store.generate(2); g.ids

# 2. Take a full OS backup now.
tmutil startbackup --block
tmutil latestbackup        # record the path

# 3. Spend both nonces, so the relays acknowledge them and shares are emitted:
#      await __store.spend('rid-0', g.ids[0], 'pay alice 0');
#      await __store.spend('rid-1', g.ids[1], 'pay alice 1');
#      await __store.sharesOut()      // record the two commitments
#    Leave the relays RUNNING. They are the witnesses.

# 4. Quit the browser. Restore ONLY the browser profile directory from the backup
#    taken in step 2, using Time Machine's restore UI or:
tmutil restore "<latestbackup>/<volume>/<path-to-profile>" /path/to/profile
#    Do not restore over your real profile. This is why step 1 says throwaway.

# 5. Reopen the same profile and check what the store now believes:
#      await __store.states()      // did the restore roll the nonces back to Generated?
#      await __store.walOut()      // is the WAL gone, or partially present?
#      await __store.startup()     // expect 'new_epoch' / 'rollback_detected'
#      await __store.spend('rid-replay', g.ids[0], 'pay mallory 99')   // must refuse
```

**PASS** means `startup()` reports `rollback_detected` from at least one relay naming a
commitment the restored store cannot account for, and the replay is refused. **FAIL** means
the replay produced a second share for a commitment the counterparty already holds one for;
in that case run `extractOnReuse` over both shares and record the recovered key, which is the
whole point of the oracle.

Three outcomes to record explicitly, because they are all informative and only one is the
case the drills model:

- the backup restored IndexedDB and the store rolled back → the drills' model is right
- the backup did not include IndexedDB → the attack is harder on this platform than modelled,
  and the reason should be recorded, not celebrated
- the backup restored IndexedDB **partially** (for example the WAL but not the nonce states,
  or a torn database) → **not modelled anywhere in this prototype**, and the most likely place
  for a real bug

## What G3 does NOT establish

- **Nothing about operator independence.** Three local processes sharing a kernel, a disk and a
  `kill` command are not three operators. The entire 2-of-3 argument rests on an assumption these
  drills are structurally unable to test.
- **No production nonce safety.** `restore-all-acknowledgers-lying` is a real exploit path and it
  is open. Two colluding acknowledgers defeat the gate completely.
- **G3 is PARTIAL until real device crash tests pass.** A renderer crash and a browser `SIGKILL`
  on desktop Chromium are not device crashes: no power loss, no kernel panic, no OS-level storage
  eviction, no low-memory tab discard, no filesystem corruption. The platform restore matrix
  (iCloud, Finder, Quick Start, Android cloud backup, Android device transfer, reinstall,
  same-device restore) is untouched.
- **The unsupported-durability result is simulated and is not evidence about any browser.**
  The `TypeError` comes from `simulateNoStrictDurability()` in this store. No engine actually
  lacking `durability` has been run; Firefox, the one candidate, would not launch.
- **Strict durability is requested and cannot be verified.** Chromium and WebKit both reflected
  `strict`; a page has no way to confirm a flush, and only physical power loss would.
- **Firefox is entirely unmeasured.** Two Playwright builds, six launch configurations and two
  direct binary invocations all failed; the exact commands and errors are tabulated above.
- **Playwright WebKit is not Safari.** Different networking stack, process model, storage
  backend configuration, ITP and eviction policy. The `webkit` column says nothing about Safari.
- **Native Safari is untested.** `safaridriver` has no profile-isolation flag, so a session
  would run against the user's real profile, and `--enable` is a security-settings change.
  Safari Technology Preview is not installed.
- **Renderer-crash injection exists only on Chromium.** `chrome://crash` has no WebKit or
  Firefox equivalent, so those boundaries are covered on other engines only by the
  process-kill drill, which is a different (harsher) failure mode. Recorded UNSUPPORTED rather
  than silently substituted.
- **The adversary model is still narrow.** A lying relay here only withholds and over-signs, plus
  the three targeted adversaries added for the binding drills. Not drilled: a relay that
  equivocates between devices, forks its view, replays another device's receipts, is honest at
  startup and lying at receipt time, or colludes on timing. Relay-to-relay collusion is drilled
  only as both simply lying.
- **Receipt canonicalization is prototype-grade.** Both sides build the signed object in the same
  key order and rely on `JSON.stringify`. A wallet needs a real canonical encoding with explicit
  domain separation.
- **Receipts carry no expiry and no device binding.** Nothing stops a receipt being presented
  later or on another device.
- **Relay identity is derived from the relay id.** Deliberate, so a restart keeps the pinned key
  and one drill can be isolated. Not how an operator should hold a key.
- **No signature scheme.** The Schnorr stand-in exists only so reuse is detectable. Not FROST,
  not rerandomized, not reviewed.
- **One operating system.** macOS 27.0.1 arm64 only. No Windows, no Linux, no iOS, no Android.
- **No device case of any kind has been tested.** See
  [Device cases: NOT TESTED](#device-cases-not-tested): power loss, kernel panic, Time Machine,
  iCloud, Quick Start, Android backup and transfer, reinstall, same-device restore, tab discard,
  storage eviction and Safari ITP are all unrun. The two that decide viability have manual
  procedures above and **have not been run**.
- **Nothing about G1.** Full G1 stays **BLOCKED (ZIP 2005)**: `qsk -> qk -> rivk_ext` is
  implemented nowhere and the ZIP is `Status: Proposed`.
- **No G4 or G5.** Second-device finishing and backup restore are not started.

## Where the real fix has to come from

A 2-of-3 threshold raises the bar from one honest party to one of three, and
`restore-all-acknowledgers-lying` is what it costs when two of them collude. It also narrows the
requirement in a way worth noticing: the honest party has to be one that *acknowledged*, so
adding operators only helps if they all acknowledge every record. Three directions, none
prototyped here:

1. **A hardware-backed, non-exportable, non-backed-up key store**, which is what
   `LOKI_IMPLEMENTATION_SPEC.md:179` already calls for on mobile and which a web page does not
   have.
2. **A non-rollback counter the page cannot forge**, held by a signing device the user carries,
   so a restored profile fails against something no relay can be talked out of.
3. **Accept rollback and remove the consequence**, by binding each commitment to one exact
   package at publication, so a replayed nonce can only ever reproduce the same share. The
   `same-package` race drills are an accidental first look at this: when the package matches, a
   second use is harmless, and the only reason it is still refused is the local nonce state.

Direction 3 is the only one available to a pure web wallet, and it needs no relays at all, which
is itself an argument for examining it before building more relay machinery.

## Files

```
g3/nonce-store.js   the store: the seven-step spend protocol, the receipt gate and its four
                    binding checks, the three-part strict-durability probe with a
                    fail-closed policy, recovery, startup, the reuse oracle
g3/page.html        loads the store; relays, pinned keys, the threshold and the
                    durability simulation are injected per page load
g3/relay.mjs        a simulated operator: Ed25519-signed receipts keyed to its relay id,
                    the honest replay refusal, and the adversarial modes (lying, forge,
                    impersonate, mismatch)
g3/drills.mjs       the drills; engine-parameterised by G3_ENGINE, with G3_SUITE=portable
                    for the five cross-engine categories. Writes a per-engine JSON summary
g3/summarise.mjs    builds the per-engine table from those summaries
g3/run-g3.sh        one command: chromium full, webkit and firefox portable, then the table
```

Engine builds used, for reproduction:

```
playwright-core 1.63.0
chromium 153.0.8010.12   ~/Library/Caches/ms-playwright/chromium-1243
webkit   26.6            ~/Library/Caches/ms-playwright/webkit-2359
firefox  155.0           ~/Library/Caches/ms-playwright/firefox-1543   (would not launch)
host     macOS 27.0.1 (Darwin 27.0), arm64
safari   27.0.1 installed, NOT TESTED
```
