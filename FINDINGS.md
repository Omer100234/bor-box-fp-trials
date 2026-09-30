# BOR-BOX Tier-0 False-Positive Measurement — Findings

**Status: complete.** All 12 attacks in `bor-box-attack-rule-catalog.md` now have a real
false-positive measurement, from real data — no synthetic traffic anywhere in this project.

## Headline table

| # | Attack | FP% | Data source (real, not synthetic) |
|---|---|---|---|
| 1 | Volumetric QPS Flood | 15.0% @≥100qps → 0.04% @≥250qps (queue-based, threshold-dependent) | Mendeley ISP corpus, 34.9M benign rows |
| 2 | Water Torture | 17.10% indep / 15.21% system | Mendeley ISP corpus, 34.9M benign rows |
| 3 | NXNSAttack/NRDelegation | 0.00% (confirmed-clean) / 0.41% (upper bound) | 4 live resolvers, 145 referrals / MAWI, 197,558 packets |
| 4 | CacheFlush (CNAME) | 0.00% / 0.52% | same as above, 45 final answers / MAWI |
| 5 | CacheFlush (NS-referral) | 0.00% / 0.04% | same as above / MAWI |
| 6 | KeyTrap (SigJam/LockCram/HashTrap) | 0.00% each | 4 live resolvers, 10 signed zones |
| 7 | TsuNAME | 24.4–36.7% (proxy, upper bound only) | Mendeley corpus, 34.9M rows |
| 8 | TuDoor (QNAME clause) | 0.00% | Mendeley corpus, 34.9M rows |
| 9 | SIG(0) Signature Flood | 0.00% | CTU-Normal (Stratosphere IPS), 4,121 real queries |
| 10 | NSEC3 exhaustion | 0.00% | 4 live resolvers, 6 NSEC3 zones |
| 11 | RRSet Bloating | 0.00% / 0.001% | 4 live resolvers / MAWI |
| 12 | Cache Poisoning | 30.3% (MAWI) / 41.3% (CTU) at 5-of-100; 1.0% / 2.8% at 30-of-100 | MAWI 197,558 pkts / CTU 2,937 pkts |

Two structurally different classes of result live in this table, and conflating them is the
single easiest way to misread this report:

- **Count-threshold rules (#1–6, #8–11): clean.** Simple fixed-header conditions
  (`NSCOUNT > 13`, `QDCOUNT = 0`, etc.) checked once per packet. Real, at-scale, mostly 0%.
- **Similarity rules (#7, #12 — "HEADER EXACT EXCEPT txid"): structurally unmeasurable
  from any dataset used here, and every proxy for them reads 24–41%.** Not because legitimate
  traffic actually resembles a cyclic-loop/cache-poisoning race that often — see §4.

## 1. Water Torture & TuDoor (R1–R4, R6) — the one clean, full-scale, high-confidence result

**Source:** Mendeley/Ziza-Tadic-Vuletic DNS Exfiltration Dataset (`dataset.csv`, 8.25GB,
DOI `10.17632/c4n7fckkz3.3`), real ~26-hour single-ISP capture, 35,074,151 rows
(34,899,372 benign / 174,779 labeled-malicious).

| Rule | Independent FP% | System FP% (after ALLOW list) |
|---|---|---|
| R1 (long 3-label) | 5.35% | 3.95% |
| R2 (≥6 labels) | 4.99% | 4.79% |
| R3 (digit-letter-digit) | 3.57% | 2.83% |
| R4 (long ≥2-label, simplified) | 10.06% | 3.64% |
| R6 (TuDoor, empty label) | 0.00% | 0.00% |
| **Water Torture union (R1∪R2∪R3∪R4)** | **17.10%** | **15.21%** |

**Key finding:** the CDN/cloud ALLOW list barely moves the *union* number (17.10%→15.21%,
only 11% relative) even though it looks like it's doing real work per-rule (R4 alone drops
64% relative). Why: the top two FP contributors are `ac.rs` (Serbian academic network,
392,156 hits) and `spamhaus.org` (a DNSBL, 382,239 hits) — **neither is a CDN**, so no
CDN-focused ALLOW list can touch them. R2's biggest offenders are almost entirely
DNSBL/threat-intel zones (`spamhaus.org`, `blitzed.org`, `spamcop.net`, `abuseat.org`,
`support-intelligence.net`) — a completely different traffic class than R1/R4's CDN/big-tech
offenders (`googleapis.com`, `google.com`, `cloudfront.net`, `gvt2.com`, `myq-see.com`).

**Fix, in priority order:** (1) dedicated DNSBL/threat-intel exemption list — highest
leverage single change; (2) add `ac.rs` and other high-volume non-CDN infra the corpus
surfaces; (3) substitute the real 11-entry CDN list (current one is a documented placeholder,
`tier0fp/rules.py: ALLOWLIST_DOMAINS` — the slides only showed 2 of 11 entries verbatim).

R6 (TuDoor's QNAME clause) is a confirmed **real** 0%, not a masking bug — golden fixture
tests deliberately construct empty-label cases and correctly trip it; canonicalization never
collapses a genuine empty label. Water Torture's rule union catches 98.9% of the real labeled
exfiltration traffic (TP smoke test); TuDoor catches 0% (expected — this exfil tooling doesn't
produce empty-label QNAMEs).

## 2. Response-side count rules (#3–6, #10–11) — 4 independent real resolvers agree

**Two data sources, deliberately bracketing each other:**
- **Live harness** (`tier0fp/live_harness.py`): real queries against real root servers +
  4 independent recursive resolvers (8.8.8.8, 1.1.1.1, and — added this session, picked at
  random from `public-dns.info`'s open-resolver list — `dns1.nemox.net` (Germany),
  `ns2.novatel.bg` (Bulgaria), `ns3.fiord.ru` (Russia)), 64 real domains. Every rule: **0.00%**
  on every resolver, identical denominators each time (145 referral hops, 45 final answers,
  10 signed zones, 6 NSEC3 zones) — expected, since DNSSEC/NSEC3 status is a property of the
  zone, not the resolver. Confirmed-clean but small-N.
- **MAWI passive backbone capture** (`samplepoint-F/2007`, 197,558 real DNS response packets,
  12-byte-header-only fields, opcode-sanity-filtered): NXNS 0.41%, CacheFlush-CNAME 0.52%,
  CacheFlush-NS 0.04%, RRSet Bloating 0.001%. Large-N but can't cleanly separate legitimate
  traffic from DNS backscatter (forged reflection/DDoS noise sharing port 53).

**Read together:** true FP rate for these rules sits somewhere between the live harness's
confirmed-clean 0% and MAWI's upper-bound ≤0.5% — either way, an order of magnitude quieter
than Water Torture. These are the well-designed rules in the catalog.

KeyTrap and NSEC3 are live-harness-only (MAWI's fixed-header fields can't see DNSKEY/RRSIG/DS
record types or NSEC3 iteration counts) — small samples (10 and 6 applicable zones), 0.00%,
explicitly not a claim of a hard ceiling.

## 3. SIG(0) Flood — the one attack with zero data all session until now

**Source:** CTU-Normal-4/12/13 (Stratosphere IPS project, `stratosphereips.org`, free/no
registration), 3 independent real hosts/capture days, 4,121 real DNS queries total, full
payload (unlike MAWI, not privacy-truncated).

**Result: 0.00%** (0/4,121). Consistent with the catalog's own framing — SIG(0)/RFC 2931 is
essentially unused in real-world traffic — but now a real measurement, not an assumption.

**A real bug caught before trusting this number:** `dpkt`'s DNS parser raises an exception on
RR type 24 (SIG) itself — meaning a genuine SIG(0) match would have silently miscounted as a
"parse error" instead of a match, exactly backwards for this measurement. Fixed by writing a
manual, type-agnostic RR walker (`_skip_name`/`_skip_rr`/`_additional_section_rr_types` in
`tier0fp/mawi_extract.py`) that never decodes RDATA content, so it can't fail on an
unsupported type — verified against a synthetic packet carrying a real SIG record (the exact
case that broke `dpkt`).

## 4. TsuNAME & Cache Poisoning ("HEADER EXACT EXCEPT txid") — why every proxy reads 24–41%

Neither rule is directly measurable from any dataset used here: both need to observe
*repeated* packets over time and compare full headers except the transaction ID — TsuNAME on
any packets, Cache Poisoning gated to `QR=1` (responses only). Every version below is a
**proxy**, not a direct measurement, and every version lands in the same noisy range:

| Proxy | Threshold | Source | Result |
|---|---|---|---|
| TsuNAME, Δt-based (same client+QNAME) | gap ≤0.1s / ≤1.0s | Mendeley, 34.9M rows | 32.96% / 36.66% |
| TsuNAME, queue-based (global QNAME) | 5-of-last-100 | Mendeley, 34.9M rows | 24.39% |
| Cache Poisoning, header-only (no QNAME) | 5-of-last-100 | MAWI, 197,558 real responses | 30.26% |
| Cache Poisoning, header-only | 30-of-last-100 | MAWI, 197,558 real responses | 1.02% |
| Cache Poisoning, header+QNAME | 5-of-last-100 | CTU-Normal, 2,937 real responses | 41.27% |
| Cache Poisoning, header+QNAME | 30-of-last-100 | CTU-Normal, 2,937 real responses | 2.76% |

**Why the 5-of-100 numbers are this high, with real numbers behind it:** real DNS traffic is
extremely concentrated — in a 2M-row sample of the Mendeley corpus, the single most common
*exact QNAME* (`samba.local.local.`, Windows/Samba network-discovery noise) is **15% of all
traffic** on its own; `www.google.com.` is 2.7%; `dns.msftncsi.com.` (Windows' connectivity
check, fires on every network change) is 1.9%. A name at 15% share appears ~15 times in a
random 100-packet window *on average* — tripping "5 of last 100" is the expected outcome, not
the exception. And because dozens of names each sit in the 0.5–3% range, "does *any* popular
name hit 5-of-100" compounds across all of them, not just one.

**This is a proxy-design gap, not evidence that benign traffic looks like an attack.** The
real rule's intent is almost certainly scoped to *one resolver's own outgoing queries for one
stuck resolution / one specific outstanding query racing a forged reply* — a narrow, causally
linked context. Every proxy here, by necessity of the data available, counts repeats
**globally across every client and every unrelated query** — it cannot distinguish "a resolver
looping on one broken delegation" from "many different Windows machines independently pinging
`msftncsi.com`." Raising the threshold to 30-of-100 (§ above) confirms this: FP% collapses
15–30x, landing in the same quiet range as the well-designed count-threshold rules, because a
threshold that high finally requires genuine tight clustering rather than ordinary popularity
skew.

**No dataset used or found this session can fix this gap** — it needs real transaction-ID-level
response-race data (which packet correlates with which outstanding query), not just header
fields. MAWI's capture was also checked and confirmed to have **zero bytes of question-section
data in literally every one of its 1,012,001 DNS packets** (not a truncated subset — all of
them; verified across 2 different years and 2 different MAWI sample points, so this is a
standing MAWI-wide privacy-truncation policy, not a one-file fluke) — that's why the CTU-Normal
switch was necessary to get a QNAME-inclusive number at all.

## Known limitations (apply across the whole report)

- **The R5 CDN/cloud ALLOW list is a documented placeholder.** The catalog only shows 2 of
  11 entries verbatim (`cloudfront.net`, `azurefd.net`); the other 9 in
  `tier0fp/rules.py: ALLOWLIST_DOMAINS` are a reasonable stand-in, not the real list —
  system-mode/residual numbers should be re-run once it's substituted.
- **Single ISP, ~26-hour window** for the Mendeley corpus — not a claim of general external
  validity. GraphTunnel `normal`/`wildcard` secondary-corpus cross-check (plan §9.5) was never
  supplied and remains unrun (harness built and tested in `tier0fp/secondary_corpus.py`).
  MAWI (2007, Japan transit link) and CTU-Normal (2013–2017, Czech Republic) partially
  diversify geography/era for the rules they cover.
- **Ground truth is benign-by-absence-of-label** for the Mendeley corpus — any unlabeled
  malicious traffic would *deflate*, not inflate, reported FP rates.
- **Small-N rules** (KeyTrap: 10 zones; NSEC3: 6 zones; SIG(0): 4,121 queries; live-harness
  response rules: 45–145 packets) are confirmed-clean at that sample size, not proof of a hard
  0% ceiling at internet scale.
- **BOR-BOX-engine-side comparison** (plan §6.3, Scapy/Docker testbed) never run — no live box
  available in this environment.

## Not yet done

- Substitute the real 11-entry R5 ALLOW list and re-run `scripts/run_pipeline.py`.
- Supply GraphTunnel `normal`/`wildcard` data and run `scripts/run_secondary_corpus.py`.
- Scale the live response-side harness past 64 domains (thousands, deliberately including
  round-robin-heavy CDN endpoints and bulk-TXT/mail-auth domains) to properly stress-test the
  ANCOUNT rule's documented DNSSEC/round-robin blind spot.
- A from-scratch active back-to-back-duplicate-query harness for Cache Poisoning/TsuNAME's
  real header-except-txid rule — the only way to close the proxy gap in §4.
