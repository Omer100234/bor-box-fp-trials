# BOR-BOX Threat Catalog — Attacks and Their Designated Rules

**Source:** "BOR-BOX: DNS Security — Secure DNS Recursive Resolvers via Intelligent Queueing" (university workshop presentation). All attack descriptions and rules below are drawn from the presentation; slide titles are cited in each section. Rule syntax is the BOR-BOX rule language (`IF IN {record} THE {field} IS {regex} LIMIT/ALLOW`, volumetric `IF NUMBER OF … LIMIT/ALLOW`, and similarity `IF IN {record} EXACT/DIFF EXCEPT {field} LIMIT/ALLOW`), where LIMIT routes a packet to the rate-limited queue and ALLOW grants it the high-priority path — the system never hard-drops (slides "The Solution: Middlebox & Rate Limiting", "Path 1", "Path 2").

---

## 1. Volumetric QPS Flood

*Cited slides: "Why secure the Resolver?", "Experiment 1: Volumetric QPS", "First Defense Strategy: Exact Domain Whitelisting"*

**The attack.** The most basic resource-exhaustion vector: an attacker blasts thousands of queries per second — in the experiment, wildcard queries against a protected zone — to saturate the resolver's UDP socket buffers and worker threads. Legitimate queries are starved of concurrency slots, producing packet drops and client timeouts; in the deck's evaluation, availability under attack fell to 54% without BOR-BOX.

**Designated rules.** Exact-match whitelisting of the zone's real names, with everything else in the zone rate-limited:

```
IF IN dns_query QNAME IS www.example.com ALLOW
IF IN dns_query QNAME IS mail.example.com ALLOW
IF IN dns_query QNAME IS home.example.com ALLOW
IF IN dns_query QNAME IS *.example.com LIMIT
```

The deck's stated impact: legitimate traffic is processed at line rate while the flood matches the wildcard rule and is aggressively rate-limited; with BOR-BOX active, availability recovered to 95.2%.

## 2. DNS Water Torture (Random Subdomain Attack)

*Cited slides: "The DNS Water Torture Attack", "DNS Water Torture Detection in the Data Plane", "Detection of the DNS Water Torture Attack by Analyzing Features of the Subdomain Name (Takeuchi et al. 2016)", "Important Notes On The Rules", "Experiment 2: DNS Water Torture"*

**The attack.** Botnets generate millions of unique, non-existent subdomains under a victim zone (e.g. `abc123xyz.target.com`). Because every name is unique, the recursive resolver can never answer from cache and must forward each query, filling its lookup queues; the victim's authoritative servers are hammered with lookups for names that don't exist and burn resources emitting NXDOMAIN ("Name Error") responses. As resources degrade, the target stops answering legitimate queries — an NXDOMAIN storm that takes down the whole domain.

**The detection idea the rules encode** (Takeuchi et al. 2016): long subdomain names are rare in legitimate traffic, negative caching absorbs short-name attacks, so the attacker is *forced* into long, unique names. The deck's takeaways: a surge of NXDOMAIN errors signals attack; limit long subdomain prefixes; limit deep label stacks; treat a random-looking character mix as a bonus signal.

**Designated rules.**

```
1) IF IN QUESTION THE QNAME is ^[a-zA-Z0-9]{8,}+\.[^.]+\.[^.]+\.$ LIMIT
2) IF IN QUESTION THE QNAME IS ^([^.]+\.){4,}[^.]+\.[^.]+\.$ LIMIT
3) IF IN QUESTION THE QNAME IS ^[^.]*[0-9][^.]*[a-z][^.]*[0-9][^.]*\. LIMIT
```

Rule 1 targets long alphanumeric first labels, rule 2 deep label stacks (many dots), rule 3 the digit–letter–digit "random mix" signature. A simplified variant also appears: `^[a-zA-Z0-9]{8,}\..+\.$ LIMIT`.

**Companion ALLOW list.** The deck notes ("Important Notes On The Rules") that the long-prefix rule limits a lot of traffic known to be fine, so trusted CDN/cloud patterns are matched *before* it:

```
.*\.cloudfront\.net\.$  ALLOW   # AWS CloudFront
.*\.akamaiedge\.net\.$  ALLOW   # Akamai
.*\.akamai\.net\.$      ALLOW   # Akamai
.*\.akamaized\.net\.$   ALLOW   # Akamai
.*\.edgekey\.net\.$     ALLOW   # Akamai edge
.*\.edgesuite\.net\.$   ALLOW   # Akamai legacy
.*\.fastly\.net\.$      ALLOW   # Fastly
.*\.cloudflare\.net\.$  ALLOW   # Cloudflare
.*\.cdn\.cloudflare\.net\.$ ALLOW # Cloudflare CDN
.*\.azureedge\.net\.$   ALLOW   # Azure CDN
.*\.azurefd\.net\.$     ALLOW   # Azure
```

In the deck's evaluation, water torture without protection cut availability to 40.8%; with the rules active it returned to 100%.

## 3. Glueless-Referral Fan-Out — NXNSAttack & NRDelegation

*Cited slide: "glueless-referral fan-out attack (NXNSAttack & NRDelegation — Afek, Bremler-Barr et al., USENIX Security 2020 & 2023)"*

**The attack.** A malicious authoritative server answers with a referral listing many nameservers while omitting their glue (IP) records. Glue normally hands the resolver the nameservers' addresses so no extra lookups are needed; without it, the resolver must resolve every listed NS name, turning one query into a storm — NXNSAttack reaches over 1600× packet amplification. NRDelegation scales the variant: ~1,500 NS names pointing at a dead server force ~2n lookups and spike resolver CPU.

**Recognition** (per the deck): the damage is measurable in the fixed 12-byte header before parsing a single record — a referral rather than an answer (QR=1, AA=0), an authority section full of NS records (high NSCOUNT), and an additional section nearly empty of glue (small ARCOUNT).

**Designated rule** (one rule — four AND-joined conditions with a single action, as the deck stresses):

```
IF IN HEADER THE QR is 1        AND
IF IN HEADER THE AA is 0        AND
IF count of nscount > 10        AND
IF count of arcount < 10        LIMIT
```

The deck notes this rule alone would admit an arbitrarily large NSCOUNT — that gap is closed by the NS-referral cache-flood rule below (§5).

## 4. CNAME Chains for Cache Flooding — DNS CacheFlush (CNAME variant)

*Cited slides: "Cname Chains For Cache Flooding (The Flushing Attack — Afek, Bremler-Barr, Danino, Shavitt, USENIX Security '24)", "Mitigation And discussion"*

**The attack.** A malicious authoritative answers a query with a long CNAME chain, each name pointing to the next. A single query for the first name forces the resolver to follow and cache the *entire* chain — many records from one request — flooding the cache with junk, evicting legitimate entries, and denying service to real clients: every name in the chain occupies a cache slot.

**Recognition:** a response (QR=1) with an abnormally large ANCOUNT, read straight from the header.

**Designated rule.**

```
IF IN HEADER THE QR is 1  AND
IF count of ancount > 9   LIMIT
```

**Stated blind spot** (from the deck): high ANCOUNT has legitimate causes — round-robin address sets, large TXT records, and especially DNSSEC, where RRSIGs roughly double the count on signed responses. Because matching traffic is rate-limited rather than dropped, legitimate traffic is only slowed, not broken, and is barely affected when no attack is underway.

## 5. NS Referral for Cache Flooding — DNS CacheFlush (NS variant)

*Cited slides: "NS - referral For Cache Flooding", "Mitigation And discussion"*

**The attack.** Same family as §4, but the malicious authoritative answers with a *referral* — "ask these nameservers" — listing a huge number of NS names (the paper uses ~1,500). One query forces the resolver to ingest and cache the whole set; every referral name occupies a cache slot, evicting legitimate entries.

**Recognition:** a referral (QR=1, AA=0) with an abnormally large NSCOUNT, read without parsing. The deck notes it is the same packet shape as NXNS but exploited to fill the cache rather than force lookups — so no glue/ARCOUNT condition is needed.

**Designated rule.**

```
IF IN HEADER THE QR is 1     AND
IF count of nscount > 13     LIMIT
```

**Stated rationale for the threshold:** a high NSCOUNT has almost no legitimate cause — only root and TLD referrals carry many NS names, and those top out around 13, the classic limit that fits a 512-byte UDP response. Unlike the ANCOUNT rule this one rarely false-positives; a rare oversized legitimate delegation is slowed, not broken. This rule also closes the unbounded-NSCOUNT gap left by the NXNS rule (§3).

## 6. KeyTrap — Algorithmic-Complexity DoS on DNSSEC

*Cited slides: "KeyTrap: Algorithmic Complexity DoS Attacks on DNSSEC", "Mitigating KeyTrap: Defensive Rules"*

**The attack.** DNSSEC prioritizes availability: resolvers must exhaustively try all provided keys and signatures, matched only by weak, non-cryptographic 16-bit key tags. Four vectors exploit this — SigJam (many signatures, one key), LockCram (many keys, one signature), KeySigTrap (keys × signatures for an O(n²) explosion), HashTrap (parent-zone DS hash collisions). A single crafted packet with colliding tags triggers validation loops causing a ~2,000,000× spike in CPU instructions and can stall major resolvers like BIND9 for up to 16 hours; the real-world fix required vendors to deliberately cap validation contrary to the DNSSEC standard.

**Designated rules** (three variants, each capping the record volume that feeds the validation loop):

```
IF NUMBER OF DNSKEY > 10 LIMIT    # Key Overload Defense — SigJam & KeySigTrap
IF NUMBER OF RRSIG  > 10 LIMIT    # Signature Overload Defense — LockCram
IF NUMBER OF DS     > 10 LIMIT    # DS Record Constraints — HashTrap
```

## 7. TsuNAME — Cyclic Dependency Loop

*Cited slide: "The TsuNAME Attack - Cyclic Dependency Loop"*

**The attack.** Domains are configured (maliciously or by accident) with cyclically dependent records — domain A's nameserver is domain B, whose nameserver is domain A. A vulnerable recursive resolver chasing the cycle fires outgoing queries at rates observed up to 5,600 qps, exhausting CPU, memory, and outgoing UDP sockets and paralyzing service to legitimate clients.

**Designated rule** (similarity rule over the last K packets):

```
IF IN HEADER EXACT EXCEPT txid LIMIT
```

**Stated impact:** structural matches that vary only by transaction ID act as a circuit breaker — after a few identical round trips trip the similarity threshold, the runaway queries are diverted to the rate-limited queue; the resolver's loop technically continues but is throttled to a slow, manageable crawl.

## 8. TuDoor — Malformed-Logic Exploitation

*Cited slides: "The TuDoor Attack - Malformed Logic Exploitation", "Experiment 3: TuDoor Attack"*

**The attack.** TuDoor systematically exploits logic flaws in the pre-processing phase of DNS response handling using malformed response packets. Vulnerable software (BIND, PowerDNS) either abruptly terminates the waiting resolution state (DoS when the real answer is later dropped) or enters a CPU-draining loop parsing non-existent sections. The malformed shapes: QDCOUNT=0 (a "response" with no question section), QDCOUNT>1 (multiple questions, violating single-query resolution), or illegal consecutive dots (empty labels) injected into the name.

**Designated rule** (conditions joined as shown in the deck):

```
1) IF IN HEADER THE QR is 1                AND
2) IF NUMBER OF QUESTION_SECTION = 0       OR
3) IF NUMBER OF QUESTION_SECTION > 1       OR
4) IF IN QUESTION THE QNAME IS (\.\.+)     LIMIT
```

In the deck's evaluation, the attack drove availability to 0% unprotected; with the rule active it recovered to 46.9%.

## 9. SIG(0) Signature Flood — CPU Exhaustion via Signed Requests (CVE-2024-1975)

*Cited slide: "SIG(0) Signature Flood — CPU Exhaustion via Signed Requests" (ISC BIND 9 advisory, July 2024, CVSS 7.5 High)*

**The attack.** SIG(0) (RFC 2931) lets a client cryptographically sign a DNS *request* by appending a SIG record to the additional section. A resolver holding a DNSSEC-validated KEY record for the signer's zone verifies that signature. The attacker publishes a KEY in a zone they control, gets it cached once, then streams SIG(0)-signed queries: signing is cheap for the attacker, verification is expensive for the resolver, so a modest stream pins the CPU and starves legitimate clients. Remotely exploitable with no authentication; affects every BIND 9 branch from 9.0 through 9.18.27/9.19.24. The deck frames it as the request-side cousin of KeyTrap — same "the harder you try, the harder you fail" pattern, triggered by the query instead of the response.

**Designated rule.**

```
IF IN HEADER THE QR IS 0  AND
IF NUMBER OF SIG > 0      LIMIT
```

## 10. NSEC3 Algorithmic-Complexity CPU Exhaustion (CVE-2023-50868)

*Cited slide: "NSEC3 Algorithmic Complexity CPU Exhaustion"*

**The attack.** Attackers weaponize DNSSEC's authenticated denial of existence: they register a zone whose NSEC3 records use the maximum allowable hash iteration count, then flood a victim resolver with queries for non-existent subdomains of it. Validating each negative response forces the resolver into repeated SHA-1 computation at the attacker's inflated iteration count. One malicious NSEC3 response multiplies CPU instruction count by ~72×, and ~150 packets per second fully saturate the resolver's CPU, dropping up to 30% of legitimate traffic.

**Designated rule** (limits iterations to 10 or fewer, matching current best practice per the deck):

```
IF IN NSEC3 THE iterations IS ^(?:1[1-9]|[2-9]\d|\d{3,})$ LIMIT
```

The regex matches any iteration value of 11 or greater (11–19, 20–99, and 100+), routing those heavy packets to the rate-limited queue.

## 11. Resource Record Set (RRSet) Bloating

*Cited slide: "Resource Record Set (RRSet) Bloating"*

**The attack.** Rogue authoritative servers pack response packets with hundreds of fictitious resource records across the authority (NS) and additional (AR) sections — syntactically valid DNS hiding a volumetric memory-exhaustion payload. The resolver's parser must allocate contiguous buffers and internal structures for every record; delivered as a high-rate flood, this burns CPU on traversal and deserialization and drives socket starvation, memory exhaustion (OOM), and process crashes.

**Designated rule.**

```
1) IF IN HEADER THE QR IS 1   AND
2) ( IF NUMBER OF ns > 50     OR
3)   IF NUMBER OF ar > 50 )   LIMIT
```

**Stated impact:** the routing decision fires before memory-heavy parsing runs in user space, diverting bloated floods at near-zero computational overhead.

## 12. DNS Cache Poisoning — Spoofed-Response Race

*Cited slides: "DNS Cache Poisoning Attack", "Experiment 3: Rapid Cache Poisoning Guessing Race"*

**The attack.** An off-path attacker floods the resolver with forged replies racing the real authoritative answer. Each forged packet must guess two secrets — the UDP source port and the 16-bit transaction ID of the outstanding query — but one correct guess is enough: the first matching response is accepted and cached, and the late legitimate reply is never seen. Blast radius: a single successful forgery poisons every client behind the resolver.

**Designated rule** (same similarity mechanism as TsuNAME, applied to responses):

```
IF IN HEADER THE QR IS 1            AND
IF IN HEADER EXACT EXCEPT txid      LIMIT
```

**Stated trade-off** (quoted design position from the deck): once the similarity threshold trips, all subsequent forged guesses — along with the late-arriving legitimate response — are diverted to the rate-limited queue. This neutralizes the poisoning attempt but temporarily delays or drops the legitimate packet, converting the attack into a localized DoS. The deck's position: in DNS, integrity strictly outweighs availability — a DoS is a client timeout, while successful poisoning transparently compromises the whole downstream network; failing to resolve a domain is vastly preferable to silently serving a malicious one.

---

## Appendix A — Rule-to-attack cross-reference

| Rule (abbreviated) | Type | Attacks it is designated to stop |
|---|---|---|
| Exact QNAME ALLOW + `*.zone` LIMIT | DFA / regex | Volumetric QPS flood (§1); zone-scoped water torture (§2) |
| Takeuchi QNAME regexes 1–3 (+ simplified variant) | DFA / regex | Water torture (§2) |
| CDN/cloud ALLOW list (11 patterns) | DFA / regex | FP suppression companion to the water-torture rules (§2) |
| QR=1 ∧ AA=0 ∧ nscount>10 ∧ arcount<10 | Volumetric count | NXNSAttack / NRDelegation (§3) |
| QR=1 ∧ ancount>9 | Volumetric count | CacheFlush, CNAME-chain variant (§4) |
| QR=1 ∧ nscount>13 | Volumetric count | CacheFlush, NS-referral variant (§5); backstop for §3's NSCOUNT gap |
| DNSKEY>10 / RRSIG>10 / DS>10 | Volumetric count | KeyTrap: SigJam, KeySigTrap / LockCram / HashTrap (§6) |
| HEADER EXACT EXCEPT txid | Similarity (K-packets) | TsuNAME loop (§7); with QR=1, cache-poisoning race (§12) |
| QR=1 ∧ (QDCOUNT=0 ∨ QDCOUNT>1 ∨ QNAME `(\.\.+)`) | Count + regex | TuDoor (§8) |
| QR=0 ∧ SIG>0 | Volumetric count | SIG(0) flood, CVE-2024-1975 (§9) |
| NSEC3 iterations ≥ 11 (regex) | DFA / regex | NSEC3 CPU exhaustion, CVE-2023-50868 (§10) |
| QR=1 ∧ (ns>50 ∨ ar>50) | Volumetric count | RRSet bloating (§11) |

## Appendix B — Architectural context

All LIMIT actions route to the rate-limited queue rather than dropping ("The Solution", "The Queue System" slides): the design goal is zero false-positive service outages, so misclassified legitimate traffic is slowed, never broken. Regex rules execute on the DFA fast path (Path 1); count and similarity rules run in the stateful C-Python engine (Path 2), with the C layer parsing packets and maintaining history buffers and the Python layer evaluating thresholds and dictating queue routing.
