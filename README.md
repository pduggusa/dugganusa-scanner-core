# @dugganusa/threat-scanner-core

> The TIMI — Technology Independent Machine Interface. The shared IOC scanning engine every DugganUSA integration is a thin wrapper around.

Extract IPs, domains, hashes, CVEs, and `.onion` addresses from arbitrary text, then correlate them against the DugganUSA threat-intel platform — **1.10M+ IOCs** drawn from **15 external feed sources** plus our own first-hand detections, part of a corpus of **~17.9M documents across 44 indexes**.

Zero native dependencies. Node builtins only (`https`). Cross-platform. In-memory caching with configurable TTL.

---

## What's New in 1.2.0

- **Validated feed, not just a big feed.** The corpus this engine correlates against is now independently validated on three live, no-auth, durable endpoints — so you can check our work, not just take our word:
  - **Novelty** — [`/api/v1/feed-uniqueness`](https://analytics.dugganusa.com/api/v1/feed-uniqueness): most of our IOCs (~75%+ live) are **not** in ThreatFox.
  - **Timeliness** — [`/api/v1/kev-lead`](https://analytics.dugganusa.com/api/v1/kev-lead): we run roughly **31 days ahead** of CISA KEV.
  - **Accuracy** — [`/api/v1/spamhaus-validation`](https://analytics.dugganusa.com/api/v1/spamhaus-validation): Spamhaus independently corroborates the calls we contribute.
- **Supply-chain coverage.** The corpus now ingests **OSV malicious-package feeds for both npm and PyPI**, plus daily **GitHub Hunt** detection of malware-staging repos and install-time / build-time execution signatures — so a `lookupIOC()` on a package name has teeth.
- Doc and description figures aligned to the current **1.10M+** IOC count.

---

## Install

```bash
npm install @dugganusa/threat-scanner-core
```

## Usage

```js
const { extractIOCs, lookupIOC, lookupBatch, summarize } = require('@dugganusa/threat-scanner-core');

// Extract IOCs from text
const iocs = extractIOCs('Found C2 at 185.39.19.176 and welcome.supp0v3.com');

// Look up a single indicator
const result = await lookupIOC('185.39.19.176', { apiKey: 'dugusa_...' });

// Batch lookup (concurrency-controlled)
const results = await lookupBatch(['185.39.19.176', 'CVE-2026-21643'], { apiKey: 'dugusa_...' });
```

## API key required

The DugganUSA STIX/correlation feed is **API-key-enforced**. Anonymous requests return `401`; an unregistered Bearer token returns `429`. The free tier is a **free, registered key** — not anonymous access. Register for a key at [analytics.dugganusa.com](https://analytics.dugganusa.com), then pass it as `options.apiKey`.

## Exports

| Export | Purpose |
|---|---|
| `extractIOCs`, `findAllMatches`, `PATTERNS` | Pattern extraction (IPv4, domain, SHA256, CVE, `.onion`) |
| `lookupIOC`, `lookupBatch` | Correlate indicators against the IOC corpus |
| `aipmAuditUrl` | Build an AIPM audit URL for a domain |
| `lookupRelay`, `huntTorRelays`, `checkTorRelay` | Tor relay intelligence |
| `summarize`, `formatTable`, `formatMarkdown`, `formatJSON`, `formatRelay` | Output formatting |
| `clearCache`, `cacheStats` | Cache control |

## The Family

Every DugganUSA integration (VS Code, Chrome, CLI, Slack, Splunk, Raycast, Sentinel, and more) is a thin wrapper around this core. CLI: [`dugganusa-cli`](https://github.com/pduggusa/dugganusa-cli).

## License

MIT — see [LICENSE](LICENSE).

---

*Built in Minneapolis. Read-only. 95% epistemic ceiling. Receipts do the work.*
