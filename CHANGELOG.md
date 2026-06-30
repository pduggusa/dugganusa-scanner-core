# Changelog

All notable changes to `@dugganusa/threat-scanner-core` are documented here.

## [1.2.1] - 2026-06-30

### Added
- Documented the fourth live validation axis — Liveness (`/api/v1/feed-efficacy`).

### Changed
- Refreshed IOC corpus copy to 1.5M+ IOCs (~1.57M live) and ~38M documents across 65 indexes.
- Reworded the Timeliness validation reference to point at the live kev-lead ledger instead of a fixed "~31 days ahead" average.

## [1.2.0] - 2026-06-27

### Added
- **README.md** — first published README for the core engine.
- **Feed-validation surfacing.** Documented the three live, no-auth, durable validation endpoints the correlation corpus is measured on: novelty (`/api/v1/feed-uniqueness`, ~75%+ of our IOCs not in ThreatFox), timeliness (`/api/v1/kev-lead`, ~31 days ahead of CISA KEV), and accuracy (`/api/v1/spamhaus-validation`).
- **Supply-chain corpus note.** Corpus now ingests OSV malicious-package feeds for npm + PyPI, plus daily GitHub Hunt detection of malware-staging repos and install-time/build-time execution signatures.

### Changed
- IOC corpus figures aligned to **1.10M+** across `package.json`, `index.js`, and `api.js` (were `1.08M+` / `1M+`).
- README documents that the feed is **API-key-enforced** (anonymous → 401, unregistered Bearer → 429); free tier is a free registered key.

## [1.1.0]

### Added
- Tor relay helpers (`lookupRelay`, `huntTorRelays`, `checkTorRelay`).
- `.onion` address extraction.
- In-memory lookup cache with configurable TTL (`clearCache`, `cacheStats`).
