# Changelog

## [1.3.2] - 2026-10-19

### Security
- **The 1.3.x fail-closed fix did not cover HTTP errors.** `httpGet` resolved any JSON body regardless of status, so a `401` (no key / unregistered key) or `429` (daily limit) returned `{ ok: true, status: 'not-found' }` and was cached for the TTL. Non-2xx now rejects, so these surface as `ok: false, status: 'unknown'`.

### Fixed
- `checkTorRelay` reported almost any IP as a Tor relay: `/tor/relays?q=` is a fuzzy search (`q=1.1.1.1` returns relay `89.247.27.1`). It now requires an exact address match.
- `lookupRelay(ip)` always returned "Relay not found": `/tor/relay/:id` takes a fingerprint, not an IP. It now resolves the IP via `checkTorRelay`.
- README install line: the package is not on the npm registry; install from GitHub.

All notable changes to `@dugganusa/threat-scanner-core` are documented here.

## [1.3.1] - 2026-09-29

### Security
- First tagged release carrying the 1.3.0 three-state result (`ok`/`status`): outages and non-2xx responses no longer read as clean. 1.3.0 was committed but never tagged.

### Changed
- Refreshed corpus figures from the live `/api/v1/search/stats` (1.9M+ IOCs, ~68M documents across 70 indexes).
- Removed the retired "275+ consumers in 46 countries" line. It counted blocked, User-Agent-less scrapers as consumers, so we stopped quoting it on 2026-05-30.

## [1.2.2] - 2026-06-30

### Fixed
- Aligned in-tool/runtime IOC-count strings to 1.5M+ (the v1.2.1 docs refresh updated the README but missed the strings the tool prints at runtime).

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
