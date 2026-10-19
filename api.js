/**
 * DugganUSA API client — lookup and correlate indicators against the DugganUSA IOC index (live counts: /api/v1/search/stats).
 *
 * Uses only Node builtins (https module). No native deps. Cross-platform.
 * Includes in-memory cache with configurable TTL.
 */

const https = require('https');

const DEFAULT_API_URL = 'https://analytics.dugganusa.com/api/v1';
const DEFAULT_CACHE_TTL = 300000; // 5 minutes
const DEFAULT_TIMEOUT = 10000;    // 10 seconds

// In-memory cache: Map<string, { ts: number, result: object }>
const cache = new Map();

/**
 * Make an HTTPS GET request and return parsed JSON.
 * @param {string} url
 * @param {Object} headers
 * @param {number} timeout
 * @returns {Promise<Object>}
 */
function httpGet(url, headers = {}, timeout = DEFAULT_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers, timeout }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        // A 401 (no/unregistered key), 429 (daily limit) or 5xx carries a parseable JSON error
        // body with no correlations. Resolving it made lookupIOC return ok:true/not-found (and
        // cache it) for every keyless call, defeating the fail-closed signal. Reject instead.
        if (res.statusCode < 200 || res.statusCode >= 300) {
          let msg = 'HTTP ' + res.statusCode;
          try { const j = JSON.parse(body); if (j.error) msg += ' (' + j.error + ')'; } catch {}
          const err = new Error(msg); err.statusCode = res.statusCode;
          return reject(err);
        }
        try { resolve(JSON.parse(body)); }
        catch { reject(new Error('Invalid JSON response')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
  });
}

/**
 * Look up a single IOC against the DugganUSA correlation API.
 *
 * @param {string} value - IP, domain, hash, or CVE
 * @param {Object} [options]
 * @param {string} [options.apiKey] - DugganUSA API key
 * @param {string} [options.apiUrl] - API base URL
 * @param {number} [options.cacheTTL] - cache TTL in ms
 * @param {number} [options.timeout] - request timeout in ms
 * @returns {Promise<{found: boolean, hits?: number, data?: Object}>}
 */
async function lookupIOC(value, options = {}) {
  const apiUrl = options.apiUrl || DEFAULT_API_URL;
  const cacheTTL = options.cacheTTL || DEFAULT_CACHE_TTL;
  const timeout = options.timeout || DEFAULT_TIMEOUT;

  // Check cache
  const cacheKey = value.toLowerCase();
  const cached = cache.get(cacheKey);
  if (cached && Date.now() - cached.ts < cacheTTL) {
    return { ...cached.result, fromCache: true };
  }

  try {
    const url = new URL(apiUrl + '/search/correlate');
    url.searchParams.set('q', value);

    const headers = {};
    if (options.apiKey) headers['Authorization'] = 'Bearer ' + options.apiKey;

    const json = await httpGet(url.toString(), headers, timeout);
    const correlations = json.data?.correlations || {};
    const totalHits = Object.values(correlations)
      .reduce((sum, hits) => sum + (Array.isArray(hits) ? hits.length : 0), 0);

    const result = totalHits > 0
      ? { found: true, ok: true, status: 'found', hits: totalHits, data: correlations }
      : { found: false, ok: true, status: 'not-found', hits: 0 };

    cache.set(cacheKey, { ts: Date.now(), result });
    return result;
  } catch (err) {
    // FAIL-CLOSED SIGNAL (2026-07-19). Previously an expired key, a 429, a
    // timeout, or an outage all returned { found: false } — indistinguishable
    // from a verified-clean lookup. Consumers filtering on `found` therefore
    // turned a CI security gate GREEN during an outage.
    // `found` is retained for backwards compatibility, but `ok:false` and
    // status:'unknown' let callers refuse to pass on absence of evidence.
    return { found: false, ok: false, status: 'unknown', hits: 0, error: err.message };
  }
}

/**
 * Batch lookup — correlate multiple IOCs with concurrency control.
 *
 * @param {string[]} values - array of IOC values
 * @param {Object} [options] - same as lookupIOC options + concurrency
 * @param {number} [options.concurrency] - max parallel requests (default: 5)
 * @returns {Promise<Array<{value: string, found: boolean, hits?: number, data?: Object}>>}
 */
async function lookupBatch(values, options = {}) {
  const concurrency = options.concurrency || 5;
  const results = [];
  const queue = [...values];

  async function worker() {
    while (queue.length) {
      const value = queue.shift();
      const result = await lookupIOC(value, options);
      results.push({ value, ...result });
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, values.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Run an AIPM audit for a domain.
 *
 * @param {string} domain
 * @param {Object} [options]
 * @returns {Promise<{url: string}>}
 */
function aipmAuditUrl(domain) {
  const clean = domain.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '');
  return 'https://aipmsec.com/audit.html?domain=' + encodeURIComponent(clean);
}

/**
 * Clear the lookup cache.
 */
function clearCache() {
  cache.clear();
}

/**
 * Get cache stats.
 */
function cacheStats() {
  return { size: cache.size, entries: [...cache.keys()] };
}

/**
 * Look up a Tor relay by IP address.
 *
 * @param {string} ip - relay IP address
 * @param {Object} [options]
 * @param {string} [options.apiKey] - DugganUSA API key
 * @param {string} [options.apiUrl] - API base URL
 * @param {number} [options.timeout] - request timeout in ms
 * @returns {Promise<Object>}
 */
async function lookupRelay(ip, options = {}) {
  // /tor/relay/:id takes a relay FINGERPRINT, so passing an IP always returned 404
  // "Relay not found". Resolve the IP through /tor/relays (exact address match) instead.
  const r = await checkTorRelay(ip, options);
  if (r.error) return { found: false, ok: false, status: 'unknown', error: r.error };
  return r.isRelay
    ? { found: true, ok: true, status: 'found', relay: r.data }
    : { found: false, ok: true, status: 'not-found' };
}

/**
 * Hunt for suspicious Tor relays.
 *
 * @param {Object} [options]
 * @param {string} [options.apiKey] - DugganUSA API key
 * @param {string} [options.apiUrl] - API base URL
 * @param {number} [options.timeout] - request timeout in ms
 * @returns {Promise<Object>}
 */
async function huntTorRelays(options = {}) {
  const apiUrl = options.apiUrl || DEFAULT_API_URL;
  const timeout = options.timeout || DEFAULT_TIMEOUT;

  try {
    const url = apiUrl + '/tor/hunt';
    const headers = {};
    if (options.apiKey) headers['Authorization'] = 'Bearer ' + options.apiKey;

    return await httpGet(url, headers, timeout);
  } catch (err) {
    return { found: false, ok: false, status: 'unknown', error: err.message };
  }
}

/**
 * Quick boolean check if an IP is a known Tor relay.
 *
 * @param {string} ip - IP address to check
 * @param {Object} [options]
 * @param {string} [options.apiKey] - DugganUSA API key
 * @param {string} [options.apiUrl] - API base URL
 * @param {number} [options.timeout] - request timeout in ms
 * @returns {Promise<{isRelay: boolean, data?: Object, error?: string}>}
 */
async function checkTorRelay(ip, options = {}) {
  const apiUrl = options.apiUrl || DEFAULT_API_URL;
  const timeout = options.timeout || DEFAULT_TIMEOUT;

  try {
    const url = new URL(apiUrl + '/tor/relays');
    url.searchParams.set('q', ip);
    url.searchParams.set('limit', '5');

    const headers = {};
    if (options.apiKey) headers['Authorization'] = 'Bearer ' + options.apiKey;

    const json = await httpGet(url.toString(), headers, timeout);
    // The search is fuzzy: q=1.1.1.1 returns relay 89.247.27.1 as its top hit. Only an exact
    // address match is a relay; anything else reported every IP-shaped string as Tor.
    const hits = json.data?.hits || json.data?.relays || [];
    const match = hits.find(h => h.address === ip || h.ip === ip) || null;
    return { isRelay: !!match, data: match };
  } catch (err) {
    return { isRelay: false, error: err.message };
  }
}

module.exports = { lookupIOC, lookupBatch, aipmAuditUrl, clearCache, cacheStats, lookupRelay, huntTorRelays, checkTorRelay, DEFAULT_API_URL };
