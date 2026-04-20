/**
 * IOC pattern extraction — the shared regex engine for all DugganUSA integrations.
 *
 * Patterns match IPv4, domains, SHA256 hashes, and CVE IDs.
 * Skip sets filter known-safe values to reduce false positives.
 * extractIOCs(text) is the primary export — returns deduped matches with indices.
 */

const PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ai|dev|xyz|info|biz|co|me|app|cloud|online|site|tech|ru|cn|ir|kp|de|fr|nl|uk|au|br|jp|kr|sg|il|sa|ae)\b/gi,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  cve: /CVE-\d{4}-\d{4,7}/gi,
  onion: /\b[a-z2-7]{56}\.onion\b/g,
};

const SKIP_IPS = new Set([
  '0.0.0.0', '127.0.0.1', '255.255.255.255',
  '10.0.0.1', '10.0.0.0', '10.255.255.255',
  '192.168.0.1', '192.168.1.1', '192.168.0.0',
  '172.16.0.1', '172.16.0.0',
  '8.8.8.8', '8.8.4.4',       // Google DNS
  '1.1.1.1', '1.0.0.1',       // Cloudflare DNS
  '9.9.9.9',                   // Quad9
  '208.67.222.222', '208.67.220.220', // OpenDNS
]);

const SKIP_DOMAINS = new Set([
  'github.com', 'google.com', 'microsoft.com', 'apple.com',
  'amazon.com', 'cloudflare.com', 'mozilla.org', 'apache.org',
  'example.com', 'localhost', 'test.com',
  'npmjs.com', 'nodejs.org', 'pypi.org',
  'w3.org', 'schema.org', 'iana.org',
  'dugganusa.com', 'analytics.dugganusa.com', 'aipmsec.com',
  'security.dugganusa.com', 'epstein.dugganusa.com',
  'youtube.com', 'twitter.com', 'facebook.com', 'linkedin.com',
  'stackoverflow.com', 'wikipedia.org', 'reddit.com',
]);

/**
 * Find all regex matches in text with their indices.
 * Uses matchAll to avoid platform-specific issues.
 * @param {string} text
 * @param {RegExp} pattern - must have global flag
 * @returns {Array<{value: string, index: number}>}
 */
function findAllMatches(text, pattern) {
  const results = [];
  for (const m of text.matchAll(pattern)) {
    results.push({ value: m[0], index: m.index });
  }
  return results;
}

/**
 * Extract all IOC candidates from text.
 * Returns deduplicated array of { value, type, index }.
 *
 * @param {string} text - the text to scan
 * @param {Object} [options]
 * @param {Set} [options.skipIPs] - additional IPs to skip
 * @param {Set} [options.skipDomains] - additional domains to skip
 * @returns {Array<{value: string, type: string, index: number}>}
 */
function extractIOCs(text, options = {}) {
  const skipIPs = options.skipIPs || SKIP_IPS;
  const skipDomains = options.skipDomains || SKIP_DOMAINS;
  const iocs = [];

  for (const [type, regex] of Object.entries(PATTERNS)) {
    const matches = findAllMatches(text, regex);
    for (const match of matches) {
      const value = match.value;
      if (type === 'ipv4' && skipIPs.has(value)) continue;
      if (type === 'domain' && skipDomains.has(value.toLowerCase())) continue;
      iocs.push({ value, type, index: match.index });
    }
  }

  // Deduplicate by value, keep first occurrence
  const seen = new Set();
  return iocs.filter(ioc => {
    if (seen.has(ioc.value.toLowerCase())) return false;
    seen.add(ioc.value.toLowerCase());
    return true;
  });
}

module.exports = { PATTERNS, SKIP_IPS, SKIP_DOMAINS, findAllMatches, extractIOCs };
