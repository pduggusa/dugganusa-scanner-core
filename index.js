/**
 * @dugganusa/threat-scanner-core
 *
 * Core IOC scanning engine for all DugganUSA integrations.
 * Extract IPs, domains, hashes, CVEs from text and correlate
 * against 1.08M+ threat indicators via the DugganUSA API.
 *
 * This is the TIMI — the Technology Independent Machine Interface.
 * Every integration (VS Code, Chrome, CLI, Slack, Splunk, etc.)
 * is a thin wrapper around this core.
 *
 * Usage:
 *   const { extractIOCs, lookupIOC, lookupBatch, summarize } = require('@dugganusa/threat-scanner-core');
 *
 *   // Extract IOCs from text
 *   const iocs = extractIOCs('Found C2 at 185.39.19.176 and welcome.supp0v3.com');
 *
 *   // Look up a single indicator
 *   const result = await lookupIOC('185.39.19.176', { apiKey: 'dugusa_...' });
 *
 *   // Batch lookup
 *   const results = await lookupBatch(['185.39.19.176', 'CVE-2026-21643']);
 *
 *   // Format results
 *   console.log(formatTable(results));
 */

const { extractIOCs, PATTERNS, SKIP_IPS, SKIP_DOMAINS, findAllMatches } = require('./patterns');
const { lookupIOC, lookupBatch, aipmAuditUrl, clearCache, cacheStats, DEFAULT_API_URL } = require('./api');
const { summarize, formatTable, formatMarkdown, formatJSON } = require('./formatter');

module.exports = {
  // Pattern extraction
  extractIOCs,
  findAllMatches,
  PATTERNS,
  SKIP_IPS,
  SKIP_DOMAINS,

  // API correlation
  lookupIOC,
  lookupBatch,
  aipmAuditUrl,
  clearCache,
  cacheStats,
  DEFAULT_API_URL,

  // Formatting
  summarize,
  formatTable,
  formatMarkdown,
  formatJSON,
};
