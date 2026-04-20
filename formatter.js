/**
 * Format correlation results for human consumption.
 * Multiple output formats: summary string, CLI table, markdown, JSON.
 */

/**
 * Build a one-line human-readable summary from correlation data.
 * @param {Object} data - correlations object from lookupIOC
 * @returns {string}
 */
function summarize(data) {
  if (!data) return 'No data';
  const parts = [];

  for (const [index, hits] of Object.entries(data)) {
    if (!Array.isArray(hits) || !hits.length) continue;
    const first = hits[0];

    switch (index) {
      case 'iocs': {
        const family = first.malware_family || first.threat_type || 'unknown';
        const source = first.source || '?';
        parts.push('IOC: ' + family + ' (via ' + source + ')');
        break;
      }
      case 'block_events':
        parts.push('Blocked ' + hits.length + 'x');
        break;
      case 'pulses':
        parts.push('In ' + hits.length + ' OTX pulse(s)');
        break;
      case 'adversaries': {
        const name = first.name || '?';
        parts.push('Adversary: ' + name);
        break;
      }
      case 'cisa_kev':
        parts.push('CISA KEV');
        break;
      default:
        parts.push(index + ': ' + hits.length + ' hit(s)');
    }
  }

  return parts.join(' | ') || 'Match found in DugganUSA index';
}

/**
 * Format a batch of results as a CLI-friendly table.
 * @param {Array<{value: string, found: boolean, hits?: number, data?: Object}>} results
 * @returns {string}
 */
function formatTable(results) {
  const lines = [];
  const header = 'STATUS  HITS  VALUE                                          SUMMARY';
  const divider = '-'.repeat(header.length);
  lines.push(header, divider);

  for (const r of results) {
    const status = r.found ? '  !!  ' : '  OK  ';
    const hits = String(r.hits || 0).padStart(4);
    const value = r.value.padEnd(45).slice(0, 45);
    const summary = r.found ? summarize(r.data) : 'clean';
    lines.push(status + hits + '  ' + value + ' ' + summary);
  }

  const found = results.filter(r => r.found).length;
  lines.push(divider);
  lines.push(found + ' threat indicator(s) found in ' + results.length + ' checked.');
  return lines.join('\n');
}

/**
 * Format results as a markdown table.
 * @param {Array<{value: string, found: boolean, hits?: number, data?: Object}>} results
 * @returns {string}
 */
function formatMarkdown(results) {
  const lines = [];
  lines.push('| Status | Value | Hits | Summary |');
  lines.push('|--------|-------|------|---------|');

  for (const r of results) {
    const status = r.found ? 'WARNING' : 'clean';
    const summary = r.found ? summarize(r.data) : '—';
    lines.push('| ' + status + ' | `' + r.value + '` | ' + (r.hits || 0) + ' | ' + summary + ' |');
  }

  const found = results.filter(r => r.found).length;
  lines.push('');
  lines.push('**' + found + ' threat indicator(s)** found in ' + results.length + ' checked.');
  return lines.join('\n');
}

/**
 * Format results as structured JSON.
 * @param {Array<{value: string, found: boolean, hits?: number, data?: Object}>} results
 * @returns {string}
 */
function formatJSON(results) {
  return JSON.stringify({
    scanned: results.length,
    found: results.filter(r => r.found).length,
    results: results.map(r => ({
      value: r.value,
      found: r.found,
      hits: r.hits || 0,
      summary: r.found ? summarize(r.data) : null,
      data: r.data || null,
    })),
    timestamp: new Date().toISOString(),
    source: 'DugganUSA Threat Scanner Core',
  }, null, 2);
}

/**
 * Format a Tor relay record as a one-line summary.
 * @param {Object} relayData - relay object from lookupRelay or checkTorRelay
 * @returns {string}
 */
function formatRelay(relayData) {
  if (!relayData) return 'No relay data';
  const nickname = relayData.nickname || relayData.name || '?';
  const flags = Array.isArray(relayData.flags) ? relayData.flags.join(',') : (relayData.flags || '?');
  const country = relayData.country || relayData.geo?.country || '?';
  const org = relayData.org || relayData.as_name || '?';
  const bw = relayData.bandwidth || relayData.observed_bandwidth || '?';
  return 'Tor Relay: ' + nickname + ' | ' + flags + ' | ' + country + ' | ' + org + ' | BW:' + bw;
}

module.exports = { summarize, formatTable, formatMarkdown, formatJSON, formatRelay };
