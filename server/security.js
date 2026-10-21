import net from 'node:net';
import ipaddr from 'ipaddr.js';

// Deliberately IPv4-literal-only. Prevents DNS rebinding and proxying to internal services.
// Range classification is conservative; additionally reject non-globally-routable ranges.
export function validateTarget(host, port) {
  const h = String(host || '').trim();
  const p = Number(port);
  if (net.isIP(h) !== 4) throw new Error('Only public IPv4 addresses are supported');
  const ip = ipaddr.parse(h);
  if (ip.range() !== 'unicast') throw new Error('Private, loopback, reserved or special-use IPs are not allowed');
  const bytes = ip.octets;
  // Globally unroutable, documentation and benchmarking ranges (defense-in-depth).
  if (bytes[0] === 0 || bytes[0] === 10 || bytes[0] === 127 || bytes[0] >= 224 ||
      (bytes[0] === 100 && bytes[1] >= 64 && bytes[1] <= 127) ||
      (bytes[0] === 169 && bytes[1] === 254) ||
      (bytes[0] === 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
      (bytes[0] === 192 && (bytes[1] === 0 || bytes[1] === 168)) ||
      (bytes[0] === 192 && bytes[1] === 0 && bytes[2] === 2) ||
      (bytes[0] === 198 && (bytes[1] === 18 || bytes[1] === 19 || (bytes[1] === 51 && bytes[2] === 100))) ||
      (bytes[0] === 203 && bytes[1] === 0 && bytes[2] === 113)) {
    throw new Error('IP address must be globally routable');
  }
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('Port must be from 1 to 65535');
  // Prevent targeting SSH, SMTP, Redis, databases and common admin ports.
  if ([21,22,23,25,53,110,111,135,139,143,389,445,465,587,636,993,995,1433,1521,2375,2376,3306,3389,5432,5672,5900,6379,9200,9300,11211,27017].includes(p)) throw new Error('This port is blocked for safety');
  return { host: h, port: p };
}

export function hostnameSlug(hostname, baseDomain) {
  const h = String(hostname || '').toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  const suffix = '.' + baseDomain.toLowerCase();
  if (!h.endsWith(suffix)) return null;
  const slug = h.slice(0, -suffix.length);
  return /^[a-z0-9-]{1,63}$/.test(slug) ? slug : null;
}
