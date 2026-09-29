/**
 * Deterministic geo-location lookup for the hackathon demo.
 *
 * In production this would call an IP intelligence API (e.g. MaxMind, ip-api).
 * For the demo we maintain a static map of the IPs that appear in synthetic
 * incidents so that the Geo location artifact is always populated.
 */

export interface GeoResult {
  ip: string;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  isp: string;
  org: string;
  asn: string;
  isPrivate: boolean;
}

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^::1$/,
  /^fc00:/,
];

function isPrivate(ip: string): boolean {
  return PRIVATE_RANGES.some(re => re.test(ip));
}

// Static map of IPs that appear across the 6 synthetic incidents
const GEO_MAP: Record<string, Omit<GeoResult, "ip" | "isPrivate">> = {
  // INC-1042 PowerShell — destination: known GitHub CDN range
  "185.199.110.153": { city: "San Francisco", region: "California", country: "United States", countryCode: "US", latitude: 37.7749, longitude: -122.4194, isp: "Fastly", org: "GitHub CDN", asn: "AS54113" },
  // INC-1041 Impossible Travel — source: Google Cloud US
  "34.120.8.15":     { city: "Council Bluffs", region: "Iowa", country: "United States", countryCode: "US", latitude: 41.2619, longitude: -95.8608, isp: "Google LLC", org: "Google Cloud", asn: "AS15169" },
  // INC-1041 Impossible Travel — destination: Wikimedia UK
  "91.198.174.192":  { city: "London", region: "England", country: "United Kingdom", countryCode: "GB", latitude: 51.5074, longitude: -0.1278, isp: "Wikimedia Foundation", org: "Wikimedia", asn: "AS14907" },
  // INC-1039 Brute Force — attacker
  "45.33.18.204":    { city: "Fremont", region: "California", country: "United States", countryCode: "US", latitude: 37.5485, longitude: -121.9886, isp: "Akamai Technologies", org: "Linode / Akamai", asn: "AS63949" },
  // INC-1038 C2 — destination
  "91.219.236.44":   { city: "Amsterdam", region: "Noord-Holland", country: "Netherlands", countryCode: "NL", latitude: 52.3676, longitude: 4.9041, isp: "Serverius-as", org: "Serverius Colocation", asn: "AS60781" },
  // INC-1039 Brute Force — target gateway (internal, mapped to RFC1918)
  "10.10.0.10":      { city: "Private Network", region: "", country: "Private", countryCode: "—", latitude: 0, longitude: 0, isp: "Private", org: "Internal", asn: "—" },
};

/**
 * Returns a GeoResult for a given IP.
 * Private IPs return a sentinel "Private Network" result.
 * Unknown public IPs return an "Unknown" result (no external call is made).
 */
export function geoLookup(ip: string): GeoResult {
  if (!ip || ip === "—") {
    return { ip, city: "N/A", region: "", country: "N/A", countryCode: "—", latitude: 0, longitude: 0, isp: "N/A", org: "N/A", asn: "—", isPrivate: false };
  }
  if (isPrivate(ip)) {
    return { ip, city: "Private Network", region: "", country: "Private", countryCode: "—", latitude: 0, longitude: 0, isp: "Private", org: "Internal RFC1918", asn: "—", isPrivate: true };
  }
  const hit = GEO_MAP[ip];
  if (hit) return { ip, ...hit, isPrivate: false };
  // Unknown public IP — return a generic result rather than fail
  return { ip, city: "Unknown", region: "Unknown", country: "Unknown", countryCode: "—", latitude: 0, longitude: 0, isp: "Unknown", org: "Unknown", asn: "—", isPrivate: false };
}

export function formatGeoValue(geo: GeoResult): string {
  if (geo.isPrivate) return `Private network (RFC1918) · ${geo.ip}`;
  if (geo.country === "N/A" || geo.country === "Unknown") return `Location unknown · ${geo.ip}`;
  const parts = [geo.city, geo.region, geo.country].filter(Boolean).filter(p => p !== "Private" && p !== "Unknown");
  return `${parts.join(", ")} · ${geo.asn} (${geo.isp})`;
}
