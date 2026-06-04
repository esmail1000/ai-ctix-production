// lib/server/knowledge-graph/mappings.ts

import type {
    GraphFindingInput,
    MitreTechniqueInput,
    OwaspInput,
} from "./types";

type Mapping = {
  cwes?: string[];
  owasp?: OwaspInput[];
  mitreTechniques?: MitreTechniqueInput[];
  impacts?: string[];
};

const KNOWN_CVE_MAPPINGS: Record<string, Mapping> = {
  "CVE-2021-41773": {
    cwes: ["CWE-22"],
    owasp: [{ id: "A01:2021", name: "Broken Access Control" }],
    mitreTechniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
      },
    ],
    impacts: ["Remote Code Execution", "Information Disclosure"],
  },

  "CVE-2021-42013": {
    cwes: ["CWE-22"],
    owasp: [{ id: "A01:2021", name: "Broken Access Control" }],
    mitreTechniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
      },
    ],
    impacts: ["Remote Code Execution"],
  },

  "CVE-2017-5638": {
    cwes: ["CWE-20"],
    owasp: [{ id: "A03:2021", name: "Injection" }],
    mitreTechniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
      },
    ],
    impacts: ["Remote Code Execution"],
  },
};

const KEYWORD_RULES: Array<Mapping & { pattern: RegExp }> = [
  {
    pattern: /sql\s*injection|\bsqli\b/i,
    cwes: ["CWE-89"],
    owasp: [{ id: "A03:2021", name: "Injection" }],
    mitreTechniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
      },
    ],
    impacts: ["Data Leakage", "Authentication Bypass"],
  },

  {
    pattern: /xss|cross[-\s]?site scripting/i,
    cwes: ["CWE-79"],
    owasp: [{ id: "A03:2021", name: "Injection" }],
    mitreTechniques: [
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        tactic: "Execution",
      },
    ],
    impacts: ["Session Hijacking", "Client-Side Code Execution"],
  },

  {
    pattern: /path traversal|directory traversal/i,
    cwes: ["CWE-22"],
    owasp: [{ id: "A01:2021", name: "Broken Access Control" }],
    mitreTechniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
      },
    ],
    impacts: ["Information Disclosure", "Remote Code Execution"],
  },

  {
    pattern: /weak password|default credential|brute force/i,
    cwes: ["CWE-521"],
    owasp: [
      {
        id: "A07:2021",
        name: "Identification and Authentication Failures",
      },
    ],
    mitreTechniques: [
      {
        id: "T1110",
        name: "Brute Force",
        tactic: "Credential Access",
      },
    ],
    impacts: ["Account Compromise"],
  },

  {
    pattern: /rce|remote code execution|command injection/i,
    cwes: ["CWE-78"],
    owasp: [{ id: "A03:2021", name: "Injection" }],
    mitreTechniques: [
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        tactic: "Execution",
      },
    ],
    impacts: ["Remote Code Execution", "System Compromise"],
  },

  {
    pattern:
      /outdated dependenc|inconsistent compiler|cargo outdated|toolchain|dependency specification/i,
    cwes: ["CWE-1104"],
    owasp: [
      {
        id: "A06:2021",
        name: "Vulnerable and Outdated Components",
      },
    ],
    mitreTechniques: [
      {
        id: "T1195",
        name: "Supply Chain Compromise",
        tactic: "Initial Access",
      },
    ],
    impacts: ["Dependency Exploitation", "Build Instability"],
  },

  {
    pattern:
      /secrets? in memory|memory not cleared|zeroize|stale data|core dump/i,
    cwes: ["CWE-244", "CWE-226"],
    owasp: [{ id: "A02:2021", name: "Cryptographic Failures" }],
    mitreTechniques: [
      {
        id: "T1005",
        name: "Data from Local System",
        tactic: "Collection",
      },
    ],
    impacts: ["Sensitive Data Exposure", "Secret Leakage"],
  },

  {
    pattern:
      /randomness generator|non-crypto randomness|entropy|fill_bytes|try_fill_bytes|getrandom/i,
    cwes: ["CWE-338", "CWE-330"],
    owasp: [{ id: "A02:2021", name: "Cryptographic Failures" }],
    mitreTechniques: [
      {
        id: "T1552",
        name: "Unsecured Credentials",
        tactic: "Credential Access",
      },
    ],
    impacts: ["Weak Key Generation", "Predictable Cryptographic Material"],
  },

  {
    pattern:
      /missing length check|length==0|validation check|deserialization|input validation/i,
    cwes: ["CWE-20", "CWE-1284"],
    owasp: [{ id: "A03:2021", name: "Injection" }],
    mitreTechniques: [
      {
        id: "T1499",
        name: "Endpoint Denial of Service",
        tactic: "Impact",
      },
    ],
    impacts: ["Denial of Service", "Input Validation Failure"],
  },

  {
    pattern:
      /constant-time|non constant-time|timing|side-channel|cache attack|microarchitectural/i,
    cwes: ["CWE-208", "CWE-385"],
    owasp: [{ id: "A02:2021", name: "Cryptographic Failures" }],
    mitreTechniques: [
      {
        id: "T1040",
        name: "Network Sniffing",
        tactic: "Credential Access",
      },
    ],
    impacts: ["Timing Side-Channel Leakage", "Sensitive Data Disclosure"],
  },

  {
    pattern:
      /aggregate verify|distinct messages|rogue key|aggregate signature|bls signature/i,
    cwes: ["CWE-347", "CWE-345"],
    owasp: [{ id: "A02:2021", name: "Cryptographic Failures" }],
    mitreTechniques: [
      {
        id: "T1606",
        name: "Forge Web Credentials",
        tactic: "Credential Access",
      },
    ],
    impacts: ["Signature Forgery", "Authentication Bypass"],
  },
];

function uniqueStrings(values: Array<string | undefined | null>) {
  return Array.from(
    new Set(
      values
        .filter(Boolean)
        .map((value) => String(value))
    )
  );
}

function normalizeOwasp(item: OwaspInput): { id: string; name?: string } {
  return typeof item === "string" ? { id: item } : item;
}

function mergeOwasp(a: OwaspInput[] = [], b: OwaspInput[] = []) {
  const map = new Map<string, { id: string; name?: string }>();

  [...a, ...b].map(normalizeOwasp).forEach((item) => {
    if (item.id) {
      map.set(item.id, { ...map.get(item.id), ...item });
    }
  });

  return Array.from(map.values());
}

function mergeMitre(
  a: MitreTechniqueInput[] = [],
  b: MitreTechniqueInput[] = []
) {
  const map = new Map<string, MitreTechniqueInput>();

  [...a, ...b].forEach((item) => {
    if (item.id) {
      map.set(item.id, { ...map.get(item.id), ...item });
    }
  });

  return Array.from(map.values());
}

export function extractCvesFromText(text: string): string[] {
  return uniqueStrings(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map(
    (cve) => cve.toUpperCase()
  );
}

export function enrichFinding(finding: GraphFindingInput): GraphFindingInput {
  const text = [
    finding.title,
    finding.description,
    finding.impacts?.join(" "),
    finding.remediations?.join(" "),
  ]
    .filter(Boolean)
    .join(" ");

  let cwes = finding.cwes ?? [];
  let owasp = finding.owasp ?? [];
  let mitreTechniques = finding.mitreTechniques ?? [];
  let impacts = finding.impacts ?? [];

  const cves = uniqueStrings([
    ...(finding.cves ?? []),
    ...extractCvesFromText(text),
  ]).map((cve) => cve.toUpperCase());

  for (const cve of cves) {
    const mapping = KNOWN_CVE_MAPPINGS[cve];

    if (!mapping) continue;

    cwes = uniqueStrings([...cwes, ...(mapping.cwes ?? [])]);
    owasp = mergeOwasp(owasp, mapping.owasp ?? []);
    mitreTechniques = mergeMitre(
      mitreTechniques,
      mapping.mitreTechniques ?? []
    );
    impacts = uniqueStrings([...impacts, ...(mapping.impacts ?? [])]);
  }

  for (const rule of KEYWORD_RULES) {
    if (!rule.pattern.test(text)) continue;

    cwes = uniqueStrings([...cwes, ...(rule.cwes ?? [])]);
    owasp = mergeOwasp(owasp, rule.owasp ?? []);
    mitreTechniques = mergeMitre(
      mitreTechniques,
      rule.mitreTechniques ?? []
    );
    impacts = uniqueStrings([...impacts, ...(rule.impacts ?? [])]);
  }

  return {
    ...finding,
    cves,
    cwes,
    owasp,
    mitreTechniques,
    impacts,
  };
}