type NvdMetric = {
  cvssData?: {
    baseScore?: number;
    baseSeverity?: string;
    vectorString?: string;
    version?: string;
  };
};

export type NvdCveIntel = {
  cveId: string;
  source: "NVD";
  published?: string;
  lastModified?: string;
  description?: string;
  cvssScore?: number;
  cvssSeverity?: string;
  cvssVector?: string;
  references: string[];
};

function pickEnglishDescription(descriptions: any[] = []) {
  return (
    descriptions.find((item) => item.lang === "en")?.value ??
    descriptions[0]?.value ??
    ""
  );
}

function pickBestMetric(metrics: any = {}) {
  const candidates: NvdMetric[] = [
    ...(metrics.cvssMetricV40 ?? []),
    ...(metrics.cvssMetricV31 ?? []),
    ...(metrics.cvssMetricV30 ?? []),
    ...(metrics.cvssMetricV2 ?? []),
  ];

  return candidates[0]?.cvssData;
}

export async function fetchNvdCve(cveId: string): Promise<NvdCveIntel | null> {
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("cveId", cveId);

  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (process.env.NVD_API_KEY) {
    headers.apiKey = process.env.NVD_API_KEY;
  }

  const response = await fetch(url, {
    headers,
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`NVD request failed for ${cveId}: ${response.status}`);
  }

  const data = await response.json();
  const item = data.vulnerabilities?.[0]?.cve;

  if (!item) return null;

  const metric = pickBestMetric(item.metrics);

  return {
    cveId,
    source: "NVD",
    published: item.published,
    lastModified: item.lastModified,
    description: pickEnglishDescription(item.descriptions),
    cvssScore: metric?.baseScore,
    cvssSeverity: metric?.baseSeverity,
    cvssVector: metric?.vectorString,
    references:
      item.references?.referenceData?.map((ref: any) => ref.url).filter(Boolean) ??
      item.references?.map((ref: any) => ref.url).filter(Boolean) ??
      [],
  };
}