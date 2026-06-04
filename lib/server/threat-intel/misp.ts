export type MispIntel = {
  source: "MISP";
  value: string;
  category?: string;
  type?: string;
  eventId?: string;
  eventInfo?: string;
  tags: string[];
};

export async function searchMispByCve(cveId: string): Promise<MispIntel[]> {
  const baseUrl = process.env.MISP_BASE_URL;
  const apiKey = process.env.MISP_API_KEY;

  if (!baseUrl || !apiKey) {
    return [];
  }

  const response = await fetch(`${baseUrl.replace(/\/$/, "")}/attributes/restSearch`, {
    method: "POST",
    headers: {
      Authorization: apiKey,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      returnFormat: "json",
      value: cveId,
      limit: 10,
      includeEventTags: true,
    }),
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`MISP request failed for ${cveId}: ${response.status}`);
  }

  const data = await response.json();
  const attributes = data.response?.Attribute ?? data.Attribute ?? [];

  return attributes.map((attr: any) => ({
    source: "MISP",
    value: String(attr.value ?? cveId),
    category: attr.category,
    type: attr.type,
    eventId: attr.event_id,
    eventInfo: attr.Event?.info,
    tags: [
      ...(attr.Tag ?? []).map((tag: any) => tag.name).filter(Boolean),
      ...(attr.Event?.Tag ?? []).map((tag: any) => tag.name).filter(Boolean),
    ],
  }));
}