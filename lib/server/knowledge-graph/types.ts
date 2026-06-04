// lib/server/knowledge-graph/types.ts

export type OwaspInput =
  | string
  | {
      id: string;
      name?: string;
    };

export type MitreTechniqueInput = {
  id: string;
  name?: string;
  tactic?: string;
};

export type GraphFindingInput = {
  id?: string;
  title: string;
  description?: string;
  severity?: string;
  riskScore?: number;

  asset?: string;
  assets?: string[];

  cves?: string[];
  cwes?: string[];
  owasp?: OwaspInput[];
  mitreTechniques?: MitreTechniqueInput[];

  impacts?: string[];
  remediations?: string[];
  exploits?: string[];
};

export type BuildGraphInput = {
  reportId: string;
  reportName?: string;
  sourceFileName?: string;
  findings: GraphFindingInput[];
};