// lib/server/knowledge-graph/neo4j.ts

import neo4j, { Driver } from "neo4j-driver";

declare global {
  // eslint-disable-next-line no-var
  var __neo4jDriver: Driver | undefined;
}

function requireEnv(name: string): string {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return value;
}

export function getNeo4jDriver(): Driver {
  if (!globalThis.__neo4jDriver) {
    globalThis.__neo4jDriver = neo4j.driver(
      requireEnv("NEO4J_URI"),
      neo4j.auth.basic(
        requireEnv("NEO4J_USERNAME"),
        requireEnv("NEO4J_PASSWORD")
      )
    );
  }

  return globalThis.__neo4jDriver;
}

export async function runCypher(
  query: string,
  params: Record<string, unknown> = {}
) {
  const driver = getNeo4jDriver();
  const database = process.env.NEO4J_DATABASE || undefined;

  const session = database
    ? driver.session({ database })
    : driver.session();

  try {
    const result = await session.run(query, params);
    return result.records;
  } finally {
    await session.close();
  }
}

let schemaReady = false;

export async function ensureKnowledgeGraphSchema() {
  if (schemaReady) return;

  const constraints = [
    `CREATE CONSTRAINT report_id IF NOT EXISTS FOR (n:Report) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT owasp_id IF NOT EXISTS FOR (n:OWASP) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT mitre_id IF NOT EXISTS FOR (n:MITRETechnique) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT impact_id IF NOT EXISTS FOR (n:Impact) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT remediation_id IF NOT EXISTS FOR (n:Remediation) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT exploit_id IF NOT EXISTS FOR (n:Exploit) REQUIRE n.id IS UNIQUE`,
    `CREATE CONSTRAINT indicator_id IF NOT EXISTS FOR (n:Indicator) REQUIRE n.id IS UNIQUE`,
  ];

  for (const query of constraints) {
    await runCypher(query);
  }

  schemaReady = true;
}