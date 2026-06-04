"use client";

import dynamic from "next/dynamic";
import { useEffect, useMemo, useState } from "react";

const CytoscapeComponent = dynamic(
  () => import("react-cytoscapejs").then((mod) => mod.default),
  {
    ssr: false,
  }
) as any;

type GraphPayload = {
  nodes: any[];
  edges: any[];
};

type AttackPathPayload = {
  paths: Array<{
    findingId: string;
    findingTitle: string;
    severity: string;
    riskScore: number;
    attackPathScore: number;
    path: {
      nodes: Array<{
        type: string;
        id: string;
        name: string;
      }>;
      relationships: Array<{
        type: string;
      }>;
    };
  }>;
};

export function KnowledgeGraphViewer({ reportId }: { reportId: string }) {
  const [graph, setGraph] = useState<GraphPayload>({
    nodes: [],
    edges: [],
  });

  const [attackPaths, setAttackPaths] = useState<AttackPathPayload>({
    paths: [],
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        setError("");

        const [graphResponse, pathsResponse] = await Promise.all([
          fetch(`/api/knowledge-graph/${reportId}?depth=4`),
          fetch(`/api/attack-paths/${reportId}?limit=10`),
        ]);

        if (!graphResponse.ok) {
          throw new Error("Failed to load knowledge graph");
        }

        if (!pathsResponse.ok) {
          throw new Error("Failed to load attack paths");
        }

        const graphData = await graphResponse.json();
        const pathsData = await pathsResponse.json();

        setGraph(graphData);
        setAttackPaths(pathsData);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Graph loading failed");
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [reportId]);

  const elements = useMemo(() => {
    return [...graph.nodes, ...graph.edges];
  }, [graph]);

  if (loading) {
    return <div>Loading knowledge graph...</div>;
  }

  if (error) {
    return <div style={{ color: "red" }}>{error}</div>;
  }

  if (!elements.length) {
    return <div>No graph data found for this report.</div>;
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 16 }}>
      <div
        style={{
          height: 700,
          border: "1px solid #ddd",
          borderRadius: 12,
          overflow: "hidden",
        }}
      >
        <CytoscapeComponent
          elements={elements}
          style={{ width: "100%", height: "100%" }}
          layout={{
            name: "cose",
            animate: true,
            fit: true,
            padding: 60,
          }}
          stylesheet={[
            {
              selector: "node",
              style: {
                label: "data(name)",
                "font-size": 9,
                "text-valign": "center",
                "text-halign": "center",
                width: 48,
                height: 48,
                "text-wrap": "wrap",
                "text-max-width": 110,
              },
            },
            {
              selector: 'node[type = "Report"]',
              style: {
                shape: "round-rectangle",
                width: 80,
                height: 45,
              },
            },
            {
              selector: 'node[type = "Finding"]',
              style: {
                shape: "ellipse",
                width: 70,
                height: 70,
              },
            },
            {
              selector: 'node[type = "Impact"]',
              style: {
                shape: "diamond",
                width: 70,
                height: 70,
              },
            },
            {
              selector: 'node[type = "Remediation"]',
              style: {
                shape: "round-rectangle",
                width: 85,
                height: 45,
              },
            },
            {
              selector: "edge",
              style: {
                label: "data(label)",
                "font-size": 7,
                "curve-style": "bezier",
                "target-arrow-shape": "triangle",
                "text-rotation": "autorotate",
              },
            },
          ]}
        />
      </div>

      <aside
        style={{
          border: "1px solid #ddd",
          borderRadius: 12,
          padding: 16,
          maxHeight: 700,
          overflow: "auto",
        }}
      >
        <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>
          Attack Paths
        </h2>

        {attackPaths.paths.length === 0 ? (
          <p>No attack paths found.</p>
        ) : (
          attackPaths.paths.map((item) => (
            <div
              key={`${item.findingId}-${item.attackPathScore}`}
              style={{
                borderBottom: "1px solid #eee",
                paddingBottom: 12,
                marginBottom: 12,
              }}
            >
              <h3 style={{ fontWeight: 700 }}>{item.findingTitle}</h3>

              <p>
                Severity: <strong>{item.severity}</strong>
              </p>

              <p>
                Risk Score: <strong>{item.riskScore}</strong>
              </p>

              <p>
                Attack Path Score: <strong>{item.attackPathScore}</strong>
              </p>

              <p style={{ fontSize: 13, marginTop: 8 }}>
                {item.path.nodes.map((node) => node.name).join(" → ")}
              </p>
            </div>
          ))
        )}
      </aside>
    </div>
  );
}