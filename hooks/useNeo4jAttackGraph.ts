// hooks/useNeo4jAttackGraph.ts

"use client";

import { useEffect, useState } from "react";

export function useNeo4jAttackGraph(reportId: string) {
  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        setError("");

        const [graphRes, pathsRes] = await Promise.all([
          fetch(`/api/knowledge-graph/${reportId}?depth=4`),
          fetch(`/api/attack-paths/${reportId}?limit=10`),
        ]);

        if (!graphRes.ok) {
          throw new Error("Failed to load knowledge graph");
        }

        if (!pathsRes.ok) {
          throw new Error("Failed to load attack paths");
        }

        const graph = await graphRes.json();
        const paths = await pathsRes.json();

        setNodes(
          graph.nodes.map((node: any) => ({
            id: node.data.id,
            label: node.data.name,
            type: node.data.type,
            severity: node.data.severity,
            riskScore: node.data.riskScore,
            raw: node.data,
          }))
        );

        setEdges(
          graph.edges.map((edge: any) => ({
            id: edge.data.id,
            source: edge.data.source,
            target: edge.data.target,
            label: edge.data.label,
            type: edge.data.type,
            raw: edge.data,
          }))
        );

        setAttackPaths(paths.paths ?? []);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Graph loading failed");
      } finally {
        setLoading(false);
      }
    }

    load();
  }, [reportId]);

  return {
    nodes,
    edges,
    attackPaths,
    loading,
    error,
  };
}