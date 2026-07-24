"use client";

import { useMemo, useState } from "react";
import { Minus, Plus, RotateCcw } from "lucide-react";
import type { GraphEdge, GraphNode } from "./types";

type Props = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootId?: string;
  selectedId?: string;
  chainMode?: boolean;
  compact?: boolean;
  onSelect?: (node: GraphNode) => void;
};

type Point = { x: number; y: number };

const typeGlyph: Record<string, string> = {
  攻击组织: "◎",
  历史事件: "◈",
  攻击步骤: "◆",
  "IOC/基础设施": "◉",
  "恶意软件/工具": "✦",
  "ATT&CK 技术": "T",
  CVE: "V",
  报告: "▤",
  输入步骤: "◇",
};

function shortLabel(value: string, max = 16) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function layout(
  nodes: GraphNode[],
  rootId: string | undefined,
  chainMode: boolean,
): Map<string, Point> {
  const points = new Map<string, Point>();
  if (!nodes.length) return points;

  if (chainMode) {
    const width = Math.max(700, (nodes.length - 1) * 150);
    nodes.forEach((node, index) => {
      const lane = index % 2 === 0 ? 0 : 1;
      points.set(node.id, {
        x: 90 + (index / Math.max(nodes.length - 1, 1)) * (width - 180),
        y: 245 + (nodes.length > 6 ? (lane ? 50 : -50) : 0),
      });
    });
    return points;
  }

  const root = nodes.find((node) => node.id === rootId) ?? nodes[0];
  points.set(root.id, { x: 500, y: 280 });
  const rest = nodes.filter((node) => node.id !== root.id);
  const groups = new Map<string, GraphNode[]>();
  rest.forEach((node) => {
    const key = node.type;
    groups.set(key, [...(groups.get(key) ?? []), node]);
  });

  const ordered = [...groups.entries()];
  let globalIndex = 0;
  ordered.forEach(([, group], groupIndex) => {
    const sectorStart = -Math.PI / 2 + (groupIndex / Math.max(ordered.length, 1)) * Math.PI * 2;
    group.forEach((node, localIndex) => {
      const ring = globalIndex % 2 === 0 ? 190 : 255;
      const spread = Math.min(1.5, group.length * 0.18);
      const offset =
        group.length === 1
          ? 0
          : (localIndex / Math.max(group.length - 1, 1) - 0.5) * spread;
      const angle = sectorStart + offset;
      points.set(node.id, {
        x: 500 + Math.cos(angle) * ring,
        y: 280 + Math.sin(angle) * ring * 0.78,
      });
      globalIndex += 1;
    });
  });
  return points;
}

export function NetworkGraph({
  nodes,
  edges,
  rootId,
  selectedId,
  chainMode = false,
  compact = false,
  onSelect,
}: Props) {
  const [zoom, setZoom] = useState(compact ? 0.9 : 1);
  const positions = useMemo(
    () => layout(nodes, rootId, chainMode),
    [nodes, rootId, chainMode],
  );
  const viewWidth = chainMode ? Math.max(1000, nodes.length * 150) : 1000;

  return (
    <div className={`network-graph ${compact ? "is-compact" : ""}`}>
      <div className="graph-tools" aria-label="图谱缩放工具">
        <button
          type="button"
          aria-label="放大"
          onClick={() => setZoom((value) => Math.min(1.6, value + 0.12))}
        >
          <Plus size={16} />
        </button>
        <button
          type="button"
          aria-label="缩小"
          onClick={() => setZoom((value) => Math.max(0.55, value - 0.12))}
        >
          <Minus size={16} />
        </button>
        <button type="button" aria-label="重置缩放" onClick={() => setZoom(1)}>
          <RotateCcw size={15} />
        </button>
        <span>{Math.round(zoom * 100)}%</span>
      </div>
      <svg
        role="img"
        aria-label="威胁情报关系图谱"
        viewBox={`0 0 ${viewWidth} 560`}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <marker
            id={`arrow-${compact ? "compact" : "full"}`}
            markerWidth="8"
            markerHeight="8"
            refX="7"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L0,6 L7,3 z" className="edge-arrow" />
          </marker>
        </defs>
        <g
          style={{
            transform: `translate(${viewWidth / 2}px, 280px) scale(${zoom}) translate(${-viewWidth / 2}px, -280px)`,
            transformOrigin: "center",
            transition: "transform 180ms ease",
          }}
        >
          {edges.map((edge) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            if (!source || !target) return null;
            const midX = (source.x + target.x) / 2;
            const midY = (source.y + target.y) / 2;
            return (
              <g key={edge.id} className={`edge edge-${edge.status ?? "positive"}`}>
                <line
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  markerEnd={`url(#arrow-${compact ? "compact" : "full"})`}
                />
                {!compact && (
                  <text x={midX} y={midY - 6} textAnchor="middle">
                    {shortLabel(edge.label, 10)}
                  </text>
                )}
              </g>
            );
          })}
          {nodes.map((node) => {
            const point = positions.get(node.id);
            if (!point) return null;
            const selected = node.id === selectedId;
            const root = node.id === rootId;
            return (
              <g
                key={node.id}
                transform={`translate(${point.x} ${point.y})`}
                className={`graph-node node-${node.status ?? "positive"} ${selected ? "is-selected" : ""} ${root ? "is-root" : ""}`}
                onClick={() => onSelect?.(node)}
                role="button"
                tabIndex={0}
                aria-label={`${node.type}：${node.label}`}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") onSelect?.(node);
                }}
              >
                <circle className="node-halo" r={root ? 36 : 28} />
                <circle className="node-core" r={root ? 29 : 22} />
                <text className="node-glyph" textAnchor="middle" y="5">
                  {typeGlyph[node.type] ?? "•"}
                </text>
                <text className="node-label" textAnchor="middle" y={root ? 53 : 43}>
                  {shortLabel(node.label, compact ? 11 : 17)}
                </text>
                {!compact && node.confidence != null && (
                  <text className="node-score" textAnchor="middle" y={root ? 69 : 58}>
                    {Math.round(node.confidence * 100)}%
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>
      {!nodes.length && <div className="graph-empty">暂无可展示的关联节点</div>}
    </div>
  );
}
