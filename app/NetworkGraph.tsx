"use client";

import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type Simulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import { Minus, Move, Plus, RotateCcw } from "lucide-react";
import {
  useEffect,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from "react";
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
type SimNode = SimulationNodeDatum & {
  id: string;
  graphNode: GraphNode;
};
type SimLink = SimulationLinkDatum<SimNode> & {
  id: string;
  source: string | SimNode;
  target: string | SimNode;
};

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

function seededStart(
  nodes: GraphNode[],
  rootId: string | undefined,
  chainMode: boolean,
  viewWidth: number,
) {
  const root = nodes.find((node) => node.id === rootId) ?? nodes[0];
  return nodes.map<SimNode>((node, index) => {
    if (chainMode) {
      return {
        id: node.id,
        graphNode: node,
        x: 85 + (index / Math.max(nodes.length - 1, 1)) * (viewWidth - 170),
        y: 280 + (index % 2 === 0 ? -12 : 12),
      };
    }
    if (node.id === root?.id) {
      return { id: node.id, graphNode: node, x: viewWidth / 2, y: 280 };
    }
    const angle = ((index - 1) / Math.max(nodes.length - 1, 1)) * Math.PI * 2;
    const ring = 145 + (index % 3) * 48;
    return {
      id: node.id,
      graphNode: node,
      x: viewWidth / 2 + Math.cos(angle) * ring,
      y: 280 + Math.sin(angle) * ring * 0.72,
    };
  });
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
  const viewWidth = chainMode ? Math.max(1000, nodes.length * 150) : 1000;
  const [zoom, setZoom] = useState(compact ? 0.9 : 1);
  const [positions, setPositions] = useState<Map<string, Point>>(new Map());
  const [draggingId, setDraggingId] = useState<string>();
  const simulationRef = useRef<Simulation<SimNode, SimLink> | null>(null);
  const simNodesRef = useRef<Map<string, SimNode>>(new Map());
  const dragStartRef = useRef<{ x: number; y: number }>();
  const dragMovedRef = useRef(false);

  useEffect(() => {
    const simNodes = seededStart(nodes, rootId, chainMode, viewWidth);
    const simNodeIds = new Set(simNodes.map((node) => node.id));
    const simLinks: SimLink[] = edges
      .filter((edge) => simNodeIds.has(edge.source) && simNodeIds.has(edge.target))
      .map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
      }));

    simNodesRef.current = new Map(simNodes.map((node) => [node.id, node]));
    setPositions(
      new Map(
        simNodes.map((node) => [
          node.id,
          { x: node.x ?? viewWidth / 2, y: node.y ?? 280 },
        ]),
      ),
    );

    const simulation = forceSimulation<SimNode>(simNodes)
      .force(
        "link",
        forceLink<SimNode, SimLink>(simLinks)
          .id((node) => node.id)
          .distance(chainMode ? 132 : compact ? 92 : 116)
          .strength(chainMode ? 0.76 : 0.42),
      )
      .force("charge", forceManyBody<SimNode>().strength(compact ? -230 : -390))
      .force(
        "collision",
        forceCollide<SimNode>()
          .radius((node) => (node.id === rootId ? 50 : compact ? 34 : 43))
          .strength(0.9),
      )
      .alpha(1)
      .alphaDecay(0.035);

    if (chainMode) {
      const indexById = new Map(nodes.map((node, index) => [node.id, index]));
      simulation
        .force(
          "chain-x",
          forceX<SimNode>((node) => {
            const index = indexById.get(node.id) ?? 0;
            return 85 + (index / Math.max(nodes.length - 1, 1)) * (viewWidth - 170);
          }).strength(0.55),
        )
        .force("chain-y", forceY<SimNode>(280).strength(0.32));
    } else {
      simulation
        .force("center", forceCenter(viewWidth / 2, 280))
        .force(
          "root-x",
          forceX<SimNode>(viewWidth / 2).strength((node) =>
            node.id === rootId ? 0.28 : 0.018,
          ),
        )
        .force(
          "root-y",
          forceY<SimNode>(280).strength((node) =>
            node.id === rootId ? 0.28 : 0.018,
          ),
        );
    }

    simulation.on("tick", () => {
      const next = new Map<string, Point>();
      simNodes.forEach((node) => {
        const margin = node.id === rootId ? 48 : 34;
        node.x = Math.max(margin, Math.min(viewWidth - margin, node.x ?? viewWidth / 2));
        node.y = Math.max(margin, Math.min(520, node.y ?? 280));
        next.set(node.id, { x: node.x, y: node.y });
      });
      setPositions(next);
    });

    simulationRef.current = simulation;
    return () => {
      simulation.stop();
      if (simulationRef.current === simulation) simulationRef.current = null;
    };
  }, [nodes, edges, rootId, chainMode, compact, viewWidth]);

  const pointerToGraph = (
    event: ReactPointerEvent<SVGGElement>,
  ): Point | undefined => {
    const svg = event.currentTarget.ownerSVGElement;
    if (!svg) return undefined;
    const rect = svg.getBoundingClientRect();
    if (!rect.width || !rect.height) return undefined;
    const rawX = ((event.clientX - rect.left) / rect.width) * viewWidth;
    const rawY = ((event.clientY - rect.top) / rect.height) * 560;
    return {
      x: viewWidth / 2 + (rawX - viewWidth / 2) / zoom,
      y: 280 + (rawY - 280) / zoom,
    };
  };

  const startDrag = (
    event: ReactPointerEvent<SVGGElement>,
    node: GraphNode,
  ) => {
    const point = pointerToGraph(event);
    const simNode = simNodesRef.current.get(node.id);
    if (!point || !simNode) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStartRef.current = { x: event.clientX, y: event.clientY };
    dragMovedRef.current = false;
    simNode.fx = point.x;
    simNode.fy = point.y;
    setDraggingId(node.id);
    simulationRef.current?.alphaTarget(0.18).restart();
  };

  const moveDrag = (
    event: ReactPointerEvent<SVGGElement>,
    node: GraphNode,
  ) => {
    if (draggingId !== node.id) return;
    const point = pointerToGraph(event);
    const simNode = simNodesRef.current.get(node.id);
    if (!point || !simNode) return;
    if (
      dragStartRef.current &&
      Math.hypot(
        event.clientX - dragStartRef.current.x,
        event.clientY - dragStartRef.current.y,
      ) > 3
    ) {
      dragMovedRef.current = true;
    }
    simNode.fx = point.x;
    simNode.fy = point.y;
    setPositions((current) => new Map(current).set(node.id, point));
  };

  const endDrag = (
    event: ReactPointerEvent<SVGGElement>,
    node: GraphNode,
  ) => {
    if (draggingId !== node.id) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    setDraggingId(undefined);
    simulationRef.current?.alphaTarget(0);
  };

  const releaseNode = (nodeId: string) => {
    const simNode = simNodesRef.current.get(nodeId);
    if (!simNode) return;
    simNode.fx = null;
    simNode.fy = null;
    simulationRef.current?.alpha(0.65).restart();
  };

  const resetGraph = () => {
    setZoom(1);
    simNodesRef.current.forEach((node) => {
      node.fx = null;
      node.fy = null;
    });
    simulationRef.current?.alpha(1).restart();
  };

  return (
    <div className={`network-graph ${compact ? "is-compact" : ""}`}>
      <div className="graph-tools" aria-label="图谱缩放工具">
        <button
          type="button"
          aria-label="放大"
          onClick={() => setZoom((value) => Math.min(1.7, value + 0.12))}
        >
          <Plus size={16} />
        </button>
        <button
          type="button"
          aria-label="缩小"
          onClick={() => setZoom((value) => Math.max(0.5, value - 0.12))}
        >
          <Minus size={16} />
        </button>
        <button type="button" aria-label="重置图谱" onClick={resetGraph}>
          <RotateCcw size={15} />
        </button>
        <span>{Math.round(zoom * 100)}%</span>
      </div>
      <div className="graph-drag-hint">
        <Move size={13} />
        拖动节点固定位置 · 双击释放
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
            transition: draggingId ? "none" : "transform 180ms ease",
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
            const dragging = node.id === draggingId;
            return (
              <g
                key={node.id}
                transform={`translate(${point.x} ${point.y})`}
                className={`graph-node node-${node.status ?? "positive"} ${selected ? "is-selected" : ""} ${root ? "is-root" : ""} ${dragging ? "is-dragging" : ""}`}
                onPointerDown={(event) => startDrag(event, node)}
                onPointerMove={(event) => moveDrag(event, node)}
                onPointerUp={(event) => endDrag(event, node)}
                onPointerCancel={(event) => endDrag(event, node)}
                onDoubleClick={() => releaseNode(node.id)}
                onClick={() => {
                  if (!dragMovedRef.current) onSelect?.(node);
                }}
                role="button"
                tabIndex={0}
                aria-label={`${node.type}：${node.label}`}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") onSelect?.(node);
                  if (event.key === "Escape") releaseNode(node.id);
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
