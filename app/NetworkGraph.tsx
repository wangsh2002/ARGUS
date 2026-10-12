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
  selectedEdgeId?: string;
  highlightIds?: string[];
  highlightEdgeIds?: string[];
  mutedIds?: string[];
  mutedEdgeIds?: string[];
  edgeAnnotations?: Record<
    string,
    {
      label: string;
      tone: "success" | "failure" | "parallel" | "candidate";
    }
  >;
  hiddenNeighborCounts?: Record<string, number>;
  focusMode?: boolean;
  compact?: boolean;
  layout?: "force" | "path" | "radial";
  pathIds?: string[];
  stabilizeExpansion?: boolean;
  onSelect?: (node: GraphNode) => void;
  onSelectEdge?: (edge: GraphEdge) => void;
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

const EMPTY_HIGHLIGHT_IDS: string[] = [];
const EMPTY_HIGHLIGHT_EDGE_IDS: string[] = [];
const EMPTY_PATH_IDS: string[] = [];
const EMPTY_MUTED_IDS: string[] = [];
const EMPTY_MUTED_EDGE_IDS: string[] = [];

const typeGlyph: Record<string, string> = {
  攻击组织: "◎",
  历史事件: "◈",
  攻击步骤: "◆",
  "IOC/基础设施": "◉",
  "IOC 集合": "#",
  "恶意软件/工具": "✦",
  "ATT&CK 技术": "T",
  CVE: "V",
  检测证据: "E",
  资产: "A",
  身份: "@",
  报告: "▤",
  输入步骤: "◇",
};

function shortLabel(value: string, max = 16) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

type LayoutTarget = Point & {
  fixed: boolean;
};

function forceLayoutTargets(
  nodes: GraphNode[],
  rootId: string | undefined,
  viewWidth: number,
) {
  const root = nodes.find((node) => node.id === rootId) ?? nodes[0];
  return new Map<string, LayoutTarget>(nodes.map((node, index) => {
    if (node.id === root?.id) {
      return [node.id, { x: viewWidth / 2, y: 280, fixed: true }];
    }
    const angle = ((index - 1) / Math.max(nodes.length - 1, 1)) * Math.PI * 2;
    const ring = 145 + (index % 3) * 48;
    return [node.id, {
      x: viewWidth / 2 + Math.cos(angle) * ring,
      y: 280 + Math.sin(angle) * ring * 0.72,
      fixed: false,
    }];
  }));
}

function stableExpansionPoint(
  nodeId: string,
  edges: GraphEdge[],
  previousNodes: Map<string, SimNode>,
  fallback: Point,
) {
  const connectedEdge = edges.find(
    (edge) =>
      (edge.source === nodeId && previousNodes.has(edge.target)) ||
      (edge.target === nodeId && previousNodes.has(edge.source)),
  );
  const anchorId = connectedEdge
    ? connectedEdge.source === nodeId
      ? connectedEdge.target
      : connectedEdge.source
    : undefined;
  const anchor = anchorId ? previousNodes.get(anchorId) : undefined;
  if (!anchor) return fallback;

  let hash = 0;
  for (let index = 0; index < nodeId.length; index += 1) {
    hash = (hash * 31 + nodeId.charCodeAt(index)) >>> 0;
  }
  const angle = ((hash % 360) * Math.PI) / 180;
  const radius = 82 + (hash % 38);
  return {
    x: Math.max(
      48,
      Math.min(952, (anchor.x ?? fallback.x) + Math.cos(angle) * radius),
    ),
    y: Math.max(
      48,
      Math.min(490, (anchor.y ?? fallback.y) + Math.sin(angle) * radius),
    ),
  };
}

function radialLayoutTargets(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootId: string | undefined,
  viewWidth: number,
) {
  const root = nodes.find((node) => node.id === rootId) ?? nodes[0];
  if (!root) return new Map<string, LayoutTarget>();

  const nodeIds = new Set(nodes.map((node) => node.id));
  const adjacency = new Map<
    string,
    Array<{ id: string; confidence: number }>
  >();
  edges.forEach((edge) => {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return;
    adjacency.set(edge.source, [
      ...(adjacency.get(edge.source) ?? []),
      { id: edge.target, confidence: edge.confidence ?? 0 },
    ]);
    adjacency.set(edge.target, [
      ...(adjacency.get(edge.target) ?? []),
      { id: edge.source, confidence: edge.confidence ?? 0 },
    ]);
  });
  adjacency.forEach((neighbors) =>
    neighbors.sort(
      (left, right) =>
        right.confidence - left.confidence ||
        left.id.localeCompare(right.id),
    ),
  );

  type Assignment = {
    depth: number;
    parentId?: string;
    branch: number;
  };
  const assignments = new Map<string, Assignment>([
    [root.id, { depth: 0, branch: 0 }],
  ]);
  const firstHop = (adjacency.get(root.id) ?? []).filter(
    (neighbor, index, neighbors) =>
      neighbors.findIndex((candidate) => candidate.id === neighbor.id) ===
      index,
  );
  firstHop.forEach((neighbor, branch) => {
    assignments.set(neighbor.id, {
      depth: 1,
      parentId: root.id,
      branch,
    });
  });

  const queue = firstHop.map((neighbor) => neighbor.id);
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const currentId = queue[cursor];
    const current = assignments.get(currentId);
    if (!current || current.depth >= 4) continue;
    (adjacency.get(currentId) ?? []).forEach((neighbor) => {
      if (assignments.has(neighbor.id)) return;
      assignments.set(neighbor.id, {
        depth: current.depth + 1,
        parentId: currentId,
        branch: current.branch,
      });
      queue.push(neighbor.id);
    });
  }

  const unassigned = nodes.filter((node) => !assignments.has(node.id));
  const connectedBranchCount = Math.max(firstHop.length, 1);
  unassigned.forEach((node, index) => {
    assignments.set(node.id, {
      depth: 2,
      branch: connectedBranchCount + index,
    });
  });
  const branchCount = Math.max(
    connectedBranchCount + unassigned.length,
    1,
  );

  const siblingGroups = new Map<string, string[]>();
  nodes.forEach((node) => {
    const assignment = assignments.get(node.id);
    if (!assignment || assignment.depth < 2 || !assignment.parentId) return;
    const key = `${assignment.parentId}:${assignment.depth}`;
    siblingGroups.set(key, [
      ...(siblingGroups.get(key) ?? []),
      node.id,
    ]);
  });
  siblingGroups.forEach((ids) => ids.sort());

  const angles = new Map<string, number>([[root.id, -Math.PI / 2]]);
  [...nodes]
    .sort(
      (left, right) =>
        (assignments.get(left.id)?.depth ?? 0) -
        (assignments.get(right.id)?.depth ?? 0),
    )
    .forEach((node) => {
      if (node.id === root.id) return;
      const assignment = assignments.get(node.id)!;
      if (!assignment.parentId) {
        angles.set(
          node.id,
          -Math.PI / 2 +
            (assignment.branch * Math.PI * 2) / branchCount,
        );
        return;
      }
      if (assignment.depth === 1) {
        angles.set(
          node.id,
          -Math.PI / 2 +
            (assignment.branch * Math.PI * 2) /
              connectedBranchCount,
        );
        return;
      }

      const parentAngle = angles.get(assignment.parentId) ?? 0;
      const siblings =
        siblingGroups.get(
          `${assignment.parentId}:${assignment.depth}`,
        ) ?? [node.id];
      const siblingIndex = siblings.indexOf(node.id);
      const sector = Math.min(
        0.72,
        (Math.PI * 1.35) / connectedBranchCount,
      );
      const offset =
        siblings.length === 1
          ? 0
          : (siblingIndex / (siblings.length - 1) - 0.5) * sector;
      angles.set(node.id, parentAngle + offset);
    });

  return new Map<string, LayoutTarget>(
    nodes.map((node) => {
      if (node.id === root.id) {
        return [
          node.id,
          { x: viewWidth / 2, y: 280, fixed: true },
        ];
      }
      const assignment = assignments.get(node.id)!;
      const depth = Math.max(assignment.depth, 1);
      const angle = angles.get(node.id) ?? 0;
      const radiusX = Math.min(400, 152 + (depth - 1) * 112);
      const radiusY = Math.min(205, 116 + (depth - 1) * 76);
      return [
        node.id,
        {
          x: viewWidth / 2 + Math.cos(angle) * radiusX,
          y: 280 + Math.sin(angle) * radiusY,
          fixed: false,
        },
      ];
    }),
  );
}

function pathLayoutTargets(
  nodes: GraphNode[],
  edges: GraphEdge[],
  pathIds: string[],
  viewWidth: number,
) {
  const nodeIds = new Set(nodes.map((node) => node.id));
  const backbone = pathIds.filter((id) => nodeIds.has(id));
  if (!backbone.length) return forceLayoutTargets(nodes, undefined, viewWidth);

  const outgoing = new Map<string, string[]>();
  const incoming = new Map<string, string[]>();
  edges.forEach((edge) => {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) return;
    outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge.target]);
    incoming.set(edge.target, [...(incoming.get(edge.target) ?? []), edge.source]);
  });

  type Assignment = {
    owner: number;
    depth: number;
    direction: "path" | "downstream" | "upstream" | "unplaced";
  };
  const assignments = new Map<string, Assignment>(
    backbone.map((id, owner) => [
      id,
      { owner, depth: 0, direction: "path" },
    ]),
  );

  const walk = (
    adjacency: Map<string, string[]>,
    direction: Assignment["direction"],
  ) => {
    const queue = backbone.map((id, owner) => ({ id, owner, depth: 0 }));
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const current = queue[cursor];
      if (current.depth >= 4) continue;
      (adjacency.get(current.id) ?? []).forEach((id) => {
        if (assignments.has(id)) return;
        const next = { id, owner: current.owner, depth: current.depth + 1 };
        assignments.set(id, {
          owner: next.owner,
          depth: next.depth,
          direction,
        });
        queue.push(next);
      });
    }
  };
  walk(outgoing, "downstream");
  walk(incoming, "upstream");

  const groups = new Map<string, string[]>();
  nodes.forEach((node) => {
    if (assignments.has(node.id)) return;
    assignments.set(node.id, {
      owner: 0,
      depth: 3,
      direction: "unplaced",
    });
  });
  nodes.forEach((node) => {
    const assignment = assignments.get(node.id)!;
    const key = `${assignment.owner}:${assignment.depth}:${assignment.direction}`;
    groups.set(key, [...(groups.get(key) ?? []), node.id]);
  });

  const left = 90;
  const right = viewWidth - 90;
  const pathX = (index: number) =>
    backbone.length === 1
      ? viewWidth / 2
      : left + ((right - left) * index) / (backbone.length - 1);

  return new Map<string, LayoutTarget>(
    nodes.map((node) => {
      const assignment = assignments.get(node.id)!;
      if (assignment.direction === "path") {
        return [
          node.id,
          { x: pathX(assignment.owner), y: 175, fixed: true },
        ];
      }
      const key = `${assignment.owner}:${assignment.depth}:${assignment.direction}`;
      const siblings = groups.get(key) ?? [node.id];
      const siblingIndex = siblings.indexOf(node.id);
      const spread = (siblingIndex - (siblings.length - 1) / 2) * 70;
      const downstreamY = Math.min(500, 175 + assignment.depth * 108);
      const upstreamY = Math.max(58, 175 - assignment.depth * 105);
      const unplacedY = 492;
      return [
        node.id,
        {
          x: Math.max(
            52,
            Math.min(
              viewWidth - 52,
              pathX(assignment.owner) + spread + assignment.depth * 14,
            ),
          ),
          y:
            assignment.direction === "downstream"
              ? downstreamY
              : assignment.direction === "upstream"
                ? upstreamY
                : unplacedY,
          fixed: false,
        },
      ];
    }),
  );
}

export function NetworkGraph({
  nodes,
  edges,
  rootId,
  selectedId,
  selectedEdgeId,
  highlightIds = EMPTY_HIGHLIGHT_IDS,
  highlightEdgeIds = EMPTY_HIGHLIGHT_EDGE_IDS,
  mutedIds = EMPTY_MUTED_IDS,
  mutedEdgeIds = EMPTY_MUTED_EDGE_IDS,
  edgeAnnotations = {},
  hiddenNeighborCounts = {},
  focusMode = false,
  compact = false,
  layout = "force",
  pathIds = EMPTY_PATH_IDS,
  stabilizeExpansion = false,
  onSelect,
  onSelectEdge,
}: Props) {
  const viewWidth = 1000;
  const [zoom, setZoom] = useState(compact ? 0.9 : 1);
  const [positions, setPositions] = useState<Map<string, Point>>(new Map());
  const [draggingId, setDraggingId] = useState<string>();
  const simulationRef = useRef<Simulation<SimNode, SimLink> | null>(null);
  const simNodesRef = useRef<Map<string, SimNode>>(new Map());
  const layoutTargetsRef = useRef<Map<string, LayoutTarget>>(new Map());
  const previousRootIdRef = useRef(rootId);
  const dragStartRef = useRef<{ x: number; y: number } | undefined>(undefined);
  const dragOffsetRef = useRef<Point>({ x: 0, y: 0 });
  const dragMovedRef = useRef(false);
  const graphRef = useRef<HTMLDivElement>(null);
  const nodeLayoutKey = nodes.map((node) => node.id).join("\u001f");
  const edgeLayoutKey = edges
    .map((edge) => `${edge.id}\u001e${edge.source}\u001e${edge.target}`)
    .join("\u001f");
  const pathLayoutKey = pathIds.join("\u001f");

  useEffect(() => {
    const previousNodes = simNodesRef.current;
    const rootChanged = previousRootIdRef.current !== rootId;
    const layoutTargets =
      layout === "path"
        ? pathLayoutTargets(nodes, edges, pathIds, viewWidth)
        : layout === "radial"
          ? radialLayoutTargets(nodes, edges, rootId, viewWidth)
          : forceLayoutTargets(nodes, rootId, viewWidth);
    const simNodes = nodes.map<SimNode>((node) => {
      const target = layoutTargets.get(node.id) ?? {
        x: viewWidth / 2,
        y: 280,
        fixed: false,
      };
      const previous =
        stabilizeExpansion && layout !== "path" && !rootChanged
          ? previousNodes.get(node.id)
          : undefined;
      const point = previous
        ? {
            x: previous.x ?? target.x,
            y: previous.y ?? target.y,
          }
        : stabilizeExpansion && layout !== "path" && previousNodes.size
          ? layout === "radial"
            ? target
            : stableExpansionPoint(node.id, edges, previousNodes, target)
          : target;
      return {
        id: node.id,
        graphNode: node,
        x: point.x,
        y: point.y,
        fx: target.fixed
          ? point.x
          : previous
            ? point.x
            : undefined,
        fy: target.fixed
          ? point.y
          : previous
            ? point.y
            : undefined,
      };
    });
    const simNodeIds = new Set(simNodes.map((node) => node.id));
    const simLinks: SimLink[] = edges
      .filter((edge) => simNodeIds.has(edge.source) && simNodeIds.has(edge.target))
      .map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
      }));

    simNodesRef.current = new Map(simNodes.map((node) => [node.id, node]));
    layoutTargetsRef.current = layoutTargets;
    previousRootIdRef.current = rootId;
    // Reset the visible layout when the graph payload changes.
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
          .distance(
            layout === "radial" ? 128 : compact ? 92 : 116,
          )
          .strength(layout === "radial" ? 0.18 : 0.42),
      )
      .force(
        "charge",
        forceManyBody<SimNode>().strength(
          layout === "radial" ? -220 : compact ? -230 : -390,
        ),
      )
      .force(
        "collision",
        forceCollide<SimNode>()
          .radius((node) =>
            node.id === rootId ? 50 : compact ? 34 : 43,
          )
          .strength(0.9),
      )
      .alpha(1)
      .alphaDecay(0.035);

    if (layout === "force") {
      simulation.force("center", forceCenter(viewWidth / 2, 280));
    }
    simulation
      .force(
        "root-x",
        forceX<SimNode>((node) =>
          layoutTargets.get(node.id)?.x ?? viewWidth / 2,
        ).strength((node) =>
          layout === "path"
            ? layoutTargets.get(node.id)?.fixed
              ? 1
              : 0.3
            : layout === "radial"
              ? 0.92
            : node.id === rootId
              ? 0.28
              : 0.018,
        ),
      )
      .force(
        "root-y",
        forceY<SimNode>((node) =>
          layoutTargets.get(node.id)?.y ?? 280,
        ).strength((node) =>
          layout === "path"
            ? layoutTargets.get(node.id)?.fixed
              ? 1
              : 0.36
            : layout === "radial"
              ? 0.92
            : node.id === rootId
              ? 0.28
              : 0.018,
        ),
      );

    simulation.on("tick", () => {
      const next = new Map<string, Point>();
      simNodes.forEach((node) => {
        const margin = node.id === rootId ? 48 : 34;
        const maxY = layout === "path" ? 500 : 490;
        node.x = Math.max(margin, Math.min(viewWidth - margin, node.x ?? viewWidth / 2));
        node.y = Math.max(margin, Math.min(maxY, node.y ?? 280));
        next.set(node.id, { x: node.x, y: node.y });
      });
      setPositions(next);
    });

    simulationRef.current = simulation;
    return () => {
      simulation.stop();
      if (simulationRef.current === simulation) simulationRef.current = null;
    };
    // Layout is tied to graph topology, not ephemeral array identities or
    // visual selection/highlight state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    nodeLayoutKey,
    edgeLayoutKey,
    rootId,
    compact,
    layout,
    pathLayoutKey,
    stabilizeExpansion,
  ]);

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
    dragMovedRef.current = false;
    if (layout === "path" && pathIds.includes(node.id)) return;
    const point = pointerToGraph(event);
    const simNode = simNodesRef.current.get(node.id);
    if (!point || !simNode) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStartRef.current = { x: event.clientX, y: event.clientY };
    dragOffsetRef.current = {
      x: (simNode.x ?? point.x) - point.x,
      y: (simNode.y ?? point.y) - point.y,
    };
    setDraggingId(node.id);
  };

  const moveDrag = (
    event: ReactPointerEvent<SVGGElement>,
    node: GraphNode,
  ) => {
    if (draggingId !== node.id) return;
    const point = pointerToGraph(event);
    const simNode = simNodesRef.current.get(node.id);
    if (!point || !simNode) return;
    const distance = dragStartRef.current
      ? Math.hypot(
          event.clientX - dragStartRef.current.x,
          event.clientY - dragStartRef.current.y,
        )
      : 0;
    if (distance <= 3) return;
    if (!dragMovedRef.current) {
      dragMovedRef.current = true;
      simulationRef.current?.alphaTarget(0.18).restart();
    }
    const nextPoint = {
      x: point.x + dragOffsetRef.current.x,
      y: point.y + dragOffsetRef.current.y,
    };
    simNode.fx = nextPoint.x;
    simNode.fy = nextPoint.y;
    setPositions((current) => new Map(current).set(node.id, nextPoint));
  };

  const endDrag = (
    event: ReactPointerEvent<SVGGElement>,
    node: GraphNode,
  ) => {
    if (draggingId !== node.id) return;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    dragStartRef.current = undefined;
    setDraggingId(undefined);
    if (dragMovedRef.current) simulationRef.current?.alphaTarget(0);
  };

  const releaseNode = (nodeId: string) => {
    const simNode = simNodesRef.current.get(nodeId);
    if (!simNode) return;
    const target = layoutTargetsRef.current.get(nodeId);
    if (target?.fixed) {
      simNode.fx = target.x;
      simNode.fy = target.y;
      simulationRef.current?.alpha(0.45).restart();
      return;
    }
    simNode.fx = null;
    simNode.fy = null;
    simulationRef.current?.alpha(0.65).restart();
  };

  const resetGraph = () => {
    setZoom(1);
    simNodesRef.current.forEach((node) => {
      const target = layoutTargetsRef.current.get(node.id);
      node.x = target?.x ?? node.x;
      node.y = target?.y ?? node.y;
      node.fx = target?.fixed ? target.x : null;
      node.fy = target?.fixed ? target.y : null;
    });
    simulationRef.current?.alpha(1).restart();
  };

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    const preventNativeSelection = (event: Event) => event.preventDefault();
    graph.addEventListener("selectstart", preventNativeSelection);
    graph.addEventListener("dragstart", preventNativeSelection);
    return () => {
      graph.removeEventListener("selectstart", preventNativeSelection);
      graph.removeEventListener("dragstart", preventNativeSelection);
    };
  }, []);

  return (
    <div
      ref={graphRef}
      className={`network-graph ${compact ? "is-compact" : ""} ${layout === "path" ? "is-path-layout" : ""} ${layout === "radial" ? "is-radial-layout" : ""} ${focusMode ? "is-focus-mode" : ""}`}
    >
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
        {layout === "path"
          ? "真实图谱 · 主路径固定 · 支持缩放与拖拽支线"
          : layout === "radial"
            ? "放射拓扑，新增关联沿当前节点向外展开"
          : stabilizeExpansion
            ? "自由拓扑，新增关联只在当前节点附近展开"
            : "点击节点查看关系 · 支持缩放浏览"}
      </div>
      <svg
        role="img"
        aria-label="威胁情报关系图谱"
        onDragStart={(event) => event.preventDefault()}
        viewBox={`0 0 ${viewWidth} 560`}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <marker
            id={`arrow-${layout}-${compact ? "compact" : "full"}`}
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
            const annotation = edgeAnnotations[edge.id];
            const annotationWidth = annotation
              ? Math.max(50, annotation.label.length * 11 + 18)
              : 0;
            return (
              <g
                key={edge.id}
                className={`edge edge-${edge.status ?? "positive"} ${highlightEdgeIds.includes(edge.id) ? "is-highlighted" : ""} ${selectedEdgeId === edge.id ? "is-selected" : ""} ${mutedEdgeIds.includes(edge.id) ? "is-muted" : ""}`}
                role={onSelectEdge ? "button" : undefined}
                tabIndex={onSelectEdge ? 0 : undefined}
                aria-label={
                  onSelectEdge
                    ? `关系：${edge.label}`
                    : undefined
                }
                onClick={(event) => {
                  event.stopPropagation();
                  onSelectEdge?.(edge);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelectEdge?.(edge);
                  }
                }}
              >
                {onSelectEdge && (
                  <line
                    className="edge-hit-area"
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                  />
                )}
                <line
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  markerEnd={`url(#arrow-${layout}-${compact ? "compact" : "full"})`}
                />
                {!compact && !annotation && (
                  <text x={midX} y={midY - 6} textAnchor="middle">
                    {shortLabel(edge.label, 10)}
                  </text>
                )}
                {!compact && annotation && (
                  <g
                    className={`edge-annotation is-${annotation.tone}`}
                    transform={`translate(${midX} ${midY + 14})`}
                    aria-label={`分支语义：${annotation.label}`}
                  >
                    <rect
                      x={-annotationWidth / 2}
                      y={-9}
                      width={annotationWidth}
                      height={18}
                      rx={4}
                    />
                    <text y={3} textAnchor="middle">
                      {annotation.label}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
          {nodes.map((node) => {
            const point = positions.get(node.id);
            if (!point) return null;
            const selected = node.id === selectedId;
            const root = node.id === rootId;
            const highlighted = highlightIds.includes(node.id);
            const dragging = node.id === draggingId;
            const evidenceClass =
              node.entity &&
              typeof node.entity.properties.evidence_class === "string"
                ? node.entity.properties.evidence_class
                : "unknown";
            const analysisState =
              node.entity &&
              typeof node.entity.properties.analysis_state === "string"
                ? node.entity.properties.analysis_state
                : "unknown";
            const iocMemberCount =
              node.type === "IOC 集合" &&
              typeof node.properties?.member_count === "number"
                ? node.properties.member_count
                : 0;
            return (
              <g
                key={node.id}
                transform={`translate(${point.x} ${point.y})`}
                className={`graph-node node-${node.status ?? "positive"} evidence-${evidenceClass} analysis-${analysisState} ${node.type === "IOC 集合" ? "is-ioc-collection" : ""} ${selected ? "is-selected" : ""} ${root ? "is-root" : ""} ${highlighted ? "is-highlighted" : ""} ${mutedIds.includes(node.id) ? "is-muted" : ""} ${dragging ? "is-dragging" : ""}`}
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
                aria-label={`${node.type}：${node.label}${iocMemberCount ? `，包含 ${iocMemberCount} 个对象` : ""}`}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") onSelect?.(node);
                  if (event.key === "Escape") releaseNode(node.id);
                }}
              >
                <circle className="node-halo" r={root ? 36 : 28} />
                <circle className="node-core" r={root ? 29 : 22} />
                <text className="node-glyph" textAnchor="middle" y="5">
                  {iocMemberCount || typeGlyph[node.type] || "•"}
                </text>
                <text className="node-label" textAnchor="middle" y={root ? 53 : 43}>
                  {shortLabel(node.label, compact ? 11 : 17)}
                </text>
                {!compact && (iocMemberCount > 0 || node.confidence != null) && (
                  <text className="node-score" textAnchor="middle" y={root ? 69 : 58}>
                    {iocMemberCount
                      ? `${iocMemberCount} 个对象`
                      : `${Math.round((node.confidence ?? 0) * 100)}%`}
                  </text>
                )}
                {!compact && (hiddenNeighborCounts[node.id] ?? 0) > 0 && (
                  <g
                    className="node-hidden-count"
                    transform={`translate(${root ? 27 : 21} ${root ? -27 : -21})`}
                    aria-label={`还有 ${hiddenNeighborCounts[node.id]} 个直接下游未展开`}
                  >
                    <circle r={12} />
                    <text textAnchor="middle" y={3}>
                      +{hiddenNeighborCounts[node.id]}
                    </text>
                  </g>
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
