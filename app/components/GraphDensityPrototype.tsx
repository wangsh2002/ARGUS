"use client";

// Swimlane projection of the currently visible real graph state.

import {
  ChevronDown,
  ChevronUp,
  Columns3,
} from "lucide-react";
import { useMemo, useState } from "react";
import { propString } from "../argus-domain";
import type { GraphEdge, GraphNode } from "../types";

type Props = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootIds: string[];
  backbone: GraphNode[];
  visibleIds: string[];
  selectedId?: string;
  onSelect: (node: GraphNode) => void;
};

function confidenceOf(node: GraphNode) {
  return node.confidence ?? 0;
}

function statusWeight(status?: string) {
  if (status === "hot" || status === "positive") return 3;
  if (status === "partial") return 2;
  if (status === "negative") return 0;
  return 1;
}

function walkTemporalPath(
  startId: string,
  nodes: GraphNode[],
  edges: GraphEdge[],
) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const path: GraphNode[] = [];
  const seen = new Set<string>();
  let currentId: string | undefined = startId;

  while (currentId && !seen.has(currentId)) {
    const node = nodeMap.get(currentId);
    if (!node) break;
    path.push(node);
    seen.add(currentId);
    const next = edges
      .filter(
        (edge) =>
          edge.source === currentId &&
          edge.label === "时序后继" &&
          !seen.has(edge.target),
      )
      .sort(
        (left, right) =>
          statusWeight(right.status) - statusWeight(left.status) ||
          (right.confidence ?? 0) - (left.confidence ?? 0),
      )[0];
    currentId = next?.target;
  }
  return path;
}

export function deriveGraphBackbone(
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootIds: string[],
  primaryEventId?: string,
  preferredPathIds: string[] = [],
) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const authoredBackbone = nodes
    .filter(
      (node) =>
        node.type === "攻击步骤" &&
        node.entity &&
        propString(node.entity, "mainline_role") === "backbone",
    )
    .sort((left, right) => {
      const orderOf = (node: GraphNode) =>
        Number(
          node.entity
            ? propString(node.entity, "mainline_order") || "999"
            : "999",
        );
      return orderOf(left) - orderOf(right) || left.id.localeCompare(right.id);
    });
  if (authoredBackbone.length >= 2) return authoredBackbone;

  const preferredPath = preferredPathIds
    .map((id) => nodeMap.get(id))
    .filter(
      (node, index, all): node is GraphNode =>
        Boolean(node) &&
        node?.type === "攻击步骤" &&
        all.findIndex((candidate) => candidate?.id === node.id) === index,
    );
  if (preferredPath.length >= 2) return preferredPath;

  const rootSet = new Set(rootIds);
  const eventIds = [
    primaryEventId,
    ...nodes.filter((node) => node.type === "历史事件").map((node) => node.id),
  ].filter((id): id is string => Boolean(id));
  const starts = eventIds.flatMap((eventId) =>
    edges
      .filter(
        (edge) =>
          edge.source === eventId &&
          edge.label === "起始步骤" &&
          nodeMap.get(edge.target)?.type === "攻击步骤",
      )
      .map((edge) => edge.target),
  );
  const fallbackStarts = nodes
    .filter(
      (node) =>
        node.type === "攻击步骤" &&
        !edges.some(
          (edge) => edge.target === node.id && edge.label === "时序后继",
        ),
    )
    .map((node) => node.id);

  return (
    [...new Set([...starts, ...fallbackStarts])]
      .map((startId) => walkTemporalPath(startId, nodes, edges))
      .filter((path) => path.length)
      .sort((left, right) => {
        const leftRoots = left.filter((node) => rootSet.has(node.id)).length;
        const rightRoots = right.filter((node) => rootSet.has(node.id)).length;
        return (
          rightRoots - leftRoots ||
          right.reduce((sum, node) => sum + confidenceOf(node), 0) /
            right.length -
            left.reduce((sum, node) => sum + confidenceOf(node), 0) /
              left.length ||
          left.length - right.length
        );
      })[0] ??
    nodes
      .filter((node) => node.type === "攻击步骤")
      .sort((left, right) => confidenceOf(right) - confidenceOf(left))
      .slice(0, 5)
  );
}

export function initialExplorationIds(
  backbone: GraphNode[],
  nodes: GraphNode[],
  edges: GraphEdge[],
  rootIds: string[],
) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const backboneIds = new Set(backbone.map((node) => node.id));
  const rootSet = new Set(rootIds);
  const visible = new Set(backboneIds);

  backbone.forEach((step) => {
    edges
      .filter(
        (edge) =>
          edge.source === step.id &&
          !backboneIds.has(edge.target) &&
          nodeMap.has(edge.target) &&
          rootSet.has(edge.target),
      )
      .forEach((edge) => visible.add(edge.target));
  });

  return [...visible];
}

function NodeButton({
  node,
  relation,
  selected,
  root,
  compact = false,
  onSelect,
}: {
  node: GraphNode;
  relation?: string;
  selected: boolean;
  root: boolean;
  compact?: boolean;
  onSelect: (node: GraphNode) => void;
}) {
  const iocMemberCount =
    node.type === "IOC 集合" &&
    typeof node.properties?.member_count === "number"
      ? node.properties.member_count
      : 0;
  return (
    <button
      type="button"
      className={`prototype-node node-${node.status ?? "positive"} analysis-${node.entity ? propString(node.entity, "analysis_state") || "unknown" : "unknown"} ${selected ? "is-selected" : ""} ${root ? "is-input-hit" : ""} ${compact ? "is-compact" : ""}`}
      aria-label={`${node.type}：${node.label}`}
      onClick={() => onSelect(node)}
    >
      {relation && <em>{relation}</em>}
      <span>{node.label}</span>
      <small>
        {iocMemberCount ? `${node.type} · ${iocMemberCount} 个对象` : node.type}
        {!iocMemberCount && node.confidence != null
          ? ` ${Math.round(node.confidence * 100)}%`
          : ""}
      </small>
    </button>
  );
}

function assignNodesToBackbone(
  nodes: GraphNode[],
  edges: GraphEdge[],
  backbone: GraphNode[],
  visibleIds: Set<string>,
) {
  const backboneIds = new Set(backbone.map((node) => node.id));
  const adjacency = new Map<string, Set<string>>();
  edges.forEach((edge) => {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, new Set());
    if (!adjacency.has(edge.target)) adjacency.set(edge.target, new Set());
    adjacency.get(edge.source)?.add(edge.target);
    adjacency.get(edge.target)?.add(edge.source);
  });
  const groups = new Map<string, GraphNode[]>(
    backbone.map((node) => [node.id, []]),
  );

  nodes
    .filter((node) => visibleIds.has(node.id) && !backboneIds.has(node.id))
    .forEach((node) => {
      let ownerId = backbone[0]?.id;
      let bestDistance = Number.POSITIVE_INFINITY;
      backbone.forEach((step) => {
        const visited = new Set([node.id]);
        let frontier = [node.id];
        for (let distance = 1; distance <= 4; distance += 1) {
          frontier = frontier
            .flatMap((id) => [...(adjacency.get(id) ?? [])])
            .filter((id) => !visited.has(id));
          frontier.forEach((id) => visited.add(id));
          if (frontier.includes(step.id)) {
            if (distance < bestDistance) {
              bestDistance = distance;
              ownerId = step.id;
            }
            break;
          }
        }
      });
      if (ownerId) groups.get(ownerId)?.push(node);
    });
  return groups;
}

const laneDefinitions = [
  {
    label: "攻击过程",
    matches: (node: GraphNode) => node.type === "攻击步骤",
  },
  {
    label: "IOC 与基础设施",
    matches: (node: GraphNode) =>
      node.type === "IOC/基础设施" ||
      node.type === "IOC 集合" ||
      node.type === "CVE" ||
      node.type === "资产" ||
      node.type === "身份",
  },
  {
    label: "检测证据",
    matches: (node: GraphNode) => node.type === "检测证据",
  },
  {
    label: "技战术与工具",
    matches: (node: GraphNode) =>
      node.type === "ATT&CK 技术" || node.type === "恶意软件/工具",
  },
  {
    label: "历史活动与组织",
    matches: (node: GraphNode) =>
      node.type === "历史事件" || node.type === "攻击组织",
  },
];

function SwimlaneVariant(props: Props) {
  const visibleSet = useMemo(
    () => new Set(props.visibleIds),
    [props.visibleIds],
  );
  const rootSet = useMemo(() => new Set(props.rootIds), [props.rootIds]);
  const groups = useMemo(
    () =>
      assignNodesToBackbone(
        props.nodes,
        props.edges,
        props.backbone,
        visibleSet,
      ),
    [props.backbone, props.edges, props.nodes, visibleSet],
  );

  return (
    <div
      className="graph-prototype-canvas graph-prototype-swimlane"
      role="img"
      aria-label="威胁情报关系图谱"
    >
      <div
        className="swimlane-grid"
        style={{
          gridTemplateColumns: `124px repeat(${Math.max(props.backbone.length, 1)}, minmax(188px, 1fr))`,
        }}
      >
        <div className="swimlane-corner">当前可见证据</div>
        {props.backbone.map((step) => (
          <div className="swimlane-phase" key={`phase-${step.id}`}>
            <span>{step.label}</span>
            <small>{Math.round(confidenceOf(step) * 100)}% 置信度</small>
          </div>
        ))}
        {laneDefinitions.map((lane) => (
          <div className="swimlane-row" key={lane.label}>
            <div className="swimlane-label">{lane.label}</div>
            {props.backbone.map((step) => {
              const laneNodes = [
                ...(lane.label === "攻击过程" && visibleSet.has(step.id)
                  ? [step]
                  : []),
                ...(groups.get(step.id) ?? []).filter(lane.matches),
              ];
              return (
                <div className="swimlane-cell" key={`${lane.label}-${step.id}`}>
                  {laneNodes.map((node) => (
                    <NodeButton
                      compact
                      key={node.id}
                      node={node}
                      selected={node.id === props.selectedId}
                      root={rootSet.has(node.id)}
                      onSelect={props.onSelect}
                    />
                  ))}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

export function GraphSwimlaneProjection(props: Props) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div
      className={`linked-swimlane-view ${collapsed ? "is-collapsed" : ""}`}
    >
      <div className="graph-prototype-heading">
        <div>
          <Columns3 size={15} />
          <strong>攻击阶段泳道</strong>
        </div>
        <p>使用同一批已展开节点，按攻击阶段重新组织，不产生第二套推断。</p>
        <button
          type="button"
          className="swimlane-collapse-button"
          aria-expanded={!collapsed}
          aria-controls="attack-stage-swimlane"
          onClick={() => setCollapsed((current) => !current)}
        >
          <span>{collapsed ? "展开" : "收起"}</span>
          {collapsed ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
        </button>
      </div>
      <div id="attack-stage-swimlane">
        {!collapsed && <SwimlaneVariant {...props} />}
      </div>
    </div>
  );
}
