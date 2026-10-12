import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import snapshot from "../lib/argus-data.json";
import { ArgusApp } from "../app/ArgusApp";
import { NetworkGraph } from "../app/NetworkGraph";
import { buildSubgraph } from "../app/argus-domain";
import type { AttackFlow, BackendFlowMatchRun, Snapshot } from "../app/types";

const data = snapshot as Snapshot;

function graphApiResponse(input: RequestInfo | URL, graphData: Snapshot = data) {
  const url = String(input);
  if (url === "/api/graph/nodes") {
    const relationCounts = new Map<string, number>();
    graphData.relationships.forEach((relationship) => {
      relationCounts.set(
        relationship.source_entity_id,
        (relationCounts.get(relationship.source_entity_id) ?? 0) + 1,
      );
      relationCounts.set(
        relationship.target_entity_id,
        (relationCounts.get(relationship.target_entity_id) ?? 0) + 1,
      );
    });
    const nodes = graphData.entities.map((entity) => ({
      id: entity.id,
      kind: entity.entity_type === "攻击组织" ? "actor" : "entity",
      label: entity.label,
      type: entity.entity_type,
      description: entity.description,
      confidence: entity.properties.confidence ?? 0.9,
      properties: { normalized_value: entity.normalized_value },
      relation_count: relationCounts.get(entity.id) ?? 0,
      evidence_count: entity.source_count,
    }));
    return {
      ok: true,
      json: async () => ({
        nodes,
        node_count: nodes.length,
        atomic_edge_count: graphData.relationships.length,
        aggregate_edge_count: 0,
        knowledge_version: "test-runtime-graph",
      }),
    } as Response;
  }
  if (url.startsWith("/api/graph/neighborhoods/")) {
    const rootId = decodeURIComponent(
      url.slice("/api/graph/neighborhoods/".length).split("?")[0],
    );
    const graph = buildSubgraph(graphData, [rootId], 64, undefined, 4);
    return {
      ok: true,
      json: async () => ({
        root_id: rootId,
        depth: 3,
        nodes: graph.nodes.map((node) => ({
          id: node.id,
          kind:
            node.type === "攻击组织"
              ? "actor"
              : node.type === "攻击步骤"
                ? "action"
                : "entity",
          label: node.label,
          type: node.type,
          description: node.entity?.description ?? "",
          confidence: node.confidence ?? 0.9,
          properties: {},
        })),
        edges: graph.edges.map((edge) => ({
          id: edge.id,
          source_id: edge.source,
          target_id: edge.target,
          type: edge.relationship?.relation_type ?? "related",
          label: edge.label,
          confidence: edge.confidence ?? 0.9,
          aggregate: false,
          evidence_ids: [],
          explanation: null,
        })),
        available_expansions: Object.fromEntries(
          graph.nodes.map((node) => [
            node.id,
            graph.edges.filter(
              (edge) => edge.source === node.id || edge.target === node.id,
            ).length,
          ]),
        ),
        knowledge_version: "test-runtime-graph",
      }),
    } as Response;
  }
  return undefined;
}

beforeEach(() => {
  window.localStorage.clear();
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation(async (input: RequestInfo | URL) =>
      graphApiResponse(input) ?? {
        ok: true,
        json: async () => ({ configured: false, model: null }),
      },
    ),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ARGUS query-centered workflows", () => {
  it("loads the production home page from scoped runtime APIs", async () => {
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/runtime/catalog") {
        return {
          ok: true,
          json: async () => ({
            meta: {
              source: "runtime-test",
              generated_at: data.meta.generated_at,
              version: "KVER-runtime-test",
            },
            stats: data.stats,
            entities: data.entities,
            reports: data.reports,
            aliases: data.aliases,
            response_rules: data.responseRules,
            algorithms: data.algorithms,
          }),
        } as Response;
      }
      if (url === "/api/attack-flows") {
        return { ok: true, json: async () => [] } as Response;
      }
      return graphApiResponse(input) ?? {
        ok: true,
        json: async () => ({ configured: false, model: null }),
      } as Response;
    });

    render(<ArgusApp />);

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "威胁情报查询与分析平台",
      }),
    ).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith(
      "/api/runtime/catalog",
      expect.objectContaining({ cache: "no-store" }),
    );
    expect(fetch).toHaveBeenCalledWith(
      "/api/attack-flows",
      expect.objectContaining({ cache: "no-store" }),
    );
    const history = screen.getByRole("region", { name: "历史研判报告" });
    const firstReport = within(history).getAllByRole("button")[0];
    fireEvent.click(firstReport);
    expect(
      await screen.findByRole("button", {
        name: /进入攻击过程|暂无关联攻击流/,
      }),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getAllByRole("button", { name: "返回综合查询" })[0],
    );
    expect(screen.getByLabelText("综合查询输入")).toHaveValue("");
    expect(
      screen.getByRole("region", { name: "历史研判报告" }),
    ).toBeInTheDocument();
  });

  it("opens an exact published flow directly with confirmed states only", async () => {
    const flowId = "PATH-DIRECT-CONFIRMED";
    const actionIds = ["DIRECT-A1", "DIRECT-A2", "DIRECT-A3"];
    const evidence = (id: string) => ({
      id: `E-${id}`,
      source_span_id: `SPAN-${id}`,
      source_id: "SRC-DIRECT",
      title: "Direct published flow report",
      publisher: "ARGUS Test",
      canonical_url: "https://example.test/direct-flow",
      locator: `line:${id}`,
      quote: `direct evidence ${id}`,
      confidence: 0.95,
    });
    const flow: AttackFlow = {
      schema_version: "1.0",
      id: flowId,
      title: "确定路径直达测试",
      description: "用于验证已知 AttackFlow 不再进入匹配页面。",
      sources: [
        {
          id: "SRC-DIRECT",
          title: "Direct published flow report",
          publisher: "ARGUS Test",
          canonical_url: "https://example.test/direct-flow",
          published_at: "2026-08-03",
        },
      ],
      actions: actionIds.map((id, index) => ({
        id,
        name: ["发送钓鱼邮件", "执行恶意载荷", "建立命令控制"][index],
        description: `已确认步骤 ${index + 1}`,
        phase: ["初始访问", "执行", "命令与控制"][index],
        confidence: "high",
        technique_ids: [],
        contexts: [],
        evidence: [evidence(`action-${index + 1}`)],
      })),
      relations: actionIds.slice(1).map((targetId, index) => ({
        id: `DIRECT-R${index + 1}`,
        source_action_id: actionIds[index],
        target_action_id: targetId,
        type: "enables",
        condition: null,
        confidence: "high",
        evidence: [evidence(`relation-${index + 1}`)],
      })),
      mainline: actionIds,
      reported_actors: [],
    };
    const fetchMock = vi.fn().mockImplementation(
      async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/runtime/catalog") {
          return {
            ok: true,
            json: async () => ({
              meta: {
                source: "runtime-direct-test",
                generated_at: data.meta.generated_at,
                version: "KVER-direct-test",
              },
              stats: data.stats,
              entities: [],
              reports: [],
              aliases: [],
              response_rules: [],
              algorithms: [],
            }),
          } as Response;
        }
        if (url === "/api/attack-flows") {
          return { ok: true, json: async () => [flow] } as Response;
        }
        if (url === `/api/attack-flows/${flowId}`) {
          return { ok: true, json: async () => flow } as Response;
        }
        return graphApiResponse(input) ?? {
          ok: true,
          json: async () => ({ configured: false, model: null }),
        } as Response;
      },
    );
    vi.stubGlobal("fetch", fetchMock);

    render(<ArgusApp />);
    const input = await screen.findByLabelText("综合查询输入");
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/attack-flows",
        expect.objectContaining({ cache: "no-store" }),
      ),
    );
    fireEvent.change(input, { target: { value: flow.title } });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByText("已发布攻击过程"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("已确认步骤").length).toBeGreaterThan(0);
    expect(screen.queryByText("路径补全")).not.toBeInTheDocument();
    expect(screen.queryByText("后续预测")).not.toBeInTheDocument();
    expect(screen.queryByText(/找到.*历史攻击流候选/)).not.toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(([input]) => String(input) === "/api/flow-matches"),
    ).toBe(false);
    const stageRail = screen.getByRole("region", { name: "攻击阶段判定" });
    within(stageRail)
      .getAllByRole("button")
      .forEach((stage) => expect(stage).toHaveAccessibleName(/已确认 · 95%/));
  });

  it("renders runtime flow candidates and preserves match states in detail", async () => {
    const flowId = "PATH-RUNTIME-FIVE-STEPS";
    const actionIds = Array.from(
      { length: 5 },
      (_, index) => `${flowId}-N-${String(index + 1).padStart(2, "0")}`,
    );
    const evidence = (id: string) => ({
      id: `E-${id}`,
      source_span_id: `SPAN-${id}`,
      source_id: "SRC-RUNTIME-FIVE",
      title: "Runtime five-step report",
      publisher: "ARGUS Test",
      canonical_url: "https://example.test/runtime-five",
      locator: `line:${id}`,
      quote: `runtime evidence ${id}`,
      confidence: 0.95,
    });
    const flow: AttackFlow = {
      schema_version: "1.0",
      id: flowId,
      title: "五步历史攻击流",
      description: "用于验证不完整线索补全与预测。",
      sources: [
        {
          id: "SRC-RUNTIME-FIVE",
          title: "Runtime five-step report",
          publisher: "ARGUS Test",
          canonical_url: "https://example.test/runtime-five",
          published_at: "2026-08-01",
        },
      ],
      actions: actionIds.map((id, index) => ({
        id,
        name: ["投递诱饵", "执行载荷", "释放测试木马", "创建计划任务", "回传数据"][index],
        description: `历史步骤 ${index + 1}`,
        phase: `阶段 ${index + 1}`,
        confidence: "high",
        technique_ids: index === 3 ? ["T1053.005"] : [],
        contexts: [
          ...(index === 0
            ? Array.from({ length: 8 }, (_, contextIndex) => ({
                id: `CTX-RUNTIME-IOC-${contextIndex + 1}`,
                entity_id: `ENTITY-RUNTIME-IOC-${contextIndex + 1}`,
                type: "infrastructure" as const,
                name: `c2-${contextIndex + 1}.example.test`,
                role: "communicates-with" as const,
                direction: "action-to-entity",
                confidence: "high" as const,
                evidence: [evidence(`ioc-${contextIndex + 1}`)],
              }))
            : []),
          ...(index === 2
            ? [
                {
                  id: "CTX-RUNTIME-MALWARE",
                  entity_id: "ENTITY-RUNTIME-MALWARE",
                  type: "malware",
                  name: "测试木马",
                  role: "uses",
                  direction: "action-to-entity",
                  confidence: "high",
                  evidence: [evidence("context")],
                },
              ]
            : []),
        ],
        evidence: [evidence(`action-${index + 1}`)],
      })),
      relations: actionIds.slice(1).map((targetId, index) => ({
        id: `REL-RUNTIME-${index + 1}`,
        source_action_id: actionIds[index],
        target_action_id: targetId,
        type: "enables",
        condition: null,
        confidence: "high",
        evidence: [evidence(`relation-${index + 1}`)],
      })),
      mainline: actionIds,
    };
    const run: BackendFlowMatchRun = {
      id: "FM-RUNTIME-FIVE",
      status: "completed",
      algorithm_version: "attack-flow-matcher/1.0",
      knowledge_snapshot: "a".repeat(64),
      query_text: "投递诱饵 → 测试木马 → 创建计划任务",
      normalized_inputs: [
        { value: "投递诱饵", kind: "auto", normalized_value: "投递诱饵" },
        { value: "测试木马", kind: "auto", normalized_value: "测试木马" },
        { value: "创建计划任务", kind: "auto", normalized_value: "创建计划任务" },
      ],
      candidates: [
        {
          flow_id: flowId,
          flow_title: flow.title,
          score: 0.91,
          matches: [
            {
              input_index: 0,
              input_value: "投递诱饵",
              input_kind: "auto",
              action_id: actionIds[0],
              match_kind: "behavior",
              matched_value: "投递诱饵",
              confidence: 1,
              explanation: "输入行为“投递诱饵”与历史行为“投递诱饵”匹配。",
            },
            {
              input_index: 1,
              input_value: "测试木马",
              input_kind: "auto",
              action_id: actionIds[2],
              match_kind: "context",
              matched_value: "测试木马",
              confidence: 0.97,
              explanation: "输入线索“测试木马”命中该行为旁的 Context“测试木马”；这不代表行为本身被直接观测。",
            },
            {
              input_index: 2,
              input_value: "创建计划任务",
              input_kind: "auto",
              action_id: actionIds[3],
              match_kind: "behavior",
              matched_value: "创建计划任务",
              confidence: 1,
              explanation: "输入行为“创建计划任务”与历史行为“创建计划任务”匹配。",
            },
          ],
          unmatched_inputs: [],
          mainline_frontier_action_id: actionIds[3],
          mainline_frontier_index: 3,
          action_states: [
            { action_id: actionIds[0], state: "input_hit" },
            { action_id: actionIds[1], state: "reconstructed" },
            { action_id: actionIds[2], state: "input_hit" },
            { action_id: actionIds[3], state: "input_hit" },
            { action_id: actionIds[4], state: "predicted" },
          ],
        },
      ],
    };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/flow-matches") {
        return { ok: true, json: async () => run };
      }
      if (url === "/api/attack-flows") {
        return { ok: true, json: async () => [flow] };
      }
      if (url === `/api/attack-flows/${flowId}`) {
        return { ok: true, json: async () => flow };
      }
      return graphApiResponse(input) ?? { ok: true, json: async () => ({ configured: false, model: null }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<ArgusApp fixture={data} />);
    fireEvent.focus(screen.getByLabelText("综合查询输入"));
    fireEvent.click(screen.getByRole("tab", { name: /攻击路径研判/ }));
    fireEvent.change(screen.getByLabelText("攻击路径查询输入"), {
      target: { value: run.query_text },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始攻击路径研判" }));

    await waitFor(() =>
      expect(
        screen.getByRole("heading", {
          level: 1,
          name: "找到 1 条达到阈值的历史攻击流候选",
        }),
      ).toBeInTheDocument(),
    );
    expect(
      document.querySelector(".activity-cluster-index > button"),
    ).toBeInTheDocument();
    expect(
      document.querySelector(
        ".activity-branch.is-selected .branch-select-mark",
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText("输入命中").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("路径补全").length).toBeGreaterThan(0);
    expect(screen.getAllByText("后续预测").length).toBeGreaterThan(0);
    expect(
      screen.getByText(/Context“测试木马”；这不代表行为本身被直接观测/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "添加节点" })).toHaveClass(
      "path-editor-add",
    );
    expect(
      screen.getByRole("button", { name: /上移投递诱饵/ }).parentElement,
    ).toHaveClass("path-editor-actions");
    const editorStatus = document.querySelector(".path-editor-status");
    expect(editorStatus).toHaveClass("is-observed");
    expect(editorStatus?.querySelector("span")).toHaveTextContent("输入命中");
    expect(editorStatus?.querySelector("b")).toHaveTextContent("100%");
    expect(
      screen.getByRole("button", { name: "进入所选路径" }),
    ).toHaveClass("path-editor-open");

    fireEvent.click(screen.getByRole("button", { name: "进入所选路径" }));
    await waitFor(() => {
      const stageRail = screen.getByRole("region", { name: "攻击阶段判定" });
      const stages = within(stageRail).getAllByRole("button");
      expect(stages[0]).toHaveAccessibleName("01 投递诱饵 输入命中 · 100%");
      expect(stages[1]).toHaveAccessibleName("02 执行载荷 路径补全 · 95%");
      expect(stages[4]).toHaveAccessibleName("05 回传数据 后续预测 · 95%");
    });
    expect(screen.queryByText(/先阻断对外 SMB/)).not.toBeInTheDocument();
    expect(
      screen.getByText(/对无法回到来源的关系保留为待验证/),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(
        document.querySelector(
          ".analysis-graph-panel .graph-node.is-ioc-collection",
        ),
      ).toBeInTheDocument(),
    );
    const graphCollection = document.querySelector(
      ".analysis-graph-panel .graph-node.is-ioc-collection",
    );
    const swimlaneCollection = document.querySelector(
      '.analysis-swimlane-panel .prototype-node[aria-label^="IOC 集合"]',
    );
    expect(graphCollection).toBeInTheDocument();
    expect(swimlaneCollection).toBeInTheDocument();
    fireEvent.click(graphCollection as Element);
    expect(
      screen.getByRole("heading", { level: 2, name: "报告关联 IOC 集合" }),
    ).toBeInTheDocument();
    expect(screen.getByText("c2-8.example.test")).toBeInTheDocument();
    expect(screen.getByLabelText("IOC 类型统计")).toHaveTextContent("域名 8");
  });

  it("shows an explicit empty result instead of forcing a historical flow", async () => {
    const run: BackendFlowMatchRun = {
      id: "FM-NO-CANDIDATE",
      status: "completed",
      algorithm_version: "attack-flow-matcher/1.0",
      knowledge_snapshot: "b".repeat(64),
      query_text: "完全无关的量子卫星攻击步骤",
      normalized_inputs: [
        {
          value: "完全无关的量子卫星攻击步骤",
          kind: "auto",
          normalized_value: "完全无关的量子卫星攻击步骤",
        },
      ],
      candidates: [],
    };
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input) === "/api/flow-matches") {
        return { ok: true, json: async () => run } as Response;
      }
      if (String(input) === "/api/attack-flows") {
        return { ok: true, json: async () => [] } as unknown as Response;
      }
      return graphApiResponse(input) ?? {
        ok: true,
        json: async () => ({ configured: false, model: null }),
      } as Response;
    });

    render(<ArgusApp fixture={data} />);
    fireEvent.focus(screen.getByLabelText("综合查询输入"));
    fireEvent.click(screen.getByRole("tab", { name: /攻击路径研判/ }));
    fireEvent.change(screen.getByLabelText("攻击路径查询输入"), {
      target: { value: run.query_text },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始攻击路径研判" }));

    await waitFor(() =>
      expect(
        screen.getByRole("heading", {
          level: 1,
          name: "没有达到阈值的历史攻击流",
        }),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/没有强行选择无关路径/)).toBeInTheDocument();
  });

});
describe("ARGUS relationship graph", () => {
  const mockGraphPointerGeometry = (
    svg: HTMLElement,
    node: HTMLElement,
  ) => {
    vi.spyOn(svg, "getBoundingClientRect").mockReturnValue({
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      right: 1000,
      bottom: 560,
      width: 1000,
      height: 560,
      toJSON: () => ({}),
    });
    Object.defineProperties(node, {
      setPointerCapture: { configurable: true, value: vi.fn() },
      hasPointerCapture: {
        configurable: true,
        value: vi.fn(() => true),
      },
      releasePointerCapture: { configurable: true, value: vi.fn() },
    });
  };
  const graphNodePosition = (node: HTMLElement) => {
    const match = node
      .getAttribute("transform")
      ?.match(/translate\(([-\d.]+) ([-\d.]+)\)/);
    if (!match) throw new Error("Graph node is missing a translate position");
    return { x: Number(match[1]), y: Number(match[2]) };
  };

  it("renders branch semantics, hidden relation counts and path focus without changing topology", () => {
    render(
      <NetworkGraph
        rootId="source"
        nodes={[
          { id: "source", label: "对外 SMB 445 认证", type: "攻击步骤" },
          { id: "blocked", label: "SMB 出口被阻断", type: "攻击步骤" },
        ]}
        edges={[
          {
            id: "blocked-edge",
            source: "source",
            target: "blocked",
            label: "被边界策略阻断",
            status: "negative",
          },
        ]}
        edgeAnnotations={{
          "blocked-edge": { label: "防守阻断", tone: "failure" },
        }}
        hiddenNeighborCounts={{ source: 2 }}
        highlightIds={["source", "blocked"]}
        highlightEdgeIds={["blocked-edge"]}
        focusMode
      />,
    );

    expect(screen.getByLabelText("分支语义：防守阻断")).toBeInTheDocument();
    expect(
      screen.getByLabelText("还有 2 个直接下游未展开"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: "威胁情报关系图谱" }).closest(".network-graph"),
    ).toHaveClass("is-focus-mode");
  });

  it("prevents native browser selection while the graph is dragged", () => {
    render(
      <NetworkGraph
        rootId="actor"
        nodes={[
          { id: "actor", label: "APT28", type: "攻击组织", status: "hot" },
        ]}
        edges={[]}
      />,
    );

    const graph = screen.getByRole("img", {
      name: "威胁情报关系图谱",
    });
    const selectStart = new Event("selectstart", {
      bubbles: true,
      cancelable: true,
    });

    expect(graph.dispatchEvent(selectStart)).toBe(false);
    expect(selectStart.defaultPrevented).toBe(true);
  });

  it("keeps a node stationary when it is clicked without being dragged", async () => {
    const onSelect = vi.fn();
    render(
      <NetworkGraph
        rootId="actor"
        nodes={[
          { id: "actor", label: "APT28", type: "攻击组织", status: "hot" },
        ]}
        edges={[]}
        onSelect={onSelect}
      />,
    );

    const svg = screen.getByRole("img", { name: "威胁情报关系图谱" });
    const actorNode = await screen.findByRole("button", {
      name: "攻击组织：APT28",
    });
    mockGraphPointerGeometry(svg, actorNode);
    const initialTransform = actorNode.getAttribute("transform");

    fireEvent.pointerDown(actorNode, {
      pointerId: 1,
      clientX: 650,
      clientY: 350,
    });
    fireEvent.pointerUp(actorNode, {
      pointerId: 1,
      clientX: 650,
      clientY: 350,
    });
    fireEvent.click(actorNode);

    await new Promise((resolve) => window.setTimeout(resolve, 80));
    expect(actorNode).toHaveAttribute("transform", initialTransform);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it("preserves node positions across semantically identical rerenders", async () => {
    const nodes = [
      { id: "actor", label: "APT28", type: "攻击组织", status: "hot" },
    ];
    const { rerender } = render(
      <NetworkGraph rootId="actor" nodes={nodes} edges={[]} />,
    );

    const svg = screen.getByRole("img", { name: "威胁情报关系图谱" });
    const actorNode = await screen.findByRole("button", {
      name: "攻击组织：APT28",
    });
    mockGraphPointerGeometry(svg, actorNode);

    fireEvent.pointerDown(actorNode, {
      pointerId: 1,
      clientX: 500,
      clientY: 280,
    });
    fireEvent.pointerMove(actorNode, {
      pointerId: 1,
      clientX: 720,
      clientY: 360,
    });
    fireEvent.pointerUp(actorNode, {
      pointerId: 1,
      clientX: 720,
      clientY: 360,
    });
    await waitFor(() => {
      expect(actorNode.getAttribute("transform")).toContain("720");
    });

    rerender(
      <NetworkGraph
        rootId="actor"
        selectedId="actor"
        nodes={[...nodes]}
        edges={[]}
        highlightIds={["actor"]}
      />,
    );

    await new Promise((resolve) => window.setTimeout(resolve, 80));
    expect(actorNode.getAttribute("transform")).toContain("720");
  });

  it("keeps existing topology stationary when a nearby relation is expanded", async () => {
    const initialNodes = [
      { id: "root", label: "对外 SMB 445 认证", type: "攻击步骤" },
      { id: "evidence", label: "边界防火墙 TCP/445", type: "检测证据" },
    ];
    const initialEdges = [
      {
        id: "observed",
        source: "root",
        target: "evidence",
        label: "边界连接证据",
      },
    ];
    const { rerender } = render(
      <NetworkGraph
        rootId="root"
        nodes={initialNodes}
        edges={initialEdges}
        stabilizeExpansion
      />,
    );

    const rootNode = await screen.findByRole("button", {
      name: "攻击步骤：对外 SMB 445 认证",
    });
    const evidenceNode = await screen.findByRole("button", {
      name: "检测证据：边界防火墙 TCP/445",
    });
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    const rootBefore = graphNodePosition(rootNode);
    const evidenceBefore = graphNodePosition(evidenceNode);

    rerender(
      <NetworkGraph
        rootId="root"
        nodes={[
          ...initialNodes,
          { id: "identity", label: "finance-ops@example.org", type: "身份" },
        ]}
        edges={[
          ...initialEdges,
          {
            id: "identity-edge",
            source: "root",
            target: "identity",
            label: "使用身份",
          },
        ]}
        stabilizeExpansion
      />,
    );

    expect(
      await screen.findByRole("button", {
        name: "身份：finance-ops@example.org",
      }),
    ).toBeInTheDocument();
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    const rootAfter = graphNodePosition(rootNode);
    const evidenceAfter = graphNodePosition(evidenceNode);
    expect(Math.hypot(
      rootAfter.x - rootBefore.x,
      rootAfter.y - rootBefore.y,
    )).toBeLessThan(3);
    expect(Math.hypot(
      evidenceAfter.x - evidenceBefore.x,
      evidenceAfter.y - evidenceBefore.y,
    )).toBeLessThan(3);
  });

  it("places expanded radial children outward from their parent branch", async () => {
    const root = {
      id: "root",
      label: "对外 SMB 445 认证",
      type: "攻击步骤",
    };
    const parent = {
      id: "parent",
      label: "Outlook 无交互触发",
      type: "攻击步骤",
    };
    const { rerender } = render(
      <NetworkGraph
        rootId="root"
        nodes={[root, parent]}
        edges={[
          {
            id: "parent-edge",
            source: "root",
            target: "parent",
            label: "自动发起认证",
          },
        ]}
        layout="radial"
        stabilizeExpansion
      />,
    );
    const parentNode = await screen.findByRole("button", {
      name: "攻击步骤：Outlook 无交互触发",
    });
    await new Promise((resolve) => window.setTimeout(resolve, 80));

    rerender(
      <NetworkGraph
        rootId="root"
        nodes={[
          root,
          parent,
          {
            id: "child",
            label: "外部 UNC 路径植入",
            type: "攻击步骤",
          },
        ]}
        edges={[
          {
            id: "parent-edge",
            source: "root",
            target: "parent",
            label: "自动发起认证",
          },
          {
            id: "child-edge",
            source: "parent",
            target: "child",
            label: "提醒到期触发",
          },
        ]}
        layout="radial"
        stabilizeExpansion
      />,
    );

    const childNode = await screen.findByRole("button", {
      name: "攻击步骤：外部 UNC 路径植入",
    });
    await new Promise((resolve) => window.setTimeout(resolve, 100));
    const parentPosition = graphNodePosition(parentNode);
    const childPosition = graphNodePosition(childNode);
    const parentVector = {
      x: parentPosition.x - 500,
      y: parentPosition.y - 280,
    };
    const childVector = {
      x: childPosition.x - 500,
      y: childPosition.y - 280,
    };
    const parentDistance = Math.hypot(parentVector.x, parentVector.y);
    const childDistance = Math.hypot(childVector.x, childVector.y);
    const directionSimilarity =
      (parentVector.x * childVector.x +
        parentVector.y * childVector.y) /
      (parentDistance * childDistance);

    expect(childDistance).toBeGreaterThan(parentDistance + 45);
    expect(directionSimilarity).toBeGreaterThan(0.94);
  });

  it("allows graph nodes to be dragged and fixed at a new position", async () => {
    render(
      <NetworkGraph
        rootId="actor"
        nodes={[
          { id: "actor", label: "APT28", type: "攻击组织", status: "hot" },
          { id: "event", label: "H1", type: "历史事件", status: "positive" },
        ]}
        edges={[
          {
            id: "edge",
            source: "actor",
            target: "event",
            label: "主导活动",
            status: "hot",
          },
        ]}
      />,
    );

    const svg = screen.getByRole("img", { name: "威胁情报关系图谱" });
    const actorNode = await screen.findByRole("button", {
      name: "攻击组织：APT28",
    });
    mockGraphPointerGeometry(svg, actorNode);
    const start = graphNodePosition(actorNode);
    const target = {
      x: Math.min(952, start.x + 160),
      y: Math.min(490, start.y + 70),
    };

    fireEvent.pointerDown(actorNode, {
      pointerId: 1,
      clientX: start.x,
      clientY: start.y,
    });
    fireEvent.pointerMove(actorNode, {
      pointerId: 1,
      clientX: target.x,
      clientY: target.y,
    });
    fireEvent.pointerUp(actorNode, {
      pointerId: 1,
      clientX: target.x,
      clientY: target.y,
    });

    await waitFor(() => {
      const position = graphNodePosition(actorNode);
      expect(position.x).toBeCloseTo(target.x, 3);
      expect(position.y).toBeCloseTo(target.y, 3);
    });
  });
});
