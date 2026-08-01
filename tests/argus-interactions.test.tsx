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
        contexts:
          index === 2
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
            : [],
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

  it("exposes the confirmed query products and actor directory in the top navigation", () => {
    render(<ArgusApp fixture={data} />);

    const navigation = screen.getByRole("navigation", { name: "主导航" });
    expect(within(navigation).getByRole("button", { name: "综合查询" })).toBeInTheDocument();
    expect(within(navigation).getByRole("button", { name: "攻击组织" })).toBeInTheDocument();
    expect(within(navigation).queryByRole("button", { name: "攻击链" })).not.toBeInTheDocument();
    expect(within(navigation).queryByRole("button", { name: "历史报告" })).not.toBeInTheDocument();
    expect(within(navigation).getByRole("button", { name: "情报图谱" })).toBeInTheDocument();
    expect(within(navigation).getByRole("button", { name: "情报入库" })).toBeInTheDocument();
    expect(within(navigation).getByRole("button", { name: "路径复核" })).toBeInTheDocument();
    expect(within(navigation).getByRole("button", { name: "ARGUS GPT" })).toBeInTheDocument();
    expect(within(navigation).queryByRole("button", { name: "调查案件" })).not.toBeInTheDocument();

    expect(screen.queryByRole("tab", { name: /综合情报查询/ })).not.toBeInTheDocument();
    fireEvent.focus(screen.getByLabelText("综合查询输入"));
    expect(screen.getByRole("tab", { name: /综合情报查询/ })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /攻击链匹配/ })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /攻击路径研判/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /ARGUS GPT/ })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /^Graph/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /攻击路径研判/ }));
    const pathInput = screen.getByLabelText("攻击路径查询输入");
    const pathForm = pathInput.closest("form");
    expect(pathForm).not.toBeNull();
    expect(
      within(pathForm!).queryByRole("button", {
        name: "上传文件",
      }),
    ).not.toBeInTheDocument();
    expect(
      within(screen.getByLabelText("搜索历史和推荐")).getByRole("button", {
        name: "上传文件",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "载入演示案例" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("0 个节点")).not.toBeInTheDocument();
  });

  it("shows only staged AttackFlow candidates in the dedicated review center", async () => {
    const pendingQueue = {
      items: [
        {
          id: "KING-PENDING-FLOW",
          ingestion_kind: "attack-flow",
          source_document_id: "SRC-DOC-NIGHTFOX",
          status: "staged",
          publishable: true,
          quality_gates: [
            { id: "flow-evidence", label: "Flow 证据", status: "pass", detail: "Action 与关系均有原文证据。" },
          ],
          attack_flow_preview: {
            flow_id: "PATH-PUB-NIGHTFOX",
            title: "NightFox 文档投递至驻留",
            description: "待人工复核的历史攻击流。",
            mainline: ["A1", "A2"],
            actions: [
              { id: "A1", local_id: "LOCAL-A1", name: "投递恶意文档", phase: "初始访问", contexts: [] },
              { id: "A2", local_id: "LOCAL-A2", name: "创建计划任务", phase: "持久化", contexts: [] },
            ],
            relations: [
              { id: "R1", source_action_id: "A1", target_action_id: "A2", type: "enables" },
            ],
            reported_actors: [],
          },
          attack_flow_candidate: {
            actions: [
              { id: "LOCAL-A1", name: "投递恶意文档", evidence: [{ quote: "NightFox 投递恶意文档。" }] },
            ],
          },
        },
      ],
      summary: {
        pending_flows: 1,
        publishable_flows: 1,
        blocked_flows: 0,
        source_documents: 1,
      },
    };
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input) === "/api/knowledge-ingestion") {
        return { ok: true, json: async () => pendingQueue } as Response;
      }
      return graphApiResponse(input) ?? {
        ok: true,
        json: async () => ({ configured: false, model: null }),
      } as Response;
    });

    render(<ArgusApp fixture={data} />);
    fireEvent.click(screen.getByRole("button", { name: "路径复核" }));

    expect(
      await screen.findByRole("heading", { level: 1, name: "路径复核" }),
    ).toBeInTheDocument();
    expect(
      (await screen.findAllByText("NightFox 文档投递至驻留")).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("1 个 Flow")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "发布 AttackFlow" })).toBeInTheDocument();
    expect(
      screen.getByText(/通过证据质量门的 AttackFlow 候选/),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("全局搜索")).not.toBeInTheDocument();
  });

  it("opens the actor directory, actor profile and alias search without changing graph data", async () => {
    render(<ArgusApp fixture={data} />);

    fireEvent.click(screen.getByRole("button", { name: "攻击组织" }));
    expect(
      screen.getByRole("heading", { level: 1, name: "攻击组织目录" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "已建立画像的攻击组织" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("分析员辅助复核").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: /APT28/ }));
    expect(
      screen.getByRole("heading", { level: 1, name: "APT28" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /历史活动 1/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /来源与证据 \d+/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "查看关系图" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "返回攻击组织目录" }),
    ).not.toBeInTheDocument();

    fireEvent.click(
      within(screen.getByRole("navigation", { name: "主导航" })).getByRole(
        "button",
        { name: "攻击组织" },
      ),
    );
    expect(
      screen.getByRole("heading", { level: 1, name: "攻击组织目录" }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "返回综合查询" }));
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "Fancy Bear" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));
    expect(
      await screen.findByRole("heading", { level: 1, name: "APT28" }),
    ).toBeInTheDocument();
  });

  it("does not carry the actor-directory back link into the graph explorer", async () => {
    render(<ArgusApp fixture={data} />);

    fireEvent.click(screen.getByRole("button", { name: "攻击组织" }));
    expect(
      screen.getByRole("heading", { level: 1, name: "攻击组织目录" }),
    ).toBeInTheDocument();

    fireEvent.click(
      within(screen.getByRole("navigation", { name: "主导航" })).getByRole(
        "button",
        { name: "情报图谱" },
      ),
    );

    expect(await screen.findByText("情报关系探索")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "返回攻击组织目录" }),
    ).not.toBeInTheDocument();
  });

  it("keeps only the three retained curated attack paths", () => {
    expect(
      data.historicalPaths.map((path) => path.name),
    ).toEqual([
        "APT28 NATO 诱饵至 Zebrocy 数据回传",
        "Lazarus 招聘诱饵至 PowerRatankba 后门",
        "APT29 DNC 访问至通信监控",
    ]);
  });

  it("loads the selected historical path from the runtime AttackFlow contract", async () => {
    const flowId = "PATH-ANNOCTR-APT28-ZEBROCY-2020";
    const source = {
      id: "ART-runtime",
      title: "Runtime AttackFlow source",
      publisher: "ARGUS test",
      canonical_url: "https://example.test/runtime-flow",
      published_at: "2026-08-01",
    };
    const evidence = (id: string, quote: string) => ({
      id,
      source_span_id: `SRC-SPAN-${id}`,
      source_id: source.id,
      title: source.title,
      publisher: source.publisher,
      canonical_url: source.canonical_url,
      locator: `line:${id}`,
      quote,
      confidence: 0.98,
    });
    const action = (sequence: number, name: string) => ({
      id: `${flowId}-N-0${sequence}`,
      name,
      description: `运行时描述 ${sequence}`,
      phase: `阶段 ${sequence}`,
      confidence: "high",
      technique_ids: [],
      contexts:
        sequence === 7
          ? [
              {
                id: "ACL-runtime-c2",
                entity_id: "ENTITY-runtime-c2",
                type: "ip",
                name: "203.0.113.77",
                role: "communicates-with",
                direction: "action-to-entity",
                confidence: "high",
                evidence: [evidence("context-7", "connected to 203.0.113.77")],
              },
            ]
          : [],
      evidence: [evidence(`action-${sequence}`, `runtime action ${sequence}`)],
    });
    const mainline = Array.from(
      { length: 7 },
      (_, index) => `${flowId}-N-0${index + 1}`,
    );
    const names = [
      "运行时打开诱饵",
      "运行时解压归档",
      "运行时释放载荷",
      "运行时复制载荷",
      "运行时创建任务",
      "运行时收集数据",
      "运行时回传数据",
    ];
    const runtimeFlow = {
      schema_version: "1.0",
      id: flowId,
      title: "运行时 AttackFlow · Zebrocy",
      description: "该摘要只来自运行时 AttackFlow 响应。",
      sources: [source],
      actions: names.map((name, index) => action(index + 1, name)).reverse(),
      relations: mainline.slice(1).map((targetActionId, index) => ({
        id: `REL-runtime-${index + 1}`,
        source_action_id: mainline[index],
        target_action_id: targetActionId,
        type: index === 0 ? "precedes" : "leads_to",
        condition: null,
        confidence: "high",
        evidence: [
          evidence(`relation-${index + 1}`, `runtime relation ${index + 1}`),
        ],
      })),
      mainline,
    };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input) === `/api/attack-flows/${flowId}`) {
        return { ok: true, json: async () => runtimeFlow };
      }
      return graphApiResponse(input) ?? { ok: true, json: async () => ({ configured: false, model: null }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<ArgusApp fixture={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "194.32.78.245" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));
    const resultToolbar = document.querySelector(".page-toolbar");
    fireEvent.click(
      within(resultToolbar as HTMLElement).getByRole("button", {
        name: "打开完整图谱",
      }),
    );
    expect(await screen.findByText("当前调查种子")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "打开唯一攻击路径" }));

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "运行时 AttackFlow · Zebrocy",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("该摘要只来自运行时 AttackFlow 响应。")).toBeInTheDocument();
    const stageRail = screen.getByRole("region", { name: "攻击阶段判定" });
    const stageButtons = within(stageRail).getAllByRole("button");
    expect(stageButtons[0]).toHaveAccessibleName(
      "01 运行时打开诱饵 输入命中 · 96%",
    );
    expect(stageButtons[6]).toHaveAccessibleName(
      "07 运行时回传数据 输入命中 · 96%",
    );
    expect(
      screen.getAllByRole("button", { name: "攻击步骤：运行时打开诱饵" }),
    ).not.toHaveLength(0);
    expect(
      screen.getAllByRole("button", { name: "IOC/基础设施：203.0.113.77" }),
    ).not.toHaveLength(0);
    fireEvent.click(stageButtons[0]);
    fireEvent.click(screen.getByRole("tab", { name: "原始信息" }));
    await waitFor(() =>
      expect(document.querySelector(".raw-relation-list")?.textContent).toContain(
        "有证据先于",
      ),
    );
    fireEvent.click(screen.getByRole("tab", { name: "证据" }));
    fireEvent.click(screen.getByRole("button", { name: /runtime action 1/ }));
    const sourceDialog = screen.getByRole("dialog", { name: "来源证据查看器" });
    expect(within(sourceDialog).getByText("SRC-SPAN-action-1", { exact: false })).toBeInTheDocument();
    expect(within(sourceDialog).getByText("runtime action 1")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/attack-flows/${flowId}`,
      expect.objectContaining({ cache: "no-store" }),
    );
  });

  it("keeps the Snapshot attack path usable when the runtime Flow request fails", async () => {
    const flowId = "PATH-ANNOCTR-APT28-ZEBROCY-2020";
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input) === `/api/attack-flows/${flowId}`) {
        throw new Error("backend offline");
      }
      return graphApiResponse(input) ?? { ok: true, json: async () => ({ configured: false, model: null }) };
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<ArgusApp fixture={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "194.32.78.245" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));
    fireEvent.click(
      within(document.querySelector(".page-toolbar") as HTMLElement).getByRole(
        "button",
        { name: "打开完整图谱" },
      ),
    );
    expect(await screen.findByText("当前调查种子")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "打开唯一攻击路径" }));

    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "APT28 NATO 诱饵至 Zebrocy 数据回传",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "攻击阶段判定" })).toBeInTheDocument();
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/attack-flows/${flowId}`,
        expect.objectContaining({ cache: "no-store" }),
      ),
    );
  });

  it("keeps knowledge ingestion staged until an explicit version publish", async () => {
    const staged = {
      id: "KING-test",
      source_document_id: "SRC-DOC-test",
      status: "staged",
      publishable: true,
      graph_write_performed: false,
      extraction_audit: {
        method: "curated-baseline",
        model: null,
        cache_hit: true,
        review_state: "curated",
        warnings: [],
        observations: [],
      },
      quality_gates: [
        {
          id: "source-integrity",
          label: "来源完整性",
          status: "pass",
          detail: "原文 SHA-256 已固定。",
        },
        {
          id: "evidence-coverage",
          label: "证据锚点覆盖",
          status: "pass",
          detail: "全部观测均可回到原文短引文。",
        },
      ],
      delta: {
        create_entities: 0,
        merge_entities: 3,
        create_relationships: 0,
        reinforce_relationships: 2,
      },
      entities: [
        {
          stage_id: "KENT-1",
          value: "CVE-2017-6742",
          kind: "vulnerability",
          confidence: 1,
          decision: "merge",
          merge_target_id: "APT28-event-H10-step-3",
          merge_target_label: "CVE-2017-6742",
          source_span_ids: ["SRC-SPAN-1"],
          quote: "CVE-2017-6742",
        },
      ],
      relations: [
        {
          stage_id: "KREL-1",
          source_stage_id: "KENT-1",
          target_stage_id: "KENT-2",
          relationship_id: "REL-1",
          relation_type: "时序后继",
          decision: "reinforce",
          confidence: 0.91,
          source_span_ids: ["SRC-SPAN-1"],
          locator: "paragraph:1",
          excerpt: "CVE-2017-6742 后部署 Jaguar Tooth。",
        },
      ],
      version: null,
    };
    const published = {
      ...staged,
      status: "published",
      graph_write_performed: true,
      version: {
        id: "KVER-test",
        status: "published",
        changes: { reinforced_entities: 3, created_evidence: 2 },
        published_at: "2026-07-28T16:30:00Z",
      },
    };
    const fetchMock = vi.mocked(fetch);
    const actorSlice = {
      meta: {
        source: "test",
        generated_at: "2026-07-28T16:30:00Z",
        version: "actor-test",
      },
      scope: {
        actor_ids: data.actors.map((actor) => actor.id),
        entity_ids: data.entities.map((entity) => entity.id),
        relationship_ids: data.relationships.map(
          (relationship) => relationship.id,
        ),
      },
      actors: data.actors,
      entities: data.entities,
      relationships: data.relationships,
      evidence: data.evidence,
      reports: data.reports,
      aliases: data.aliases,
    };
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        json: async () => staged,
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => published,
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => actorSlice,
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          status: "rolled_back",
          changes: { removed_evidence: 2 },
          rolled_back_at: "2026-07-28T16:35:00Z",
        }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: async () => actorSlice,
      } as Response);

    render(<ArgusApp fixture={data} />);
    fireEvent.click(screen.getByRole("button", { name: "情报入库" }));

    expect(
      screen.getByRole("heading", { level: 1, name: "情报入库" }),
    ).toBeInTheDocument();
    expect(screen.getByText("当前处于暂存通道")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "自动抽取 AttackFlow" }),
    );

    expect(await screen.findByText("尚未写入历史图谱")).toBeInTheDocument();
    expect(screen.getByText("仅暂存")).toBeInTheDocument();
    expect(screen.getByText("证据锚点覆盖")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "发布知识版本" }));
    expect(
      await screen.findByText("知识版本 KVER-test 已发布"),
    ).toBeInTheDocument();

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "回滚版本" }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "回滚版本" }));
    expect(await screen.findByText("本次知识增量已回滚")).toBeInTheDocument();
    expect(screen.getByText("已移除 2 条版本证据。")).toBeInTheDocument();
  });

  it("publishes a reviewed AttackFlow and opens it without a snapshot rebuild", async () => {
    const flowId = "PATH-PUB-TEST";
    const actionIds = ["PATH-PUB-TEST-A001", "PATH-PUB-TEST-A002"];
    const evidence = {
      id: "EVD-PUB-TEST",
      source_span_id: "SRC-SPAN-PUB-TEST",
      source_id: "SRC-DOC-PUB-TEST",
      title: "NightFox reviewed incident",
      publisher: "Example CERT",
      canonical_url: "https://example.invalid/nightfox-reviewed",
      locator: "paragraph:1",
      quote: "NightFox 被报告通过钓鱼邮件投递恶意文档。",
      confidence: 0.95,
    };
    const runtimeFlow: AttackFlow = {
      schema_version: "1.0",
      id: flowId,
      title: "NightFox 文档投递至计划任务驻留",
      description: "经人工复核的攻击过程。",
      sources: [
        {
          id: "SRC-DOC-PUB-TEST",
          title: evidence.title,
          publisher: evidence.publisher,
          canonical_url: evidence.canonical_url,
          published_at: "2026-08-01",
        },
      ],
      reported_actors: [
        {
          id: `${flowId}-ACTOR001`,
          reported_name: "NightFox",
          actor_id: null,
          confidence: "medium",
          evidence: [evidence],
        },
      ],
      actions: actionIds.map((id, index) => ({
        id,
        name: index === 0 ? "投递恶意文档" : "创建计划任务",
        description: "人工复核动作",
        phase: index === 0 ? "初始访问" : "持久化",
        confidence: "high",
        technique_ids: [],
        contexts: [],
        evidence: [{ ...evidence, id: `${evidence.id}-${index}` }],
      })),
      relations: [
        {
          id: `${flowId}-R001`,
          source_action_id: actionIds[0],
          target_action_id: actionIds[1],
          type: "enables",
          condition: null,
          confidence: "high",
          evidence: [{ ...evidence, id: `${evidence.id}-relation` }],
        },
      ],
      mainline: actionIds,
    };
    const staged = {
      id: "KING-PUB-TEST",
      ingestion_kind: "attack-flow",
      source_document_id: "SRC-DOC-PUB-TEST",
      status: "staged",
      publishable: true,
      graph_write_performed: false,
      extraction_audit: {
        method: "analyst-reviewed-candidate",
        model: null,
        cache_hit: false,
        review_state: "reviewed",
        warnings: [],
        observations: [],
      },
      quality_gates: [
        { id: "flow-evidence", label: "来源证据", status: "pass", detail: "通过" },
        { id: "flow-relations", label: "关系合法性", status: "pass", detail: "通过" },
        { id: "flow-mainline", label: "主干完整性", status: "pass", detail: "通过" },
      ],
      delta: {
        create_entities: 1,
        merge_entities: 1,
        create_relationships: 1,
        reinforce_relationships: 0,
      },
      canonical_delta: { create_entities: 0, merge_entities: 0, mentions: 0 },
      document_scope: {
        scope: "attack-lifecycle-candidate",
        attack_path_eligible: true,
        reason: "人工复核的 AttackFlow 发布候选。",
      },
      path_outcome: {
        status: "extracted",
        path_count: 1,
        no_path_reason: null,
        detail: "形成 1 条待发布的人工复核攻击流。",
      },
      entities: [],
      canonical_entities: [],
      relations: [],
      event_graph_extraction: null,
      publish_mode: "create",
      attack_flow_candidate: {
        title: runtimeFlow.title,
        description: runtimeFlow.description,
        actions: [],
        relations: [],
        mainline: [],
        reported_actors: [],
      },
      flow_candidate_summary: {
        status: "single",
        candidate_count: 1,
        recommendation: "merge",
        merge_target_flow_id: flowId,
        suggested_action_map: {
          A1: actionIds[0],
          A2: actionIds[1],
        },
        reason: "共享强 Context 身份锚点且行为与关系结构兼容。",
      },
      attack_flow_preview: {
        flow_id: flowId,
        title: runtimeFlow.title,
        description: runtimeFlow.description,
        mainline: actionIds,
        actions: runtimeFlow.actions.map((action, index) => ({
          id: action.id,
          local_id: `A${index + 1}`,
          name: action.name,
          phase: action.phase,
          contexts: index === 0 ? [] : [
            {
              id: `${flowId}-C001`,
              name: "198.51.100.77",
              role: "communicates-with",
              resolution: {
                status: "create",
                canonical_key: "ipv4:198.51.100.77",
              },
            },
          ],
        })),
        relations: runtimeFlow.relations,
        reported_actors: [
          {
            id: `${flowId}-ACTOR001`,
            reported_name: "NightFox",
            actor_id: null,
          },
        ],
      },
      version: null,
    };
    const revised = {
      ...staged,
      publish_mode: "merge",
      merge_review: {
        target_flow_id: flowId,
        confirmed: true,
        action_map: staged.flow_candidate_summary.suggested_action_map,
      },
    };
    const published = {
      ...revised,
      status: "published",
      graph_write_performed: true,
      version: {
        id: "KVER-PUB-TEST",
        status: "published",
        changes: { supported_attack_flow_id: flowId },
        published_at: "2026-08-01T00:00:00Z",
      },
    };
    const actorSlice = {
      meta: { source: "test", generated_at: "2026-08-01", version: "test" },
      scope: { actor_ids: [], entity_ids: [], relationship_ids: [] },
      actors: [],
      entities: [],
      relationships: [],
      evidence: [],
      reports: [],
      aliases: [],
    };
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => staged } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => revised } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => published } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => actorSlice } as Response)
      .mockResolvedValueOnce({ ok: true, json: async () => runtimeFlow } as Response);

    render(<ArgusApp fixture={data} />);
    fireEvent.click(screen.getByRole("button", { name: "情报入库" }));
    fireEvent.click(
      screen.getByRole("button", { name: "载入 AttackFlow 发布案例" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "生成入库预览" }));

    expect(await screen.findByText(/AttackFlow 发布预览/)).toBeInTheDocument();
    expect(screen.getByText(/来源报告称：NightFox.*未确认归属/)).toBeInTheDocument();
    expect(screen.getByText(`建议合并到 ${flowId}`)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/knowledge-ingestion",
      expect.objectContaining({
        body: expect.stringContaining('"attack_flow_candidate"'),
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: "按建议合并" }));
    expect(await screen.findByText("补充来源")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/knowledge-ingestion",
      expect.objectContaining({
        body: expect.stringContaining('"confirmed":true'),
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: "发布知识版本" }));
    expect(
      await screen.findByRole("button", { name: "查看已发布攻击流" }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "查看已发布攻击流" }));

    expect(
      await screen.findByRole("heading", { level: 1, name: runtimeFlow.title }),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/attack-flows/${flowId}`,
      expect.objectContaining({ cache: "no-store" }),
    );
  });

  it("keeps search dominant on the home page and compacts it only after navigation", async () => {
    render(<ArgusApp fixture={data} />);

    const header = screen.getByRole("banner", { name: "全局页头" });
    expect(
      within(header).getByRole("navigation", { name: "主导航" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("综合查询输入")).toBeInTheDocument();
    expect(screen.queryByLabelText("全局搜索")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "194.32.78.245" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "194.32.78.245",
      }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("全局搜索")).toHaveValue(
      "194.32.78.245",
    );
  });

  it("reveals search history and recommendations only while search is active", () => {
    render(<ArgusApp fixture={data} />);

    expect(screen.getByLabelText("搜索历史和推荐")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    fireEvent.focus(screen.getByLabelText("综合查询输入"));
    expect(screen.getByLabelText("搜索历史和推荐")).toBeInTheDocument();
    expect(screen.getByLabelText("搜索历史和推荐")).toHaveAttribute(
      "aria-hidden",
      "false",
    );
    expect(screen.getByRole("heading", { name: "推荐搜索" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "近期报告" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /攻击路径研判/ }));
    expect(
      screen.getByRole("button", {
        name: "取得 DNC 环境访问 → 监控邮件与聊天",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: /PidLidReminderFileParameter/,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Jaguar Tooth/ }),
    ).not.toBeInTheDocument();

    fireEvent.pointerDown(document.body);
    expect(screen.getByLabelText("搜索历史和推荐")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });

  it("shows IOC overview, evidence, reports and attack context on one page", async () => {
    render(<ArgusApp fixture={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "194.32.78.245" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", { level: 1, name: "194.32.78.245" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "情报概览" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "来源证据" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "历史报告" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "关联攻击链" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("tablist", { name: "情报详情" })).not.toBeInTheDocument();
    expect(screen.getAllByText("QuoIntelligence").length).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", { name: "查看完整攻击路径" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: "威胁情报关系图谱" }),
    ).not.toBeInTheDocument();
  });

  it("uses the graph-backed result for ATT&CK intelligence", async () => {
    render(<ArgusApp fixture={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "T1053.005" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "T1053.005",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "相关情报实体" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "关系图谱" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tablist", { name: "情报详情" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: "威胁情报关系图谱" }),
    ).toBeInTheDocument();
  });

  it("opens a completed report from the home page without a separate report library", () => {
    render(<ArgusApp fixture={data} />);
    const reportHistory = screen.getByRole("region", { name: "历史研判报告" });
    expect(within(reportHistory).getByRole("heading", { name: "历史研判报告" })).toBeInTheDocument();
    expect(
      within(reportHistory)
        .getAllByRole("button")
        .every((button) => button.classList.contains("home-report-card")),
    ).toBe(true);
    expect(
      screen.queryByRole("navigation", { name: "历史报告" }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: /APT28 campaign directed against Polish government institutions/,
      }),
    );

    expect(
      screen.getByRole("link", { name: /查看原始来源/ }),
    ).toHaveAttribute("href", expect.stringContaining("cert.pl"));
    expect(document.querySelector(".report-document-preview")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /从此报告查询攻击链/ }),
    ).not.toBeInTheDocument();
  });

  it("keeps the GPT surface explicit when no model endpoint is configured", async () => {
    render(<ArgusApp fixture={data} />);
    fireEvent.click(screen.getByRole("button", { name: "ARGUS GPT" }));

    expect(await screen.findByText("模型服务未配置")).toBeInTheDocument();
    expect(screen.getByText(/模型未配置时不会返回模拟回答/)).toBeInTheDocument();
    expect(screen.getByText(/只用于解释、总结和提供参考建议/)).toBeInTheDocument();
    expect(screen.queryByText(/加入攻击链/)).not.toBeInTheDocument();
  });

  it("returns through nested investigation pages in reverse entry order", async () => {
    render(<ArgusApp fixture={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "194.32.78.245" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "194.32.78.245",
      }),
    ).toBeInTheDocument();
    const resultToolbar = document.querySelector(".page-toolbar");
    expect(resultToolbar).not.toBeNull();
    fireEvent.click(
      within(resultToolbar as HTMLElement).getByRole("button", {
        name: "打开完整图谱",
      }),
    );

    expect(await screen.findByText("当前调查种子")).toBeInTheDocument();
    expect(
      (await screen.findAllByRole("button", { name: /^攻击步骤：/ })).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", {
        name: "恶意软件/工具：Zebrocy Delphi",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "ATT&CK 技术：T1041",
      }),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "打开唯一攻击路径" }),
    );
    expect(
      screen.queryByRole("heading", {
        name: /识别到 .*攻击活动簇/,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "APT28 NATO 诱饵至 Zebrocy 数据回传",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "返回情报图谱" }),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "返回情报图谱" }),
    );
    expect(await screen.findByText("当前调查种子")).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "返回情报查询结果" }),
    );
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "194.32.78.245",
      }),
    ).toBeInTheDocument();

    const intelBack = document.querySelector(".page-toolbar .back-link");
    expect(intelBack).toHaveTextContent("返回综合查询");
    fireEvent.click(intelBack as HTMLElement);
    expect(
      screen.getByRole("heading", { name: "威胁情报查询与分析平台" }),
    ).toBeInTheDocument();
  });

  it("returns from top-level destinations to the page that launched them", async () => {
    render(<ArgusApp fixture={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "194.32.78.245" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "194.32.78.245",
      }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "情报图谱" }));
    fireEvent.click(
      screen.getByRole("button", { name: "返回情报查询结果" }),
    );
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "194.32.78.245",
      }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "ARGUS GPT" }));
    expect(
      await screen.findByRole("button", { name: "返回情报查询结果" }),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "返回情报查询结果" }),
    );
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "194.32.78.245",
      }),
    ).toBeInTheDocument();
  });


  it("opens the evidence-first relationship explorer from the top navigation", async () => {
    render(<ArgusApp fixture={data} />);
    fireEvent.click(screen.getByRole("button", { name: "情报图谱" }));

    expect(await screen.findByText("情报关系探索")).toBeInTheDocument();
    const rootSearch = screen.getByLabelText("搜索图谱根实体");
    expect(rootSearch).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "情报图谱综合入口" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "从一个真实实体开始探索" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "知识库概览" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("进入图谱后")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: "威胁情报关系图谱" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "图谱搜索提示" }),
    ).not.toBeInTheDocument();

    fireEvent.focus(rootSearch);
    let searchAssist = screen.getByRole("region", {
      name: "图谱搜索提示",
    });
    expect(within(searchAssist).queryByText("最近调查")).not.toBeInTheDocument();
    expect(within(searchAssist).getByText("推荐调查入口")).toBeInTheDocument();
    expect(within(searchAssist).getByText("ATT&CK 技术")).toBeInTheDocument();

    fireEvent.change(rootSearch, { target: { value: "APT28" } });
    searchAssist = screen.getByRole("region", {
      name: "图谱搜索提示",
    });
    const actorMatch = within(searchAssist)
      .getAllByRole("button")
      .find((button) =>
        within(button).queryByText("APT28", { selector: "strong" }),
      );
    expect(actorMatch).toBeDefined();
    expect(actorMatch!).toHaveTextContent(/条关系/);
    expect(actorMatch!).toHaveTextContent(/个来源/);
    fireEvent.click(actorMatch!);

    expect(
      screen.queryByRole("region", { name: "图谱搜索提示" }),
    ).not.toBeInTheDocument();
    expect(rootSearch).toHaveValue("");
    expect(await screen.findByText("当前调查种子")).toBeInTheDocument();
    expect(rootSearch.closest(".graph-explorer-hero")).toHaveClass(
      "is-compact",
    );
    const rootContext = screen
      .getByText("当前调查种子")
      .closest(".graph-root-context");
    expect(rootContext).not.toBeNull();
    expect(within(rootContext as HTMLElement).getByText("APT28")).toBeInTheDocument();

    fireEvent.focus(rootSearch);
    searchAssist = screen.getByRole("region", {
      name: "图谱搜索提示",
    });
    const recentSection = within(searchAssist).getByRole("region", {
      name: "最近调查",
    });
    expect(
      within(recentSection).getByRole("button", { name: /APT28/ }),
    ).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(
      screen.queryByRole("region", { name: "图谱搜索提示" }),
    ).not.toBeInTheDocument();

    expect(screen.getByText("当前调查种子")).toBeInTheDocument();
    const graph = screen.getByRole("img", {
      name: "威胁情报关系图谱",
    });
    expect(graph).toBeVisible();
    expect(graph.closest(".network-graph")).not.toHaveClass("is-path-layout");
    expect(graph.closest(".network-graph")).toHaveClass("is-radial-layout");
    expect(
      screen.getByText("放射拓扑，新增关联沿当前节点向外展开"),
    ).toBeInTheDocument();
    const relationships = await screen.findAllByRole("button", {
      name: /关系：/,
    });
    fireEvent.click(relationships[0]);
    expect(screen.getByText("当前关系")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: /打开唯一攻击路径|研判 .* 条候选路径/,
      }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /保存/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /返回/ }));
    expect(screen.getByRole("heading", { name: "威胁情报查询与分析平台" })).toBeInTheDocument();
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
