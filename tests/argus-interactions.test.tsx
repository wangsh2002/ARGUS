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
import {
  adviceForCase,
  citationsForCase,
  createCaseFromReport,
  historicalFindings,
} from "../app/argus-domain";
import {
  buildInvestigationExport,
  exportToMarkdown,
} from "../app/report-export";
import type { InvestigationCase, Snapshot } from "../app/types";

const data = snapshot as Snapshot;
const storageKey = "argus:investigation-cases:v1";

beforeEach(() => {
  window.localStorage.clear();
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ configured: false, model: null }),
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ARGUS query-centered workflows", () => {
  it("keeps search dominant on the home page and compacts it only after navigation", async () => {
    render(<ArgusApp data={data} />);

    const header = screen.getByRole("banner", { name: "全局页头" });
    expect(
      within(header).getByRole("navigation", { name: "主导航" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("综合查询输入")).toBeInTheDocument();
    expect(screen.queryByLabelText("全局搜索")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "cdn-meeting-update.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "cdn-meeting-update.com",
      }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("全局搜索")).toHaveValue(
      "cdn-meeting-update.com",
    );
  });

  it("searches a real IOC and keeps evidence and chain context at equal weight", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "cdn-meeting-update.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", { level: 1, name: "cdn-meeting-update.com" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /来源证据/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /历史报告/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /关联攻击链/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "威胁情报关系图谱" })).toBeInTheDocument();
  });

  it("turns ordered analyst input into an editable traceable chain", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("tab", { name: /攻击链/ }));
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "Outlook 提醒 → 远程 SMB → NTLM 泄露" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(
      await screen.findByRole("heading", { level: 2, name: "主攻击路径" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Outlook 提醒").length).toBeGreaterThan(0);
    expect(screen.getAllByText("远程 SMB").length).toBeGreaterThan(0);
    expect(screen.getAllByText("NTLM 泄露").length).toBeGreaterThan(0);
    expect(screen.getByRole("img", { name: "威胁情报关系图谱" })).toBeInTheDocument();
    expect(screen.getByText("真实时序为主 · ATT&CK 为补充")).toBeInTheDocument();
  });

  it("lets an analyst add a node and then revise its investigation details", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("tab", { name: /攻击链/ }));
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "可疑邮件 → PowerShell 执行" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    fireEvent.click(
      await screen.findByRole("button", { name: /添加节点/ }),
    );
    const editor = await screen.findByRole("dialog", {
      name: "编辑攻击链节点",
    });
    fireEvent.change(within(editor).getByLabelText("节点名称"), {
      target: { value: "恶意脚本回连 C2" },
    });
    fireEvent.change(within(editor).getByLabelText("与前序节点的关系"), {
      target: { value: "执行后回连" },
    });
    fireEvent.change(within(editor).getByLabelText("攻击阶段"), {
      target: { value: "命令与控制" },
    });
    fireEvent.click(within(editor).getByRole("button", { name: "保存节点" }));

    expect(screen.getAllByText("恶意脚本回连 C2").length).toBeGreaterThan(0);
    expect(screen.getAllByText("执行后回连").length).toBeGreaterThan(0);

    fireEvent.click(
      screen.getByRole("listitem", { name: /恶意脚本回连 C2/ }),
    );
    fireEvent.click(screen.getByRole("button", { name: "编辑节点" }));
    expect(screen.getByLabelText("节点名称")).toHaveValue("恶意脚本回连 C2");
  });

  it("opens a verifiable public report and builds a source-backed workspace", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "历史报告" }));
    fireEvent.click(
      screen.getByRole("button", {
        name: /Midnight Blizzard: Guidance for responders/,
      }),
    );

    expect(
      screen.getByRole("link", { name: /查看原始来源/ }),
    ).toHaveAttribute("href", expect.stringContaining("microsoft.com"));
    fireEvent.click(
      screen.getByRole("button", { name: /从此报告创建攻击链/ }),
    );

    expect(
      await screen.findByRole("heading", { level: 2, name: "主攻击路径" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "历史总结" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "处置建议" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "归因辅助" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /全部来源/ }));
    fireEvent.click(
      screen.getByRole("button", {
        name: /Midnight Blizzard: Guidance for responders/,
      }),
    );
    expect(screen.getByRole("dialog", { name: "来源证据查看器" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /查看原始来源/ })).toHaveAttribute(
      "href",
      expect.stringContaining("microsoft.com"),
    );
  });

  it("saves analyst review state in the browser demo store", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("tab", { name: /攻击链/ }));
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "可疑邮件 → PowerShell 执行 → 恶意域名回连" },
    });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));
    fireEvent.click(await screen.findByRole("button", { name: /保存/ }));

    await waitFor(() => {
      const saved = JSON.parse(
        window.localStorage.getItem(storageKey) ?? "[]",
      ) as InvestigationCase[];
      expect(saved[0]?.sourceKind).toBe("query");
      expect(saved[0]?.steps).toHaveLength(3);
    });
    expect(screen.getByText("已保存在本机")).toBeInTheDocument();
  });

  it("keeps the GPT surface explicit when no model endpoint is configured", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "ARGUS GPT" }));

    expect(await screen.findByText("模型服务未配置")).toBeInTheDocument();
    expect(screen.getByText(/模型未配置时不会返回模拟回答/)).toBeInTheDocument();
    expect(screen.getByText(/加入攻击链前必须人工确认/)).toBeInTheDocument();
  });

  it("opens an actor panorama graph and returns to the archive", async () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "攻击组织" }));
    const actorList = document.querySelector(".actor-list");
    expect(actorList).not.toBeNull();
    fireEvent.click(
      within(actorList as HTMLElement).getByRole("button", { name: /APT28/ }),
    );
    fireEvent.click(screen.getByRole("button", { name: /全景图谱/ }));

    expect(await screen.findByText("APT28 全景图谱")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /返回/ }));
    expect(screen.getByRole("heading", { name: "攻击组织总揽" })).toBeInTheDocument();
  });
});

describe("ARGUS report export", () => {
  it("exports the chain, synthesis, conditional advice and sources", () => {
    const investigation = createCaseFromReport(
      data,
      "RPT-SEED-4296b034cca50574da",
    );
    const citations = citationsForCase(data, investigation);
    const findings = historicalFindings(data, investigation, citations);
    const advice = adviceForCase(data, investigation);
    const markdown = exportToMarkdown(
      buildInvestigationExport(investigation, findings, advice, citations),
    );

    expect(markdown).toContain("## 攻击链");
    expect(markdown).toContain("## 历史报告综合总结");
    expect(markdown).toContain("## 参考处置建议");
    expect(markdown).toContain("仅供安全分析参考");
    expect(markdown).toContain("microsoft.com");
  });
});

describe("ARGUS relationship graph", () => {
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
    const actorNode = await screen.findByRole("button", {
      name: "攻击组织：APT28",
    });
    Object.defineProperties(actorNode, {
      setPointerCapture: { value: vi.fn() },
      hasPointerCapture: { value: vi.fn(() => true) },
      releasePointerCapture: { value: vi.fn() },
    });

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
  });
});
