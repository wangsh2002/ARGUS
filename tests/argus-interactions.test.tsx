import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import snapshot from "../lib/argus-data.json";
import { ArgusApp } from "../app/ArgusApp";
import type { Snapshot } from "../app/types";

const data = snapshot as Snapshot;

afterEach(() => cleanup());

describe("ARGUS interactive workflows", () => {
  it("searches a real IOC and opens its intelligence result", () => {
    render(<ArgusApp data={data} />);
    const input = screen.getByLabelText("综合查询输入");
    fireEvent.change(input, { target: { value: "cdn-meeting-update.com" } });
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(screen.getAllByText("cdn-meeting-update.com").length).toBeGreaterThan(0);
    expect(screen.getByText("MATCHED INTELLIGENCE")).toBeInTheDocument();
    expect(screen.getByText(/来自 ARGUS 数据库/)).toBeInTheDocument();
  });

  it("splits an attack-chain query and displays real graph alignment", () => {
    render(<ArgusApp data={data} />);
    fireEvent.change(screen.getByLabelText("综合查询输入"), {
      target: { value: "Outlook 提醒 → 远程 SMB → NTLM 泄露" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "Graph" }));
    fireEvent.click(screen.getByRole("button", { name: "执行查询" }));

    expect(screen.getByText(/攻击链输入已拆分为/)).toBeInTheDocument();
    expect(screen.getByText("攻击链匹配图谱")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "威胁情报关系图谱" })).toBeInTheDocument();
  });

  it("loads a stored report and produces a deterministic analysis workspace", () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "情报综合分析" }));
    const reportButton = screen.getByRole("button", {
      name: /云身份渗透与 OAuth 持久访问链/,
    });
    fireEvent.click(reportButton);
    fireEvent.click(screen.getByRole("button", { name: /开始综合分析/ }));

    expect(screen.getByText("报告证据与历史图谱匹配")).toBeInTheDocument();
    expect(screen.getByText("归因候选与可解释匹配历史")).toBeInTheDocument();
    expect(screen.getByText("处置响应与综合建议")).toBeInTheDocument();
  });

  it("keeps the GPT surface honest while the model service is disconnected", () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "GPT" }));
    fireEvent.change(screen.getByPlaceholderText("输入安全分析问题或上传情报……"), {
      target: { value: "分析这份情报" },
    });
    fireEvent.click(screen.getByRole("button", { name: "发送" }));

    expect(screen.getByText("GPT 模型服务尚未接入")).toBeInTheDocument();
    expect(screen.getByText(/不会生成模拟回答/)).toBeInTheDocument();
  });

  it("opens an actor panorama graph and returns to the archive", () => {
    render(<ArgusApp data={data} />);
    fireEvent.click(screen.getByRole("button", { name: "攻击组织总揽" }));
    const actorList = document.querySelector(".actor-list");
    expect(actorList).not.toBeNull();
    fireEvent.click(
      within(actorList as HTMLElement).getAllByRole("button", {
        name: /全景图谱/,
      })[0],
    );

    expect(screen.getByText("APT28 全景图谱")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /返回组织档案/ }));
    expect(screen.getByRole("heading", { name: "攻击组织总揽" })).toBeInTheDocument();
  });
});
