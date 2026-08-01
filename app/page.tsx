import type { Metadata } from "next";
import { ArgusApp } from "./ArgusApp";

export const metadata: Metadata = {
  title: "ARGUS 威胁情报分析平台",
  description:
    "从查询与证据出发，还原可追溯攻击链，综合历史报告并生成边界清晰的参考处置建议。",
};

export default function Home() {
  return <ArgusApp />;
}
