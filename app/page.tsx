import type { Metadata } from "next";
import data from "@/lib/argus-data.json";
import { ArgusApp } from "./ArgusApp";
import type { Snapshot } from "./types";

export const metadata: Metadata = {
  title: "ARGUS 可追溯攻击链研判平台",
  description:
    "从查询与证据出发，还原可追溯攻击链，综合历史报告并生成边界清晰的参考处置建议。",
};

export default function Home() {
  return <ArgusApp data={data as Snapshot} />;
}
