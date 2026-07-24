import type { Metadata } from "next";
import data from "@/lib/argus-data.json";
import { ArgusApp } from "./ArgusApp";
import type { Snapshot } from "./types";

export const metadata: Metadata = {
  title: "ARGUS 威胁归因与情报分析平台",
  description:
    "连接 IOC、攻击链、历史证据与可解释归因路径的威胁情报工作台。",
};

export default function Home() {
  return <ArgusApp data={data as Snapshot} />;
}
