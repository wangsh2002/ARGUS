"use client";

import {
  Bot,
  ClipboardCheck,
  Database,
  Menu,
  Network,
  Search,
  Shield,
  Users,
  X,
} from "lucide-react";
import { useState } from "react";
import type { AppPage } from "../types";

const items: Array<{
  id: AppPage;
  label: string;
  icon: typeof Search;
}> = [
  { id: "search", label: "综合查询", icon: Search },
  { id: "actors", label: "攻击组织", icon: Users },
  { id: "graph", label: "情报图谱", icon: Network },
  { id: "ingest", label: "情报入库", icon: Database },
  { id: "fragment-review", label: "路径复核", icon: ClipboardCheck },
  { id: "gpt", label: "ARGUS GPT", icon: Bot },
];

function queryDisplayValue(query: string) {
  if (!query.trim().startsWith("{")) return query;
  try {
    const parsed = JSON.parse(query) as {
      title?: unknown;
      case_id?: unknown;
    };
    if (typeof parsed.title === "string") {
      return `${typeof parsed.case_id === "string" ? `${parsed.case_id} · ` : ""}${parsed.title}`;
    }
  } catch {
    // Keep incomplete JSON editable as-is.
  }
  return query;
}

export function ArgusShell({
  page,
  query,
  onQuery,
  onSearch,
  onNavigate,
  children,
}: {
  page: AppPage;
  query: string;
  onQuery: (value: string) => void;
  onSearch: () => void;
  onNavigate: (page: AppPage) => void;
  children: React.ReactNode;
}) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const isHome = page === "search";
  const showGlobalSearch =
    !isHome &&
    page !== "graph" &&
    page !== "ingest" &&
    page !== "fragment-review";
  const current =
    page === "intel" ||
    page === "actor" ||
    page === "path-review" ||
    page === "path" ||
    page === "report"
      ? page === "actor"
        ? "actors"
        : "search"
      : page;

  return (
    <div className={`argus-app ${isHome ? "is-home" : "is-subpage"}`}>
      <header className="app-header" aria-label="全局页头">
        <button
          type="button"
          className="brand"
          aria-label="返回综合查询"
          onClick={() => onNavigate("search")}
        >
          <span className="brand-mark">
            <Shield size={20} />
          </span>
          <span className="brand-copy">
            <strong>ARGUS</strong>
            <small>情报研判中心</small>
          </span>
        </button>

        {showGlobalSearch && (
          <form
            className="global-search"
            onSubmit={(event) => {
              event.preventDefault();
              onSearch();
            }}
          >
            <Search size={17} />
            <input
              aria-label="全局搜索"
              value={queryDisplayValue(query)}
              onChange={(event) => onQuery(event.target.value)}
              placeholder="搜索 IOC、报告、组织或攻击链"
            />
            <button type="submit" aria-label="提交全局搜索">
              <Search size={16} />
            </button>
          </form>
        )}

        <nav
          className={`top-navigation ${mobileNavOpen ? "is-open" : ""}`}
          aria-label="主导航"
        >
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <button
                type="button"
                key={item.id}
                className={current === item.id ? "active" : ""}
                aria-current={current === item.id ? "page" : undefined}
                onClick={() => {
                  setMobileNavOpen(false);
                  onNavigate(item.id);
                }}
              >
                <Icon size={15} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="header-context">
          <span className="header-status">
            <span />
            DEMO
          </span>
          <div className="analyst-avatar" aria-label="当前分析员">
            AN
          </div>
        </div>

        <button
          type="button"
          className="mobile-navigation-toggle"
          aria-label={mobileNavOpen ? "关闭主导航" : "打开主导航"}
          aria-expanded={mobileNavOpen}
          onClick={() => setMobileNavOpen((open) => !open)}
        >
          {mobileNavOpen ? <X size={19} /> : <Menu size={19} />}
        </button>
      </header>
      <div className="app-main">
        <div className="app-content">{children}</div>
      </div>
    </div>
  );
}
