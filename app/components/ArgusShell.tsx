"use client";

import {
  Bot,
  BriefcaseBusiness,
  FileStack,
  GitBranch,
  Search,
  Shield,
  Users,
} from "lucide-react";
import type { AppPage } from "../types";

const items: Array<{
  id: AppPage;
  label: string;
  icon: typeof Search;
}> = [
  { id: "search", label: "综合查询", icon: Search },
  { id: "chain-intake", label: "攻击链", icon: GitBranch },
  { id: "cases", label: "调查案件", icon: BriefcaseBusiness },
  { id: "reports", label: "历史报告", icon: FileStack },
  { id: "actors", label: "攻击组织", icon: Users },
  { id: "gpt", label: "ARGUS GPT", icon: Bot },
];

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
  const isHome = page === "search";
  const current =
    page === "intel" || page === "graph"
      ? "search"
      : page === "chain"
        ? "chain-intake"
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

        {!isHome && (
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
              value={query}
              onChange={(event) => onQuery(event.target.value)}
              placeholder="搜索 IOC、报告、组织或攻击链"
            />
            <button type="submit" aria-label="提交全局搜索">
              <Search size={16} />
            </button>
          </form>
        )}

        <nav className="top-navigation" aria-label="主导航">
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <button
                type="button"
                key={item.id}
                className={current === item.id ? "active" : ""}
                aria-current={current === item.id ? "page" : undefined}
                onClick={() => onNavigate(item.id)}
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
      </header>
      <div className="app-main">
        <div className="app-content">{children}</div>
      </div>
    </div>
  );
}
