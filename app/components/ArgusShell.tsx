"use client";

import {
  Bot,
  BriefcaseBusiness,
  FileStack,
  GitBranch,
  Menu,
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
  const [mobileOpen, setMobileOpen] = useState(false);
  const current = page === "intel" || page === "graph" ? "search" : page === "chain" ? "chain-intake" : page;
  return (
    <div className="argus-app">
      <aside className={`app-sidebar ${mobileOpen ? "is-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark">
            <Shield size={24} />
          </span>
          <span>
            <strong>ARGUS</strong>
            <small>情报研判中心</small>
          </span>
          <button
            type="button"
            className="mobile-close"
            aria-label="关闭导航"
            onClick={() => setMobileOpen(false)}
          >
            <X size={18} />
          </button>
        </div>
        <nav aria-label="主导航">
          <span className="nav-label">ANALYSIS</span>
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <button
                type="button"
                key={item.id}
                className={current === item.id ? "active" : ""}
                onClick={() => {
                  onNavigate(item.id);
                  setMobileOpen(false);
                }}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <span className="live-dot" />
          <div>
            <strong>本地情报快照</strong>
            <small>仅展示已入库事实</small>
          </div>
        </div>
      </aside>

      <div className="app-main">
        <header className="app-header">
          <button
            type="button"
            className="mobile-menu"
            aria-label="打开导航"
            onClick={() => setMobileOpen(true)}
          >
            <Menu size={19} />
          </button>
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
              placeholder="搜索 IOC、历史事件、攻击组织或报告"
            />
            <kbd>⌘ K</kbd>
          </form>
          <div className="header-context">
            <span className="header-status">
              <span />
              DEMO
            </span>
            <div className="analyst-avatar">AN</div>
          </div>
        </header>
        <div className="app-content">{children}</div>
      </div>
    </div>
  );
}
