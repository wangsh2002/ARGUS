"use client";

import {
  ArrowRight,
  BookOpen,
  CalendarDays,
  ChevronRight,
  CircleDotDashed,
  Crosshair,
  Database,
  ExternalLink,
  FileCheck2,
  Filter,
  GitBranch,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
  Users,
  Wrench,
} from "lucide-react";
import { useMemo, useState } from "react";
import { actorContextEntities } from "../actor-knowledge";
import { formatDate, propString } from "../argus-domain";
import type {
  Actor,
  ActorKnowledgeSlice,
  ActorKnowledgeSync,
  Entity,
  EntityAlias,
  Evidence,
  Relationship,
} from "../types";

type ActorProfileTab =
  | "overview"
  | "activities"
  | "techniques"
  | "assets"
  | "evidence";

type ActorSummary = {
  actor: Actor;
  entity: Entity;
  aliases: EntityAlias[];
  activities: Entity[];
  techniques: Entity[];
  tools: Entity[];
  iocs: Entity[];
  cves: Entity[];
  evidence: Evidence[];
  relationships: Relationship[];
  latestActivity: string | null;
  reportCount: number;
};

const statusLabels: Record<string, string> = {
  verified: "已核验公开组织",
  "agent-assisted-reviewed": "分析员辅助复核",
  "curator-confirmed": "人工确认",
  internal_cluster: "内部待归并活动簇",
  partial: "部分核验",
};

function actorStatusLabel(status: string) {
  return statusLabels[status] ?? "待核验";
}

function displayText(value: string) {
  return value.replace(/[—–]/g, "-");
}

function actorEntity(data: ActorKnowledgeSlice, actor: Actor) {
  return data.entities.find((entity) => entity.id === actor.id);
}

function otherEntityId(relationship: Relationship, id: string) {
  return relationship.source_entity_id === id
    ? relationship.target_entity_id
    : relationship.source_entity_id;
}

function uniqueEntities(entities: Array<Entity | undefined>) {
  const index = new Map<string, Entity>();
  entities.forEach((entity) => {
    if (entity) index.set(entity.id, entity);
  });
  return [...index.values()];
}

function dateValue(entity: Entity) {
  return entity.last_seen || entity.first_seen || "";
}

function buildActorSummary(data: ActorKnowledgeSlice, actor: Actor): ActorSummary | null {
  const entity = actorEntity(data, actor);
  if (!entity) return null;
  const context = actorContextEntities(data, actor.id);
  const contextEntities = context.entities.filter((item) => item.id !== actor.id);
  const activities = contextEntities
    .filter((item) => item.entity_type === "历史事件")
    .sort((left, right) => dateValue(right).localeCompare(dateValue(left)));
  const entitiesByType = (type: string) =>
    uniqueEntities(
      contextEntities.filter((item) => item.entity_type === type),
    );
  const relationshipIds = new Set(
    context.relationships.map((relationship) => relationship.id),
  );
  const evidence = data.evidence
    .filter((item) => relationshipIds.has(item.relationship_id))
    .sort(
      (left, right) =>
        right.report_date.localeCompare(left.report_date) ||
        right.confidence - left.confidence,
    );
  const latestActivity =
    activities.map(dateValue).filter(Boolean).sort().at(-1) ?? null;

  const summary: ActorSummary = {
    actor,
    entity,
    aliases: data.aliases.filter((alias) => alias.entity_id === actor.id),
    activities,
    techniques: entitiesByType("ATT&CK 技术"),
    tools: entitiesByType("恶意软件/工具"),
    iocs: entitiesByType("IOC/基础设施"),
    cves: entitiesByType("CVE"),
    evidence,
    relationships: context.relationships,
    latestActivity,
    reportCount: new Set(evidence.map((item) => item.report_id)).size,
  };

  const hasProfileKnowledge =
    summary.activities.length > 0 ||
    summary.techniques.length > 0 ||
    summary.tools.length > 0 ||
    summary.iocs.length > 0 ||
    summary.cves.length > 0;

  return hasProfileKnowledge ? summary : null;
}

function syncTime(sync: ActorKnowledgeSync) {
  if (!sync.updatedAt) return "当前构建快照";
  const value = new Date(sync.updatedAt);
  if (Number.isNaN(value.getTime())) return "刚刚更新";
  return value.toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function ActorSyncControl({ sync }: { sync: ActorKnowledgeSync }) {
  return (
    <button
      type="button"
      className={`actor-sync-control is-${sync.status}`}
      onClick={sync.refresh}
      disabled={sync.status === "loading"}
      title={sync.error}
    >
      <RefreshCw
        size={14}
        className={sync.status === "loading" ? "is-spinning" : undefined}
      />
      <span>
        {sync.status === "offline" ? "实时数据暂不可用" : syncTime(sync)}
      </span>
    </button>
  );
}

function buildActorSummaries(data: ActorKnowledgeSlice) {
  return data.actors
    .map((actor) => buildActorSummary(data, actor))
    .filter((summary): summary is ActorSummary => Boolean(summary));
}

function compactAliasList(summary: ActorSummary, limit = 3) {
  return summary.aliases.slice(0, limit).map((alias) => alias.alias);
}

function activityRelationship(
  summary: ActorSummary,
  activityId: string,
  entityId: string,
) {
  return summary.relationships.find(
    (relationship) =>
      (relationship.source_entity_id === activityId &&
        relationship.target_entity_id === entityId) ||
      (relationship.target_entity_id === activityId &&
        relationship.source_entity_id === entityId),
  );
}

function relatedActivities(summary: ActorSummary, entityId: string) {
  return summary.activities.filter((activity) =>
    Boolean(activityRelationship(summary, activity.id, entityId)),
  );
}

function evidenceForRelationship(
  summary: ActorSummary,
  relationship?: Relationship,
) {
  if (!relationship) return [];
  return summary.evidence.filter(
    (evidence) => evidence.relationship_id === relationship.id,
  );
}

export function ActorDirectoryView({
  data,
  onOpenActor,
  sync,
}: {
  data: ActorKnowledgeSlice;
  onOpenActor: (actorId: string) => void;
  sync: ActorKnowledgeSync;
}) {
  const summaries = useMemo(() => buildActorSummaries(data), [data]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [sector, setSector] = useState("all");
  const sectors = useMemo(() => {
    const counts = new Map<string, number>();
    summaries.forEach(({ actor }) =>
      actor.target_sectors.forEach((item) =>
        counts.set(item, (counts.get(item) ?? 0) + 1),
      ),
    );
    return [...counts.entries()].sort(
      (left, right) =>
        right[1] - left[1] || left[0].localeCompare(right[0]),
    );
  }, [summaries]);
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const filtered = summaries.filter((summary) => {
    const matchesQuery =
      !normalizedQuery ||
      [
        summary.actor.label,
        summary.actor.origin_label,
        ...summary.actor.target_sectors,
        ...summary.aliases.map((alias) => alias.alias),
      ]
        .join(" ")
        .toLocaleLowerCase()
        .includes(normalizedQuery);
    const matchesStatus =
      status === "all" ||
      (status === "verified"
        ? summary.actor.profile_status !== "internal_cluster"
        : summary.actor.profile_status === status);
    const matchesSector =
      sector === "all" || summary.actor.target_sectors.includes(sector);
    return matchesQuery && matchesStatus && matchesSector;
  });
  const verified = filtered.filter(
    (summary) => summary.actor.profile_status !== "internal_cluster",
  );
  const clusters = filtered.filter(
    (summary) => summary.actor.profile_status === "internal_cluster",
  );
  const totalActivities = new Set(
    summaries.flatMap((summary) =>
      summary.activities.map((activity) => activity.id),
    ),
  ).size;
  const totalTechniques = new Set(
    summaries.flatMap((summary) =>
      summary.techniques.map((technique) => technique.id),
    ),
  ).size;
  const totalReports = new Set(
    summaries.flatMap((summary) =>
      summary.evidence.map((evidence) => evidence.report_id),
    ),
  ).size;

  return (
    <main className="page-frame actor-directory-page">
      <header className="actor-directory-heading">
        <div>
          <span className="actor-section-label">对手知识库</span>
          <h1>攻击组织目录</h1>
          <p>
            浏览已建立画像的组织与内部活动簇，从历史活动、技战术和来源证据进入长期对手分析。
          </p>
        </div>
        <div className="actor-directory-scope">
          <ShieldCheck size={18} />
          <span>
            <strong>库内覆盖概览</strong>
            <small>统计只反映当前已入库公开情报</small>
          </span>
          <ActorSyncControl sync={sync} />
        </div>
      </header>

      <section className="actor-coverage-panel" aria-label="情报库覆盖概览">
        <div className="actor-coverage-summary">
          <span>当前收录</span>
          <strong>{summaries.length}</strong>
          <p>
            其中 {summaries.length - clusters.length} 个已建立组织画像，
            {clusters.length} 个内部待归并活动簇。
          </p>
        </div>
        <dl className="actor-coverage-metrics">
          <div>
            <dt>历史活动</dt>
            <dd>{totalActivities}</dd>
            <small>经关系图谱关联</small>
          </div>
          <div>
            <dt>ATT&amp;CK 技术</dt>
            <dd>{totalTechniques}</dd>
            <small>由历史活动派生</small>
          </div>
          <div>
            <dt>支撑报告</dt>
            <dd>{totalReports}</dd>
            <small>具备关系级证据</small>
          </div>
        </dl>
        <div className="actor-sector-overview">
          <div>
            <strong>主要目标行业</strong>
            <small>点击标签筛选目录</small>
          </div>
          <div className="actor-sector-cloud">
            {sectors.slice(0, 8).map(([item, count]) => (
              <button
                type="button"
                className={sector === item ? "is-active" : ""}
                key={item}
                onClick={() => setSector(sector === item ? "all" : item)}
              >
                {item}
                <span>{count}</span>
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="actor-directory-controls" aria-label="目录筛选">
        <label className="actor-directory-search">
          <Search size={17} />
          <span className="sr-only">搜索组织名称或别名</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索组织名称、厂商命名、地区或目标行业"
          />
        </label>
        <label className="actor-directory-filter">
          <Filter size={15} />
          <span>画像状态</span>
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="all">全部状态</option>
            <option value="verified">已建立组织画像</option>
            <option value="internal_cluster">内部活动簇</option>
          </select>
        </label>
        <label className="actor-directory-filter">
          <Target size={15} />
          <span>目标行业</span>
          <select
            value={sector}
            onChange={(event) => setSector(event.target.value)}
          >
            <option value="all">全部行业</option>
            {sectors.map(([item]) => (
              <option value={item} key={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <span className="actor-directory-result-count">
          {filtered.length} 个匹配对象
        </span>
      </section>

      {verified.length > 0 && (
        <ActorDirectorySection
          title="已建立画像的攻击组织"
          description="公开来源已形成可复核组织档案，可进入历史活动与技战术画像。"
          summaries={verified}
          onOpenActor={onOpenActor}
        />
      )}

      {clusters.length > 0 && (
        <ActorDirectorySection
          title="待归并活动簇"
          description="当前证据支持行为聚类，但尚不足以确认公开组织身份。"
          summaries={clusters}
          onOpenActor={onOpenActor}
          cluster
        />
      )}

      {filtered.length === 0 && (
        <section className="actor-directory-empty">
          <CircleDotDashed size={25} />
          <strong>没有符合条件的攻击组织</strong>
          <p>调整名称、画像状态或目标行业后重新筛选。</p>
          <button
            type="button"
            onClick={() => {
              setQuery("");
              setStatus("all");
              setSector("all");
            }}
          >
            清除筛选
          </button>
        </section>
      )}
    </main>
  );
}

function ActorDirectorySection({
  title,
  description,
  summaries,
  onOpenActor,
  cluster = false,
}: {
  title: string;
  description: string;
  summaries: ActorSummary[];
  onOpenActor: (actorId: string) => void;
  cluster?: boolean;
}) {
  return (
    <section className="actor-directory-section">
      <header>
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
        <span>{summaries.length} 个对象</span>
      </header>
      <div className="actor-directory-grid">
        {summaries.map((summary) => (
          <button
            type="button"
            className={`actor-directory-card${cluster ? " is-cluster" : ""}`}
            key={summary.actor.id}
            onClick={() => onOpenActor(summary.actor.id)}
          >
            <div className="actor-card-heading">
              <span className="actor-card-mark">
                {cluster ? <CircleDotDashed size={21} /> : <Users size={21} />}
              </span>
              <span className="actor-card-identity">
                <span>{actorStatusLabel(summary.actor.profile_status)}</span>
                <strong>{summary.actor.label}</strong>
              </span>
              <ChevronRight size={19} />
            </div>
            <p className="actor-card-origin">{summary.actor.origin_label}</p>
            <div className="actor-card-aliases">
              {compactAliasList(summary).map((alias) => (
                <span key={alias}>{alias}</span>
              ))}
              {summary.aliases.length > 3 && (
                <small>另有 {summary.aliases.length - 3} 个命名</small>
              )}
            </div>
            <div className="actor-card-sectors">
              {summary.actor.target_sectors.slice(0, 4).map((item) => (
                <span key={item}>{item}</span>
              ))}
            </div>
            <dl className="actor-card-stats">
              <div>
                <dt>历史活动</dt>
                <dd>{summary.activities.length}</dd>
              </div>
              <div>
                <dt>关联 TTP</dt>
                <dd>{summary.techniques.length}</dd>
              </div>
              <div>
                <dt>工具</dt>
                <dd>{summary.tools.length}</dd>
              </div>
              <div>
                <dt>来源报告</dt>
                <dd>{summary.reportCount}</dd>
              </div>
            </dl>
            <div className="actor-card-footer">
              <span>
                最近活动
                <strong>{formatDate(summary.latestActivity)}</strong>
              </span>
              <span className="actor-card-open">
                查看组织画像
                <ArrowRight size={14} />
              </span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

export function ActorProfileView({
  data,
  actorId,
  onOpenGraph,
  onOpenPath,
  sync,
}: {
  data: ActorKnowledgeSlice;
  actorId?: string;
  onOpenGraph: (entity: Entity) => void;
  onOpenPath: (query: string) => void;
  sync: ActorKnowledgeSync;
}) {
  const summary = useMemo(() => {
    const actor = data.actors.find((item) => item.id === actorId);
    return actor ? buildActorSummary(data, actor) : null;
  }, [actorId, data]);
  const [tab, setTab] = useState<ActorProfileTab>("overview");

  if (!summary) {
    return (
      <main className="page-frame actor-profile-page">
        <section className="actor-directory-empty">
          <Users size={25} />
          <strong>未找到攻击组织画像</strong>
          <p>该组织可能尚未进入当前公开情报库。</p>
        </section>
      </main>
    );
  }

  const { actor, entity } = summary;
  const tabs: Array<{
    id: ActorProfileTab;
    label: string;
    count?: number;
  }> = [
    { id: "overview", label: "概览" },
    { id: "activities", label: "历史活动", count: summary.activities.length },
    { id: "techniques", label: "技战术", count: summary.techniques.length },
    {
      id: "assets",
      label: "关联资产",
      count: summary.tools.length + summary.iocs.length + summary.cves.length,
    },
    { id: "evidence", label: "来源与证据", count: summary.reportCount },
  ];

  return (
    <main className="page-frame actor-profile-page">
      <div className="page-toolbar actor-profile-toolbar">
        <div className="toolbar-actions">
          <ActorSyncControl sync={sync} />
          <button
            type="button"
            className="secondary-button"
            onClick={() => onOpenGraph(entity)}
          >
            <Network size={16} /> 查看关系图
          </button>
          {summary.activities[0] && (
            <button
              type="button"
              className="primary-button"
              onClick={() => onOpenPath(summary.activities[0].label)}
            >
              <GitBranch size={16} /> 查看代表性路径
            </button>
          )}
        </div>
      </div>

      <header
        className={`actor-profile-identity${
          actor.profile_status === "internal_cluster" ? " is-cluster" : ""
        }`}
      >
        <div className="actor-profile-mark">
          {actor.profile_status === "internal_cluster" ? (
            <CircleDotDashed size={27} />
          ) : (
            <Users size={27} />
          )}
        </div>
        <div className="actor-profile-title">
          <span>{actorStatusLabel(actor.profile_status)}</span>
          <h1>{actor.label}</h1>
          <p>{actor.origin_label}</p>
          <div className="actor-profile-aliases">
            {summary.aliases.slice(0, 5).map((alias) => (
              <span key={alias.id}>{alias.alias}</span>
            ))}
            {summary.aliases.length > 5 && (
              <small>另有 {summary.aliases.length - 5} 个已收录命名</small>
            )}
          </div>
        </div>
        <dl className="actor-profile-facts">
          <div>
            <dt>活跃时间</dt>
            <dd>
              {actor.active_from || "未记录"} 至 {actor.active_to || "今"}
            </dd>
          </div>
          <div>
            <dt>最近活动</dt>
            <dd>{formatDate(summary.latestActivity)}</dd>
          </div>
          <div>
            <dt>画像核对</dt>
            <dd>{formatDate(actor.updated_at)}</dd>
          </div>
          <div>
            <dt>来源等级</dt>
            <dd>{Math.round(actor.source_grade * 100)} / 100</dd>
          </div>
        </dl>
      </header>

      <nav className="actor-profile-tabs" aria-label="攻击组织画像内容">
        {tabs.map((item) => (
          <button
            type="button"
            className={tab === item.id ? "is-active" : ""}
            aria-current={tab === item.id ? "page" : undefined}
            onClick={() => setTab(item.id)}
            key={item.id}
          >
            {item.label}
            {typeof item.count === "number" && <span>{item.count}</span>}
          </button>
        ))}
      </nav>

      {tab === "overview" && (
        <ActorOverview
          summary={summary}
          onOpenPath={onOpenPath}
          onOpenTab={setTab}
        />
      )}
      {tab === "activities" && (
        <ActorActivities summary={summary} onOpenPath={onOpenPath} />
      )}
      {tab === "techniques" && <ActorTechniques summary={summary} />}
      {tab === "assets" && <ActorAssets summary={summary} />}
      {tab === "evidence" && (
        <ActorEvidence summary={summary} data={data} />
      )}
    </main>
  );
}

function ActorOverview({
  summary,
  onOpenPath,
  onOpenTab,
}: {
  summary: ActorSummary;
  onOpenPath: (query: string) => void;
  onOpenTab: (tab: ActorProfileTab) => void;
}) {
  return (
    <div className="actor-profile-content actor-overview">
      <section className="actor-attribution-summary">
        <div>
          <span className="actor-section-label">公开归因摘要</span>
          <h2>身份边界与分析结论</h2>
          <p>{displayText(summary.actor.public_attribution)}</p>
        </div>
        <aside>
          <ShieldCheck size={18} />
          <strong>{actorStatusLabel(summary.actor.profile_status)}</strong>
          <span>
            画像结论来自已入库公开来源，单次攻击归因仍需结合本案证据复核。
          </span>
        </aside>
      </section>

      <div className="actor-overview-grid">
        <section className="actor-profile-section actor-behavior-profile">
          <header>
            <div>
              <h2>对手行为画像</h2>
              <p>目标和动机来自组织档案，不代表每次活动都具备全部特征。</p>
            </div>
          </header>
          <div className="actor-behavior-columns">
            <div>
              <span>
                <Target size={15} /> 主要目标行业
              </span>
              <div>
                {summary.actor.target_sectors.map((item) => (
                  <strong key={item}>{item}</strong>
                ))}
              </div>
            </div>
            <div>
              <span>
                <Crosshair size={15} /> 主要行动动机
              </span>
              <div>
                {summary.actor.motivations.map((item) => (
                  <strong key={item}>{item}</strong>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="actor-profile-section actor-capability-summary">
          <header>
            <div>
              <h2>能力摘要</h2>
              <p>技术通过组织关联历史活动派生，不作为直接归因断言。</p>
            </div>
            <button type="button" onClick={() => onOpenTab("techniques")}>
              查看全部 <ArrowRight size={14} />
            </button>
          </header>
          <dl>
            <div>
              <dt>历史活动</dt>
              <dd>{summary.activities.length}</dd>
            </div>
            <div>
              <dt>关联技术</dt>
              <dd>{summary.techniques.length}</dd>
            </div>
            <div>
              <dt>工具与恶意软件</dt>
              <dd>{summary.tools.length}</dd>
            </div>
            <div>
              <dt>关系级证据</dt>
              <dd>{summary.evidence.length}</dd>
            </div>
          </dl>
          <div className="actor-technique-preview">
            {summary.techniques.slice(0, 4).map((technique) => (
              <span key={technique.id}>
                <strong>{technique.label}</strong>
                  <small>
                    {displayText(
                      technique.description || "历史活动关联技术",
                    )}
                  </small>
              </span>
            ))}
          </div>
        </section>
      </div>

      <section className="actor-profile-section actor-activity-preview">
        <header>
          <div>
            <h2>近期与代表性活动</h2>
            <p>从组织历史活动进入 ARGUS 攻击路径，继续核验步骤、分支和来源。</p>
          </div>
          <button type="button" onClick={() => onOpenTab("activities")}>
            查看全部 <ArrowRight size={14} />
          </button>
        </header>
        <div>
          {summary.activities.slice(0, 4).map((activity) => (
            <button
              type="button"
              key={activity.id}
              onClick={() => onOpenPath(activity.label)}
            >
              <span className="actor-activity-date">
                <CalendarDays size={15} />
                {formatDate(activity.last_seen || activity.first_seen)}
              </span>
              <span className="actor-activity-copy">
                <strong>{activity.label}</strong>
                <small>
                  {displayText(
                    activity.description || "已关联历史攻击活动",
                  )}
                </small>
              </span>
              <span className="actor-activity-meta">
                <small>
                  {
                    summary.relationships.filter(
                      (relationship) =>
                        relationship.source_entity_id === activity.id ||
                        relationship.target_entity_id === activity.id,
                    ).length
                  }{" "}
                  条关系
                </small>
                <span>
                  查看攻击路径 <ArrowRight size={13} />
                </span>
              </span>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}

function ActorActivities({
  summary,
  onOpenPath,
}: {
  summary: ActorSummary;
  onOpenPath: (query: string) => void;
}) {
  return (
    <div className="actor-profile-content">
      <section className="actor-profile-section actor-activity-list">
        <header>
          <div>
            <h2>历史活动与路径</h2>
            <p>按活动实体的公开时间排序。缺少活动时间时保持未记录状态。</p>
          </div>
          <span>{summary.activities.length} 个历史活动</span>
        </header>
        <div>
          {summary.activities.map((activity) => {
            const linked = summary.relationships.filter(
              (relationship) =>
                relationship.source_entity_id === activity.id ||
                relationship.target_entity_id === activity.id,
            );
            const linkedIds = new Set(
              linked.map((relationship) =>
                otherEntityId(relationship, activity.id),
              ),
            );
            const techniques = summary.techniques.filter((item) =>
              linkedIds.has(item.id),
            );
            const tools = summary.tools.filter((item) => linkedIds.has(item.id));
            const evidenceCount = summary.evidence.filter((item) =>
              linked.some(
                (relationship) => relationship.id === item.relationship_id,
              ),
            ).length;
            return (
              <article key={activity.id}>
                <div className="actor-activity-timeline">
                  <span />
                  <time>
                    {formatDate(activity.last_seen || activity.first_seen)}
                  </time>
                </div>
                <div className="actor-activity-detail">
                  <div>
                    <strong>{activity.label}</strong>
                    <p>
                      {displayText(
                        activity.description || "已关联历史攻击活动。",
                      )}
                    </p>
                  </div>
                  <dl>
                    <div>
                      <dt>关联技术</dt>
                      <dd>{techniques.length}</dd>
                    </div>
                    <div>
                      <dt>关联工具</dt>
                      <dd>{tools.length}</dd>
                    </div>
                    <div>
                      <dt>证据</dt>
                      <dd>{evidenceCount}</dd>
                    </div>
                  </dl>
                  <div className="actor-activity-tags">
                    {techniques.slice(0, 3).map((item) => (
                      <span key={item.id}>{item.label}</span>
                    ))}
                    {tools.slice(0, 2).map((item) => (
                      <span key={item.id}>{item.label}</span>
                    ))}
                  </div>
                  <button type="button" onClick={() => onOpenPath(activity.label)}>
                    打开攻击路径 <ArrowRight size={14} />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function ActorTechniques({ summary }: { summary: ActorSummary }) {
  return (
    <div className="actor-profile-content">
      <section className="actor-profile-section actor-technique-list">
        <header>
          <div>
            <h2>历史活动关联技战术</h2>
            <p>每项技术都保留活动上下文，不把 ATT&amp;CK 标签自动连成攻击链。</p>
          </div>
          <span>{summary.techniques.length} 项技术</span>
        </header>
        <div className="actor-technique-grid">
          {summary.techniques.map((technique) => {
            const activities = relatedActivities(summary, technique.id);
            const relationship = activities[0]
              ? activityRelationship(
                  summary,
                  activities[0].id,
                  technique.id,
                )
              : undefined;
            const evidence = evidenceForRelationship(summary, relationship);
            return (
              <article key={technique.id}>
                <div className="actor-technique-heading">
                  <span>{technique.label}</span>
                  <ShieldCheck size={17} />
                </div>
                <strong>
                  {displayText(
                    propString(technique, "sub") || technique.description,
                  )}
                </strong>
                <p>
                  {displayText(
                    technique.description ||
                      "该技术通过已入库历史活动与组织建立关联。",
                  )}
                </p>
                <dl>
                  <div>
                    <dt>出现活动</dt>
                    <dd>{activities.length}</dd>
                  </div>
                  <div>
                    <dt>关系证据</dt>
                    <dd>{evidence.length}</dd>
                  </div>
                </dl>
                <div>
                  {activities.slice(0, 3).map((activity) => (
                    <span key={activity.id}>{activity.label}</span>
                  ))}
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function ActorAssets({ summary }: { summary: ActorSummary }) {
  const groups = [
    {
      title: "恶意软件与工具",
      icon: Wrench,
      entities: summary.tools,
      empty: "暂无可核验的工具关系",
    },
    {
      title: "基础设施与 IOC",
      icon: Database,
      entities: summary.iocs,
      empty: "暂无可核验的基础设施关系",
    },
    {
      title: "漏洞与利用对象",
      icon: Crosshair,
      entities: summary.cves,
      empty: "暂无可核验的漏洞关系",
    },
  ];
  return (
    <div className="actor-profile-content actor-assets-grid">
      {groups.map(({ title, icon: Icon, entities, empty }) => (
        <section className="actor-profile-section actor-asset-group" key={title}>
          <header>
            <div>
              <Icon size={18} />
              <h2>{title}</h2>
            </div>
            <span>{entities.length}</span>
          </header>
          {entities.length ? (
            <div>
              {entities.map((entity) => {
                const activities = relatedActivities(summary, entity.id);
                return (
                  <article key={entity.id}>
                    <span>{entity.entity_type}</span>
                    <strong>{entity.label}</strong>
                    <p>
                      {displayText(
                        entity.description ||
                          "已建立来源支持的组织上下文关系。",
                      )}
                    </p>
                    <small>
                      {activities.length
                        ? `关联 ${activities.length} 个历史活动`
                        : `${entity.source_count} 个来源`}
                    </small>
                  </article>
                );
              })}
            </div>
          ) : (
            <p className="actor-asset-empty">{empty}</p>
          )}
        </section>
      ))}
    </div>
  );
}

function ActorEvidence({
  summary,
  data,
}: {
  summary: ActorSummary;
  data: ActorKnowledgeSlice;
}) {
  const reports = new Map(data.reports.map((report) => [report.id, report]));
  const relationships = new Map(
    data.relationships.map((relationship) => [
      relationship.id,
      relationship,
    ]),
  );
  const entities = new Map(data.entities.map((entity) => [entity.id, entity]));
  const evidence = summary.evidence.slice(0, 20);
  return (
    <div className="actor-profile-content">
      <section className="actor-profile-section actor-evidence-ledger">
        <header>
          <div>
            <h2>判断与证据账本</h2>
            <p>展示关系判断、原文位置和来源报告，便于逐项复核。</p>
          </div>
          <span>{summary.reportCount} 份支撑报告</span>
        </header>
        <div className="actor-evidence-table" role="table">
          <div role="row" className="actor-evidence-table-head">
            <span role="columnheader">判断关系</span>
            <span role="columnheader">原文证据</span>
            <span role="columnheader">来源与状态</span>
          </div>
          {evidence.map((item) => {
            const report = reports.get(item.report_id);
            const relationship = relationships.get(item.relationship_id);
            const source = relationship
              ? entities.get(relationship.source_entity_id)
              : undefined;
            const target = relationship
              ? entities.get(relationship.target_entity_id)
              : undefined;
            return (
              <article role="row" key={item.id}>
                <div role="cell">
                  <GitBranch size={16} />
                  <span>
                    <strong>
                      {source?.label || "未知实体"}
                      <small>{relationship?.relation_type || "关联"}</small>
                      {target?.label || "未知实体"}
                    </strong>
                    <small>
                      {relationship?.evidence_count || 1} 条关系证据
                    </small>
                  </span>
                </div>
                <div role="cell">
                  <strong>
                    {displayText(item.report_title || report?.title || "")}
                  </strong>
                  <p>
                    {displayText(
                      item.excerpt ||
                        "该关系已关联来源，但当前未保存原文摘录。",
                    )}
                  </p>
                </div>
                <div role="cell">
                  <span>
                    <BookOpen size={14} />
                    {item.publisher || report?.source}
                  </span>
                  <small>
                    {formatDate(item.report_date)}
                    {"，"}
                    {displayText(item.location || "位置未记录")}
                  </small>
                  <span>
                    <FileCheck2 size={14} />
                    置信度 {Math.round(item.confidence * 100)}%
                  </span>
                  {report?.external_url && (
                    <a
                      href={report.external_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      查看原始来源 <ExternalLink size={13} />
                    </a>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}
