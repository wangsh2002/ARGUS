"use client";

import { useCallback, useEffect, useState } from "react";
import {
  requestActorKnowledge,
} from "./actor-knowledge";
import {
  adaptAttackFlowToPathCandidate,
  requestAttackFlow,
  requestAttackFlows,
} from "./attack-flow";
import { searchSnapshot } from "./argus-domain";
import { requestFlowMatchAnalysis } from "./backend-path";
import { ArgusShell } from "./components/ArgusShell";
import {
  ActorDirectoryView,
  ActorProfileView,
} from "./components/ActorViews";
import { AttackPathAnalysisView } from "./components/AttackPathAnalysisView";
import { AttackPathReviewView } from "./components/AttackPathReviewView";
import { GPTView } from "./components/GPTView";
import { IntelView } from "./components/IntelView";
import { KnowledgeIngestionView } from "./components/KnowledgeIngestionView";
import { PathFragmentReviewCenter } from "./components/PathFragmentReviewCenter";
import {
  FullGraphView,
  ReportAnalysisView,
} from "./components/LibraryViews";
import { SearchView } from "./components/SearchView";
import { EmptyState } from "./components/Primitives";
import {
  actorKnowledgeFromFixture,
  adaptEntityIntelligence,
  buildPathWorkspace,
  catalogFromFixture,
  pathWorkspaceFromFixture,
  requestEntityIntelligence,
  requestRuntimeCatalog,
} from "./runtime-knowledge";
import type {
  AppPage,
  ActorKnowledgeSlice,
  ActorKnowledgeSync,
  AttackFlow,
  BackendFlowMatchAnalysis,
  Entity,
  GraphEdge,
  GraphNode,
  PathCandidate,
  Report,
  RuntimeCatalog,
  SearchMode,
  Snapshot,
  IntelligenceWorkspace,
  PathWorkspace,
} from "./types";

type GraphContext = {
  title: string;
  subtitle: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootId?: string;
};

type PageState = {
  page: AppPage;
  query: string;
  submittedQuery: string;
  mode: SearchMode;
  graphContext?: GraphContext;
  selectedReport?: Report;
  selectedPath?: PathCandidate;
  selectedActorId?: string;
  selectedEntityId?: string;
  pathAnalysis?: BackendFlowMatchAnalysis;
  pathAnalysisStatus?: "idle" | "loading" | "ready" | "offline";
  pathAnalysisError?: string;
};

type NavigationState = {
  current: PageState;
  history: PageState[];
};

const pageLabels: Record<AppPage, string> = {
  search: "综合查询",
  intel: "情报查询结果",
  actors: "攻击组织目录",
  actor: "攻击组织画像",
  "path-review": "攻击链候选",
  path: "攻击路径研判",
  ingest: "情报入库",
  "fragment-review": "路径复核",
  report: "历史研判报告",
  gpt: "ARGUS GPT",
  graph: "情报图谱",
};

export function ArgusApp({ fixture }: { fixture?: Snapshot }) {
  const [catalog, setCatalog] = useState<RuntimeCatalog | undefined>(() =>
    fixture ? catalogFromFixture(fixture) : undefined,
  );
  const [catalogStatus, setCatalogStatus] = useState<"loading" | "ready" | "offline">(
    fixture ? "ready" : "loading",
  );
  const [catalogError, setCatalogError] = useState("");
  const [flows, setFlows] = useState<AttackFlow[]>([]);
  const [flowStatus, setFlowStatus] = useState<"loading" | "ready" | "offline">(
    fixture ? "ready" : "loading",
  );
  const [actorKnowledge, setActorKnowledge] = useState<ActorKnowledgeSlice | undefined>(
    () => (fixture ? actorKnowledgeFromFixture(fixture) : undefined),
  );
  const [entityWorkspace, setEntityWorkspace] = useState<IntelligenceWorkspace>();
  const [entityStatus, setEntityStatus] = useState<"idle" | "loading" | "ready" | "offline">("idle");
  const [entityError, setEntityError] = useState("");
  const [actorKnowledgeState, setActorKnowledgeState] = useState<
    Omit<ActorKnowledgeSync, "refresh">
  >({
    status: fixture ? "ready" : "idle",
    updatedAt: fixture?.meta.generated_at,
  });
  const [navigation, setNavigation] = useState<NavigationState>({
    current: {
      page: "search",
      query: "",
      submittedQuery: "",
      mode: "intel",
    },
    history: [],
  });
  const {
    page,
    query,
    submittedQuery,
    mode,
    graphContext,
    selectedReport,
    selectedPath,
    pathAnalysis,
    pathAnalysisStatus,
    pathAnalysisError,
    selectedActorId,
    selectedEntityId,
  } = navigation.current;

  const pathWorkspace: PathWorkspace | undefined = fixture
    ? pathWorkspaceFromFixture(fixture, flows)
    : catalog
      ? buildPathWorkspace(catalog, flows, actorKnowledge)
      : undefined;
  const activeEntityWorkspace = fixture ?? entityWorkspace;
  const activeEntityStatus =
    fixture && selectedEntityId ? "ready" : entityStatus;

  const refreshCatalog = useCallback(async () => {
    if (fixture) return;
    try {
      const nextCatalog = await requestRuntimeCatalog();
      setCatalog(nextCatalog);
      setCatalogStatus("ready");
      setCatalogError("");
    } catch (error) {
      setCatalogStatus("offline");
      setCatalogError(
        error instanceof Error ? error.message : "运行时知识目录暂时不可用。",
      );
    }
  }, [fixture]);

  const refreshFlows = useCallback(async () => {
    if (fixture) return;
    try {
      setFlows(await requestAttackFlows());
      setFlowStatus("ready");
    } catch {
      setFlowStatus("offline");
    }
  }, [fixture]);

  const refreshActorKnowledge = useCallback(async () => {
    setActorKnowledgeState((current) => ({
      ...current,
      status: "loading",
      error: undefined,
    }));
    try {
      const slice = await requestActorKnowledge();
      setActorKnowledge(slice);
      setActorKnowledgeState({
        status: "ready",
        updatedAt: slice.meta.generated_at,
        version: slice.meta.version,
      });
    } catch (error) {
      setActorKnowledgeState((current) => ({
        ...current,
        status: "offline",
        error:
          error instanceof Error ? error.message : "组织知识暂时不可用。",
      }));
    }
  }, []);

  useEffect(() => {
    void refreshCatalog();
    void refreshFlows();
  }, [refreshCatalog, refreshFlows]);

  const actorKnowledgeSync: ActorKnowledgeSync = {
    ...actorKnowledgeState,
    refresh: () => {
      void refreshActorKnowledge();
    },
  };

  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [page]);

  useEffect(() => {
    if (page === "actors" || page === "actor") {
      void refreshActorKnowledge();
    }
  }, [page, refreshActorKnowledge]);

  useEffect(() => {
    if (page !== "intel" || !selectedEntityId || !catalog) return;
    if (fixture) return;
    let active = true;
    requestEntityIntelligence(selectedEntityId)
      .then((readModel) => {
        if (!active) return;
        setEntityWorkspace(adaptEntityIntelligence(catalog, readModel));
        setEntityStatus("ready");
      })
      .catch((error) => {
        if (!active) return;
        setEntityWorkspace(undefined);
        setEntityStatus("offline");
        setEntityError(
          error instanceof Error ? error.message : "实体详情暂时不可用。",
        );
      });
    return () => {
      active = false;
    };
  }, [catalog, fixture, page, selectedEntityId]);

  const updateCurrent = (patch: Partial<Omit<PageState, "page">>) => {
    setNavigation((current) => {
      return {
        ...current,
        current: { ...current.current, ...patch },
      };
    });
  };

  const openPage = (
    nextPage: AppPage,
    patch: Partial<Omit<PageState, "page">> = {},
  ) => {
    setNavigation((current) => {
      const nextState = {
        ...current.current,
        ...patch,
        page: nextPage,
      };
      if (current.current.page === nextPage) {
        return { ...current, current: nextState };
      }
      return {
        current: nextState,
        history: [...current.history, current.current],
      };
    });
  };

  const resetToPage = (nextPage: AppPage) => {
    setNavigation((current) => ({
      current: { ...current.current, page: nextPage },
      history: [],
    }));
  };

  const goBack = () => {
    setNavigation((current) => {
      const previousState = current.history.at(-1);
      if (!previousState) {
        return {
          current: { ...current.current, page: "search" },
          history: [],
        };
      }
      return {
        current: previousState,
        history: current.history.slice(0, -1),
      };
    });
  };

  const previousPage =
    navigation.history.at(-1)?.page ?? "search";
  const backLabel = `返回${pageLabels[previousPage]}`;

  const startFlowMatchAnalysis = (input: string) => {
    void requestFlowMatchAnalysis(input)
      .then((analysis) => {
        setFlowStatus("ready");
        setFlows((current) => [
          ...current.filter(
            (flow) => !analysis.flows.some((item) => item.id === flow.id),
          ),
          ...analysis.flows,
        ]);
        setNavigation((current) => {
          if (current.current.submittedQuery !== input) return current;
          return {
            ...current,
            current: {
              ...current.current,
              pathAnalysis: analysis,
              pathAnalysisStatus: "ready",
              pathAnalysisError: undefined,
            },
          };
        });
      })
      .catch((error: unknown) => {
        setNavigation((current) => {
          if (current.current.submittedQuery !== input) return current;
          return {
            ...current,
            current: {
              ...current.current,
              pathAnalysisStatus: "offline",
              pathAnalysisError:
                error instanceof Error
                  ? error.message
                  : "攻击路径后端暂时不可用。",
            },
          };
        });
      });
  };

  const openPathReview = (
    input: string,
    patch: Partial<Omit<PageState, "page">> = {},
    runBackend = true,
  ) => {
    openPage("path-review", {
      ...patch,
      query: input,
      submittedQuery: input,
      mode: "path",
      selectedPath: undefined,
      pathAnalysis: undefined,
      pathAnalysisStatus: runBackend ? "loading" : "idle",
      pathAnalysisError: undefined,
    });
    if (runBackend) startFlowMatchAnalysis(input);
  };

  const submit = (forcedMode?: SearchMode) => {
    const nextMode = forcedMode ?? mode;
    if (!query.trim()) return;
    const submittedQuery = query.trim();
    if (nextMode === "gpt") {
      openPage("gpt", { submittedQuery });
      return;
    }
    if (nextMode === "path") {
      openPathReview(submittedQuery);
      return;
    }
    if (!catalog) return;
    const result = searchSnapshot(catalog, submittedQuery);
    const entity = result.entities[0]?.entity;
    const normalizedQuery = submittedQuery.toLocaleLowerCase();
    const flowHit = flows.find((flow) =>
      [
        flow.title,
        ...flow.actions.map((action) => action.name),
        ...flow.actions.flatMap((action) =>
          action.contexts.map((context) => context.name),
        ),
      ].some((value) => value.toLocaleLowerCase().includes(normalizedQuery)),
    );
    if (nextMode === "graph") {
      if (entity) {
        openPage("graph", {
          submittedQuery,
          graphContext: {
            title: `${entity.label} 关系图谱`,
            subtitle: "运行时关系邻域",
            nodes: [],
            edges: [],
            rootId: entity.id,
          },
        });
        return;
      }
      if (flowHit) {
        openPage("graph", {
          submittedQuery,
          graphContext: {
            title: `${flowHit.title} 关系图谱`,
            subtitle: "运行时 AttackFlow 邻域",
            nodes: [],
            edges: [],
            rootId: flowHit.id,
          },
        });
        return;
      }
    }
    if (entity?.entity_type === "攻击组织") {
      openPage("actor", {
        submittedQuery,
        mode: "intel",
        selectedActorId: entity.id,
      });
      return;
    }
    if (entity) {
      setEntityStatus("loading");
      setEntityError("");
      openPage("intel", {
        submittedQuery,
        mode: "intel",
        selectedEntityId: entity.id,
      });
      return;
    }
    if (flowHit) {
      void openPublishedFlow(flowHit.id);
      return;
    }
    const report = result.reports[0]?.report;
    if (report) {
      openReport(report);
      return;
    }
    openPage("intel", {
      submittedQuery,
      mode: "intel",
      selectedEntityId: undefined,
    });
  };

  const openEntityGraph = (entity: Entity) => {
    openPage("graph", {
      graphContext: {
        title: `${entity.label} 关系图谱`,
        subtitle: "运行时关系邻域",
        nodes: [],
        edges: [],
        rootId: entity.id,
      },
    });
  };

  const openGraphLibrary = () => {
    openPage("graph", {
      graphContext: {
        title: "情报关系探索",
        subtitle: "从真实实体开始探索跨报告知识关系",
        nodes: [],
        edges: [],
      },
    });
  };

  const openActor = (actorId: string) => {
    const actor = actorKnowledge?.actors.find((item) => item.id === actorId);
    const entity = catalog?.entities.find((item) => item.id === actorId);
    openPage("actor", {
      selectedActorId: actorId,
      query: actor?.label ?? entity?.label ?? query,
      submittedQuery: actor?.label ?? entity?.label ?? submittedQuery,
    });
  };

  const navigate = (nextPage: AppPage) => {
    if (nextPage === "graph") {
      openGraphLibrary();
      return;
    }
    if (nextPage === "search") {
      resetToPage("search");
      return;
    }
    openPage(nextPage);
  };

  const openReport = (report: Report) => {
    openPage("report", {
      selectedReport: report,
      query: report.title,
    });
  };

  const openHistoricalAnalysis = (report: Report) => {
    const reportInput = report.extracted_text.trim() || report.title;
    openPathReview(reportInput, { selectedReport: report });
  };

  const openSelectedPath = (candidate: PathCandidate) => {
    setNavigation((current) => {
      const reviewedState = {
        ...current.current,
        selectedPath: candidate,
      };
      return {
        current: { ...reviewedState, page: "path" },
        history: [...current.history, reviewedState],
      };
    });
    if (!candidate.historicalPathId) return;
    const previousPath = pathWorkspace?.historicalPaths.find(
      (path) => path.id === candidate.historicalPathId,
    );
    void requestAttackFlow(candidate.historicalPathId)
      .then((flow) => {
        const runtimeCandidateBase = adaptAttackFlowToPathCandidate(
          flow,
          previousPath,
        );
        const reviewedStepByAction = new Map(
          candidate.steps.flatMap((step) => {
            const actionId = step.pathNodeId ?? step.entityId;
            return actionId ? [[actionId, step] as const] : [];
          }),
        );
        const runtimeCandidate = {
          ...candidate,
          ...runtimeCandidateBase,
          activityId: candidate.activityId,
          reason: candidate.reason,
          gap: candidate.gap,
          confidence: candidate.confidence,
          analysisQuery: candidate.analysisQuery,
          backendAnalysisId: candidate.backendAnalysisId,
          knowledgeSnapshot: candidate.knowledgeSnapshot,
          steps: runtimeCandidateBase.steps.map((step) => {
            const reviewed = reviewedStepByAction.get(
              step.pathNodeId ?? step.entityId ?? "",
            );
            return reviewed
              ? {
                  ...step,
                  analysisState: reviewed.analysisState,
                  confidence: reviewed.confidence,
                  matchKind: reviewed.matchKind,
                  matchReason: reviewed.matchReason,
                }
              : step;
          }),
        };
        setFlows((current) => [
          ...current.filter((item) => item.id !== flow.id),
          flow,
        ]);
        setNavigation((current) => {
          if (
            current.current.selectedPath?.historicalPathId !== flow.id
          ) {
            return current;
          }
          return {
            ...current,
            current: {
              ...current.current,
              selectedPath: runtimeCandidate,
            },
          };
        });
      })
      .catch(() => undefined);
  };

  const openPublishedFlow = async (flowId: string) => {
    const flow = await requestAttackFlow(flowId);
    setFlows((current) => [
      ...current.filter((item) => item.id !== flow.id),
      flow,
    ]);
    openPage("path", {
      selectedPath: adaptAttackFlowToPathCandidate(flow),
      query: flow.title,
      submittedQuery: flow.title,
    });
  };

  const startPathFromGraph = (
    candidates: PathCandidate[],
    contextLabel: string,
  ) => {
    if (candidates.length === 1) {
      openSelectedPath(candidates[0]);
      return;
    }
    if (candidates.length > 1) {
      const candidateQuery = candidates
        .map((candidate) => candidate.title)
        .join("；");
      openPathReview(
        candidateQuery || contextLabel,
        {},
        false,
      );
    }
  };

  const startPathFromActor = (pathQuery: string) => {
    openPathReview(pathQuery);
  };

  const refreshRuntimeKnowledge = async () => {
    await Promise.all([
      refreshCatalog(),
      refreshFlows(),
      refreshActorKnowledge(),
    ]);
  };

  return (
    <ArgusShell
      page={page}
      query={query}
      onQuery={(value) => updateCurrent({ query: value })}
      onSearch={() => submit("intel")}
      onNavigate={navigate}
    >
      {!catalog && (
        <main className="page-frame">
          <EmptyState
            title={catalogStatus === "loading" ? "正在加载运行时知识" : "运行时知识不可用"}
            description={
              catalogStatus === "loading"
                ? "正在读取当前知识版本、实体与报告目录。"
                : catalogError || "当前无法连接知识后端。"
            }
          />
        </main>
      )}
      {page === "search" && catalog && (
        <SearchView
          data={catalog}
          query={query}
          mode={mode}
          onQuery={(value) => updateCurrent({ query: value })}
          onMode={(value) => updateCurrent({ mode: value })}
          onSubmit={() => submit()}
          onOpenReport={openReport}
        />
      )}
      {page === "intel" && activeEntityStatus === "loading" && (
        <main className="page-frame">
          <EmptyState title="正在加载实体详情" description="正在读取关系、证据和关联 AttackFlow。" />
        </main>
      )}
      {page === "intel" && activeEntityStatus === "offline" && (
        <main className="page-frame">
          <EmptyState title="实体详情不可用" description={entityError} />
        </main>
      )}
      {page === "intel" && activeEntityStatus === "ready" && activeEntityWorkspace && (
        <IntelView
          key={submittedQuery || query}
          data={activeEntityWorkspace}
          query={submittedQuery || query}
          backLabel={backLabel}
          onBack={goBack}
          onOpenGraph={openEntityGraph}
          onOpenPath={openSelectedPath}
        />
      )}
      {page === "intel" && activeEntityStatus !== "loading" && !selectedEntityId && (
        <main className="page-frame">
          <EmptyState title="数据库中没有直接匹配" description="ARGUS 不会为未入库内容生成模拟情报。" />
        </main>
      )}
      {page === "actors" && actorKnowledge && (
        <ActorDirectoryView
          data={actorKnowledge}
          onOpenActor={openActor}
          sync={actorKnowledgeSync}
        />
      )}
      {page === "actor" && actorKnowledge && (
        <ActorProfileView
          key={selectedActorId}
          data={actorKnowledge}
          actorId={selectedActorId}
          onOpenGraph={openEntityGraph}
          onOpenPath={startPathFromActor}
          sync={actorKnowledgeSync}
        />
      )}
      {(page === "actors" || page === "actor") && !actorKnowledge && (
        <main className="page-frame">
          <EmptyState
            title={
              actorKnowledgeState.status === "offline"
                ? "攻击组织知识不可用"
                : "正在加载攻击组织知识"
            }
            description={
              actorKnowledgeState.error ?? "正在读取组织画像、别名与证据关系。"
            }
          />
        </main>
      )}
      {page === "path" && pathWorkspace && (
        <AttackPathAnalysisView
          key={
            selectedPath?.historicalPathId
              ? pathWorkspace.historicalPaths.find(
                  (path) => path.id === selectedPath.historicalPathId,
                )?.projection?.generated_at
              : selectedPath?.id
          }
          data={pathWorkspace}
          query={submittedQuery || query}
          selectedPath={selectedPath}
          backLabel={backLabel}
          onBack={goBack}
        />
      )}
      {page === "path-review" && pathWorkspace && (
        <AttackPathReviewView
          key={`${submittedQuery || query}:${pathAnalysis?.id ?? "local"}`}
          data={pathWorkspace}
          query={submittedQuery || query}
          initialSelection={selectedPath}
          backendAnalysis={pathAnalysis}
          analysisStatus={
            pathAnalysisStatus ??
            (flowStatus === "offline" ? "offline" : "idle")
          }
          analysisError={
            pathAnalysisError ??
            (flowStatus === "offline"
              ? "历史 AttackFlow 列表暂时不可用；当前输入和已加载结果仍会保留。"
              : undefined)
          }
          backLabel={backLabel}
          onBack={goBack}
          onOpenPath={openSelectedPath}
        />
      )}
      {page === "report" && (
        <ReportAnalysisView
          report={selectedReport}
          backLabel={backLabel}
          onBack={goBack}
          onOpenAnalysis={openHistoricalAnalysis}
        />
      )}
      {page === "ingest" && (
        <KnowledgeIngestionView
          onOpenGraph={openGraphLibrary}
          onOpenPublishedFlow={openPublishedFlow}
          onKnowledgeChanged={refreshRuntimeKnowledge}
        />
      )}
      {page === "fragment-review" && <PathFragmentReviewCenter />}
      {page === "gpt" && (
        <GPTView
          initialPrompt={mode === "gpt" ? query : ""}
          backLabel={backLabel}
          onBack={goBack}
        />
      )}
      {page === "graph" && graphContext && pathWorkspace && (
        <FullGraphView
          data={pathWorkspace}
          rootId={graphContext.rootId}
          backLabel={backLabel}
          showBack={
            previousPage !== "search" &&
            previousPage !== "actors" &&
            previousPage !== "actor"
          }
          onBack={goBack}
          onStartPath={startPathFromGraph}
          onOpenActor={openActor}
        />
      )}
    </ArgusShell>
  );
}
