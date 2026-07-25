"use client";

import { useEffect, useState } from "react";
import {
  actorGraph,
  buildSubgraph,
  caseGraph,
  createCaseFromQuery,
  createCaseFromReport,
  searchSnapshot,
} from "./argus-domain";
import { loadCases, removeCase, saveCases, upsertCase } from "./case-store";
import { ArgusShell } from "./components/ArgusShell";
import { ChainIntakeView } from "./components/ChainIntakeView";
import { ChainWorkspace } from "./components/ChainWorkspace";
import { GPTView } from "./components/GPTView";
import { IntelView } from "./components/IntelView";
import {
  ActorsView,
  CasesView,
  FullGraphView,
  ReportsView,
} from "./components/LibraryViews";
import { SearchView } from "./components/SearchView";
import type {
  Actor,
  AppPage,
  GptSuggestedNode,
  GraphEdge,
  GraphNode,
  InvestigationCase,
  SearchMode,
  Snapshot,
} from "./types";

type GraphContext = {
  title: string;
  subtitle: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootId?: string;
  returnPage: AppPage;
};

export function ArgusApp({ data }: { data: Snapshot }) {
  const [page, setPage] = useState<AppPage>("search");
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [mode, setMode] = useState<SearchMode>("intel");
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [currentCase, setCurrentCase] = useState<InvestigationCase>();
  const [graphContext, setGraphContext] = useState<GraphContext>();

  useEffect(() => {
    const stored = loadCases();
    if (stored.length) {
      // Hydrate the versioned browser store after SSR has completed.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setCases(stored);
      setCurrentCase(stored[0]);
      return;
    }
    const seed = createCaseFromReport(data);
    setCases([seed]);
    setCurrentCase(seed);
    saveCases([seed]);
  }, [data]);

  const openCase = (investigation: InvestigationCase) => {
    setCurrentCase(investigation);
    setPage("chain");
  };

  const createFromReport = (reportId: string) => {
    const next = createCaseFromReport(data, reportId);
    setCurrentCase(next);
    setPage("chain");
  };

  const createFromQuery = (value: string) => {
    const next = createCaseFromQuery(data, value);
    setCurrentCase(next);
    setQuery(value);
    setPage("chain");
  };

  const submit = (forcedMode?: SearchMode) => {
    const nextMode = forcedMode ?? mode;
    if (!query.trim()) return;
    setSubmittedQuery(query.trim());
    if (nextMode === "gpt") {
      setPage("gpt");
      return;
    }
    if (nextMode === "chain") {
      createFromQuery(query.trim());
      return;
    }
    if (nextMode === "graph") {
      const result = searchSnapshot(data, query.trim());
      const entity = result.entities[0]?.entity;
      if (entity) {
        const graph = buildSubgraph(data, [entity.id], 42);
        setGraphContext({
          title: `${entity.label} 关系图谱`,
          subtitle: `${graph.nodes.length} 个节点 · ${graph.edges.length} 条关系`,
          ...graph,
          rootId: entity.id,
          returnPage: "search",
        });
        setPage("graph");
        return;
      }
    }
    setMode("intel");
    setPage("intel");
  };

  const openEntityGraph = (entity: Snapshot["entities"][number]) => {
    const graph = buildSubgraph(data, [entity.id], 42);
    setGraphContext({
      title: `${entity.label} 关系图谱`,
      subtitle: `${graph.nodes.length} 个节点 · ${graph.edges.length} 条关系`,
      ...graph,
      rootId: entity.id,
      returnPage: page,
    });
    setPage("graph");
  };

  const openActorGraph = (actor: Actor) => {
    const graph = actorGraph(data, actor);
    setGraphContext({
      title: `${actor.label} 全景图谱`,
      subtitle: `${graph.nodes.length} 个节点 · ${graph.edges.length} 条关系`,
      ...graph,
      rootId: actor.id,
      returnPage: "actors",
    });
    setPage("graph");
  };

  const openCaseGraph = () => {
    if (!currentCase) return;
    const graph = caseGraph(data, currentCase);
    setGraphContext({
      title: `${currentCase.title} · 攻击链图谱`,
      subtitle: `${graph.nodes.length} 个节点 · ${graph.edges.length} 条关系`,
      ...graph,
      rootId: currentCase.steps[0]?.id,
      returnPage: "chain",
    });
    setPage("graph");
  };

  const saveCurrentCase = () => {
    if (!currentCase) return;
    const nextCases = upsertCase(cases, currentCase);
    const saved = nextCases.find((item) => item.id === currentCase.id);
    setCases(nextCases);
    if (saved) setCurrentCase(saved);
    saveCases(nextCases);
  };

  const deleteCase = (caseId: string) => {
    const nextCases = removeCase(cases, caseId);
    setCases(nextCases);
    saveCases(nextCases);
    if (currentCase?.id === caseId) setCurrentCase(nextCases[0]);
  };

  const addGptNode = (node: GptSuggestedNode) => {
    const base = currentCase ?? createCaseFromReport(data);
    const stepId = `gpt-${node.id}-${Date.now().toString(36)}`;
    const previous = base.steps.at(-1);
    const next: InvestigationCase = {
      ...base,
      steps: [
        ...base.steps,
        {
          id: stepId,
          label: node.label,
          type: node.type,
          relation: node.relation,
          phase: "待研判",
          confidence: node.confidence,
          evidenceCount: 0,
          status: "partial",
          origin: "gpt",
          reviewStatus: "candidate",
          description: "ARGUS GPT 建议的候选节点，需由分析师补充来源并确认。",
        },
      ],
      links: previous
        ? [
            ...base.links,
            {
              id: `gpt-link-${Date.now().toString(36)}`,
              source: previous.id,
              target: stepId,
              label: node.relation,
              confidence: node.confidence,
              status: "partial",
            },
          ]
        : base.links,
    };
    setCurrentCase(next);
    setPage("chain");
  };

  if (page === "graph" && graphContext) {
    return (
      <FullGraphView
        title={graphContext.title}
        subtitle={graphContext.subtitle}
        nodes={graphContext.nodes}
        edges={graphContext.edges}
        rootId={graphContext.rootId}
        onBack={() => setPage(graphContext.returnPage)}
      />
    );
  }

  return (
    <ArgusShell
      page={page}
      query={query}
      onQuery={setQuery}
      onSearch={() => submit("intel")}
      onNavigate={(nextPage) => setPage(nextPage)}
    >
      {page === "search" && (
        <SearchView
          data={data}
          query={query}
          mode={mode}
          cases={cases}
          onQuery={setQuery}
          onMode={setMode}
          onSubmit={() => submit()}
          onOpenCase={openCase}
          onOpenReport={createFromReport}
        />
      )}
      {page === "intel" && (
        <IntelView
          data={data}
          query={submittedQuery || query}
          onBack={() => setPage("search")}
          onCreateCase={createFromQuery}
          onOpenGraph={openEntityGraph}
        />
      )}
      {page === "chain-intake" && (
        <ChainIntakeView
          data={data}
          initialValue={mode === "chain" ? query : ""}
          onCreateFromQuery={createFromQuery}
          onCreateFromReport={createFromReport}
          onOpenGpt={() => setPage("gpt")}
        />
      )}
      {page === "chain" &&
        (currentCase ? (
          <ChainWorkspace
            data={data}
            investigation={currentCase}
            onSave={saveCurrentCase}
            onBack={() => setPage("chain-intake")}
            onOpenGraph={openCaseGraph}
            onOpenGpt={() => setPage("gpt")}
          />
        ) : (
          <ChainIntakeView
            data={data}
            initialValue=""
            onCreateFromQuery={createFromQuery}
            onCreateFromReport={createFromReport}
            onOpenGpt={() => setPage("gpt")}
          />
        ))}
      {page === "cases" && (
        <CasesView
          cases={cases}
          onOpen={openCase}
          onDelete={deleteCase}
          onCreate={() => setPage("chain-intake")}
        />
      )}
      {page === "reports" && (
        <ReportsView data={data} onCreateCase={createFromReport} />
      )}
      {page === "actors" && (
        <ActorsView data={data} onOpenGraph={openActorGraph} />
      )}
      {page === "gpt" && (
        <GPTView
          data={data}
          initialPrompt={mode === "gpt" ? query : ""}
          investigation={currentCase}
          onAddSuggestedNode={addGptNode}
          onOpenChain={() => currentCase && setPage("chain")}
        />
      )}
    </ArgusShell>
  );
}
