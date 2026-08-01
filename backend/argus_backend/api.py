from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from .application import ArgusApplication
from .attack_flow_extraction import AttackFlowLanguageModel
from .models import (
    AttackFlow,
    AttackFlowDraft,
    AttackFlowMergeReview,
    FlowMatchRequest,
    FlowMatchRun,
    PanoramicGraphIndex,
    PanoramicGraphNeighborhood,
    SourceArchiveRequest,
    SourceArchiveResponse,
)
from .repository import SqliteRepository


def create_app(
    database_path: Path | str,
    attack_flow_language_model: AttackFlowLanguageModel | None = None,
) -> FastAPI:
    repository = SqliteRepository(Path(database_path))
    repository.ensure_schema()
    application = ArgusApplication(
        repository,
        attack_flow_language_model=attack_flow_language_model,
    )

    app = FastAPI(title="ARGUS Explainable CTI API", version="0.1.0")

    @app.post("/v1/sources", response_model=SourceArchiveResponse)
    def archive_source(request: SourceArchiveRequest) -> SourceArchiveResponse:
        return application.archive_source(request)

    @app.get("/v1/attack-flows", response_model=list[AttackFlow])
    def list_attack_flows() -> list[AttackFlow]:
        try:
            return application.list_attack_flows()
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get("/v1/attack-flows/{flow_id}", response_model=AttackFlow)
    def get_attack_flow(flow_id: str) -> AttackFlow:
        try:
            return application.get_attack_flow(flow_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get("/v1/graph/nodes", response_model=PanoramicGraphIndex)
    def get_panoramic_graph_index() -> PanoramicGraphIndex:
        return application.get_panoramic_graph_index()

    @app.get("/v1/runtime/catalog")
    def get_runtime_catalog() -> dict:
        return application.get_runtime_catalog()

    @app.get("/v1/runtime/entities/{entity_id}")
    def get_entity_intelligence(entity_id: str) -> dict:
        try:
            return application.get_entity_intelligence(entity_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.get(
        "/v1/graph/neighborhoods/{node_id}",
        response_model=PanoramicGraphNeighborhood,
    )
    def get_panoramic_graph_neighborhood(
        node_id: str,
        depth: int = 2,
        limit: int = 96,
    ) -> PanoramicGraphNeighborhood:
        if depth < 1 or depth > 4:
            raise HTTPException(status_code=422, detail="depth must be between 1 and 4")
        if limit < 8 or limit > 256:
            raise HTTPException(status_code=422, detail="limit must be between 8 and 256")
        try:
            return application.get_panoramic_graph_neighborhood(
                node_id, depth, limit
            )
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.post("/v1/flow-matches", response_model=FlowMatchRun)
    def match_attack_flows(request: FlowMatchRequest) -> FlowMatchRun:
        try:
            return application.match_attack_flows(request)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get("/v1/flow-matches/{run_id}", response_model=FlowMatchRun)
    def get_flow_match_run(run_id: str) -> FlowMatchRun:
        try:
            return application.get_flow_match_run(run_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.post("/v1/knowledge-ingestions")
    def stage_knowledge_ingestion(request: dict) -> dict:
        source_document_id = str(request.get("source_document_id", "")).strip()
        projection_goal = str(
            request.get("projection_goal", "incident-response")
        ).strip()
        if not source_document_id:
            raise HTTPException(
                status_code=422, detail="source_document_id is required"
            )
        try:
            attack_flow_candidates = None
            if "attack_flow_candidates" in request:
                raw_candidates = request["attack_flow_candidates"]
                if not isinstance(raw_candidates, list):
                    raise ValueError("attack_flow_candidates must be a list")
                attack_flow_candidates = [
                    AttackFlowDraft.model_validate(candidate)
                    for candidate in raw_candidates
                ]
            attack_flow_candidate = (
                AttackFlowDraft.model_validate(request["attack_flow_candidate"])
                if request.get("attack_flow_candidate") is not None
                else None
            )
            merge_review = (
                AttackFlowMergeReview.model_validate(request["merge_review"])
                if request.get("merge_review") is not None
                else None
            )
            return application.stage_knowledge_ingestion(
                source_document_id,
                projection_goal=projection_goal,
                attack_flow_candidate=attack_flow_candidate,
                attack_flow_candidates=attack_flow_candidates,
                merge_review=merge_review,
                extract_attack_flows=bool(request.get("extract_attack_flows", False)),
            )
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except ValidationError as error:
            raise HTTPException(status_code=422, detail=error.errors()) from error

    @app.get("/v1/knowledge-ingestions")
    def list_knowledge_ingestions(status: str = "staged") -> dict:
        if status != "staged":
            raise HTTPException(status_code=422, detail="only staged is supported")
        return application.list_pending_attack_flow_ingestions()

    @app.put("/v1/knowledge-ingestions/{ingestion_id}")
    def revise_knowledge_ingestion(ingestion_id: str, request: dict) -> dict:
        if request.get("attack_flow_candidate") is None:
            raise HTTPException(
                status_code=422,
                detail="attack_flow_candidate is required",
            )
        try:
            candidate = AttackFlowDraft.model_validate(
                request["attack_flow_candidate"]
            )
            merge_review = (
                AttackFlowMergeReview.model_validate(request["merge_review"])
                if request.get("merge_review") is not None
                else None
            )
            return application.revise_attack_flow_ingestion(
                ingestion_id,
                candidate,
                merge_review,
            )
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except (ValueError, ValidationError) as error:
            detail = error.errors() if isinstance(error, ValidationError) else str(error)
            raise HTTPException(status_code=422, detail=detail) from error

    @app.post("/v1/knowledge-ingestions/{ingestion_id}/reject")
    def reject_knowledge_ingestion(ingestion_id: str) -> dict:
        try:
            return application.reject_attack_flow_ingestion(ingestion_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/v1/knowledge-ingestions/{ingestion_id}")
    def get_knowledge_ingestion(ingestion_id: str) -> dict:
        try:
            return application.get_knowledge_ingestion(ingestion_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.post("/v1/knowledge-ingestions/{ingestion_id}/publish")
    def publish_knowledge_ingestion(ingestion_id: str) -> dict:
        try:
            return application.publish_knowledge_ingestion(ingestion_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/v1/knowledge-versions/{version_id}/rollback")
    def rollback_knowledge_version(version_id: str) -> dict:
        try:
            return application.rollback_knowledge_version(version_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.get("/v1/actor-knowledge")
    def get_actor_knowledge() -> dict:
        return application.get_actor_knowledge()

    return app
