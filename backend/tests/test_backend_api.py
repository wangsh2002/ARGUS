from hashlib import sha256
from pathlib import Path
import shutil
import sqlite3

from fastapi.testclient import TestClient

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONTENT = (
    "NCSC reported exploitation of CVE-2017-6742 on Cisco routers.\n\n"
    "Jaguar Tooth executes CLI commands to collect device information."
)
EXAMPLE_SHA256 = "08108ad9fcf8b0ae252442450af0a2b333e9fd9cb3096affe34ac7f66895eaa5"
CURATED_ALERT_CONTENT = (
    "边界 Cisco IOS 路由器在 09:13 触发 CVE-2017-6742 利用告警。"
    "随后在设备上发现 Jaguar Tooth 植入，并记录到通过 CLI 执行 "
    "show version、show interfaces 等系统信息收集命令。"
)


def make_client(tmp_path: Path) -> TestClient:
    tmp_path.mkdir(parents=True, exist_ok=True)
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    curated_source_id = (
        "SRC-DOC-" + sha256(CURATED_ALERT_CONTENT.encode("utf-8")).hexdigest()[:16]
    )
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE raw_reports SET source_ref = source_ref || ':fixture' WHERE source_ref = ?",
            (curated_source_id,),
        )
    return TestClient(create_app(database_path=database_path))


def test_archive_source_is_content_addressed_and_returns_evidence_anchors(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    request = {
        "title": "Jaguar Tooth advisory extract",
        "publisher": "UK NCSC",
        "canonical_url": "https://www.ncsc.gov.uk/news/apt28-exploits-known-vulnerability",
        "published_at": "2023-04-18",
        "mime_type": "text/plain",
        "content": EXAMPLE_CONTENT,
    }

    first = client.post("/v1/sources", json=request)
    duplicate = client.post("/v1/sources", json=request)

    assert first.status_code == 200
    assert duplicate.status_code == 200
    archived = first.json()
    assert archived["created"] is True
    assert duplicate.json()["created"] is False
    assert archived["source_document"]["id"] == f"SRC-DOC-{EXAMPLE_SHA256[:16]}"
    assert [span["locator"] for span in archived["source_spans"]] == [
        "paragraph:1",
        "paragraph:2",
    ]
    assert all(span["text"] in EXAMPLE_CONTENT for span in archived["source_spans"])


def test_runtime_catalog_does_not_present_interactive_queries_as_reports(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    archived = client.post(
        "/v1/sources",
        json={
            "title": "交互式攻击路径研判输入",
            "publisher": "ARGUS interactive input",
            "canonical_url": "https://argus.local/interactive-query/test",
            "published_at": "2026-08-01",
            "mime_type": "text/plain",
            "content": "打开 ZIPX 诱饵 → 释放 Zebrocy",
        },
    )

    assert archived.status_code == 200
    reports = client.get("/v1/runtime/catalog").json()["reports"]
    assert all(report["source"] != "ARGUS interactive input" for report in reports)


def test_reads_a_published_activity_as_an_explicit_attack_flow(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    listed = client.get("/v1/attack-flows").json()
    flow_id = listed[0]["id"]

    response = client.get(f"/v1/attack-flows/{flow_id}")

    assert response.status_code == 200
    flow = response.json()
    assert flow["schema_version"] == "1.0"
    assert len(flow["mainline"]) >= 2
    assert set(flow["mainline"]) <= {
        action["id"] for action in flow["actions"]
    }
    assert all(action["evidence"] for action in flow["actions"])
    assert all(relation["evidence"] for relation in flow["relations"])


def test_lists_the_current_published_attack_flow_corpus(
    tmp_path: Path,
) -> None:
    flows = make_client(tmp_path).get("/v1/attack-flows").json()

    assert len(flows) >= 40
    assert len({flow["id"] for flow in flows}) == len(flows)
    assert all(flow["mainline"] for flow in flows)
    assert all(flow["sources"] for flow in flows)
    assert all(
        source["id"].startswith("SRC-DOC-")
        for flow in flows
        for source in flow["sources"]
    )
    assert all(
        len({source["id"] for source in flow["sources"]})
        == len(flow["sources"])
        for flow in flows
    )


def test_attack_flow_read_requires_explicit_mainline_and_evidence(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    flow = client.get("/v1/attack-flows").json()[0]
    flow_id = flow["id"]
    with sqlite3.connect(tmp_path / "argus_cti.db") as connection:
        connection.execute(
            "DELETE FROM analysis_projections WHERE path_id = ?",
            (flow_id,),
        )
    assert client.get(f"/v1/attack-flows/{flow_id}").status_code == 422

    client = make_client(tmp_path / "evidence")
    action_id = flow["mainline"][0]
    with sqlite3.connect(tmp_path / "evidence" / "argus_cti.db") as connection:
        connection.execute(
            "DELETE FROM path_evidence_links WHERE node_id = ?",
            (action_id,),
        )
    assert client.get(f"/v1/attack-flows/{flow_id}").status_code == 422


def test_reads_full_source_documents_with_evidence_backed_annotations(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    with sqlite3.connect(tmp_path / "argus_cti.db") as connection:
        flow_id = connection.execute(
            """
            SELECT DISTINCT path_id
            FROM action_context_links
            ORDER BY path_id
            LIMIT 1
            """
        ).fetchone()[0]

    response = client.get(f"/v1/attack-flows/{flow_id}/source-documents")

    assert response.status_code == 200
    documents = response.json()
    assert documents
    assert all(document["content"] for document in documents)
    annotations = [
        annotation
        for document in documents
        for annotation in document["annotations"]
    ]
    assert annotations
    assert "attack-process" in {annotation["kind"] for annotation in annotations}
    assert {annotation["kind"] for annotation in annotations} & {
        "ioc",
        "software",
        "vulnerability",
        "asset",
    }
    for document in documents:
        for annotation in document["annotations"]:
            assert 0 <= annotation["start_offset"] < annotation["end_offset"]
            assert annotation["end_offset"] <= len(document["content"])
            assert document["content"][
                annotation["start_offset"] : annotation["end_offset"]
            ].strip()


def test_source_documents_include_unlinked_report_entity_mentions(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    database = tmp_path / "argus_cti.db"
    with sqlite3.connect(database) as connection:
        flow_id, source_id = connection.execute(
            """
            SELECT path_id, source_document_id
            FROM flow_source_supports
            ORDER BY path_id
            LIMIT 1
            """
        ).fetchone()
        span_id, span_text = connection.execute(
            """
            SELECT id, text FROM source_spans
            WHERE source_document_id = ? AND length(text) > 8
            ORDER BY start_offset
            LIMIT 1
            """,
            (source_id,),
        ).fetchone()
        marker = span_text.strip().split()[0]
        connection.execute(
            """
            INSERT INTO entities (
              id, entity_type, canonical_key, label, normalized_value,
              source_count, created_at, updated_at
            ) VALUES ('ENT-REPORT-ONLY', '恶意软件/工具', 'tool:report-only',
                      ?, 'report-only', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (marker,),
        )
        connection.execute(
            """
            INSERT INTO entity_mentions (
              id, entity_id, source_document_id, source_span_id, ingestion_id,
              original_value, canonical_value, value_type, confidence
            ) VALUES ('EMN-REPORT-ONLY', 'ENT-REPORT-ONLY', ?, ?,
                      'TEST-REPORT-MENTION', ?, 'report-only', 'tool', 0.9)
            """,
            (source_id, span_id, marker),
        )
        connection.commit()

    response = client.get(f"/v1/attack-flows/{flow_id}/source-documents")

    assert response.status_code == 200
    annotation = next(
        item
        for document in response.json()
        for item in document["annotations"]
        if item["id"] == "ANN-EMN-REPORT-ONLY"
    )
    assert annotation["label"] == marker
    assert annotation["action_ids"] == []


def test_source_annotation_route_rejects_unknown_attack_flow(tmp_path: Path) -> None:
    response = make_client(tmp_path).get(
        "/v1/attack-flows/PATH-UNKNOWN/source-documents"
    )

    assert response.status_code == 404
