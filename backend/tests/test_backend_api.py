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


def test_reads_a_curated_activity_as_an_explicit_attack_flow(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    flow_id = "PATH-ANNOCTR-APT28-ZEBROCY-2020"

    response = client.get(f"/v1/attack-flows/{flow_id}")

    assert response.status_code == 200
    flow = response.json()
    assert flow["schema_version"] == "1.0"
    assert flow["mainline"] == [
        f"{flow_id}-N-{index:02d}" for index in range(1, 8)
    ]
    assert [action["id"] for action in flow["actions"]] == flow["mainline"]
    assert flow["actions"][0]["name"] == "打开 ZIPX 诱饵"
    assert all(action["evidence"] for action in flow["actions"])
    assert all(relation["evidence"] for relation in flow["relations"])


def test_lists_only_the_three_retained_curated_attack_flows(
    tmp_path: Path,
) -> None:
    flows = make_client(tmp_path).get("/v1/attack-flows").json()

    assert [flow["id"] for flow in flows] == [
        "PATH-ANNOCTR-APT28-ZEBROCY-2020",
        "PATH-ANNOCTR-APT29-DNC-2015",
        "PATH-ANNOCTR-LAZARUS-REDBANC-2018",
    ]
    assert all(flow["mainline"] for flow in flows)


def test_attack_flow_read_requires_explicit_mainline_and_evidence(
    tmp_path: Path,
) -> None:
    client = make_client(tmp_path)
    flow_id = "PATH-ANNOCTR-APT28-ZEBROCY-2020"
    with sqlite3.connect(tmp_path / "argus_cti.db") as connection:
        connection.execute(
            "DELETE FROM analysis_projections WHERE path_id = ?",
            (flow_id,),
        )
    assert client.get(f"/v1/attack-flows/{flow_id}").status_code == 422

    client = make_client(tmp_path / "evidence")
    action_id = f"{flow_id}-N-01"
    with sqlite3.connect(tmp_path / "evidence" / "argus_cti.db") as connection:
        connection.execute(
            "DELETE FROM path_evidence_links WHERE node_id = ?",
            (action_id,),
        )
    assert client.get(f"/v1/attack-flows/{flow_id}").status_code == 422
