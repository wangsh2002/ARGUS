from pathlib import Path
import shutil

from fastapi.testclient import TestClient

from argus_backend.api import create_app


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def make_client(tmp_path: Path) -> TestClient:
    database_path = tmp_path / "argus_cti.db"
    shutil.copy2(REPOSITORY_ROOT / "data" / "argus_cti.db", database_path)
    return TestClient(create_app(database_path=database_path))


def test_showcase_partial_path_has_hits_completion_and_prediction(
    tmp_path: Path,
) -> None:
    response = make_client(tmp_path).post(
        "/v1/flow-matches",
        json={
            "query_text": (
                "Drop Zebrocy malware executable → "
                "Create scheduled task for persistence"
            )
        },
    )

    assert response.status_code == 200
    candidates = response.json()["candidates"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["flow_title"].startswith("APT28 Zebrocy")
    states = [item["state"] for item in candidate["action_states"]]
    assert states.count("input_hit") == 2
    assert "reconstructed" in states
    assert "predicted" in states


def test_showcase_combined_alert_matches_multiple_attack_flows(
    tmp_path: Path,
) -> None:
    response = make_client(tmp_path).post(
        "/v1/flow-matches",
        json={
            "query_text": (
                "EDR alert A: Create scheduled task for persistence; "
                "EDR alert B: Drop and detonate FlawedGrace"
            )
        },
    )

    assert response.status_code == 200
    titles = {
        candidate["flow_title"] for candidate in response.json()["candidates"]
    }
    assert any(title.startswith("APT28 Zebrocy") for title in titles)
    assert any(title.startswith("TA505 September 2021") for title in titles)


def test_showcase_report_observations_match_multiple_report_flows(
    tmp_path: Path,
) -> None:
    response = make_client(tmp_path).post(
        "/v1/flow-matches",
        json={
            "query_text": "\n".join(
                [
                    "Send initial tax-themed phishing email",
                    "Deliver document with macros",
                    "Send IRS-themed emails",
                    "Request victims enable macros",
                ]
            )
        },
    )

    assert response.status_code == 200
    candidates = response.json()["candidates"]
    assert len(candidates) >= 2
    assert all(candidate["score"] >= 0.6 for candidate in candidates[:2])
