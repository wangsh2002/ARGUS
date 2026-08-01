import os
from pathlib import Path

from dotenv import load_dotenv

from .api import create_app
from .attack_flow_extraction import deepseek_attack_flow_from_environment


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPOSITORY_ROOT / ".env.local", override=False)
database_path = Path(
    os.environ.get(
        "ARGUS_DATABASE_PATH",
        str(REPOSITORY_ROOT / "data" / "argus_cti.db"),
    )
)

app = create_app(
    database_path=database_path,
    attack_flow_language_model=deepseek_attack_flow_from_environment(),
)
