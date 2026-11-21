"""
PCAP ANALYZER - Config Manager
VCAS.PRIVATE & QNTSOFTWARE
"""

import os
import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".pcapanalyzer"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _load() -> dict:
    CONFIG_DIR.mkdir(exist_ok=True)
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def _save(data: dict):
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


def set_api_key(key: str):
    data = _load()
    data["gemini_api_key"] = key
    _save(data)


def get_api_key() -> str | None:
    # Priority: env var > config file
    env_key = os.environ.get("GEMINI_API_KEY")
    if env_key:
        return env_key
    return _load().get("gemini_api_key")


def set_local_ai(model: str):
    data = _load()
    data["local_ai_model"] = model
    _save(data)


def get_local_ai() -> str | None:
    return _load().get("local_ai_model")


def get_all() -> dict:
    return _load()
