"""
PCAP ANALYZER - AI Analysis Engine
VCAS.PRIVATE × QNTSOFTWARE

High-performance AI orchestration for network intelligence, threat classification,
and CTF challenge solving via Google Gemini API and local Ollama LLMs.
"""

import json
import sys
import re
from typing import Optional
from .parser       import Packet
from .prompt_engine import build_smart_prompt, detect_protocol_from_description, suggest_filter_from_description
from .lang          import L


def analyze_with_gemini(packets: list[Packet], description: str, api_key: str) -> dict:
    try:
        import google.generativeai as genai
    except ImportError:
        print("\033[91m[ERROR] google-generativeai is not installed: pip install google-generativeai\033[0m")
        sys.exit(1)

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.0-flash")

    prompt = build_smart_prompt(packets, description)

    proto, _ = detect_protocol_from_description(description)
    print(f"\033[36m[*] {L('detected_protocol', proto=proto)}\033[0m")
    print(f"\033[36m[*] {L('sending_to_gemini')}\033[0m")

    try:
        response = model.generate_content(prompt)
        raw = response.text
    except Exception as e:
        print(f"\033[91m[ERROR] Gemini API: {e}\033[0m")
        sys.exit(1)

    return _parse_ai_response(raw)


def analyze_with_localai(packets: list[Packet], description: str, model_name: str) -> dict:
    try:
        import requests
    except ImportError:
        print("\033[91m[ERROR] requests is not installed: pip install requests\033[0m")
        sys.exit(1)

    prompt = build_smart_prompt(packets, description)

    proto, _ = detect_protocol_from_description(description)
    print(f"\033[36m[*] {L('detected_protocol', proto=proto)}\033[0m")
    print(f"\033[36m[*] {L('sending_to_localai', model=model_name)}\033[0m")

    try:
        resp = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model_name,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.05, "num_ctx": 32768}
            },
            timeout=600
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "")
    except requests.exceptions.ConnectionError:
        print("\033[91m[ERROR] Connection to Ollama failed. Is Ollama service running? (ollama serve)\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[91m[ERROR] Local AI error: {e}\033[0m")
        sys.exit(1)

    return _parse_ai_response(raw)


def _parse_ai_response(raw: str) -> dict:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)

    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start != -1 and end > start:
        raw = raw[start:end]

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "packet_summaries": [],
            "key_packet_indices": [],
            "highlights": [],
            "executive_summary": raw[:800],
            "detailed_analysis": raw,
            "ctf_answer": "N/A",
            "decoded_values": [],
            "protocol_findings": {},
            "security_recommendations": [],
            "threat_level": "UNKNOWN",
            "attack_vectors": [],
            "ioc_list": [],
        }


def merge_ai_results(packets: list[Packet], analysis: dict) -> list[Packet]:
    summaries      = {s["index"]: s for s in analysis.get("packet_summaries", [])}
    key_indices    = set(analysis.get("key_packet_indices", []))
    highlights_map: dict[int, list] = {}
    for h in analysis.get("highlights", []):
        pi = h.get("packet_index", 0)
        highlights_map.setdefault(pi, []).append(h.get("field", ""))

    for p in packets:
        if p.index in summaries:
            p.raw_summary = summaries[p.index].get("summary", p.raw_summary)
        if p.index in key_indices:
            p.is_key_packet    = True
            p.importance_score = 1.0
        p.highlighted_fields = highlights_map.get(p.index, [])

    return packets
