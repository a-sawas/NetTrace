"""
ai_classifier.py
Stage 2: Classify network connections
All risk scores are determined exclusively by the AI.
"""

import json
import time
import re

# ─────────────────────────────────────────────
GEMINI_API_KEY = "TYPE_YOUR_API_KEY_HERE"  # Replace with your actual Gemini API key
# ─────────────────────────────────────────────

BATCH_SIZE  = 15
MAX_RETRIES = 3

SYSTEM_PROMPT = """You are a cybersecurity expert analyzing network connection logs.
You will receive a numbered list of network connections.
For EACH connection, you must return a JSON array where each element has:
  - "index": the connection number (integer, starting from 0)
  - "label": a short attack label (e.g. "brute_force_ssh", "port_scan", "rdp_lateral_movement", "normal_traffic", "data_exfiltration", "smb_exploit", "dns_tunneling")
  - "risk_score": an integer from 0 to 100 (0 = completely safe, 100 = confirmed attack)

Base your risk_score on: port number, protocol, packet count, duration, flags, and known attack patterns.
High packet count in short time = high risk. SYN floods = high risk. Normal HTTP/HTTPS = low risk.

Return ONLY the JSON array. No explanation, no markdown, no extra text. Just the raw JSON array."""


def _call_gemini(prompt_text):
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=GEMINI_API_KEY)

    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents=SYSTEM_PROMPT + "\n\n" + prompt_text,
        config=types.GenerateContentConfig(
            temperature=0.1,
            max_output_tokens=4096,
        )
    )

    if response.candidates and response.candidates[0].content.parts:
        return response.candidates[0].content.parts[0].text.strip()

    if hasattr(response, "text") and response.text:
        return response.text.strip()

    raise ValueError("Gemini returned an empty response.")


def _parse_response(raw):
    text = raw.strip()

    # Strip markdown code fences if present (e.g. ```json ... ```)
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
    if text.endswith("```"):
        text = text[:-3].strip()

    # Extract the JSON array even if surrounded by stray text
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        text = match.group(0)

    return json.loads(text)


def classify_connections(connections):
    for conn in connections:
        conn["label"]      = "unclassified"
        conn["risk_score"] = 0

    total       = len(connections)
    num_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE

    print(f"[AI] Gemini 2.0 Flash — {total} connections, {num_batches} batch(es)")

    for batch_num in range(num_batches):
        start = batch_num * BATCH_SIZE
        end   = min(start + BATCH_SIZE, total)
        batch = connections[start:end]

        prompt_text = "\n".join(
            f"Connection {i}:\n{conn['raw_text']}\n"
            for i, conn in enumerate(batch)
        )

        print(f"[AI] Batch {batch_num + 1}/{num_batches}...", end=" ", flush=True)

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                results = _parse_response(_call_gemini(prompt_text))

                for item in results:
                    idx = item.get("index", -1)
                    if 0 <= idx < len(batch):
                        batch[idx]["label"]      = item.get("label", "unknown")
                        batch[idx]["risk_score"] = max(0, min(100, int(item.get("risk_score", 0))))

                print("OK")
                break

            except json.JSONDecodeError as e:
                print(f"\n  JSON error (attempt {attempt}): {e}")
                if attempt < MAX_RETRIES:
                    time.sleep(3)

            except Exception as e:
                msg = str(e).lower()
                print(f"\n  API error (attempt {attempt}): {e}")
                if "429" in msg or "quota" in msg or "rate" in msg:
                    wait = 30 * attempt
                    print(f"  Rate limited — waiting {wait}s...")
                    time.sleep(wait)
                elif attempt < MAX_RETRIES:
                    time.sleep(3)
        else:
            print(f"  FAILED after {MAX_RETRIES} attempts — marked as unclassified.")

    print("[AI] Classification complete.")

    # Debug print 
    for conn in connections:
        if "10.0.0" in conn.get("src", "") or "10.0.0" in conn.get("dst", ""):
            print(f"  {conn['src']} → {conn['dst']}  port={conn['port']}  risk={conn['risk_score']}  label={conn['label']}")

    return connections


def classify_demo(connections):
    """No API call — hardcoded scores for the 7 demo connections."""
    demo_scores = [
        ("brute_force_ssh",      91),
        ("smb_exploit",          88),
        ("rdp_lateral_movement", 85),
        ("data_exfiltration",    72),
        ("normal_https",         18),
        ("dns_tunneling",        61),
        ("suspicious_http",      54),
    ]
    for i, conn in enumerate(connections):
        label, score = demo_scores[i] if i < len(demo_scores) else ("normal_traffic", 20)
        conn["label"]      = label
        conn["risk_score"] = score

    print("[AI] Demo classification applied (no API call made).")
    return connections