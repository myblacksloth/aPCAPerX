"""
Pull the configured Ollama model through the HTTP API.

This script avoids the Ollama CLI because some minimal Compose contexts can
trigger its interactive launcher, which requires a TTY and breaks one-shot jobs.
"""

import json
import os
import urllib.request


def main() -> None:
    """Pull the model selected by PCAPCAPER_AI_MODEL and stream progress logs."""
    model = os.getenv("PCAPCAPER_AI_MODEL", "qwen2.5:0.5b")
    base_url = os.getenv("PCAPCAPER_AI_BASE_URL", "http://ai:11434").rstrip("/")
    print(f"Pulling Ollama model {model} from {base_url}", flush=True)

    request = urllib.request.Request(
        f"{base_url}/api/pull",
        data=json.dumps({"name": model, "stream": True}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=None) as response:
        for raw_line in response:
            try:
                event = json.loads(raw_line.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            status = event.get("status")
            if status:
                print(status, flush=True)

    print(f"Model {model} is ready", flush=True)


if __name__ == "__main__":
    main()
