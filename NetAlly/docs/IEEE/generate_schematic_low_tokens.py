import argparse
import importlib.util
import os
from pathlib import Path


SKILL_SCRIPT = Path(r"C:\Users\sdlab\.codex\skills\scientific-schematics\scripts\generate_schematic_ai.py")


def load_skill_module():
    spec = importlib.util.spec_from_file_location("schematic_ai", SKILL_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--doc-type", default="journal")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--api-key")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    module = load_skill_module()

    class LowTokenGenerator(module.ScientificSchematicGenerator):
        def _make_request(self, model, messages, modalities=None):
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/scientific-writer",
                "X-Title": "Scientific Schematic Generator (Low Token Wrapper)",
            }
            payload = {
                "model": model,
                "messages": messages,
                "max_tokens": args.max_tokens,
            }
            if modalities:
                payload["modalities"] = modalities

            response = module.requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=120,
            )

            try:
                response_json = response.json()
            except module.json.JSONDecodeError:
                response_json = {"raw_text": response.text[:500]}

            if response.status_code != 200:
                error_detail = response_json.get("error", response_json)
                raise RuntimeError(f"API request failed (HTTP {response.status_code}): {error_detail}")

            return response_json

    generator = LowTokenGenerator(api_key=args.api_key or os.getenv("OPENROUTER_API_KEY"), verbose=args.verbose)
    results = generator.generate_iterative(
        user_prompt=args.prompt,
        output_path=args.output,
        iterations=min(args.iterations, 2),
        doc_type=args.doc_type,
    )

    if not results.get("success"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
