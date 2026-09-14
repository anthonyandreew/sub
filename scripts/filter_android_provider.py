#!/usr/bin/env python3
"""Create the Android-safe subset of the generated Stash proxy provider."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def is_android_safe(node: str) -> bool:
    """Keep only transports verified on the target Android setup."""
    # Hysteria2 is QUIC-based and all subscription Hysteria2 nodes time out on
    # this Android setup, while VLESS TCP and gRPC nodes connect successfully.
    if 'type: "hysteria2"' in node:
        return False
    if 'type: "vless"' in node:
        return not (
            'network: "xhttp"' in node
            or "reality-opts:" in node
            or "encryption:" in node
        )
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.input.read_text(encoding="utf-8")
    chunks = re.split(r"(?=^  - name: )", source, flags=re.MULTILINE)
    header, nodes = chunks[0], [chunk for chunk in chunks[1:] if chunk.strip()]
    safe_nodes = [node for node in nodes if is_android_safe(node)]
    if not safe_nodes:
        raise SystemExit("No Android-compatible nodes; refusing to overwrite provider.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(header + "".join(safe_nodes), encoding="utf-8")
    print(f"Generated {len(safe_nodes)} Android-compatible nodes in {args.output}")


if __name__ == "__main__":
    main()
