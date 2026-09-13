#!/usr/bin/env python3
"""Split a classical direct-routing list into efficient Stash text rule sets."""

from __future__ import annotations

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    output = {"ipv4": [], "domains": [], "ipv6": []}
    for line in args.input.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rule_type, separator, value = line.partition(",")
        if not separator:
            continue
        value = value.strip()
        if rule_type == "IP-CIDR":
            output["ipv4"].append(value)
        elif rule_type == "IP-CIDR6":
            output["ipv6"].append(value)
        elif rule_type in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
            prefix = {"DOMAIN": "", "DOMAIN-SUFFIX": "+.", "DOMAIN-KEYWORD": "keyword:"}[rule_type]
            output["domains"].append(prefix + value)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    names = {"ipv4": "russia-direct-ipv4.txt", "domains": "russia-direct-domains.txt", "ipv6": "russia-direct-ipv6.txt"}
    for kind, filename in names.items():
        values = list(dict.fromkeys(output[kind]))
        (args.output_dir / filename).write_text("\n".join(values) + "\n", encoding="utf-8")
        print(f"{filename}: {len(values)} rules")


if __name__ == "__main__":
    main()
