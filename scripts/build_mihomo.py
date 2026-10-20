#!/usr/bin/env python3
"""Build deterministic Mihomo profiles without publishing the source subscription URL.

Use MIHOMO_SUBSCRIPTION_URL or --input. Only VLESS and Hysteria2 are selected;
malformed selected entries never overwrite the last working output. Nodes are
not filtered by this machine's connectivity.
"""

from __future__ import annotations

import argparse
import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import parse_qs, urlsplit
import urllib.request

from build_stash_provider import parse_subscription

OUTPUT_PATHS = (
    "VPN_Mihomo_Auto.yaml",
    "clash_config_clashmi.yaml",
    "mihomo/providers/proxyplankton_sub_clash.yaml",
)
TEST_URL = "https://www.gstatic.com/generate_204"
ALLOWED_SCHEMES = {"vless", "hysteria2", "hy2"}
METADATA_SCHEMES = {"happ", "incy"}
RESERVED_NAMES = {"AUTO", "PROXY", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}


def xhttp_options(uri: str, original: dict) -> dict:
    """Translate Xray's URL-encoded extra into native Mihomo transport fields."""
    query = parse_qs(urlsplit(uri).query, keep_blank_values=True)
    values = query.get("extra", [])
    options = copy.deepcopy(original)
    if not values:
        return options
    try:
        if len(values) != 1:
            raise ValueError()
        extra = json.loads(values[0])
        if not isinstance(extra, dict):
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError("Invalid XHTTP extra JSON; keeping the previous profile") from None
    strings = {"mode": "mode", "host": "host", "path": "path",
               "uplinkHTTPMethod": "uplink-http-method", "uplinkDataPlacement": "uplink-data-placement",
               "uplinkDataKey": "uplink-data-key"}
    numbers = {"uplinkChunkSize": "uplink-chunk-size", "scMaxEachPostBytes": "sc-max-each-post-bytes",
               "scMinPostsIntervalMs": "sc-min-posts-interval-ms"}
    # This is an inbound/server setting, not a Mihomo client transport field.
    allowed = set(strings) | set(numbers) | {"xmux", "serverMaxHeaderBytes"}
    if set(extra) - allowed:
        raise ValueError("Unsupported XHTTP extra fields; keeping the previous profile")
    for source, target in strings.items():
        if source in extra:
            value = extra[source]
            if not isinstance(value, str) or not value:
                raise ValueError("Invalid XHTTP text setting")
            if target in options and options[target] != value:
                raise ValueError("Conflicting XHTTP URI and extra settings")
            options[target] = value

    def scalar(value):
        if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"\d+(?:-\d+)?", str(value)):
            raise ValueError("Invalid XHTTP numeric/range setting")
        return str(value)

    for source, target in numbers.items():
        if source in extra:
            options[target] = scalar(extra[source])
    if "xmux" in extra:
        xmux = extra["xmux"]
        mapping = {"maxConcurrency": "max-concurrency", "maxConnections": "max-connections"}
        if not isinstance(xmux, dict) or set(xmux) - set(mapping):
            raise ValueError("Unsupported XHTTP XMUX settings")
        options["reuse-settings"] = {mapping[key]: scalar(value) for key, value in xmux.items()}
    return options


def merge_nodes(groups: list[list[dict]]) -> list[dict]:
    """Deduplicate equal connections, preserving different nodes with equal labels."""
    result, seen, names = [], set(), set(RESERVED_NAMES)
    for group in groups:
        for item in group:
            identity = json.dumps({key: value for key, value in item.items() if key != "name"}, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            node = copy.deepcopy(item)
            label, number = node["name"], 2
            while node["name"] in names:
                node["name"] = f"{label} ({number})"
                number += 1
            names.add(node["name"])
            result.append(node)
    return result


def read_subscription(text: str, excluded: dict[str, int] | None = None) -> list[dict]:
    text = text.strip()
    if not text:
        raise ValueError("Empty subscription; keeping the previous profile")
    if "<!doctype html" in text[:200].lower() or "<html" in text[:200].lower():
        raise ValueError("Subscription returned HTML; keeping the previous profile")
    if "://" not in text:
        try:
            text = base64.b64decode("".join(text.split()) + "=" * (-len("".join(text.split())) % 4),
                                    validate=True).decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Subscription is neither URI text nor valid Base64") from exc
    selected = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*|@_wg)://", line)
        if not match:
            raise ValueError("Invalid subscription record; keeping the previous profile")
        scheme = match[1].lower()
        if scheme not in ALLOWED_SCHEMES:
            if excluded is not None and scheme not in METADATA_SCHEMES:
                label = "amneziawg" if scheme == "@_wg" else scheme
                excluded[label] = excluded.get(label, 0) + 1
            continue
        scheme = "hysteria2" if scheme == "hy2" else scheme
        selected.append(scheme + "://" + line.split("://", 1)[1])
    nodes, skipped = parse_subscription("\n".join(selected))
    if skipped:
        # Do not log raw links, credentials, or parser exceptions containing them.
        raise ValueError("Invalid VLESS/Hysteria2 connection; keeping the previous profile")
    if not nodes:
        raise ValueError("No VLESS/Hysteria2 connections; keeping the previous profile")
    result = []
    for item, uri in zip(nodes, selected):
        node = copy.deepcopy(item)
        if node["type"] == "hysteria2":
            node["password"] = node.pop("auth")
            if not node["password"]:
                raise ValueError("Hysteria2 connection has no password")
            node.pop("client-fingerprint", None)
            node.pop("tls", None)
        elif node["type"] == "vless":
            if not node.get("uuid"):
                raise ValueError("VLESS connection has no UUID")
            if "sni" in node:
                node["servername"] = node.pop("sni")
            # gRPC uses HTTP/2, even when a share link advertises http/1.1.
            if node.get("network") == "grpc" and node.get("tls"):
                node["alpn"] = ["h2"]
            node["udp"] = True
            if node.get("network") == "xhttp":
                node.setdefault("skip-cert-verify", False)
                node["xhttp-opts"] = xhttp_options(uri, node.get("xhttp-opts", {}))
        result.append(node)
    return merge_nodes([result])


def read_rules(directory: Path) -> dict:
    providers = {}
    for name, behavior in (("russia-direct-domains", "domain"),
                           ("russia-direct-ipv4", "ipcidr"),
                           ("russia-direct-ipv6", "ipcidr")):
        payload = list(dict.fromkeys(
            line.strip() for line in (directory / f"{name}.txt").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ))
        if not payload:
            raise ValueError(f"Empty direct rule set: {name}")
        if behavior == "ipcidr":
            for cidr in payload:
                ipaddress.ip_network(cidr)
        providers[name] = {"type": "inline", "behavior": behavior, "payload": payload}
    return providers


def build_profile(nodes: list[dict], rule_providers: dict, repository: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Repository must be OWNER/REPO")
    raw = f"https://raw.githubusercontent.com/{repository}/main"
    health_check = {
        "enable": True, "url": TEST_URL, "interval": 30,
        "timeout": 5000, "lazy": False, "expected-status": "204",
    }
    return {
        "mode": "rule", "log-level": "warning", "allow-lan": False,
        "ipv6": True, "unified-delay": True, "tcp-concurrent": True,
        "profile": {"store-selected": True, "store-fake-ip": True},
        "dns": {
            "enable": True, "ipv6": True, "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": ["*.lan", "*.local", "+.home.arpa"],
            "default-nameserver": ["77.88.8.8", "1.1.1.1"],
            "proxy-server-nameserver": ["system"],
            "nameserver": ["https://1.1.1.1/dns-query#AUTO", "https://1.0.0.1/dns-query#AUTO"],
            "nameserver-policy": {
                "rule-set:russia-direct-domains": ["77.88.8.8", "77.88.8.1"],
                # Health checks must not depend on AUTO already being usable.
                "www.gstatic.com": ["system"],
                "raw.githubusercontent.com": ["system"],
            },
        },
        "proxy-providers": {
            "proxyplankton_sub_clash": {
                "type": "http", "url": f"{raw}/mihomo/providers/proxyplankton_sub_clash.yaml",
                "path": "./providers/proxyplankton_sub_clash.yaml", "interval": 300,
                "proxy": "PROXY", "payload": copy.deepcopy(nodes),
                "health-check": health_check,
            },
        },
        "proxy-groups": [{
            "name": "AUTO", "type": "url-test", "use": ["proxyplankton_sub_clash"],
            "url": TEST_URL, "interval": 30, "timeout": 5000,
            "tolerance": 200, "lazy": False, "max-failed-times": 2,
            "expected-status": "204", "empty-fallback": "REJECT",
        }, {
            "name": "PROXY", "type": "select", "proxies": ["AUTO"],
            "use": ["proxyplankton_sub_clash"], "empty-fallback": "REJECT",
        }],
        "rule-providers": copy.deepcopy(rule_providers),
        "rules": [
            "DOMAIN-SUFFIX,local,DIRECT", "DOMAIN-SUFFIX,lan,DIRECT",
            "DOMAIN-SUFFIX,home.arpa,DIRECT",
            "DOMAIN,raw.githubusercontent.com,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR6,::1/128,DIRECT,no-resolve",
            "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
            "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
            "RULE-SET,russia-direct-domains,DIRECT",
            "RULE-SET,russia-direct-ipv4,DIRECT,no-resolve",
            "RULE-SET,russia-direct-ipv6,DIRECT,no-resolve",
            "MATCH,PROXY",
        ],
    }


def yaml_document(value: dict, profile_url: str | None = None) -> str:
    header = "# Generated by scripts/build_mihomo.py. JSON-compatible YAML.\n"
    if profile_url:
        header = f"#SUBSCRIBED {profile_url}\n" + header
    return header + json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def build_outputs(text: str, rules: Path, repository: str,
                  excluded: dict[str, int] | None = None) -> dict[str, str]:
    nodes = read_subscription(text, excluded)
    return outputs_from_nodes(nodes, rules, repository)


def outputs_from_nodes(nodes: list[dict], rules: Path, repository: str) -> dict[str, str]:
    config = build_profile(nodes, read_rules(rules), repository)
    raw = f"https://raw.githubusercontent.com/{repository}/main"
    profile = yaml_document(config, f"{raw}/VPN_Mihomo_Auto.yaml")
    return {
        OUTPUT_PATHS[0]: profile,
        OUTPUT_PATHS[1]: profile,
        OUTPUT_PATHS[2]: yaml_document({"proxies": nodes}),
    }


def write_outputs(outputs: dict[str, str], destination: Path) -> None:
    # All parsing and rendering has finished before any live file is replaced.
    for relative, content in outputs.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=target.parent, prefix=".mihomo-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
            os.replace(name, target)
        finally:
            Path(name).unlink(missing_ok=True)


def download(url: str) -> str:
    if urlsplit(url).scheme != "https":
        raise ValueError("Source subscription must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "Mihomo-profile-builder/1.0",
                                                "Accept": "text/plain"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read(8 * 1024 * 1024).decode("utf-8")


def read_sources(sources: str, excluded: dict[str, int] | None = None) -> list[dict]:
    """Each line is an HTTPS subscription or one VLESS/HY2 connection."""
    records = list(dict.fromkeys(line.strip() for line in sources.splitlines() if line.strip()))
    if not records:
        raise ValueError("No subscription sources configured")
    groups = []
    for index, source in enumerate(records, 1):
        if source.lower().startswith("https://"):
            try:
                content = download(source)
            except Exception:
                raise ValueError(f"Cannot download subscription source {index}; keeping the previous profile") from None
        elif source.split(":", 1)[0].lower() in ALLOWED_SCHEMES and "://" in source:
            content = source
        else:
            raise ValueError(f"Invalid subscription source {index}; use HTTPS, VLESS or Hysteria2")
        groups.append(read_subscription(content, excluded))
    return merge_nodes(groups)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, help="Saved Base64/plain URI subscription")
    parser.add_argument("--rules-dir", type=Path, default=Path("stash/rules"))
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--repository", default="anthonyandreew/sub")
    args = parser.parse_args()
    source_inputs = "\n".join(os.environ.get(key, "") for key in
                              ("MIHOMO_SUBSCRIPTION_URL", "MIHOMO_ADDITIONAL_SOURCES"))
    private_urls = [line.strip() for line in source_inputs.splitlines() if line.strip().lower().startswith("https://")]
    try:
        excluded = {}
        if args.input:
            nodes = read_subscription(args.input.read_text(encoding="utf-8"), excluded)
        elif source_inputs.strip():
            nodes = read_sources(source_inputs, excluded)
        else:
            parser.error("Provide --input or MIHOMO_SUBSCRIPTION_URL")
        outputs = outputs_from_nodes(nodes, args.rules_dir, args.repository)
        if any(url in value for url in private_urls for value in outputs.values()):
            raise ValueError("Refusing to publish the private source subscription URL")
        write_outputs(outputs, args.output_dir)
    except Exception as exc:
        # Downloader exception strings may contain a private URL; redact it.
        message = str(exc)
        for source in source_inputs.splitlines():
            if source.strip():
                message = message.replace(source.strip(), "[subscription]")
        raise SystemExit(f"Build failed; previous files kept: {message}") from None
    if excluded:
        summary = ", ".join(f"{scheme}: {count}" for scheme, count in sorted(excluded.items()))
        print(f"Excluded connection types ({sum(excluded.values())}): {summary}; only VLESS/Hysteria2 are selected")
    print(f"Built {len(nodes)} connections and {len(outputs)} Mihomo files; source URL omitted")


if __name__ == "__main__":
    main()
