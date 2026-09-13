#!/usr/bin/env python3
"""Build a Stash proxy-provider YAML file from a URI subscription."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SUPPORTED_SCHEMES = {"hysteria2", "vless", "wg"}
AMNEZIA_WG_FIELDS = {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}


def scalar(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def yaml_lines(value, indent=0):
    pad = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield f"{pad}{key}:"
                yield from yaml_lines(item, indent + 2)
            else:
                yield f"{pad}{key}: {scalar(item)}"
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                first = True
                for key, child in item.items():
                    if first:
                        if isinstance(child, (dict, list)):
                            yield f"{pad}- {key}:"
                            yield from yaml_lines(child, indent + 4)
                        else:
                            yield f"{pad}- {key}: {scalar(child)}"
                        first = False
                    elif isinstance(child, (dict, list)):
                        yield f"{pad}  {key}:"
                        yield from yaml_lines(child, indent + 4)
                    else:
                        yield f"{pad}  {key}: {scalar(child)}"
            elif isinstance(item, list):
                yield f"{pad}-"
                yield from yaml_lines(item, indent + 2)
            else:
                yield f"{pad}- {scalar(item)}"


def first(query, key, default=""):
    return query.get(key, [default])[0]


def proxy_name(parts, query, used_names):
    name = unquote(parts.fragment) or first(query, "remarks") or first(query, "flag")
    name = name.strip() or f"{parts.scheme}-{parts.hostname or 'node'}"
    original = name
    number = 2
    while name in used_names:
        name = f"{original} ({number})"
        number += 1
    used_names.add(name)
    return name


def parse_hysteria2(parts, query, name):
    proxy = {"name": name, "type": "hysteria2", "server": parts.hostname,
             "port": parts.port or 443, "auth": unquote(parts.username or "")}
    for key in ("sni", "obfs", "obfs-password"):
        if first(query, key):
            proxy[key] = first(query, key)
    if first(query, "alpn"):
        proxy["alpn"] = [x for x in first(query, "alpn").split(",") if x]
    return proxy


def parse_vless(parts, query, name):
    network = first(query, "type", "tcp") or "tcp"
    if network not in {"tcp", "ws", "h2", "http", "grpc", "xhttp"}:
        raise ValueError(f"unsupported VLESS transport {network!r}")
    proxy = {"name": name, "type": "vless", "server": parts.hostname,
             "port": parts.port or 443, "uuid": unquote(parts.username), "network": network}
    if first(query, "encryption") not in {"", "none"}:
        proxy["encryption"] = first(query, "encryption")
    if first(query, "flow"):
        proxy["flow"] = first(query, "flow")
    security = first(query, "security")
    if security in {"tls", "reality"}:
        proxy["tls"] = True
    if first(query, "sni"):
        proxy["sni"] = first(query, "sni")
    if first(query, "fp"):
        proxy["client-fingerprint"] = first(query, "fp")
    if first(query, "alpn"):
        proxy["alpn"] = [x for x in first(query, "alpn").split(",") if x]
    if security == "reality":
        reality = {target: first(query, source) for source, target in
                   {"pbk": "public-key", "sid": "short-id", "spx": "spider-x"}.items()
                   if first(query, source)}
        if not reality.get("public-key"):
            raise ValueError("Reality VLESS node is missing pbk")
        proxy["reality-opts"] = reality
    if network == "grpc" and first(query, "serviceName"):
        proxy["grpc-opts"] = {"grpc-service-name": first(query, "serviceName")}
    elif network == "ws":
        options = {}
        if first(query, "path"):
            options["path"] = first(query, "path")
        if first(query, "host"):
            options["headers"] = {"Host": first(query, "host")}
        if options:
            proxy["ws-opts"] = options
    elif network == "h2":
        options = {}
        if first(query, "path"):
            options["path"] = first(query, "path")
        if first(query, "host"):
            options["host"] = [first(query, "host")]
        if options:
            proxy["h2-opts"] = options
    elif network == "xhttp":
        options = {target: first(query, source) for source, target in
                   (("mode", "mode"), ("path", "path"), ("host", "host")) if first(query, source)}
        if options:
            proxy["xhttp-opts"] = options
    return proxy


def parse_wireguard(parts, query, name):
    private_key, public_key, ip = first(query, "privateKey"), first(query, "publicKey"), first(query, "ip")
    if not (private_key and public_key and ip):
        raise ValueError("WireGuard node is missing privateKey, publicKey, or ip")
    proxy = {"name": name, "type": "wireguard", "server": parts.hostname,
             "port": parts.port or 51820, "ip": ip, "private-key": private_key, "public-key": public_key}
    if first(query, "presharedKey"):
        proxy["preshared-key"] = first(query, "presharedKey")
    if first(query, "dns"):
        proxy["dns"] = [x.strip() for x in first(query, "dns").split(",") if x.strip()]
    if first(query, "mtu").isdigit():
        proxy["mtu"] = int(first(query, "mtu"))
    return proxy


def is_amnezia_wireguard(scheme, query, name):
    return scheme == "wg" and (bool(AMNEZIA_WG_FIELDS.intersection(query)) or
                               any(x in name.lower() for x in ("amnezia", "amneziawg", "awg")))


def parse_subscription(text):
    normalized = "".join(text.split())
    try:
        decoded = base64.b64decode(normalized + "=" * (-len(normalized) % 4)).decode("utf-8")
    except Exception:
        decoded = text
    proxies, skipped, names = [], [], set()
    for raw_uri in decoded.splitlines():
        raw_uri = raw_uri.strip()
        if not raw_uri:
            continue
        parts = urlsplit(raw_uri.replace("@_wg://", "amneziawg://", 1))
        scheme = parts.scheme.lower()
        if scheme == "amneziawg":
            skipped.append("amneziawg: not supported by Stash")
            continue
        if scheme not in SUPPORTED_SCHEMES:
            skipped.append(f"{scheme or 'invalid'}: unsupported")
            continue
        try:
            query = parse_qs(parts.query, keep_blank_values=True)
            name = proxy_name(parts, query, names)
            if is_amnezia_wireguard(scheme, query, name):
                skipped.append(f"{scheme}: AmneziaWG is not supported by Stash")
                continue
            if not parts.hostname:
                raise ValueError("missing server hostname")
            proxy = parse_hysteria2(parts, query, name) if scheme == "hysteria2" else \
                    parse_vless(parts, query, name) if scheme == "vless" else parse_wireguard(parts, query, name)
            proxies.append(proxy)
        except (TypeError, ValueError) as exc:
            skipped.append(f"{scheme}: {exc}")
    return proxies, skipped


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Stash-config-updater/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--subscription-url")
    source.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = download(args.subscription_url) if args.subscription_url else args.input.read_text(encoding="utf-8")
    proxies, skipped = parse_subscription(text)
    if not proxies:
        raise SystemExit("No Stash-compatible proxies were parsed; refusing to overwrite provider.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(["# Generated by scripts/build_stash_provider.py. Do not edit manually.", "proxies:", *yaml_lines(proxies, 2)]) + "\n", encoding="utf-8")
    print(f"Generated {len(proxies)} proxies in {args.output}")
    if skipped:
        print("Skipped entries:", file=sys.stderr)
        for item in skipped:
            print(f"  - {item}", file=sys.stderr)


if __name__ == "__main__":
    main()
