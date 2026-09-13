#!/usr/bin/env python3
"""Build a Stash proxy-provider YAML file from a Base64 URI subscription.

The input subscription URL is deliberately not stored in this repository. Use
--subscription-url locally or the STASH_SUBSCRIPTION_URL GitHub Actions secret.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


SUPPORTED_SCHEMES = {"hysteria2", "vless", "wg", "_wg"}


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
    proxy = {
        "name": name,
        "type": "hysteria2",
        "server": parts.hostname,
        "port": parts.port or 443,
        "auth": unquote(parts.username or ""),
    }
    for key in ("sni", "obfs", "obfs-password"):
        value = first(query, key)
        if value:
            proxy[key] = value
    alpn = first(query, "alpn")
    if alpn:
        proxy["alpn"] = [value for value in alpn.split(",") if value]
    return proxy


def parse_vless(parts, query, name):
    network = first(query, "type", "tcp") or "tcp"
    if network not in {"tcp", "ws", "h2", "http", "grpc", "xhttp"}:
        raise ValueError(f"unsupported VLESS transport {network!r}")
    proxy = {
        "name": name,
        "type": "vless",
        "server": parts.hostname,
        "port": parts.port or 443,
        "uuid": unquote(parts.username),
        "network": network,
    }
    encryption = first(query, "encryption")
    if encryption and encryption != "none":
        proxy["encryption"] = encryption
    flow = first(query, "flow")
    if flow:
        proxy["flow"] = flow
    security = first(query, "security")
    if security in {"tls", "reality"}:
        proxy["tls"] = True
    sni = first(query, "sni")
    if sni:
        proxy["sni"] = sni
    fingerprint = first(query, "fp")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    alpn = first(query, "alpn")
    if alpn:
        proxy["alpn"] = [value for value in alpn.split(",") if value]
    if security == "reality":
        reality = {}
        mapping = {"pbk": "public-key", "sid": "short-id", "spx": "spider-x"}
        for source, target in mapping.items():
            value = first(query, source)
            if value:
                reality[target] = value
        if not reality.get("public-key"):
            raise ValueError("Reality VLESS node is missing pbk")
        proxy["reality-opts"] = reality
    if network == "grpc":
        service_name = first(query, "serviceName")
        if service_name:
            proxy["grpc-opts"] = {"grpc-service-name": service_name}
    elif network == "ws":
        options = {}
        path = first(query, "path")
        host = first(query, "host")
        if path:
            options["path"] = path
        if host:
            options["headers"] = {"Host": host}
        if options:
            proxy["ws-opts"] = options
    elif network == "h2":
        options = {}
        path = first(query, "path")
        host = first(query, "host")
        if path:
            options["path"] = path
        if host:
            options["host"] = [host]
        if options:
            proxy["h2-opts"] = options
    elif network == "xhttp":
        options = {}
        for source, target in (("mode", "mode"), ("path", "path"), ("host", "host")):
            value = first(query, source)
            if value:
                options[target] = value
        if options:
            proxy["xhttp-opts"] = options
    return proxy


def parse_wireguard(parts, query, name):
    private_key = first(query, "privateKey")
    public_key = first(query, "publicKey")
    ip = first(query, "ip")
    if not (private_key and public_key and ip):
        raise ValueError("WireGuard node is missing privateKey, publicKey, or ip")
    proxy = {
        "name": name,
        "type": "wireguard",
        "server": parts.hostname,
        "port": parts.port or 51820,
        "ip": ip,
        "private-key": private_key,
        "public-key": public_key,
    }
    preshared_key = first(query, "presharedKey")
    if preshared_key:
        proxy["preshared-key"] = preshared_key
    dns = first(query, "dns")
    if dns:
        proxy["dns"] = [item.strip() for item in dns.split(",") if item.strip()]
    mtu = first(query, "mtu")
    if mtu.isdigit():
        proxy["mtu"] = int(mtu)
    return proxy


def normalize_uri(uri):
    # A few subscription generators emit @_wg:// instead of wg://.
    return uri.replace("@_wg://", "_wg://", 1)


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
        parts = urlsplit(normalize_uri(raw_uri))
        scheme = parts.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            skipped.append(f"{scheme or 'invalid'}: unsupported")
            continue
        try:
            query = parse_qs(parts.query, keep_blank_values=True)
            name = proxy_name(parts, query, names)
            if scheme == "hysteria2":
                proxy = parse_hysteria2(parts, query, name)
            elif scheme == "vless":
                proxy = parse_vless(parts, query, name)
            else:
                proxy = parse_wireguard(parts, query, name)
            if not parts.hostname:
                raise ValueError("missing server hostname")
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
    content = ["# Generated by scripts/build_stash_provider.py. Do not edit manually.", "proxies:"]
    content.extend(yaml_lines(proxies, 2))
    args.output.write_text("\n".join(content) + "\n", encoding="utf-8")
    print(f"Generated {len(proxies)} proxies in {args.output}")
    if skipped:
        print("Skipped entries:", file=sys.stderr)
        for item in skipped:
            print(f"  - {item}", file=sys.stderr)


if __name__ == "__main__":
    main()
