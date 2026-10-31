#!/usr/bin/env python3
"""Prepare experimental Karing imports from the published Mihomo snapshot.

Does not contact subscription sources or change Mihomo output. These are import
candidates, not a claim that Karing preserves every field or routing group.
"""
import copy
import json
from pathlib import Path

XHTTP_FIELDS = {
    "mode": "mode", "host": "host", "path": "path",
    "uplink-http-method": "uplink_http_method",
    "uplink-data-placement": "uplink_data_placement",
    "uplink-data-key": "uplink_data_key", "uplink-chunk-size": "uplink_chunk_size",
    "session-placement": "session_placement", "session-key": "session_key",
    "session-table": "session_id_table", "session-length": "session_id_length",
    "seq-placement": "seq_placement", "seq-key": "seq_key",
    "x-padding-key": "x_padding_key", "x-padding-header": "x_padding_header",
    "x-padding-placement": "x_padding_placement", "x-padding-method": "x_padding_method",
    "x-padding-obfs-mode": "x_padding_obfs_mode", "x-padding-bytes": "x_padding_bytes",
    "sc-max-each-post-bytes": "sc_max_each_post_bytes",
    "sc-min-posts-interval-ms": "sc_min_posts_interval_ms",
}
XMUX_FIELDS = {
    "max-concurrency": "max_concurrency", "max-connections": "max_connections",
    "c-max-reuse-times": "c_max_reuse_times", "h-max-request-times": "h_max_request_times",
    "h-max-reusable-secs": "h_max_reusable_secs", "h-keep-alive-period": "h_keep_alive_period",
}


def read_document(path):
    return json.loads("\n".join(line for line in path.read_text().splitlines()
                                if not line.startswith("#")))


def native_cdn(node):
    if node["type"] != "vless" or node.get("network") != "xhttp" or not node.get("tls"):
        raise ValueError("The Karing test requires VLESS/XHTTP with TLS")
    options = node["xhttp-opts"]
    if set(options) - set(XHTTP_FIELDS) - {"reuse-settings"}:
        raise ValueError("Unmapped XHTTP fields; refusing a partial conversion")
    transport = {"type": "xhttp", **{dst: copy.deepcopy(options[src])
                 for src, dst in XHTTP_FIELDS.items() if src in options}}
    reuse = options.get("reuse-settings", {})
    if set(reuse) - set(XMUX_FIELDS):
        raise ValueError("Unmapped XMUX fields; refusing a partial conversion")
    if reuse:
        transport["xmux"] = {XMUX_FIELDS[k]: copy.deepcopy(v) for k, v in reuse.items()}
    tls = {"enabled": True, "server_name": node.get("servername") or node["server"],
           "insecure": node.get("skip-cert-verify", False), "alpn": node.get("alpn") or ["h2"]}
    if node.get("client-fingerprint"):
        tls["utls"] = {"enabled": True, "fingerprint": node["client-fingerprint"]}
    return {"type": "vless", "tag": node["name"], "server": node["server"],
            "server_port": node["port"], "uuid": node["uuid"], "packet_encoding": "xudp",
            "tls": tls, "transport": transport}


def flatten_profile(profile):
    """Expose provider payloads as static proxies for importers without payload support."""
    config = copy.deepcopy(profile)
    providers = config.pop("proxy-providers")
    config["proxies"] = [copy.deepcopy(node) for p in providers.values() for node in p["payload"]]
    for group in config["proxy-groups"]:
        members = list(group.get("proxies", []))
        for provider in group.pop("use", []):
            members.extend(node["name"] for node in providers[provider]["payload"])
        group["proxies"] = list(dict.fromkeys(members))
    return config


def clash_yaml_document(config, url):
    """Emit block YAML: a JSON object may be misidentified as sing-box on import."""
    def scalar(value):
        return json.dumps(value, ensure_ascii=False)

    def block(value, indent=0):
        padding = " " * indent
        lines = []
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, (dict, list)) and item:
                    lines.append(f"{padding}{scalar(key)}:")
                    lines.extend(block(item, indent + 2))
                else:
                    lines.append(f"{padding}{scalar(key)}: {scalar(item)}")
        else:
            for item in value:
                if isinstance(item, (dict, list)) and item:
                    lines.append(f"{padding}-")
                    lines.extend(block(item, indent + 2))
                else:
                    lines.append(f"{padding}- {scalar(item)}")
        return lines

    # Start with the Clash server list, rather than an ambiguous JSON object.
    nodes = block(config["proxies"], 2)
    rest = block({k: v for k, v in config.items() if k != "proxies"})
    return "\n".join([f"#SUBSCRIBED {url}", "# Experimental Karing Clash import.",
                       "proxies:", *nodes, *rest]) + "\n"


def main():
    root = Path(__file__).resolve().parents[1]
    profile = read_document(root / "VPN_Mihomo_Auto.yaml")
    reserve = profile["proxy-providers"]["proxyplankton_whitelist"]["payload"]
    if len(reserve) != 1:
        raise ValueError("The single-node Karing test expects exactly one CDN node")
    path = root / "karing_finland_wl_config.json"
    config = json.loads(path.read_text())
    outbound = native_cdn(reserve[0])
    config["outbounds"] = [outbound, {"type": "direct", "tag": "direct"}]
    config["route"]["final"] = outbound["tag"]
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
    url = "https://raw.githubusercontent.com/anthonyandreew/sub/refs/heads/main/VPN_Karing_Auto_Test.yaml"
    flat = flatten_profile(profile)
    (root / "VPN_Karing_Auto_Test.yaml").write_text(clash_yaml_document(flat, url))
    print(f"Prepared Karing import candidates: one native CDN node and {len(flat['proxies'])} Clash nodes")


if __name__ == "__main__":
    main()
