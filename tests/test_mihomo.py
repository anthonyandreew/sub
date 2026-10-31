"""Subscription replacement, format conversion, and safe publication checks."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_mihomo import build_outputs, read_sources, read_subscription

GRPC = ("vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?"
        "type=grpc&security=tls&sni=example.com&serviceName=grpc&alpn=http%2F1.1#Primary")
HY2 = ("hysteria2://test-password@192.0.2.2:8443?"
       "sni=example.net&obfs=salamander&obfs-password=obfs-test#Backup")
XHTTP_EXTRA = {
    "mode": "packet-up", "uplinkHTTPMethod": "GET", "uplinkDataPlacement": "header",
    "uplinkDataKey": "X-Data", "uplinkChunkSize": 2048, "scMaxEachPostBytes": 32768,
    "scMinPostsIntervalMs": 10, "serverMaxHeaderBytes": 65536,
    "xmux": {"maxConcurrency": 0, "maxConnections": 1},
}


def xhttp(extra=XHTTP_EXTRA, name="CDN"):
    query = {"type": "xhttp", "security": "tls", "sni": "cdn.example.com", "fp": "firefox",
             "host": "cdn.example.com", "path": "/assets/config.json", "mode": "packet-up", "alpn": "h2",
             "extra": json.dumps(extra)}
    return "vless://22222222-2222-4222-8222-222222222222@cdn.example.com:443?" + urlencode(query) + "#" + name


def document(text):
    return json.loads("\n".join(line for line in text.splitlines() if not line.startswith("#")))


class MihomoTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.rules = Path(self.directory.name) / "rules"
        self.rules.mkdir()
        for suffix, payload in (("domains", "+.example.ru\n"),
                                ("ipv4", "192.0.2.0/24\n"), ("ipv6", "2001:db8::/32\n")):
            (self.rules / f"russia-direct-{suffix}.txt").write_text(payload)

    def build(self, text):
        return build_outputs(text, self.rules, "owner/repo")

    def test_base64_and_plain_subscription_are_equivalent(self):
        text = GRPC + "\n" + HY2
        encoded = base64.b64encode(text.encode()).decode().rstrip("=")
        self.assertEqual(self.build(text), self.build(encoded))

    def test_native_mihomo_fields_and_grpc_http2(self):
        grpc, hy2 = read_subscription(GRPC + "\n" + HY2)
        self.assertEqual(grpc["servername"], "example.com")
        self.assertNotIn("sni", grpc)
        self.assertEqual(grpc["alpn"], ["h2"])
        self.assertEqual(grpc["grpc-opts"]["grpc-service-name"], "grpc")
        self.assertEqual(hy2["password"], "test-password")
        self.assertNotIn("auth", hy2)

    def test_refresh_replaces_membership_and_embedded_fallback(self):
        old = self.build(GRPC + "\n" + HY2)
        replacement = HY2.replace("192.0.2.2", "192.0.2.3").replace("#Backup", "#Replacement")
        new = self.build(replacement)
        self.assertNotEqual(old, new)
        provider = document(new["mihomo/providers/proxyplankton_sub_clash.yaml"])["proxies"]
        self.assertEqual([node["name"] for node in provider], ["Replacement"])
        profile = document(new["VPN_Mihomo_Auto.yaml"])
        self.assertEqual(profile["proxy-providers"]["proxyplankton_sub_clash"]["payload"], provider)
        self.assertEqual(set(new), {"VPN_Mihomo_Auto.yaml", "mihomo/providers/proxyplankton_sub_clash.yaml"})

    def test_unchanged_subscription_does_not_create_spurious_changes(self):
        self.assertEqual(self.build(GRPC + "\n" + HY2), self.build(GRPC + "\n" + HY2))

    def test_candidates_are_not_filtered_by_local_network(self):
        profile = document(self.build(GRPC + "\n" + HY2)["VPN_Mihomo_Auto.yaml"])
        self.assertEqual(len(profile["proxy-providers"]["proxyplankton_sub_clash"]["payload"]), 2)
        self.assertEqual(profile["proxy-groups"][0]["empty-fallback"], "REJECT")
        self.assertEqual(profile["rules"][-1], "MATCH,PROXY")
        manual = profile["proxy-groups"][1]
        self.assertEqual((manual["name"], manual["type"], manual["proxies"], manual["use"]),
                         ("PROXY", "select", ["AUTO"], ["proxyplankton_sub_clash"]))

    def test_provider_refresh_and_self_contained_rules(self):
        profile = document(self.build(GRPC)["VPN_Mihomo_Auto.yaml"])
        provider = profile["proxy-providers"]["proxyplankton_sub_clash"]
        self.assertEqual(provider["url"], "https://raw.githubusercontent.com/owner/repo/main/mihomo/providers/proxyplankton_sub_clash.yaml")
        self.assertEqual(provider["interval"], 3600)
        self.assertTrue(provider["health-check"]["enable"])
        self.assertEqual(provider["proxy"], "PROXY")
        self.assertTrue(all(rule["type"] == "inline" for rule in profile["rule-providers"].values()))

    def test_happ_routing_metadata_does_not_create_a_proxy(self):
        self.assertEqual(read_subscription(GRPC + "\nhapp://routing/metadata"), read_subscription(GRPC))

    def test_mixed_subscription_selects_only_vless_and_hysteria2(self):
        excluded = {}
        extra = ["@_wg://example.com?privateKey=redacted", "amneziawg://example.com",
                 "mierus://user:password@example.com?port=9001", "vpn://encoded",
                 "wg://example.com", "tuic://user:password@example.com:443#Unknown",
                 "happ://routing/metadata"]
        nodes = read_subscription(GRPC + "\n" + HY2 + "\n" + "\n".join(extra), excluded)
        self.assertEqual([node["type"] for node in nodes], ["vless", "hysteria2"])
        self.assertEqual(excluded, {"amneziawg": 2, "mierus": 1, "vpn": 1, "wg": 1, "tuic": 1})

    def test_only_excluded_types_do_not_replace_last_good_profile(self):
        with self.assertRaisesRegex(ValueError, "No VLESS/Hysteria2"):
            read_subscription("amneziawg://example.com\nvpn://encoded")

    def test_bad_selected_connection_is_not_silently_removed(self):
        with self.assertRaises(ValueError):
            read_subscription(GRPC + "\nvless://user@#broken")

    def test_malformed_non_uri_record_is_not_silently_removed(self):
        with self.assertRaises(ValueError):
            read_subscription(GRPC + "\ntruncated subscription response")

    def test_hy2_alias_and_case_insensitive_schemes(self):
        nodes = read_subscription(GRPC.replace("vless://", "VLESS://") + "\n" + HY2.replace("hysteria2://", "HY2://"))
        self.assertEqual([node["type"] for node in nodes], ["vless", "hysteria2"])

    def test_bad_response_does_not_overwrite_last_good_profile(self):
        root = Path(self.directory.name)
        bad = root / "subscription.txt"
        bad.write_text("<!doctype html><html>Unavailable</html>")
        target = root / "VPN_Mihomo_Auto.yaml"
        target.write_text("last good configuration")
        result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/build_mihomo.py"),
                                 "--input", str(bad), "--rules-dir", str(self.rules), "--output-dir", str(root)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), "last good configuration")

    def test_empty_and_invalid_responses_are_rejected(self):
        for text in ("", "not a subscription", "<html>Error</html>",
                     base64.b64encode(b"https://example.com/error").decode()):
            with self.subTest(text=text), self.assertRaises(ValueError):
                read_subscription(text)

    def test_complete_cdn_extra_translation(self):
        node = read_subscription(xhttp())[0]
        self.assertEqual(node["client-fingerprint"], "firefox")
        self.assertEqual(node["alpn"], ["h2"])
        self.assertEqual(node["xhttp-opts"], {
            "host": "cdn.example.com", "path": "/assets/config.json", "mode": "packet-up",
            "uplink-http-method": "GET", "uplink-data-placement": "header", "uplink-data-key": "X-Data",
            "uplink-chunk-size": "2048", "sc-max-each-post-bytes": "32768", "sc-min-posts-interval-ms": "10",
            "reuse-settings": {"max-concurrency": "0", "max-connections": "1"},
        })
        self.assertNotIn("serverMaxHeaderBytes", json.dumps(node))

    def test_xhttp_without_extra_is_preserved(self):
        uri = "vless://22222222-2222-4222-8222-222222222222@cdn.example.com:443?type=xhttp&mode=auto&path=%2Ftest#CDN"
        self.assertEqual(read_subscription(uri)[0]["xhttp-opts"], {"mode": "auto", "path": "/test"})

    def test_cdn_session_aliases_and_padding_obfuscation(self):
        # Modern x-ui emits both sessionID* names and their legacy aliases.
        extra = {
            "mode": "packet-up", "seqKey": "page", "seqPlacement": "query",
            "sessionIDKey": "X-Auth-Token", "sessionKey": "X-Auth-Token",
            "sessionIDPlacement": "header", "sessionPlacement": "header",
            "sessionIDLength": "8-12", "sessionIDTable": "base36",
            "uplinkHTTPMethod": "GET", "uplinkDataKey": "X-Data",
            "uplinkDataPlacement": "header", "uplinkChunkSize": "3000-4000",
            "xPaddingBytes": "100-1000", "xPaddingHeader": "X-Cache",
            "xPaddingKey": "_padding", "xPaddingMethod": "tokenish",
            "xPaddingObfsMode": True, "xPaddingPlacement": "queryInHeader",
            "xmux": {"maxConcurrency": 0, "maxConnections": 1},
        }
        options = read_subscription(xhttp(extra))[0]["xhttp-opts"]
        self.assertEqual(options, {
            "host": "cdn.example.com", "path": "/assets/config.json", "mode": "packet-up",
            "seq-key": "page", "seq-placement": "query", "session-key": "X-Auth-Token",
            "session-placement": "header", "session-length": "8-12", "session-table": "base36",
            "uplink-http-method": "GET", "uplink-data-key": "X-Data",
            "uplink-data-placement": "header", "uplink-chunk-size": "3000-4000",
            "x-padding-bytes": "100-1000", "x-padding-header": "X-Cache",
            "x-padding-key": "_padding", "x-padding-method": "tokenish",
            "x-padding-obfs-mode": True, "x-padding-placement": "queryInHeader",
            "reuse-settings": {"max-concurrency": "0", "max-connections": "1"},
        })
        # New-only and legacy-only session names must describe the same transport.
        for removed in (("sessionKey", "sessionPlacement"), ("sessionIDKey", "sessionIDPlacement")):
            with self.subTest(removed=removed):
                self.assertEqual(read_subscription(xhttp({k: v for k, v in extra.items() if k not in removed}))[0]["xhttp-opts"], options)
        for change in ({"sessionKey": "different"}, {"sessionPlacement": "cookie"},
                       {"sessionIDLength": True}, {"sessionIDTable": []},
                       {"xPaddingObfsMode": "true"}, {"xPaddingPlacement": []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                read_subscription(xhttp(dict(extra, **change)))

    def test_xhttp_padding_bytes_is_preserved_for_xui_subscriptions(self):
        for value in (100, "100-1000"):
            with self.subTest(value=value):
                uri = xhttp({"mode": "auto", "xPaddingBytes": value}).replace("mode=packet-up", "mode=auto")
                node = read_subscription(uri)[0]
                self.assertEqual(node["xhttp-opts"]["mode"], "auto")
                self.assertEqual(node["xhttp-opts"]["x-padding-bytes"], str(value))

    def test_invalid_or_unsupported_extra_stops_the_build(self):
        for extra in [None, [], {"unknownField": 1}, {"xmux": []}, {"xmux": {"unknown": 1}},
                      {"uplinkChunkSize": True}, {"scMinPostsIntervalMs": -1}, {"uplinkHTTPMethod": []},
                      {"mode": "stream-up"}, {"xPaddingBytes": True}, {"xPaddingBytes": []},
                      {"xPaddingBytes": "invalid"}]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                read_subscription(xhttp(extra))
        with self.assertRaises(ValueError):
            read_subscription(xhttp().replace("extra=", "extra=%7Bbroken"))

    def test_multiple_https_and_inline_sources_share_the_converter(self):
        bodies = {"https://one.example/sub/private": base64.b64encode((GRPC + "\n" + xhttp()).encode()).decode(),
                  "https://two.example/sub/private": HY2 + "\n" + xhttp(name="Same-node-other-label")}
        with patch("build_mihomo.download", side_effect=bodies.__getitem__) as download:
            nodes = read_sources("\n".join([*bodies, xhttp(), *bodies, ""]))
        self.assertEqual(download.call_count, 2)
        self.assertEqual([node["name"] for node in nodes], ["Primary", "CDN", "Backup"])

    def test_different_nodes_with_equal_names_and_reserved_names(self):
        nodes = read_sources("\n".join([GRPC, HY2.replace("#Backup", "#Primary"), xhttp(name="AUTO")]))
        self.assertEqual([node["name"] for node in nodes], ["Primary", "Primary (2)", "AUTO (2)"])

    def test_a_failed_source_does_not_publish_a_partial_list(self):
        private = "https://one.example/sub/secret-token"
        with patch("build_mihomo.download", side_effect=OSError(private)), self.assertRaises(ValueError) as error:
            read_sources(GRPC + "\n" + private)
        self.assertNotIn(private, str(error.exception))
        with patch("build_mihomo.download", return_value="<html>Unavailable</html>"), self.assertRaises(ValueError):
            read_sources(GRPC + "\n" + private)
        with self.assertRaises(ValueError):
            read_sources(GRPC + "\nhttp://insecure.example/sub")


if __name__ == "__main__":
    unittest.main()
