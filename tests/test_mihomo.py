"""Subscription replacement, format conversion, and safe publication checks."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_mihomo import build_outputs, read_subscription

GRPC = ("vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?"
        "type=grpc&security=tls&sni=example.com&serviceName=grpc&alpn=http%2F1.1#Primary")
HY2 = ("hysteria2://test-password@192.0.2.2:8443?"
       "sni=example.net&obfs=salamander&obfs-password=obfs-test#Backup")


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
        provider = document(new["mihomo/providers/subfam.yaml"])["proxies"]
        self.assertEqual([node["name"] for node in provider], ["Replacement"])
        profile = document(new["VPN_Mihomo_Auto.yaml"])
        self.assertEqual(profile["proxy-providers"]["subfam"]["payload"], provider)
        self.assertEqual(new["VPN_Mihomo_Auto.yaml"], new["clash_config_clashmi.yaml"])

    def test_unchanged_subscription_does_not_create_spurious_changes(self):
        self.assertEqual(self.build(GRPC + "\n" + HY2), self.build(GRPC + "\n" + HY2))

    def test_candidates_are_not_filtered_by_local_network(self):
        profile = document(self.build(GRPC + "\n" + HY2)["VPN_Mihomo_Auto.yaml"])
        self.assertEqual(len(profile["proxy-providers"]["subfam"]["payload"]), 2)
        self.assertEqual(profile["proxy-groups"][0]["empty-fallback"], "REJECT")
        self.assertEqual(profile["rules"][-1], "MATCH,AUTO")

    def test_provider_refresh_and_self_contained_rules(self):
        profile = document(self.build(GRPC)["VPN_Mihomo_Auto.yaml"])
        provider = profile["proxy-providers"]["subfam"]
        self.assertEqual(provider["url"], "https://raw.githubusercontent.com/owner/repo/main/mihomo/providers/subfam.yaml")
        self.assertEqual(provider["interval"], 300)
        self.assertTrue(provider["health-check"]["enable"])
        self.assertTrue(all(rule["type"] == "inline" for rule in profile["rule-providers"].values()))

    def test_happ_routing_metadata_does_not_create_a_proxy(self):
        self.assertEqual(read_subscription(GRPC + "\nhapp://routing/metadata"), read_subscription(GRPC))

    def test_unknown_protocol_fails_instead_of_publishing_partial_list(self):
        with self.assertRaises(ValueError):
            read_subscription(GRPC + "\ntuic://user:password@example.com:443#Unknown")

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


if __name__ == "__main__":
    unittest.main()
