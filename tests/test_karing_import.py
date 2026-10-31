"""Check lossless source preparation, not unverified Karing runtime behavior."""
import copy
import unittest

from test_mihomo import GRPC, xhttp
from build_mihomo import build_profile, read_subscription
from build_karing_test import flatten_profile, native_cdn


class KaringImportTests(unittest.TestCase):
    def test_native_preserves_required_session_padding_and_xmux(self):
        extra = {"mode": "packet-up", "sessionIDPlacement": "header", "sessionIDKey": "X-Auth-Token",
                 "sessionIDTable": "base36", "sessionIDLength": "8-12", "seqKey": "page",
                 "seqPlacement": "query", "uplinkChunkSize": "3000-4000", "uplinkHTTPMethod": "GET",
                 "uplinkDataPlacement": "header", "uplinkDataKey": "X-Data", "xPaddingBytes": "100-1000",
                 "xPaddingKey": "_rupl", "xPaddingHeader": "X-Cache", "xPaddingPlacement": "queryInHeader",
                 "xPaddingMethod": "tokenish", "xPaddingObfsMode": True,
                 "xmux": {"maxConcurrency": 0, "maxConnections": 1}}
        node = read_subscription(xhttp(extra))[0]
        original = copy.deepcopy(node)
        transport = native_cdn(node)["transport"]
        self.assertEqual(transport["session_key"], "X-Auth-Token")
        self.assertEqual(transport["session_placement"], "header")
        self.assertEqual((transport["session_id_table"], transport["session_id_length"]), ("base36", "8-12"))
        self.assertEqual(transport["x_padding_placement"], "queryInHeader")
        self.assertTrue(transport["x_padding_obfs_mode"])
        self.assertEqual(transport["xmux"], {"max_concurrency": "0", "max_connections": "1"})
        self.assertEqual(node, original)

    def test_flat_copy_has_all_nodes_but_preserves_paid_reserve_priority(self):
        normal, paid = read_subscription(GRPC), read_subscription(xhttp())
        source = build_profile(normal, {}, "owner/repo", paid)
        before = copy.deepcopy(source)
        flat = flatten_profile(source)
        groups = {g["name"]: g for g in flat["proxy-groups"]}
        self.assertEqual(groups["Proxy"]["proxies"], ["Auto Pre", "Primary"])
        self.assertEqual(groups["Auto Final"]["proxies"], ["Primary"])
        self.assertEqual(groups["Auto Pre"]["proxies"], ["Auto Final", "Primary", "CDN"])
        self.assertEqual(groups["Auto Pre"]["type"], "fallback")
        self.assertNotIn("proxy-providers", flat)
        self.assertEqual(len(flat["proxies"]), 2)
        self.assertEqual(source, before)

    def test_unknown_transport_fields_do_not_silently_disappear(self):
        node = read_subscription(xhttp())[0]
        node["xhttp-opts"]["unknown-option"] = "required"
        with self.assertRaisesRegex(ValueError, "Unmapped XHTTP"):
            native_cdn(node)
