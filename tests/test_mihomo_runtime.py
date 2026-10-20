"""Exercise real provider replacement and offline bootstrap with a local HTTP source."""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_mihomo import GRPC, HY2
from build_mihomo import build_profile, read_subscription


@unittest.skipUnless(os.environ.get("MIHOMO_BINARY"), "Set MIHOMO_BINARY for real-core integration tests")
class RuntimeTests(unittest.TestCase):
    def test_hot_replacement_failed_refresh_and_offline_bootstrap(self):
        original = read_subscription(GRPC)
        replacement = read_subscription(HY2)
        current = {"body": json.dumps({"proxies": original}).encode()}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(current["body"])

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        profile = build_profile(original, {}, "owner/repo")
        profile["rule-providers"] = {}
        profile["rules"] = ["MATCH,AUTO"]
        profile["dns"] = {"enable": False}
        profile["proxy-providers"]["subfam"]["url"] = f"http://127.0.0.1:{server.server_port}/provider"
        profile["proxy-providers"]["subfam"]["proxy"] = "DIRECT"
        # Membership tests do not probe the documentation-only test IP addresses.
        profile["proxy-providers"]["subfam"]["health-check"]["enable"] = False
        profile["proxy-groups"][0]["lazy"] = True

        def run_core(config, check):
            with tempfile.TemporaryDirectory() as directory:
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0))
                    port = probe.getsockname()[1]
                secret = secrets.token_hex(24)
                config = dict(config, **{"external-controller": f"127.0.0.1:{port}", "secret": secret})
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(config))

                def api(path, method="GET"):
                    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                                     headers={"Authorization": f"Bearer {secret}"})
                    with urllib.request.urlopen(request, timeout=10) as response:
                        body = response.read()
                        return json.loads(body) if body else {}

                with (Path(directory) / "core.log").open("w") as log:
                    process = subprocess.Popen([os.environ["MIHOMO_BINARY"], "-d", directory, "-f", str(path)],
                                               stdout=log, stderr=log)
                    try:
                        for _ in range(100):
                            try:
                                # The controller starts before configuration and
                                # provider registration finish. /version alone
                                # can be ready while provider PUT still returns 404.
                                api("/providers/proxies/subfam")
                                break
                            except (OSError, urllib.error.URLError):
                                if process.poll() is not None:
                                    self.fail("Mihomo stopped before its API became ready")
                                time.sleep(.05)
                        else:
                            self.fail("Mihomo API did not start")
                        check(api)
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()

        def names(api):
            return [node["name"] for node in api("/providers/proxies/subfam")["proxies"]]

        def replacement_check(api):
            api("/providers/proxies/subfam", "PUT")
            self.assertEqual(names(api), ["Primary"])
            current["body"] = json.dumps({"proxies": replacement}).encode()
            api("/providers/proxies/subfam", "PUT")
            self.assertEqual(names(api), ["Backup"])
            self.assertEqual(api("/proxies/AUTO")["all"], ["Backup"])
            current["body"] = b"<!doctype html><html>Unavailable</html>"
            with self.assertRaises(urllib.error.HTTPError):
                api("/providers/proxies/subfam", "PUT")
            self.assertEqual(names(api), ["Backup"])

        run_core(profile, replacement_check)
        profile["proxy-providers"]["subfam"]["url"] = "http://127.0.0.1:9/unavailable"

        def offline_check(api):
            self.assertEqual(names(api), ["Primary"])
            self.assertEqual(api("/proxies/AUTO")["all"], ["Primary"])

        run_core(profile, offline_check)

    def test_provider_bootstraps_through_embedded_proxy_and_preserves_manual_selection(self):
        requests = []
        body = {}

        class Handler(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                requests.append("CONNECT " + self.path)
                self.send_response(200)
                self.end_headers()
                self.close_connection = False
                self.handle_one_request()

            def do_GET(self):
                # CONNECT to the unresolvable origin proves the embedded HTTP
                # proxy is used; this fixture supplies the tunnel's response.
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        node = {"name": "Bootstrap", "type": "http", "server": "127.0.0.1", "port": server.server_port}
        second = dict(node, name="Second")
        body["proxies"] = [node, second]
        config = build_profile([node, second], {}, "owner/repo")
        config["rules"] = ["MATCH,PROXY"]
        provider = config["proxy-providers"]["subfam"]
        provider["url"] = "http://subscription.invalid/provider"
        provider["health-check"]["enable"] = False
        config["proxy-groups"][0]["lazy"] = True
        config["dns"] = {"enable": False}
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            secret = secrets.token_hex(24)
            config.update({"external-controller": f"127.0.0.1:{port}", "secret": secret})
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config))

            def api(endpoint, method="GET", data=None):
                request = urllib.request.Request(f"http://127.0.0.1:{port}{endpoint}", method=method,
                    data=json.dumps(data).encode() if data is not None else None,
                    headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"})
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request, timeout=10) as response:
                    content = response.read()
                    return json.loads(content) if content else {}

            with (Path(directory) / "core.log").open("w") as log:
                process = subprocess.Popen([os.environ["MIHOMO_BINARY"], "-d", directory, "-f", str(path)],
                                           stdout=log, stderr=log)
                try:
                    for _ in range(100):
                        try:
                            api("/providers/proxies/subfam")
                            break
                        except OSError:
                            if process.poll() is not None:
                                self.fail("Mihomo stopped before its API became ready")
                            time.sleep(.05)
                    else:
                        self.fail("Mihomo provider did not become ready")
                    api("/providers/proxies/subfam", "PUT")
                    self.assertTrue(any(url == "CONNECT subscription.invalid:80" for url in requests))
                    api("/proxies/PROXY", "PUT", {"name": "Second"})
                    body["proxies"] = [second]
                    api("/providers/proxies/subfam", "PUT")
                    self.assertEqual(api("/proxies/PROXY")["now"], "Second")
                    self.assertEqual(api("/proxies/AUTO")["all"], ["Second"])
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
