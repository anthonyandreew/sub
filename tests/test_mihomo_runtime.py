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
        profile["proxy-providers"]["proxyplankton_sub_clash"]["url"] = f"http://127.0.0.1:{server.server_port}/provider"
        profile["proxy-providers"]["proxyplankton_sub_clash"]["proxy"] = "DIRECT"
        # Membership tests do not probe the documentation-only test IP addresses.
        profile["proxy-providers"]["proxyplankton_sub_clash"]["health-check"]["enable"] = False
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
                                api("/providers/proxies/proxyplankton_sub_clash")
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
            return [node["name"] for node in api("/providers/proxies/proxyplankton_sub_clash")["proxies"]]

        def replacement_check(api):
            api("/providers/proxies/proxyplankton_sub_clash", "PUT")
            self.assertEqual(names(api), ["Primary"])
            current["body"] = json.dumps({"proxies": replacement}).encode()
            api("/providers/proxies/proxyplankton_sub_clash", "PUT")
            self.assertEqual(names(api), ["Backup"])
            self.assertEqual(api("/proxies/AUTO")["all"], ["Backup"])
            current["body"] = b"<!doctype html><html>Unavailable</html>"
            with self.assertRaises(urllib.error.HTTPError):
                api("/providers/proxies/proxyplankton_sub_clash", "PUT")
            self.assertEqual(names(api), ["Backup"])

        run_core(profile, replacement_check)
        profile["proxy-providers"]["proxyplankton_sub_clash"]["url"] = "http://127.0.0.1:9/unavailable"

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
        provider = config["proxy-providers"]["proxyplankton_sub_clash"]
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
                            api("/providers/proxies/proxyplankton_sub_clash")
                            break
                        except OSError:
                            if process.poll() is not None:
                                self.fail("Mihomo stopped before its API became ready")
                            time.sleep(.05)
                    else:
                        self.fail("Mihomo provider did not become ready")
                    api("/providers/proxies/proxyplankton_sub_clash", "PUT")
                    self.assertTrue(any(url == "CONNECT subscription.invalid:80" for url in requests))
                    api("/proxies/PROXY", "PUT", {"name": "Second"})
                    body["proxies"] = [second]
                    api("/providers/proxies/proxyplankton_sub_clash", "PUT")
                    self.assertEqual(api("/proxies/PROXY")["now"], "Second")
                    self.assertEqual(api("/proxies/AUTO")["all"], ["Second"])
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

    def test_paid_reserve_priority_failover_and_recovery(self):
        # Real HTTP tunnels distinguish health probes from application traffic.
        states = [{"alive": True, "traffic": 0, "delay": .08},
                  {"alive": True, "traffic": 0, "delay": .12},
                  {"alive": True, "traffic": 0, "delay": 0}]
        nodes = []
        for index, state in enumerate(states):
            def handler_for(state, index):
                class Handler(BaseHTTPRequestHandler):
                    def do_CONNECT(self):
                        self.send_response(200)
                        self.end_headers()
                        self.close_connection = False
                        self.handle_one_request()

                    def do_GET(self):
                        if "health" in self.path:
                            time.sleep(state["delay"])
                            if not state["alive"]:
                                self.close_connection = True
                                return
                            self.send_response(204)
                            self.end_headers()
                        else:
                            state["traffic"] += 1
                            data = str(index).encode()
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(data)))
                            self.end_headers()
                            self.wfile.write(data)

                    do_HEAD = do_GET

                    def log_message(self, *args):
                        pass
                return Handler

            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state, index))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            nodes.append({"name": f"Node {index}", "type": "http", "server": "127.0.0.1",
                          "port": server.server_port})

        def free_port():
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                return probe.getsockname()[1]

        from build_mihomo import PRIMARY_AUTO
        config = build_profile(nodes[:2], {}, "owner/repo", nodes[2:])
        config.update({"dns": {"enable": False}, "rules": ["MATCH,PROXY"], "rule-providers": {}})
        health = {"url": "http://health.invalid/health", "interval": 1, "timeout": 500,
                  "lazy": False, "expected-status": "204"}
        for provider in config["proxy-providers"].values():
            provider.update({"type": "inline", "health-check": dict(health, enable=True)})
            for key in ("url", "path", "interval", "proxy"):
                provider.pop(key, None)
        for group in config["proxy-groups"]:
            if group["type"] != "select":
                group.update(health)
        port, mixed = free_port(), free_port()
        secret = secrets.token_hex(24)
        config.update({"external-controller": f"127.0.0.1:{port}", "secret": secret, "mixed-port": mixed})
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(endpoint):
            request = urllib.request.Request(f"http://127.0.0.1:{port}{endpoint}",
                                             headers={"Authorization": f"Bearer {secret}"})
            with direct.open(request, timeout=3) as response:
                return json.load(response)

        def wait_for(predicate):
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    if predicate():
                        return
                except OSError:
                    pass
                time.sleep(.2)
            self.fail("Mihomo selection timeout: " + json.dumps({name: api(endpoint) for name, endpoint in (("auto", "/proxies/AUTO"), ("normal", "/proxies/AUTO%201"), ("provider", "/providers/proxies/proxyplankton_sub_clash"))}))

        def traffic():
            # Set the local proxy explicitly; urllib may bypass localhost otherwise.
            request = urllib.request.Request("http://traffic.invalid/traffic")
            request.set_proxy(f"127.0.0.1:{mixed}", "http")
            with direct.open(request, timeout=5) as response:
                return response.read().decode()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config))
            with (Path(directory) / "core.log").open("w") as log:
                process = subprocess.Popen([os.environ["MIHOMO_BINARY"], "-d", directory, "-f", str(path)],
                                           stdout=log, stderr=log)
                try:
                    wait_for(lambda: api("/providers/proxies/proxyplankton_sub_clash")["proxies"][1].get("extra", {}).get(health["url"], {}).get("alive", False))
                    wait_for(lambda: api("/providers/proxies/proxyplankton_whitelist")["proxies"][0].get("extra", {}).get(health["url"], {}).get("alive", False))
                    normal = api("/providers/proxies/proxyplankton_sub_clash")["proxies"]
                    reserve = api("/providers/proxies/proxyplankton_whitelist")["proxies"][0]
                    self.assertGreater(normal[1]["extra"][health["url"]]["history"][-1]["delay"],
                                       reserve["extra"][health["url"]]["history"][-1]["delay"])
                    self.assertEqual(api("/proxies/AUTO")["now"], PRIMARY_AUTO)
                    self.assertIn(traffic(), ["0", "1"])
                    self.assertEqual(states[2]["traffic"], 0)
                    states[0]["alive"] = False
                    wait_for(lambda: not api("/providers/proxies/proxyplankton_sub_clash")["proxies"][0]["extra"][health["url"]]["alive"])
                    self.assertEqual(traffic(), "1")
                    self.assertEqual(states[2]["traffic"], 0)
                    states[1]["alive"] = False
                    wait_for(lambda: api("/proxies/AUTO")["now"] == "Node 2")
                    self.assertEqual(traffic(), "2")
                    paid_traffic = states[2]["traffic"]
                    states[0]["alive"] = True
                    wait_for(lambda: api("/proxies/AUTO")["now"] == PRIMARY_AUTO)
                    self.assertEqual(traffic(), "0")
                    self.assertEqual(states[2]["traffic"], paid_traffic)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
