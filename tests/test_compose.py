from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class ComposeTests(unittest.TestCase):
    def test_worker_boundary_and_internal_ports(self):
        document = yaml.safe_load((ROOT / "compose.yaml").read_text())
        services = document["services"]
        self.assertTrue(document["networks"]["internal"]["internal"])
        for name in ("api", "worker", "inference"):
            service = services[name]
            self.assertEqual(service["user"], "10001:10001")
            self.assertTrue(service["read_only"])
            self.assertIn("ALL", service["cap_drop"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
        worker = services["worker"]
        self.assertEqual(worker["mem_limit"], "3g")
        self.assertEqual(worker["memswap_limit"], "3g")
        self.assertIn("--pool=prefork", worker["command"])
        self.assertTrue(worker["volumes"][0]["read_only"])
        self.assertNotIn("ports", worker)
        for name, service in services.items():
            if name != "api":
                self.assertNotIn("ports", service)
            self.assertNotIn("privileged", service)
            self.assertNotIn("docker.sock", str(service))

    def test_broker_cache_and_readiness_dependencies(self):
        services = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
        self.assertIn("noeviction", str(services["broker"]["command"]))
        self.assertIn("allkeys-lru", str(services["cache"]["command"]))
        self.assertEqual(services["worker"]["depends_on"]["api"]["condition"], "service_healthy")
        self.assertNotIn("worker", services["api"]["depends_on"])
        self.assertFalse(services["inference"]["volumes"][0]["bind"]["create_host_path"])

    def test_context_excludes_secrets_samples_and_keeps_benchmark(self):
        ignore = (ROOT / ".dockerignore").read_text()
        self.assertIn(".env", ignore)
        self.assertIn("models/", ignore)
        self.assertIn("!scripts/benchmark_cache.py", ignore)
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("scripts/benchmark_cache.py", dockerfile)
        self.assertNotIn("COPY . ", dockerfile)
        self.assertIn("0ef753e81d98bf209f71b03cd331dfc190b5b54d", (ROOT / "requirements.txt").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
