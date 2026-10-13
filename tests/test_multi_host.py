"""Several standalone Proxmox hosts shown as one lab (sources.MultiPve + config in server.py)."""
import tempfile
import unittest
from pathlib import Path

import collect
import demo
import server
import sources
from tests.test_collect import FakeClock, boot


class StandaloneHost:
    """One node of the demo cluster, answering like a standalone Proxmox host would."""

    def __init__(self, pve, node, cafile, vmid_shift=None):
        self.pve, self.node, self.cafile = pve, node, cafile
        self.down = False
        self.vmid_shift = vmid_shift or {}

    def __getattr__(self, name):           # node-scoped calls: same as the demo cluster
        if self.down:
            raise sources.SourceError(f"PVE {self.node}: connection refused")
        return getattr(self.pve, name)

    def _check(self):
        if self.down:
            raise sources.SourceError(f"PVE {self.node}: connection refused")

    def resources(self):
        self._check()
        out = []
        for r in self.pve.resources():
            if r.get("node") != self.node:
                continue
            if r.get("vmid") in self.vmid_shift:
                r = dict(r, vmid=self.vmid_shift[r["vmid"]])
            out.append(r)
        return out

    def cluster_status(self):
        self._check()
        return [dict(e, local=1) for e in self.pve.cluster_status() if e.get("name") == self.node]

    def tasks(self):
        self._check()
        return [t for t in self.pve.tasks() if t.get("node") == self.node]


def two_hosts(**kw):
    clock = FakeClock()
    pve = demo.DemoPve(clock=clock)
    a = StandaloneHost(pve, "pve1", "/etc/homelab-pulse/pve-ca.pem")
    b = StandaloneHost(pve, "pve2", "/etc/homelab-pulse/hosts.d/pve2-ca.pem", **kw)
    return sources.MultiPve([("primary", a), ("pve2", b)]), a, b, clock


class MultiPveTests(unittest.TestCase):
    def test_merges_hosts_and_routes_node_calls(self):
        m, a, b, _ = two_hosts()
        res = m.resources()
        self.assertEqual(sorted(r["node"] for r in res if r["type"] == "node"), ["pve1", "pve2"])
        self.assertEqual(len([r for r in res if r["type"] in ("lxc", "qemu")]), 11)
        self.assertIs(m.owner["pve2"], b)
        self.assertEqual(m.node_cafile("pve2"), "/etc/homelab-pulse/hosts.d/pve2-ca.pem")
        self.assertEqual(m.node_cafile("pve1"), "/etc/homelab-pulse/pve-ca.pem")
        self.assertIn("cpu", m.node_status("pve2"))
        with self.assertRaises(sources.SourceError):
            m.node_status("pve9")

    def test_standalone_hosts_are_not_a_cluster(self):
        m, *_ = two_hosts()
        st = m.cluster_status()
        self.assertEqual(sorted(e["name"] for e in st), ["pve1", "pve2"])
        self.assertFalse(any(e.get("type") == "cluster" for e in st))
        single = sources.MultiPve([("primary", demo.DemoPve())])
        self.assertTrue(any(e.get("type") == "cluster" for e in single.cluster_status()))

    def test_duplicate_vmid_kept_once_and_reported(self):
        m, *_ = two_hosts(vmid_shift={200: 100})     # pve2's guest 200 renumbered to clash with pve1's 100
        res = m.resources()
        hundreds = [r for r in res if r.get("vmid") == 100]
        self.assertEqual([r["node"] for r in hundreds], ["pve1"])
        self.assertEqual(m.conflicts, [(100, "pve1", "pve2")])

    def test_silent_host_shows_offline_until_all_fail(self):
        m, a, b, _ = two_hosts()
        m.resources()
        b.down = True
        res = m.resources()
        nodes = {r["node"]: r["status"] for r in res if r["type"] == "node"}
        self.assertEqual(nodes, {"pve1": "online", "pve2": "offline"})
        self.assertIn("pve2", m.down)
        self.assertEqual({t.get("node") for t in m.tasks()}, {"pve1"})
        a.down = True
        with self.assertRaisesRegex(sources.SourceError, "primary: .*pve2: "):
            m.resources()

    def test_never_answered_host_is_named_by_label(self):
        m, a, b, _ = two_hosts()
        b.down = True
        nodes = {r["node"]: r["status"] for r in m.resources() if r["type"] == "node"}
        self.assertEqual(nodes["pve2"], "offline")     # label doubles as the name


class CollectorTests(unittest.TestCase):
    def make(self, **kw):
        m, a, b, clock = two_hosts(**kw)
        net = demo.DemoNet(clock=clock)
        c = collect.Collector(m, "live", net, probe_fn=net.probe, overrides_path="/nonexistent",
                              ca_path="/etc/homelab-pulse/pve-ca.pem", clock=clock)
        return c, a, b, clock

    def test_two_hosts_one_lab(self):
        c, *_ = self.make()
        boot(c)
        s = c.snapshot()
        self.assertEqual([n["name"] for n in s["nodes"]], ["pve1", "pve2"])
        self.assertFalse(s["clustered"])
        self.assertEqual(c.lab_name, "homelab")
        by = {p["id"]: p for p in s["probes"]}
        self.assertIn("node:pve2", by)
        spec = c.checks["node:pve2"].spec
        self.assertEqual(spec["cafile"], "/etc/homelab-pulse/hosts.d/pve2-ca.pem")   # each host's own CA
        self.assertEqual(c.checks["node:pve1"].spec["cafile"], "/etc/homelab-pulse/pve-ca.pem")
        g = {g["vmid"]: g for g in s["guests"]}
        self.assertEqual(g[202]["node"], "pve2")
        self.assertTrue(g[202]["fs"])                                   # agent calls routed to pve2

    def test_offline_host_raises_node_alert(self):
        c, a, b, clock = self.make()
        boot(c)
        b.down = True
        clock.t += 5
        c.poll_fast()
        conds = collect.build_conditions(c.snapshot(), {}, [], clock.t)
        self.assertIn("node:pve2", {x["key"] for x in conds})
        self.assertNotIn("source:pve", {x["key"] for x in conds})     # pve1 still answers

    def test_vmid_conflict_becomes_a_warning(self):
        c, *_ = self.make(vmid_shift={200: 100})
        boot(c)
        conds = {x["key"]: x for x in collect.build_conditions(c.snapshot(), {}, [], c.clock())}
        self.assertEqual(conds["conflict:100"]["severity"], "warning")
        self.assertIn("pve1 and pve2", conds["conflict:100"]["title"])


class ConfigTests(unittest.TestCase):
    def test_extra_hosts_from_directory(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "pve2-token").write_text("pulse@pve!ct120=secret\n")
            (p / "pve2.env").write_text(f"# second host\nPULSE_PVE_HOST=192.168.1.102\nPULSE_PVE_TOKEN_FILE={p}/pve2-token\n"
                                        f"PULSE_PVE_CA=\"{p}/pve2-ca.pem\"\n")
            (p / "broken.env").write_text("PULSE_PVE_HOST=10.0.0.9\n")          # no token: skipped
            (p / "notes.txt").write_text("ignored")
            hosts = server.extra_hosts(d)
        self.assertEqual(hosts, [("pve2", {"host": "192.168.1.102", "port": 8006, "token": "pulse@pve!ct120=secret",
                                           "ca": f"{d}/pve2-ca.pem", "tls_name": None})])
        self.assertEqual(server.extra_hosts("/nonexistent/hosts.d"), [])

    def test_live_collector_uses_multi_source_only_with_extra_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "tok").write_text("pulse@pve!x=y")
            (p / "db").mkdir()
            env = {"PULSE_PVE": "live", "PULSE_PVE_HOST": "192.168.1.101", "PULSE_PVE_TOKEN_FILE": str(p / "tok"),
                   "PULSE_PVE_HOSTS_DIR": str(p / "hosts.d"), "PULSE_DB": str(p / "db" / "pulse.db"),
                   "PULSE_ADMIN_PASSWORD_FILE": str(p / "nope"), "PULSE_PUBLIC_URL": "http://x/"}
            self.assertIsInstance(server.build_collector(env).pve, sources.PveClient)
            (p / "hosts.d").mkdir()
            (p / "hosts.d" / "pve2.env").write_text(f"PULSE_PVE_HOST=192.168.1.102\nPULSE_PVE_TOKEN_FILE={p / 'tok'}\n")
            c = server.build_collector(env)
            self.assertIsInstance(c.pve, sources.MultiPve)
            self.assertEqual([label for label, _ in c.pve.clients], ["primary", "pve2"])
            c.store.close() if hasattr(c.store, "close") else None


if __name__ == "__main__":
    unittest.main()
