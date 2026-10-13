"""Adding a standalone host: add-host.sh (on that host) and homelab-pulse-hosts (in the container)."""
import base64
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import hosts
import server

ROOT = Path(__file__).resolve().parent.parent
CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
TOKEN = "pulse@pve!remote=8c4b4c1e-2b6f-4e9a-9d0e-1f2a3b4c5d6e"


def bundle(**kw):
    b = {"host": "192.168.1.102", "port": 8006, "token": TOKEN, "ca": CA}
    b.update(kw)
    return base64.b64encode(json.dumps(b).encode()).decode()


class HostsCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name) / "hosts.d"

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_writes_files_server_reads(self):
        self.assertEqual(hosts.main(["--dir", str(self.d), "--no-restart", "add", "pve02", bundle()]), 0)
        self.assertEqual(stat.S_IMODE((self.d / "pve02.token").stat().st_mode), 0o640)
        self.assertEqual((self.d / "pve02-ca.pem").read_text(), CA)
        self.assertEqual(server.extra_hosts(self.d), [("pve02", {"host": "192.168.1.102", "port": 8006, "token": TOKEN,
                                                                  "ca": str(self.d / "pve02-ca.pem"), "tls_name": None})])
        self.assertEqual(hosts.listing(self.d), [("pve02", "192.168.1.102")])

    def test_add_replaces_and_remove_cleans_up(self):
        hosts.add(self.d, "pve02", bundle())
        hosts.add(self.d, "pve02", bundle(host="192.168.1.120"))
        self.assertEqual(hosts.listing(self.d), [("pve02", "192.168.1.120")])
        hosts.remove(self.d, "pve02")
        self.assertEqual(list(self.d.iterdir()), [])
        with self.assertRaises(hosts.HostError):
            hosts.remove(self.d, "pve02")

    def test_bad_input_rejected(self):
        for label, b in [("Bad Label", bundle()), ("primary", bundle()), ("pve02", "not-base64!"),
                         ("pve02", bundle(token="nope")), ("pve02", bundle(host="a b;rm -rf /")),
                         ("pve02", bundle(ca="hello")), ("pve02", bundle(port=99999)),
                         ("pve02", base64.b64encode(b"[1, 2]").decode())]:
            with self.subTest(label=label, b=b[:20]), self.assertRaises(hosts.HostError):
                hosts.add(self.d, label, b)
        self.assertFalse(self.d.exists() and any(self.d.iterdir()))

    def test_cli_errors_exit_nonzero(self):
        self.assertEqual(hosts.main(["--dir", str(self.d), "--no-restart", "add", "pve02", "garbage"]), 1)
        self.assertEqual(hosts.main(["--dir", str(self.d), "--no-restart", "list"]), 0)


STUBS = {
    "pveversion": 'echo "pve-manager/9.2.20/49318c671b82f31e (running kernel: 7.0.14-19-pve)"',
    "pvesh": r'''echo '[{"type":"node","name":"PVE02","ip":"192.168.1.102","local":1}]' ''',
    "pveum": r'''case "$1 $2 $3" in
  "user list "*) if [ -n "$HAVE_USER" ]; then echo '[{"userid":"pulse@pve"}]'; else echo '[{"userid":"root@pam"}]'; fi ;;
  "user token list") if [ -n "$HAVE_TOKEN" ]; then echo '[{"tokenid":"remote"}]'; else echo '[]'; fi ;;
  "user token add") echo '{"full-tokenid":"pulse@pve!remote","value":"8c4b4c1e-2b6f-4e9a-9d0e-1f2a3b4c5d6e"}' ;;
  "user add pulse@pve"|"acl modify /") ;;
  *) echo "UNEXPECTED pveum $*" >&2; exit 99 ;;
esac''',
}


class AddHostScriptTests(unittest.TestCase):
    def run_script(self, *args, env_extra=None, dry=True):
        d = tempfile.mkdtemp()
        for name, body in STUBS.items():
            f = Path(d) / name
            f.write_text("#!/bin/sh\n" + body + "\n")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}", PULSE_ASSUME_ROOT="1", **(env_extra or {}))
        return subprocess.run(["bash", str(ROOT / "add-host.sh"), *(["--dry-run"] if dry else []), *args],
                              capture_output=True, text=True,
                              env=env, timeout=30)

    def test_fresh_host_plan(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("+ pveum user add pulse@pve", r.stdout)
        self.assertIn("+ pveum acl modify / --users pulse@pve --roles PVEAuditor", r.stdout)
        self.assertIn("+ pveum user token add pulse@pve remote --privsep 0", r.stdout)
        self.assertIn("homelab-pulse-hosts add pve02 <bundle>", r.stdout)       # label from the node name
        self.assertNotIn("UNEXPECTED", r.stderr)

    def test_existing_token_needs_rotate(self):
        r = self.run_script(env_extra={"HAVE_USER": "1", "HAVE_TOKEN": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--rotate-token", r.stderr)
        r = self.run_script("--rotate-token", "--label", "laptop", env_extra={"HAVE_USER": "1", "HAVE_TOKEN": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("+ pveum user token remove pulse@pve remote", r.stdout)
        self.assertNotIn("pveum user add", r.stdout)
        self.assertIn("homelab-pulse-hosts add laptop", r.stdout)

    def test_remove(self):
        r = self.run_script("--remove", env_extra={"HAVE_USER": "1", "HAVE_TOKEN": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("+ pveum user token remove pulse@pve remote", r.stdout)
        self.assertIn("+ pveum user delete pulse@pve", r.stdout)

    def test_real_run_prints_a_bundle_the_container_accepts(self):
        with tempfile.TemporaryDirectory() as d:
            ca = Path(d) / "ca.pem"
            ca.write_text(CA)
            r = self.run_script(dry=False, env_extra={"PULSE_PVE_CA_SRC": str(ca)})
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            line = next(x for x in r.stdout.splitlines() if x.startswith("homelab-pulse-hosts add "))
            _, _, label, b = line.split(" ")
            self.assertEqual(label, "pve02")
            self.assertEqual(hosts.decode_bundle(b), {"host": "192.168.1.102", "port": 8006, "token": TOKEN, "ca": CA})

    def test_bad_label(self):
        r = self.run_script("--label", "Primary Host")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
