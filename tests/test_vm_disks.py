"""Disk usage inside VMs, read from the QEMU guest agent (get-fsinfo)."""
import copy
import unittest

import collect
import early
import settings
from tests.test_collect import boot, make

GB = 1024 ** 3


def fs(name, mount, kind, total, used):
    return {"name": name, "mountpoint": mount, "type": kind, "total-bytes": total, "used-bytes": used}


class FilesystemTests(unittest.TestCase):
    def test_keeps_real_filesystems_once_each(self):
        data = {"result": [
            fs("sda8", "/", "squashfs", GB // 3, GB // 3),                 # read-only appliance root
            fs("sda1", "/mnt/boot", "vfat", 32 * 1024 ** 2, 1),            # too small to matter
            fs("sda8", "/mnt/data/supervisor", "ext4", 30 * GB, 12 * GB),  # bind mount of the same device
            fs("sda8", "/mnt/data", "ext4", 30 * GB, 12 * GB),
            fs("overlay", "/var/lib/docker/x", "overlay", 30 * GB, 12 * GB),
            fs("sdb1", "/srv", "XFS", 100 * GB, 10 * GB),
            {"name": "broken", "mountpoint": "/x", "type": "ext4"},          # no sizes reported
        ]}
        self.assertEqual(collect.vm_filesystems(data), [
            {"mount": "/mnt/data", "type": "ext4", "used": 12 * GB, "total": 30 * GB},
            {"mount": "/srv", "type": "xfs", "used": 10 * GB, "total": 100 * GB},
        ])

    def test_windows_and_bare_list(self):
        data = [fs("C:", "C:\\", "NTFS", 64 * GB, 40 * GB)]
        self.assertEqual(collect.vm_filesystems(data), [{"mount": "C:\\", "type": "ntfs", "used": 40 * GB,
                                                         "total": 64 * GB}])
        self.assertEqual(collect.vm_filesystems({}), [])


class CollectorTests(unittest.TestCase):
    def test_demo_vms_get_filesystems(self):
        c, _clock = make()
        boot(c)
        by = {g["vmid"]: g for g in c.snapshot()["guests"]}
        self.assertEqual([f["mount"] for f in by[103]["fs"]], ["/mnt/data"])        # HAOS: data partition only
        self.assertEqual([f["mount"] for f in by[202]["fs"]], ["/"])
        self.assertEqual(by[105]["fs"], [])                                         # VM without the guest agent
        self.assertEqual(by[100]["fs"], [])                                         # containers: Proxmox reports disk
        self.assertEqual(by[203]["fs"], [])                                         # stopped

    def test_agentless_vm_is_not_asked_every_poll(self):
        c, clock = make()
        boot(c)
        calls = []
        orig = c.pve.agent_fsinfo
        c.pve.agent_fsinfo = lambda node, vmid: calls.append(vmid) or orig(node, vmid)
        clock.t += 60
        c.poll_slow()
        self.assertNotIn(105, calls)          # failed once at boot: waits AGENT_RETRY_S
        self.assertIn(202, calls)

    def test_old_source_without_fsinfo(self):
        c, _clock = make()
        boot(c)
        g = next(g for g in c.guests if g["vmid"] == 202)
        c.fs_cache.clear()
        del_pve = type("P", (), {})()          # a source that has no agent_fsinfo at all
        c.pve, real = del_pve, c.pve
        c._refresh_fs(g, c.clock())
        c.pve = real
        self.assertEqual(c.meta[202]["fs"], [])

    def test_nearly_full_vm_raises_early_warning(self):
        c, _clock = make()
        boot(c)
        c.poll_alerts()
        att = {a["key"]: a for a in c.snapshot()["attention"]}
        self.assertEqual(att["warn:vm_disk:202:/"]["severity"], "warning")
        self.assertEqual(att["warn:vm_disk:202:/"]["title"], "nas disk 93 % full")
        self.assertEqual(c.snapshot()["vm_disk"], {"warn_pct": 90, "crit_pct": 97})


class EarlyTests(unittest.TestCase):
    def ev(self, guests, **patch):
        cfg = copy.deepcopy(settings.DEFAULTS["warnings"])
        cfg["storage_full"]["enabled"] = False
        for k, v in patch.items():
            cfg["vm_disk"][k] = v
        return {c["key"]: c for c in early.evaluate({"nodes": [], "guests": guests}, {}, cfg, {}, 0)}

    def vm(self, vmid, *fss, running=True, kind="qemu"):
        return {"vmid": vmid, "name": f"vm{vmid}", "type": kind, "running": running,
                "fs": [{"mount": m, "used": u, "total": 100} for m, u in fss]}

    def test_levels_and_titles(self):
        c = self.ev([self.vm(1, ("/", 91)), self.vm(2, ("/", 50), ("/srv", 98)), self.vm(3, ("C:\\", 95), ("D:\\", 10))])
        self.assertEqual({k: v["severity"] for k, v in c.items()},
                         {"warn:vm_disk:1:/": "warning", "warn:vm_disk:2:/srv": "critical", "warn:vm_disk:3:C:\\": "warning"})
        self.assertEqual(c["warn:vm_disk:1:/"]["title"], "vm1 disk 91 % full")
        self.assertEqual(c["warn:vm_disk:2:/srv"]["title"], "vm2 /srv 98 % full")
        self.assertEqual(c["warn:vm_disk:3:C:\\"]["title"], "vm3 disk 95 % full")
        self.assertEqual(c["warn:vm_disk:1:/"]["target"], 1)

    def test_stopped_containers_and_disabled_are_quiet(self):
        self.assertEqual(self.ev([self.vm(1, ("/", 99), running=False), self.vm(2, ("/", 99), kind="lxc")]), {})
        self.assertEqual(self.ev([self.vm(1, ("/", 99))], enabled=False), {})

    def test_saved_1_1_settings_get_the_new_rule(self):
        old = copy.deepcopy(settings.DEFAULTS)
        del old["warnings"]["vm_disk"]
        self.assertEqual(settings.validate(old)["warnings"]["vm_disk"], settings.DEFAULTS["warnings"]["vm_disk"])


if __name__ == "__main__":
    unittest.main()
