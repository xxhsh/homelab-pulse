"""The Proxmox API, read-only. The demo stand-in with identical shapes lives in demo.py.

Every call returns the raw JSON `data` the API returns, so the rest of the app can't tell a demo
source from a live one. Node-scoped calls take the node name: in a cluster any node's API answers
for all of them.
"""
import http.client
import json
import socket
import urllib.parse

from probes import private_ca_context


class SourceError(Exception):
    pass


class PveClient:
    """TLS is verified against the cluster CA. Node certs are issued for the node *name*, not its
    IP, so we connect by IP and verify as `tls_name`, which is detected from /cluster/status on the
    first call (that one call verifies the chain only) unless given explicitly."""

    def __init__(self, host, port, token, cafile, tls_name=None, timeout=8):
        self.host, self.port, self.timeout = host, port, timeout
        self.auth = "PVEAPIToken=" + token
        self.cafile = cafile
        self.tls_name = tls_name

    def _context(self, check_name):
        ctx = private_ca_context(self.cafile)
        ctx.check_hostname = check_name
        return ctx

    def _request(self, path, check_name=True):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        conn.sock = self._context(check_name).wrap_socket(sock, server_hostname=self.tls_name or self.host)
        try:
            conn.request("GET", "/api2/json" + path, headers={"Authorization": self.auth})
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise SourceError(f"PVE {path.split('?')[0]}: HTTP {r.status} {r.reason}".strip())
            return json.loads(body)["data"]
        finally:
            conn.close()

    def _get(self, path):
        if self.tls_name is None:
            local = [e for e in self._request("/cluster/status", check_name=False)
                     if e.get("type") == "node" and e.get("local")]
            if not local:
                raise SourceError("PVE /cluster/status: no local node in the answer")
            self.tls_name = local[0]["name"]
        return self._request(path)

    def resources(self):
        return self._get("/cluster/resources")

    def cluster_status(self):
        return self._get("/cluster/status")

    def node_status(self, node):
        return self._get(f"/nodes/{node}/status")

    def node_network(self, node):
        return self._get(f"/nodes/{node}/network")

    def guest_config(self, node, kind, vmid):
        return self._get(f"/nodes/{node}/{kind}/{vmid}/config")

    def lxc_interfaces(self, node, vmid):
        return self._get(f"/nodes/{node}/lxc/{vmid}/interfaces")

    def agent_interfaces(self, node, vmid):
        return self._get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")

    def agent_fsinfo(self, node, vmid):
        """Filesystems inside a VM, from the QEMU guest agent. Readable with PVEAuditor on PVE 9
        (VM.GuestAgent.Audit); PVE 8 needs VM.Monitor, like agent_interfaces."""
        return self._get(f"/nodes/{node}/qemu/{vmid}/agent/get-fsinfo")

    def disks(self, node):
        return self._get(f"/nodes/{node}/disks/list")

    def backup_runs(self, node, limit=3):
        """Recent vzdump jobs. (Listing the backup storage itself needs more than PVEAuditor on
        PVE 9, but the job log is readable with Sys.Audit and says everything we need.)"""
        return self._get(f"/nodes/{node}/tasks?typefilter=vzdump&source=all&limit={limit}")

    def task_log(self, node, upid):
        return self._get(f"/nodes/{node}/tasks/{urllib.parse.quote(upid, safe='')}/log?limit=20000")

    def tasks(self):
        return self._get("/cluster/tasks")

    # Proxmox keeps these round-robin databases for a year; Pulse reads them for long graphs and
    # storage forecasts instead of recording metrics itself. timeframe: hour|day|week|month|year
    def rrd(self, node, kind, vmid, timeframe):
        return self._get(f"/nodes/{node}/{kind}/{vmid}/rrddata?timeframe={timeframe}&cf=AVERAGE")

    def node_rrd(self, node, timeframe):
        return self._get(f"/nodes/{node}/rrddata?timeframe={timeframe}&cf=AVERAGE")

    def storage_rrd(self, node, storage, timeframe):
        return self._get(f"/nodes/{node}/storage/{storage}/rrddata?timeframe={timeframe}&cf=AVERAGE")


class MultiPve:
    """Several standalone Proxmox hosts (or clusters) shown as one lab, with the PveClient interface.

    Cluster-wide calls are merged; node-scoped calls go to the host that answered for that node.
    A host that doesn't answer keeps its last known nodes, reported offline, so the dashboard shows
    "pve2 is offline" instead of the node silently disappearing. Only when no host answers does a
    call fail. VMIDs must be unique across hosts: a guest whose VMID was already seen on an earlier
    host is left out and listed in `conflicts` (the dashboard turns that into a warning).
    """

    def __init__(self, clients):
        self.clients = list(clients)           # [(label, client)], first one is the primary
        self.owner = {}                        # node name -> client
        self.known = {}                        # label -> node names from the last good answer
        self.conflicts = []                    # [(vmid, kept node, dropped node)] from the last resources()
        self.down = {}                         # label -> error text, for hosts that didn't answer

    def _all(self, call):
        out, errors = [], {}
        for label, cl in self.clients:
            try:
                out.append((label, cl, call(cl)))
            except (SourceError, OSError, ValueError) as e:
                errors[label] = str(e)
        self.down = errors
        if not out:
            raise SourceError("; ".join(f"{k}: {v}" for k, v in errors.items()) or "no Proxmox host configured")
        return out

    def _for(self, node):
        cl = self.owner.get(node)
        if cl is None:
            raise SourceError(f"PVE: no host is known to serve node {node}")
        return cl

    def resources(self):
        merged, seen, conflicts = [], {}, []
        for label, cl, res in self._all(lambda c: c.resources()):
            names = {r["node"] for r in res if r.get("type") == "node"}
            self.known[label] = sorted(names)
            for n in names:
                self.owner[n] = cl
            for r in res:
                if r.get("type") in ("lxc", "qemu"):
                    vmid = int(r["vmid"])
                    if vmid in seen:
                        conflicts.append((vmid, seen[vmid], r.get("node")))
                        continue
                    seen[vmid] = r.get("node")
                merged.append(r)
        for label in self.down:                # last known nodes of a silent host, shown offline
            for n in self.known.get(label, [label]):
                if not any(r.get("type") == "node" and r.get("node") == n for r in merged):
                    merged.append({"type": "node", "node": n, "status": "offline", "id": f"node/{n}"})
        self.conflicts = conflicts
        return merged

    def cluster_status(self):
        nodes, clusters = [], []
        for _label, cl, st in self._all(lambda c: c.cluster_status()):
            for e in st:
                if e.get("type") == "node":
                    self.owner[e["name"]] = cl
                    nodes.append(e)
                elif e.get("type") == "cluster":
                    clusters.append(e)
        # one cluster keeps its name; several hosts are one lab, not one cluster
        return nodes + (clusters if len(self.clients) == 1 else [])

    def tasks(self):
        return [t for _label, _cl, ts in self._all(lambda c: c.tasks()) for t in ts]

    def node_status(self, node):
        return self._for(node).node_status(node)

    def node_network(self, node):
        return self._for(node).node_network(node)

    def guest_config(self, node, kind, vmid):
        return self._for(node).guest_config(node, kind, vmid)

    def lxc_interfaces(self, node, vmid):
        return self._for(node).lxc_interfaces(node, vmid)

    def agent_interfaces(self, node, vmid):
        return self._for(node).agent_interfaces(node, vmid)

    def agent_fsinfo(self, node, vmid):
        return self._for(node).agent_fsinfo(node, vmid)

    def disks(self, node):
        return self._for(node).disks(node)

    def backup_runs(self, node, limit=3):
        return self._for(node).backup_runs(node, limit)

    def task_log(self, node, upid):
        return self._for(node).task_log(node, upid)

    def rrd(self, node, kind, vmid, timeframe):
        return self._for(node).rrd(node, kind, vmid, timeframe)

    def node_rrd(self, node, timeframe):
        return self._for(node).node_rrd(node, timeframe)

    def storage_rrd(self, node, storage, timeframe):
        return self._for(node).storage_rrd(node, storage, timeframe)

    def node_cafile(self, node):
        """The CA to verify this node's web UI with (each standalone host has its own)."""
        return getattr(self.owner.get(node), "cafile", None)
