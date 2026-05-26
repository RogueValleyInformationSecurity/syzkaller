# Setup: Linux host, Proxmox VE cluster, x86-64 kernel

These are instructions for fuzzing the Linux kernel on virtual machines running on a
[Proxmox VE](https://www.proxmox.com/) cluster, using the `proxmox` VM backend.

For each fuzzing instance `syz-manager` clones a prepared cloud-init **template VM**, spreads
the clones across the configured cluster nodes (round-robin), assigns each one a deterministic
static IP, boots it, and destroys it on shutdown. The kernel serial console is captured by
SSH-ing into the node the VM landed on and streaming the VM's serial socket, so kernel panics are
captured even when the guest is otherwise dead.

This backend is a good fit when you already operate a Proxmox cluster with **shared storage**
(e.g. Ceph RBD): clones placed on shared storage can run on any node, so capacity scales with the
whole cluster.

## What the backend does and does not do

The backend **clones and manages** VMs. It does **not** build images. Before fuzzing you must
have, on the cluster:

- A **cloud-init template VM** (see below).
- A **storage** the clones live on (shared storage strongly recommended).
- A Proxmox **resource pool** (optional but recommended — makes bulk cleanup trivial).
- An **API token** for `syz-manager`.
- **SSH access from the `syz-manager` host to each node** (used only for the serial console).

## Template VM

Create a VM that the backend will clone, and convert it to a template:

- Disk on the shared storage, with a syzkaller-compatible Linux rootfs and a running SSH server.
  The [create-image.sh](/tools/create-image.sh) script produces a suitable rootfs; import it as
  the template's disk.
- **Cloud-init** enabled (add a CloudInit drive in the Proxmox UI / `qm set <vmid> --ide2
  <storage>:cloudinit`). The backend injects the SSH key, user, and static IP via cloud-init.
- A **serial console**: the kernel must boot with `console=ttyS0` on its cmdline. The backend sets
  `serial0=socket` on each clone automatically; you just need the kernel to log to `ttyS0`.
- The kernel built with the usual syzkaller coverage options
  (`CONFIG_KCOV=y`, `CONFIG_DEBUG_INFO=y`, `CONFIG_KASAN=y`, `CONFIG_KASAN_INLINE=y`, debugfs
  mounted at `/sys/kernel/debug`). See [kernel_configs.md](kernel_configs.md).

Then `qm template <template_vmid>`.

> Note: with `full_clone` disabled (the default) the backend makes **linked clones**, which are
> fast and space-efficient but require the template's disk to be on shared storage. Set
> `full_clone: true` (and a `storage`) to make independent full clones instead.

## API token

Create a dedicated user/token with permission to clone, configure, start, stop and delete VMs in
the chosen pool/storage, for example:

```
pveum user add syzkaller@pve
pveum acl modify /pool/syzkaller --user syzkaller@pve --role PVEVMAdmin
pveum acl modify /storage/vm-rbd  --user syzkaller@pve --role PVEDatastoreUser
pveum user token add syzkaller@pve fuzz --privsep 0
```

The token id is `syzkaller@pve!fuzz`; note the printed secret.

## Node SSH (serial console)

The serial console is read by running, on the node, roughly:

```
ssh <node_ssh_user>@<node addr> socat - UNIX-CONNECT:/var/run/qemu-server/<vmid>.serial0
```

So the `syz-manager` host must be able to SSH into each node without a password. By default the
backend uses the user `root` and your **system SSH configuration** (i.e. `~/.ssh/config` and your
agent/keys), matching a typical keyless-root-ssh-to-nodes setup. Set `node_ssh_user` and/or
`node_ssh_key` to override. `socat` is installed on Proxmox nodes by default.

## Disable HA / autostart

Fuzzing VMs are expected to crash. Do **not** put the clones (or the template) under Proxmox HA,
and leave autostart off — the backend sets `onboot=0` on each clone so a panicked VM is not
restarted underneath the fuzzer.

## syz-manager configuration

```json
{
	"target": "linux/amd64",
	"http": ":56741",
	"workdir": "/syzkaller/workdir",
	"kernel_obj": "/linux/",
	"syzkaller": "/syzkaller/gopath/src/github.com/google/syzkaller",
	"sshkey": "/syzkaller/proxmox.id_rsa",
	"ssh_user": "root",
	"procs": 8,
	"type": "proxmox",
	"vm": {
		"count": 6,
		"api_url": "https://192.168.0.201:8006/api2/json",
		"api_token_id": "syzkaller@pve!fuzz",
		"api_token_secret": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		"insecure_tls": true,
		"nodes": [
			{"name": "pve1", "addr": "192.168.0.201"},
			{"name": "pve2", "addr": "192.168.0.202"},
			{"name": "pve3", "addr": "192.168.0.203"}
		],
		"storage": "vm-rbd",
		"pool": "syzkaller",
		"template_vmid": 9000,
		"full_clone": false,
		"vmid_base": 7000,
		"ip_base": "192.168.0.130",
		"ip_prefix": 24,
		"gateway": "192.168.0.1",
		"cores": 2,
		"memory": 2048
	}
}
```

The top-level `sshkey`/`ssh_user` are used to connect to the **guest** VMs; the backend injects the
corresponding public key and user into each clone via cloud-init.

### `vm` parameters

| Parameter          | Description |
|--------------------|-------------|
| `count`            | Number of VMs to run in parallel. |
| `api_url`          | Proxmox API base URL, including `/api2/json`. |
| `api_token_id`     | API token id, `user@realm!tokenname`. |
| `api_token_secret` | API token secret. |
| `insecure_tls`     | Skip TLS verification (for self-signed PVE certificates). |
| `nodes`            | Cluster members to schedule onto. `name` is the Proxmox node name; `addr` is its SSH host. VMs are distributed round-robin. |
| `storage`          | Target storage for full clones (e.g. a Ceph pool). Required only when `full_clone` is true. |
| `pool`             | Resource pool the clones are placed in. |
| `template_vmid`    | VMID of the template to clone. |
| `full_clone`       | Make full (independent) clones instead of linked clones. Default false. |
| `vmid_base`        | Instance `i` gets VMID `vmid_base + i`. If 0, the cluster's next free id is used. |
| `ip_base`          | Instance `i` gets the IPv4 address `ip_base + i` (assigned via cloud-init). |
| `ip_prefix`        | CIDR prefix length for the static IP. Default 24. |
| `gateway`          | Default gateway for the static IP (optional). |
| `cores`, `memory`  | Per-VM CPU cores and memory (MiB). 0 means inherit from the template. |
| `node_ssh_user`    | User to SSH into nodes as for the console. Default `root`. |
| `node_ssh_key`     | SSH key for node access. Empty means use the system SSH config/agent. |

A deterministic `vmid_base`/`ip_base` (instead of dynamic allocation) keeps a fixed pool of VMs
collision-free and lets the backend safely delete-then-recreate a VMID if a previous run left one
behind.
