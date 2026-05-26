// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package proxmox allows to use VMs running on a Proxmox VE cluster as syzkaller VMs.
//
// syz-manager clones a prepared cloud-init template VM for each instance, distributes
// the clones across the configured cluster nodes (round-robin), assigns deterministic
// static IPs, and captures the kernel serial console by SSH-ing into the node the VM
// landed on and streaming its serial socket. Instances are destroyed (stopped + deleted)
// on close, so the cluster does not accumulate dead VMs.
//
// The template, the storage (ideally shared, e.g. Ceph RBD, so clones can be placed on
// any node), the resource pool, and an API token are expected to exist already; this
// backend does not build images. Crashed fuzzing VMs must not be restarted, so configure
// them with HA disabled and onboot=0 (the latter is set automatically).
package proxmox

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	goproxmox "github.com/luthermonson/go-proxmox"
)

func init() {
	var _ vmimpl.Infoer = (*instance)(nil)
	vmimpl.Register("proxmox", vmimpl.Type{
		Ctor: ctor,
		// Clones are creatable on demand, so overcommit (image/patch testing) is fine.
		Overcommit: true,
	})
}

// NodeConfig describes one cluster member the backend may schedule VMs onto.
type NodeConfig struct {
	// Proxmox node name, as used by the API (e.g. "pve1").
	Name string `json:"name"`
	// SSH host (ip or hostname) of the node, used to stream the serial console.
	Addr string `json:"addr"`
}

type Config struct {
	// Number of VMs to run in parallel (1 by default).
	Count int `json:"count"`

	// Proxmox API connection.
	APIURL         string `json:"api_url"`          // e.g. "https://192.168.0.201:8006/api2/json"
	APITokenID     string `json:"api_token_id"`     // e.g. "syzkaller@pve!fuzz"
	APITokenSecret string `json:"api_token_secret"` // the token UUID secret
	InsecureTLS    bool   `json:"insecure_tls"`     // skip TLS verification (self-signed PVE certs)

	// Cluster placement.
	Nodes   []NodeConfig `json:"nodes"`   // cluster members to schedule onto (round-robin)
	Storage string       `json:"storage"` // target storage for full clones (e.g. "vm-rbd")
	Pool    string       `json:"pool"`    // Proxmox resource pool to put VMs in (for cleanup)

	// Source template.
	TemplateVMID int  `json:"template_vmid"` // VMID of the cloud-init template to clone
	FullClone    bool `json:"full_clone"`    // full clone (default: linked clone, needs shared storage)

	// Deterministic per-instance identity and networking.
	VMIDBase int    `json:"vmid_base"` // instance i gets VMID vmid_base+i (0 => use cluster nextid)
	IPBase   string `json:"ip_base"`   // instance i gets IP ip_base+i (IPv4), assigned via cloud-init
	IPPrefix int    `json:"ip_prefix"` // CIDR prefix length for the static IP (24 by default)
	Gateway  string `json:"gateway"`   // default gateway for the static IP (optional)

	// VM shape overrides (0 => inherit from template).
	Cores  int `json:"cores"`
	Memory int `json:"memory"` // in MiB

	// SSH to the node for the serial console.
	NodeSSHUser string `json:"node_ssh_user"` // user to ssh into the node as (root by default)
	NodeSSHKey  string `json:"node_ssh_key"`  // optional key; empty => use the system ssh config/agent
}

type Pool struct {
	env      *vmimpl.Env
	cfg      *Config
	client   *goproxmox.Client
	tmplNode string // node the template VM resides on
	sshUser  string // ssh user for the guest (cloud-init ciuser)
	idMu     sync.Mutex
}

type instance struct {
	cfg      *Config
	client   *goproxmox.Client
	env      *vmimpl.Env
	debug    bool
	os       string
	name     string
	nodeName string // Proxmox node the VM runs on.
	nodeAddr string // ssh host of that node.
	vmid     int
	vmimpl.SSHOptions
	forwardPort int
	closed      chan bool
	consolew    io.Closer
	timeouts    targets.Timeouts
}

func (cfg *Config) validate() error {
	if cfg.Count < 1 || cfg.Count > 1000 {
		return fmt.Errorf("invalid config param count: %v, want [1, 1000]", cfg.Count)
	}
	if cfg.APIURL == "" || cfg.APITokenID == "" || cfg.APITokenSecret == "" {
		return fmt.Errorf("api_url, api_token_id and api_token_secret are required")
	}
	if len(cfg.Nodes) == 0 {
		return fmt.Errorf("config param nodes is empty")
	}
	for i, n := range cfg.Nodes {
		if n.Name == "" || n.Addr == "" {
			return fmt.Errorf("nodes[%v]: both name and addr are required", i)
		}
	}
	if cfg.TemplateVMID <= 0 {
		return fmt.Errorf("config param template_vmid is required")
	}
	if cfg.FullClone && cfg.Storage == "" {
		return fmt.Errorf("config param storage is required for full clones")
	}
	if cfg.IPBase == "" {
		return fmt.Errorf("config param ip_base is required")
	}
	if ip := net.ParseIP(cfg.IPBase); ip == nil || ip.To4() == nil {
		return fmt.Errorf("config param ip_base %q is not a valid IPv4 address", cfg.IPBase)
	}
	return nil
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count:       1,
		IPPrefix:    24,
		NodeSSHUser: "root",
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse proxmox vm config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	hc := &http.Client{Transport: &http.Transport{}}
	if cfg.InsecureTLS {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	client := goproxmox.NewClient(cfg.APIURL,
		goproxmox.WithHTTPClient(hc),
		goproxmox.WithAPIToken(cfg.APITokenID, cfg.APITokenSecret),
	)

	sshUser := env.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}
	pool := &Pool{
		env:     env,
		cfg:     cfg,
		client:  client,
		sshUser: sshUser,
	}
	// Validate connectivity and locate the template's node in a single call.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	node, err := pool.findVMNode(ctx, cfg.TemplateVMID)
	if err != nil {
		return nil, fmt.Errorf("failed to locate template VM %v in the cluster: %w", cfg.TemplateVMID, err)
	}
	pool.tmplNode = node
	log.Logf(0, "proxmox: connected, template %v is on node %v", cfg.TemplateVMID, node)
	return pool, nil
}

// findVMNode returns the cluster node a VM with the given VMID currently resides on.
func (pool *Pool) findVMNode(ctx context.Context, vmid int) (string, error) {
	cluster, err := pool.client.Cluster(ctx)
	if err != nil {
		return "", err
	}
	resources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return "", err
	}
	for _, r := range resources {
		if r.Type == "qemu" && int(r.VMID) == vmid {
			return r.Node, nil
		}
	}
	return "", fmt.Errorf("VM %v not found in cluster", vmid)
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) nextVMID(ctx context.Context, index int) (int, error) {
	if pool.cfg.VMIDBase > 0 {
		return pool.cfg.VMIDBase + index, nil
	}
	pool.idMu.Lock()
	defer pool.idMu.Unlock()
	cluster, err := pool.client.Cluster(ctx)
	if err != nil {
		return 0, err
	}
	return cluster.NextID(ctx)
}

func (pool *Pool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	node := pool.cfg.Nodes[index%len(pool.cfg.Nodes)]
	vmid, err := pool.nextVMID(ctx, index)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate VMID: %w", err)
	}
	ip, err := addIPv4(pool.cfg.IPBase, index)
	if err != nil {
		return nil, err
	}
	name := sanitizeName(fmt.Sprintf("%v-%v", pool.env.Name, index))

	// Create a per-instance SSH key and inject it via cloud-init.
	sshKey := filepath.Join(workdir, "key")
	if out, err := osutil.RunCmd(time.Minute, "", "ssh-keygen",
		"-t", "ed25519", "-N", "", "-C", "syzkaller", "-f", sshKey); err != nil {
		return nil, fmt.Errorf("failed to execute ssh-keygen: %w\n%s", err, out)
	}
	pubKey, err := os.ReadFile(sshKey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read generated public key: %w", err)
	}

	inst := &instance{
		cfg:      pool.cfg,
		client:   pool.client,
		env:      pool.env,
		debug:    pool.env.Debug,
		os:       pool.env.OS,
		name:     name,
		nodeName: node.Name,
		nodeAddr: node.Addr,
		vmid:     vmid,
		SSHOptions: vmimpl.SSHOptions{
			Addr: ip,
			Port: 22,
			User: pool.sshUser,
			Key:  sshKey,
		},
		closed:   make(chan bool),
		timeouts: pool.env.Timeouts,
	}

	// In case a previous run left a VM with this VMID around, delete it first so the
	// clone does not fail with a conflict (idempotent restart).
	destroyVM(pool.client, node.Name, vmid, pool.env.Debug)

	ok := false
	defer func() {
		if !ok {
			destroyVM(pool.client, node.Name, vmid, pool.env.Debug)
		}
	}()

	if err := pool.clone(ctx, node.Name, vmid, name); err != nil {
		return nil, err
	}
	if err := inst.configure(ctx, string(pubKey), ip); err != nil {
		return nil, err
	}
	if err := inst.start(ctx); err != nil {
		return nil, err
	}

	log.Logf(0, "proxmox: created VM %v (%q) on node %v, waiting for ssh at %v", vmid, name, node.Name, ip)
	if err := vmimpl.WaitForSSH(5*time.Minute, inst.SSHOptions,
		pool.env.OS, nil, false, pool.env.Debug); err != nil {
		return nil, vmimpl.MakeBootError(err, nil)
	}
	ok = true
	return inst, nil
}

func (pool *Pool) clone(ctx context.Context, targetNode string, newID int, name string) error {
	node, err := pool.client.Node(ctx, pool.tmplNode)
	if err != nil {
		return fmt.Errorf("failed to get template node %v: %w", pool.tmplNode, err)
	}
	tmpl, err := node.VirtualMachine(ctx, pool.cfg.TemplateVMID)
	if err != nil {
		return fmt.Errorf("failed to get template VM %v: %w", pool.cfg.TemplateVMID, err)
	}
	opts := &goproxmox.VirtualMachineCloneOptions{
		NewID:  newID,
		Name:   name,
		Target: targetNode,
		Pool:   pool.cfg.Pool,
	}
	if pool.cfg.FullClone {
		opts.Full = 1
		// A target storage may only be specified for full clones; linked clones
		// must stay on the template's storage.
		opts.Storage = pool.cfg.Storage
	}
	_, task, err := tmpl.Clone(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to clone template VM %v: %w", pool.cfg.TemplateVMID, err)
	}
	if err := task.Wait(ctx, time.Second, 10*time.Minute); err != nil {
		return fmt.Errorf("clone task failed: %w", err)
	}
	return nil
}

func (inst *instance) vm(ctx context.Context) (*goproxmox.VirtualMachine, error) {
	node, err := inst.client.Node(ctx, inst.nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %v: %w", inst.nodeName, err)
	}
	return node.VirtualMachine(ctx, inst.vmid)
}

func (inst *instance) configure(ctx context.Context, pubKey, ip string) error {
	vm, err := inst.vm(ctx)
	if err != nil {
		return err
	}
	ipconfig := fmt.Sprintf("ip=%s/%d", ip, inst.cfg.IPPrefix)
	if inst.cfg.Gateway != "" {
		ipconfig += ",gw=" + inst.cfg.Gateway
	}
	opts := []goproxmox.VirtualMachineOption{
		{Name: "sshkeys", Value: encodeSSHKeys(pubKey)},
		{Name: "ciuser", Value: inst.User},
		{Name: "ipconfig0", Value: ipconfig},
		// A unix-socket serial port the node exposes; we stream the kernel console from it.
		{Name: "serial0", Value: "socket"},
		// Crashed fuzzing VMs must not be auto-started.
		{Name: "onboot", Value: 0},
	}
	if inst.cfg.Cores > 0 {
		opts = append(opts, goproxmox.VirtualMachineOption{Name: "cores", Value: inst.cfg.Cores})
	}
	if inst.cfg.Memory > 0 {
		opts = append(opts, goproxmox.VirtualMachineOption{Name: "memory", Value: inst.cfg.Memory})
	}
	task, err := vm.Config(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to configure VM %v: %w", inst.vmid, err)
	}
	if err := task.Wait(ctx, time.Second, 2*time.Minute); err != nil {
		return fmt.Errorf("VM config task failed: %w", err)
	}
	return nil
}

func (inst *instance) start(ctx context.Context) error {
	vm, err := inst.vm(ctx)
	if err != nil {
		return err
	}
	task, err := vm.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start VM %v: %w", inst.vmid, err)
	}
	if err := task.Wait(ctx, time.Second, 2*time.Minute); err != nil {
		return fmt.Errorf("VM start task failed: %w", err)
	}
	return nil
}

// destroyVM stops and deletes a VM, ignoring errors (best-effort cleanup).
func destroyVM(client *goproxmox.Client, nodeName string, vmid int, debug bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	node, err := client.Node(ctx, nodeName)
	if err != nil {
		return
	}
	vm, err := node.VirtualMachine(ctx, vmid)
	if err != nil {
		// VM does not exist (the common case on first create) - nothing to do.
		return
	}
	if vm.IsRunning() {
		if task, err := vm.Stop(ctx); err == nil {
			task.Wait(ctx, time.Second, time.Minute)
		} else if debug {
			log.Logf(0, "proxmox: failed to stop VM %v: %v", vmid, err)
		}
	}
	if task, err := vm.Delete(ctx); err == nil {
		task.Wait(ctx, time.Second, 2*time.Minute)
	} else if debug {
		log.Logf(0, "proxmox: failed to delete VM %v: %v", vmid, err)
	}
}

func (inst *instance) Close() error {
	close(inst.closed)
	if inst.consolew != nil {
		inst.consolew.Close()
	}
	destroyVM(inst.client, inst.nodeName, inst.vmid, inst.debug)
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	if inst.forwardPort != 0 {
		return "", fmt.Errorf("proxmox: Forward port already set")
	}
	if port == 0 {
		return "", fmt.Errorf("proxmox: Forward port is zero")
	}
	inst.forwardPort = port
	return fmt.Sprintf("127.0.0.1:%v", port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	err := vmimpl.SCP(hostSrc, vmDst, vmimpl.SCPOptions{
		Debug:   inst.debug,
		Key:     inst.Key,
		Port:    inst.Port,
		User:    inst.User,
		Addr:    inst.Addr,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	// Stream the kernel serial console by ssh-ing into the node and reading the VM's
	// serial unix socket. This survives a guest hang/panic, unlike reading dmesg over
	// the guest ssh connection.
	socat := fmt.Sprintf("socat - UNIX-CONNECT:/var/run/qemu-server/%v.serial0", inst.vmid)
	dmesg, err := vmimpl.OpenConsoleByCmd("ssh", inst.nodeSSHArgs(socat))
	if err != nil {
		return nil, nil, err
	}
	inst.consolew = dmesg

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		dmesg.Close()
		return nil, nil, err
	}
	rpipeErr, wpipeErr, err := osutil.LongPipe()
	if err != nil {
		dmesg.Close()
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}

	args := vmimpl.SSHArgsForward(inst.debug, inst.Key, inst.Port, inst.forwardPort, false)
	args = append(args, inst.User+"@"+inst.Addr, "cd / && exec "+command)
	if inst.debug {
		log.Logf(0, "running command: ssh %#v", args)
	}
	cmd := osutil.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipeErr
	if err := cmd.Start(); err != nil {
		dmesg.Close()
		rpipe.Close()
		wpipe.Close()
		rpipeErr.Close()
		wpipeErr.Close()
		return nil, nil, err
	}
	wpipe.Close()
	wpipeErr.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("console", vmimpl.OutputConsole, dmesg)
	merger.Add("ssh", vmimpl.OutputStdout, rpipe)
	merger.Add("ssh-err", vmimpl.OutputStderr, rpipeErr)

	return vmimpl.Multiplex(ctx, cmd, merger, vmimpl.MultiplexConfig{
		Console: dmesg,
		Close:   inst.closed,
		Debug:   inst.debug,
		Scale:   inst.timeouts.Scale,
	})
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	if inst.os == targets.Linux {
		output, wait, _ := vmimpl.DiagnoseLinux(rep, inst.ssh)
		return output, wait
	}
	return nil, false
}

func (inst *instance) Info() ([]byte, error) {
	return []byte(fmt.Sprintf("vmid: %v\nnode: %v (%v)\n", inst.vmid, inst.nodeName, inst.nodeAddr)), nil
}

// ssh runs a command on the guest and returns its combined output.
func (inst *instance) ssh(args ...string) ([]byte, error) {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.Key, inst.Port, false), inst.User+"@"+inst.Addr)
	return osutil.RunCmd(time.Minute, "", "ssh", append(sshArgs, args...)...)
}

// nodeSSHArgs builds ssh arguments for connecting to the Proxmox node (not the guest).
// When no explicit key is given we rely on the system ssh configuration/agent, which
// matches a keyless-root-ssh-to-nodes setup.
func (inst *instance) nodeSSHArgs(command string) []string {
	systemSSHCfg := inst.cfg.NodeSSHKey == ""
	args := vmimpl.SSHArgs(inst.debug, inst.cfg.NodeSSHKey, 22, systemSSHCfg)
	args = append(args, inst.cfg.NodeSSHUser+"@"+inst.nodeAddr)
	return append(args, command)
}

// encodeSSHKeys percent-encodes an SSH public key for the Proxmox cloud-init
// `sshkeys` parameter. Proxmox URL-decodes the value server-side and rejects a
// literal '+' (and other reserved bytes) in it. url.QueryEscape encodes '+',
// '/' and '=' correctly but renders spaces as '+', so convert those back to %20.
func encodeSSHKeys(pubKey string) string {
	return strings.ReplaceAll(url.QueryEscape(strings.TrimSpace(pubKey)), "+", "%20")
}

// addIPv4 returns the IPv4 address that is `offset` addresses after base.
func addIPv4(base string, offset int) (string, error) {
	ip := net.ParseIP(base).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid IPv4 address %q", base)
	}
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += uint32(offset)
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String(), nil
}

// sanitizeName turns an arbitrary string into a valid Proxmox VM name (a DNS label).
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		res = "syzkaller"
	}
	return res
}
