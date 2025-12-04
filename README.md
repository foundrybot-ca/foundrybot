# FoundryBot  
**One foundation. Any cloud. Any hypervisor. Any hardware.**

A **minimal, self-contained OS foundry**:

- It **installs a fresh OS from scratch** every time.
- It **wires networking/storage/security/runtime** in a predictable way.
- It **produces images for any target** (clouds, hypervisors, bare metal, PXE).
- It can optionally **capture everything into a fully self-contained “darksite” bundle** that lets you rebuild years later with **zero external dependencies**.

It does **not** depend on **ANY** of these tools, but at the same works seemelessly **WITH ALL OF THEM**

- Git  
- Terraform  
- Packer
- Tailscale/Netbird
- Ansible/Salt/Puppet/Chef  
- Cloud-init  
- Any SaaS or third-party CI/CD

You only need **Bash** and a few standard tools. FoundryBot will happily integrate *with* your existing stack, but it does **not require** any of it.


---

## The Problem: Image Sprawl & Fragile Pipelines

Most teams end up with:

- An **AWS AMI**
- An **Azure image**
- A **VMware template**
- A **Proxmox/Cloud-Init template**
- A **bare-metal installer ISO**
- A **PXE rootfs**

Each is slightly different. Over time they **drift**, break in different ways, and slowly lock you into specific platforms and tools.

Typical issues:

- “Works in AWS but not in Azure/VMware.”
- Snapshots or images can’t be trusted after upgrades.
- Mirrors and package repos change or disappear.
- Your CI pipeline *requires* Git, Packer, Terraform, and a dozen other pieces just to get a basic OS running.
- Disaster recovery assumes “the cloud will be fine” and collapses when it isn’t.

**FoundryBot fixes this by rebuilding the world every time, from scratch, to a known-good release** using battle tested methods at its core **iso9660**


---

## The FoundryBot Model

FoundryBot gives you **two core entry points**:

- `deploy.sh` — fast, online, uses live Internet sources  
- `build.sh` — slow, offline-capable, creates a **fully self-contained CI/CD bundle**

Both follow the same philosophy:

> **Rebuild > restore.**  
> The host OS is disposable; the **last build** is the source of truth.


---

## `deploy.sh` — Online Foundation Builder

`deploy.sh` is the **day-to-day entry point**:

- Uses **traditional live Internet sources**:
  - Public Debian/Ubuntu/etc. mirrors
  - Public container registries
  - Normal HTTPS outbound
- Assumes a **forward-facing network device** with egress.
- Installs:
  - The **OS** from scratch
  - **Network plumbing** (L3/L2, VLANs, WG devices, etc. as configured)
  - **Storage plumbing** (ZFS/LVM/filesystems as configured)
  - **Container runtime** (Docker/containerd/CRIO, as applicable)
  - **Secure defaults** (nftables default-deny, SSH key-only, minimal exposed services)
- Sets up **WireGuard devices and keys**, but:
  - **No peers are added by default.**
  - You drop into your own mesh/overlay cleanly.

Once the foundation is laid, `deploy.sh` **hands off**:

- You can apply **your own configuration** with:
  - Ansible / Salt / Puppet / Chef / Bash / Terraform / etc.
- Or use the **optional** `apply.py` as a reference Phase-2 step.

**Key properties of `deploy.sh`:**

- Fast (relative to `build.sh`)
- Uses current upstream packages and registries
- No reliance on Git, Packer, Terraform, or any CM tool
- Perfect for:
  - Labs
  - CI pipelines
  - Day-to-day environment creation
  - “I just need a clean, secure, K8s-ready base today”


---

## `build.sh` — Self-Contained CI/CD Time Capsule

`build.sh` is the **full pipeline / time-capsule mode**.

Where `deploy.sh` uses live sources every time, `build.sh`:

- Downloads **all artifacts once**
- **Re-packs** them into a **darksite directory structure**
- Produces **self-contained images** that can be:
  - Moved to any cloud / hypervisor
  - Used to rebuild without any Internet access
  - Used to restore even if:
    - Cloud snapshots are broken
    - Repos have changed or vanished
    - The original region/provider is unavailable

Think of `build.sh` as:

> **A complete CI/CD pipeline baked into an image bundle.**  
> It captures **everything** needed to replay the build later.

### What `build.sh` Captures

- OS packages, kernels, installer bits
- Repo metadata at the time of build
- Container images and supporting binaries
- Your **deployment artifacts** for all targets:
  - AWS-specific configs
  - Azure-specific configs
  - On-prem/VMware/Proxmox tweaks
  - Any number of **per-target directories** under a darksite structure
- Optional:
  - Snapshots of VMs
  - Service data
  - Cluster templates

You can have **different configs per target** without duplicating the base OS:

- `darksite/aws/…`
- `darksite/azure/…`
- `darksite/proxmox/…`
- etc.

`build.sh` doesn’t care what you put there. It just makes sure it’s all **embedded** into the bundle.


### Behavioral Contract

- Every time you run `build.sh`, the **world is rebuilt** from scratch.
- The result of the **last `build.sh` run** becomes the **canonical release**.
- Any future `deploy.sh` runs that **consume that bundle** will **always return you to that last release**:
  - Same packages
  - Same kernel
  - Same artifacts
  - Same wiring defaults

This means:

> **You don’t trust the cloud.  
> You trust the last build.**


### `deploy.sh` vs `build.sh` Summary

| Mode       | Script      | Uses live Internet? | Self-contained bundle? | Typical Use Case                               |
|-----------|-------------|---------------------|------------------------|-----------------------------------------------|
| Online    | `deploy.sh` | Yes                 | No                     | Daily builds, CI, quick lab/test environments |
| Timecapsule | `build.sh` | Yes (during build only) | **Yes** (after build) | DR, compliance, long-lived environments, air-gapped/offline rebuilds |


---

## No Third-Party Tool Lock-In

A core design goal:

> **FoundryBot requires *no* third-party tooling at all.**

To run the pipeline you need:

- A POSIX-compliant **Bash**
- `sudo`
- A handful of common tools (exact list may vary, but conceptually minimal), e.g.:
  - `qemu-img`
  - `xorriso`
  - `ovmf` (for UEFI)
  - basic coreutils, `curl`, `sed`, `awk`, etc.

You do **not** need:

- Git (no `git` commands required)
- Terraform
- Packer
- Ansible/Salt/Puppet/Chef
- Tailscale/Netbird or other snd tools
- Any cloud-specific image tooling
- Any SaaS CI/CD service

FoundryBot **can** integrate into Git, Terraform, Ansible, etc. if you want — but that’s **your** choice, not a requirement.


---

## What FoundryBot Actually Produces

From a single build, FoundryBot can emit:

- **KVM/QEMU**
  - QCOW2 disks
  - Bootable ISO
- **Proxmox**
  - Uploadable VM templates
  - ISO for self-deploying instances
- **VMware (ESXi/vSphere)**
  - VMDK / OVA-compatible disks (via `qemu-img` convert)
- **AWS**
  - RAW disks suitable for `import-snapshot` → AMI
- **Azure**
  - Fixed VHDs suitable for `az image create`
- **GCP**
  - Tarball + RAW compatible with `gcloud compute images import`
- **Bare metal / USB**
  - Self-deploying ISO that installs the OS + wiring + your baseline
- **PXE/iPXE**
  - Kernel + initrd + parameters for autoinstall or darksite boot

All of these are derived from the **same foundation**. You never maintain multiple “golden images” — you maintain **one foundry**.


---

## Phase-1 vs Phase-2

FoundryBot is deliberately split into **two phases**:

### Phase-1: Foundation (FoundryBot responsibility)

- OS install from scratch
- Partitioning, filesystems, and/or ZFS/LVM (if configured)
- Network wiring
- Storage wiring
- Container runtime
- Secure defaults:
  - nftables default deny
  - SSH key-only auth
  - Services bound to intended planes
- WireGuard devices created, keys generated (no peers)

### Phase-2: Configuration/Policy (Your responsibility)

You decide how to configure:

- Kubernetes clusters
- Databases
- Applications
- Monitoring
- Identity and RBAC
- Mesh topology (WireGuard peers, etc.)

Options:

- **Use your tools:** Ansible / Salt / Puppet / Chef / Bash / etc.
- **Or use `apply.py`** as a reference implementation / optional helper.


---

## Disaster Recovery with FoundryBot

A typical DR flow with a `build.sh` artifact:

1. Region/cloud/hardware fails. Snapshots are broken or missing. Repos are unavailable.
2. You still have your **FoundryBot bundle / ISO / image** stored in:
   - Object storage
   - Tape
   - Another cloud
   - A USB disk in a safe
3. You:
   - Convert to the new platform (qcow2 → vhd → raw → etc.)
   - Boot the self-deploying ISO or template
4. FoundryBot:
   - Rebuilds the OS from the embedded artifacts
   - Restores embedded VMs/services (if included)
   - Recreates the exact state of the **last `build.sh` run**
5. You reapply Phase-2 configuration if needed and rejoin meshes/clusters.

**No dependence on:**

- Cloud snapshots
- Cloud images
- External package repos
- Cloud metadata services

Just the **bundle** and a hypervisor/metal that can boot it.


---

## Mental Model

If you want one sentence to explain FoundryBot:

> **Most people ship images. FoundryBot ships a foundry.**  
>  
> Every run **rebuilds the world from scratch**, and you always return to the **last release** you captured with `build.sh`.

If you have more than one “golden image”, you’ve already failed.  
FoundryBot gives you **one foundation, many targets, and one source of truth**.
