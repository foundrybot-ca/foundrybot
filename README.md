# FoundryBot

> **Build once, deploy everywhere. Prove first, then pull. Bind private, never public.**  
> Secure-by-default image and installer repacking for real-world ops — darksite‑first, reproducible, and stubbornly simple.

---

## Why this exists

FoundryBot is a build/deploy tool-kit that makes **full‑custody zero trust** practical for anyone. 
It doesn’t try to replace your tools — it hardens the **substrate** they run on:

- Private, encrypted **L3 hub‑and‑spoke** networks (WireGuard) come up before anything public.
- A **darksite** content store (≈ 2 TB) carries *everything* needed to rebuild the world offline.
- Repacked installers/images (Debian/Ubuntu/RHEL family) are **reproducible** and **version‑pinned**.
- Postinstall profiles (hardening, Docker, K8s, devstack) keep ops familiar but safer.

It’s “Kubernetes‑like” in spirit — cattle, not pets — but pointed at **hypervisors and images** for deploy/DR automation across any execution target.

---

## What it does well

- **Works in any current environment.** Air‑gapped labs, clouds, colo, remote ISPs — if you can host a private UDP port and a content share, you’re in.  
- **Works well** with ZFS for seamless snapshots, rollbacks, and clones—adding ZFS-grade durability, resilience, and security.
- **Rebuild/Clone, don’t restore.** Disaster recovery is **deterministic**: rebuild the node and stream pinned userland; no drift from “latest.”  
- **Private first‑boot.** Nodes join encrypted fabrics (`wg*`) and bind services to those IPs; public listeners stay closed.  
- **Same tools, safer path.** Keep Ansible/Terraform/Packer/CI; FoundryBot repacks images and supplies identity & networks.  
- **Fleet ergonomics.** Target “clusters” (e.g., K8s workers vs. managers), rotate WireGuard peers at scale, and re‑materialize images on demand.

---

## Legacy vs. FoundryBot (concrete deltas)

| Legacy “push to public IP” | FoundryBot “pull on private fabric” |
|---|---|
| Stock image, bootstrap over Internet; public SSH/agents | atm: uses SSH, ideally it should be a "deploy" appliance with api and "baked" into its usecase. this tool allows you to be as simple or as complex as you like and when you done you have platfourm.
| Mirrors drift; restores pick up **new** package versions | Darksite with **frozen, pinned** artifacts; rebuild yields the **exact** point‑in‑time |
| VLANs/SGs approximate isolation | Deterministic **WireGuard L3 hub‑and‑spoke**, per‑fabric allowlists |
| Snapshots/backups with unknown coherency | **Rebuildable** nodes; boot‑env rollback; optional ZFS snapshots/sanoid |
| Secrets/keys spread early | Tight custody: **only the `admin` key** at bring‑up; explicit admission thereafter |

**Default access posture:** until you rotate/expand, **only the `admin` key** can reach bootstrap/control surfaces. You can rename/rotate on day‑zero.

---

## File descriptions (WIP but functional)

### `apply.py` — *Network Fabrics Applier (WIP)*
- **Currently** the *./deploy.sh* process is broken in two, ie: I didnt "bake in" things to ensure that it can intergrate into an existing wg fabric.
- **This Version** brings the *"cluster"* that is deployed using the *deploy* tool, it applys all of the salt states and builds the backend wireguard fabirc
- **NOTE** the script by defualt is designed to intergrate with existing stuff.. henc it uses the public netowrk to to inital connectioons.. the *APPLY* script is ment to build the rest fo the world, and when complete.. then .. move over to the wireguard netwwork. Ie: its not going to break anything to try.

### `build.sh` — *World Builder (darksite + payload)*
- Pulls **every single file** required to (re)build the world — *from your repo manifests and artifact lists*.  
- Produces a **darksite** with *all* payloads (packages, images, overlays) **included and version‑controlled**.  
- DR angle: if a hypervisor dies 8 months from now, you rebuild it and **replay the exact build** with the **exact files** from 8 months ago.  
  - No “restore to latest” surprises.  
  - No chasing stale mirrors.  
  - It’s not a backup; it’s a **time capsule** that runs the *"postinstall.sh"* on first boot.

### `clonebot.sh` — *Proxmox Clone Orchestrator (cloud‑init aware)*
- Completely automates Proxmox clone creation — no more click‑next‑next‑yes.  
- Clones are **cloud‑init enabled** and **unique** (machine‑id, SSH host keys, instance‑id).  
- Deploys a **fresh** instance by executing `postinstaller.sh` on first boot, i.e., not a brittle “frozen VM,” but a **re‑materialized** deployment.  
- Philosophy: don’t “restore a clone,” just **blow it away and rebuild**; identity and role are asserted on first boot.  
- Ops pattern: detect failure (e.g., “service failed 3 times”), nuke, and replace from the golden recipe — similar to **Kubernetes** reconciliation.

### `deploy.sh` — *(WIP)* This autmates the entire install process of any number of pre-defined VM's microvm's or container workloads” currently its deploying a kubernetes cluster.
- A staging ground for CKA‑style ops: today it demos simple flows; tomorrow it might be point‑and‑shoot desktops, follow‑the‑sun, or SDN bring‑up.  
- Execution targets: usable across Anaconda‑based installers (CentOS/Rocky/RHEL and cousins), Debian/Ubuntu autoinstall, and cloud images.  
- Adds **`shl`**, an example of using Salt to command 3, 300, or 3M targets for effortless day‑to‑day operations — or to deploy legions of K8s resources.

---

## Usage sketches

- **Cron‑driven fleets:** Upload a golden image at 05:00, run cloning at 05:10, and by 06:30 a **fleet of 100 workstations** appears, each pre‑personalized (per‑user golden image). Toss in your favorite xRDP and — presto — remote fleet!  
- **Power sanity:** Shut down the servers when not in use. Save power, cost, heat — and avoid long‑lived drift. 🙂  
- **Service reliability:** Treat instances as disposable; let health checks trigger **rebuilds** instead of hand‑repair.

---

## DR philosophy — rebuild > restore

- **Rebuild** is deterministic (pinned content + scripted image/materialization).  
- **Restore** often drifts (backups restore into a **newer world** with subtly different dependencies).  
- With optional **ZFS + sanoid** (WIP on Linux), MTTR is:  
  1) revert `/boot` or the UEFI entry (boot‑env),  
  2) reboot the fleet, or  
  3) **rebuild the node** and let every hosted VM **recreate itself** from the darksite + postinstall.  
- Worst case: roll back to the last snapshot (~15 minutes ago) or re‑emit the exact image from the last release.

> **Note on ZFS:** on Linux it isn’t in‑kernel; until native integration, some rough edges are expected. It’s WIP here. Canonical has exposed ZFS options for years, but it’s still not “baked‑in” on all platforms — another story for another day.

---

## K8s status (WIP)

I’m new to Kubernetes (CKA studies in progress). FoundryBot borrows the *idea* of reconciliation (cattle, not pets) and applies it to **hypervisor‑level** deploy/DR.  
Goal: “point‑and‑shoot” pods and node bring‑up over private fabrics. **Training starts on Dec 8, 2025 — can’t wait.**

---

## Compatibility & scope

- **Distros/Installers:** Debian/Ubuntu (preseed/autoinstall), RHEL/Rocky/CentOS (Kickstart/Anaconda), plus cloud images.  
- **Targets:** Proxmox templates, VMs, bare metal, cloud AMIs.  
- **Networks:** Multi‑fabric WireGuard hub‑and‑spoke; deterministic addressing (e.g., `10.78.0.0/16`, hubs at `.1`).  
- **Identity:** Cloud‑init‑friendly; uniqueness enforced (machine‑id, SSH host keys, instance‑id).  
- **Keys:** **NOTE: you MUST provide at least one admin public key.** Username/password login is disabled by default. Only **admin keys** are permitted (no `user@host` SSH by default). You can change this, but the default is strict. See the `shl` command and examples.

---

## FAQ

**Why Bash?**  
Because it has zero dependencies and works with every modern Linux. In fact, the **entire** deployment uses a small set of standard packages and a single Bash entrypoint. Bash is the right tool for early‑boot — there’s no Python when no OS is installed, but Bash is there. 🙂

**“The script is messy.”**  
Guilty — it’s **WIP and atomic**. The goal is functional reliability first, with minimal moving parts. Once the design settles, it will be split into clean modules.

**Is this a backup solution?**  
No. It’s a **reproducible build + darksite** approach. You don’t restore mystery tarballs; you **recreate** exact systems using pinned artifacts.

**How does this reduce MTTR?**  
It’s a no‑nonsense time capsule. You don’t lose backups or repair partial failures. Linux often relies on third‑party repos; traditional backups assume those repos still exist and are compatible. Here, you either revert to a snapshot/bookmark or you rebuild from scratch — avoiding the “fix one thing, break another” spiral. With snapshots/replication and ZFS, it’s **stupid powerful**.

**Do I have to change my toolchain?**  
Nope. It’s easy and works with **any CI/CD pipeline**:

1. Take the **outputs** (artifacts/packages) of your existing pipeline and add them to the `darksite/` directory.  
2. Modify `postinstall.sh`:  
   - sign and add your darksite repo  
   - extend the existing `apt install` with whatever you need

Once it behaves as expected, use it as the **source** for Terraform, etc. It will be treated like any other image — the difference is kernel‑level WireGuard support and as many network fabrics as you’d like, with **no changes** to your higher‑level tooling.

**Is ZFS required?**  
No. It’s a WIP enhancement. The rebuild‑over‑restore ethos stands with or without ZFS.

---

## Quick start (mental model)

1. Put artifacts into `darksite/` (≈ 2 TB).  
2. Define fabrics: `wg0=bootstrap`, `wg1=control (10.78.0.0/16)`, `wg2=data`, `wg3=storage`.  
3. Run `build.sh` to mint the darksite + payload and repack images.  
4. Use `clonebot.sh` to fan out **cloud‑init** clones with unique identity.  
5. Bind services to `wg*` IPs (e.g., SSH → `10.78.0.1:22`); close public listeners.  
6. Scale, rotate peers, and let health checks **recreate** failed instances.

---

## Status & roadmap

- **Working:** darksite builds, private fabrics, Proxmox clone automation, role‑based postinstall, single‑key custody at boot.  
- **WIP:** ZFS boot‑env polish on Linux, K8s integration, improved identity tooling, split‑out modules (post‑MVP).  
- **Stretch:** attestations, signed SBOMs everywhere, one‑click Packer pipelines, cross‑cloud AMI promotion.

---

## Inspiration / related work

- UNIX‑side cousin: **OccamBSD** — <https://github.com/michaeldexter/occambsd>  
- CKA journey credit: Alta3 training — starting on the 8th.

---

## In short

- **Prove first, then pull** (private fabrics before public anything).  
- **Rebuild, don’t restore** (darksite + pinned artifacts).  
- **Make the secure path the easy path** (bind to `wg*`, close the rest).  
- **It’s a hobby — and it’s stupid powerful.** Anyone can use it, anywhere, with the tools they already love.

---

# Requirements

**1) A build machine where `./deploy.sh` will be executed**  
Any modern Linux box (laptop, workstation, or another VM).  
Bash + standard tools (`curl`, `xorriso`, `qemu-img`, etc.).  
A Debian ISO (Trixie / 13.x works out of the box).  
Your SSH key (`~/.ssh/id_ed25519.pub`) for the admin user.

> **This script targets a remote host.** Images are built and stored on the build server.

**Install packages on the build server**
```bash
sudo apt-get update && sudo apt-get install -y \
  xorriso syslinux-common isolinux grub-pc-bin grub-efi-amd64-bin \
  debootstrap squashfs-tools genisoimage \
  qemu-utils parted e2fsprogs \
  awscli curl jq rsync
```

**2) A target hypervisor/server that will run the instances**  
- Proxmox node (for this example), or  
- Cloud account (AWS / other KVM-based clouds), or  
- Bare-metal box that can boot UEFI images.

The script itself is agnostic: it builds signed images and talks to whatever can load them.  
Proxmox is the default “easy path” to show the idea.

---

# Install & execute

**Step 1: Install the target hypervisor/HW**
- Install Proxmox on your **target** server.
- As `root`, `ssh-copy-id` to the Proxmox host and ensure your **build** machine can SSH to it.
- `git clone https://github.com/foundrybot-ca/foundryBot.git` on your build server.
- Configure as needed.
- `chmod +x deploy.sh`
- `sudo -i`
- `./deploy.sh`

---

# VMs created

- **master** — preconfigured with Salt/Ansible and optional Semaphore; keys are copied to minions (included)  
- **prometheus** — scrape logs securely regardless of location (open the UDP port as needed) *(optional)*  
- **grafana** — automatically imports bootstrapped devices into pre‑defined dashboards *(optional)*  
- **k8s** — jumphost *(optional)*  
- **storage** — storage network backplane *(note: 1420 MTU)* *(optional)*  
- **k8s-lb1** — basic HAProxy load balancer  
- **k8s-lb2**  
- **k8s-cp1** — K8s control planes (x3)  
- **k8s-cp2**  
- **k8s-cp3**  
- **k8s-w1** — K8s workers (x3)  
- **k8s-w2**  
- **k8s-w3**

---

# Step 2: Deploy configuration

At this point you have a **master** and 12 blank **minions**. This is by design so your existing tools can take over (builds, redeployments, network meshes).

I’ve also included a couple of tools to get you started.

> **Optional:**  
> The script can also be deployed via exported variables and called from cron for “timed” deployments — e.g., spin up at 07:00, tear down at 16:00, power off.

**Examples**

Deploy to Proxmox using the script defaults:
```bash
ISO_ORIG=/root/debian-13.1.0-amd64-netinst.iso \
TARGET=proxmox-all \
./deploy.sh
```

Proxmox cluster on “dragon” with custom admin + GNOME:
```bash
ISO_ORIG=/root/debian-13.1.0-amd64-netinst.iso \
INPUT=2 \                             # 2|dragon -> 10.100.10.226
TARGET=proxmox-cluster \
ADMIN_USER=admin \
GUI_PROFILE=gnome \
./deploy.sh
```
