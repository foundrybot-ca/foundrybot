# FoundryBot

> **Build once, deploy everywhere. Prove first, then pull. Bind private, never public.**  
> Secure-by-default image and installer repacking for real-world ops — darksite-first, reproducible, and stubbornly simple.

---

## Why this exists

FoundryBot is a hobby-turned-power-tool: a build/deploy foundry that makes **full‑custody zero trust** practical on day one.  
It doesn’t try to replace your tools — it hardens the **substrate** they run on:

- Private, encrypted **L3 hub‑and‑spoke** networks (WireGuard) come up before anything public.
- A **darksite** content store (≈2 TB) carries *everything* needed to rebuild the world offline.
- Repacked installers/images (Debian/Ubuntu/RHEL family) are **reproducible** and **version‑pinned**.
- Postinstall profiles (hardening, Docker, K8s, devstack) keep ops familiar but safer.

It’s “Kubernetes‑like” in spirit — cattle, not pets — but pointed at **hypervisors and images** for deploy/DR automation across any execution target.

---

## What it does well

- **Works in any current environment.** Air‑gapped labs, clouds, colo, remote ISPs — if you can host a private UDP and a content share, you’re in.  
- **Rebuild, don’t restore.** Disaster recovery is **deterministic**: rebuild the node and stream pinned userland; no drift from “latest.”  
- **Private first-boot.** Nodes join encrypted fabrics (`wg*`) and bind services to those IPs; public listeners stay closed.  
- **Same tools, safer path.** Keep Ansible/Terraform/Packer/CI; FoundryBot repacks images and supplies identity & networks.  
- **Fleet ergonomics.** Target “clusters” (e.g., K8s workers vs. managers), rotate WireGuard peers at scale, and rematerialize images on demand.

---

## Legacy vs. FoundryBot (concrete deltas)

| Legacy “push to public IP” | FoundryBot “pull on private fabric” |
|---|---|
| Stock image, bootstrap over Internet; public SSH/agents | Minimal signed base; `wg*` fabric comes up first; no public bootstrap |
| Mirrors drift; restores pick up **new** package versions | Darksite with **frozen, pinned** artifacts; rebuild yields the **exact** point-in-time |
| VLANs/SGs approximate isolation | Deterministic **WireGuard L3 hub‑and‑spoke**, per‑fabric allowlists |
| Snapshots/backups with unknown coherency | **Rebuildable** nodes; boot‑env rollback; optional ZFS snapshots/sanoid |
| Secrets/keys spread early | Tight custody: **only the `admin` key** at bring‑up; explicit admission thereafter |

**Default access posture:** until you rotate/expand, **only the `admin` key** can reach bootstrap/control surfaces. You can rename/rotate on day‑zero.

---

## File descriptions (WIP but functional)

### `apply.py` — *Network Fabrics Applier (WIP)*
- Purpose: apply **network fabrics** and minimal role packages.  
- Scope: focuses on fabric definition & binding; package install strictly “as per role.”  
- Status: work‑in‑progress; expect rapid iteration as K8s and identity workflows settle.

### `build.sh` — *World Builder (darksite + payload)*
- Pulls **every single file** required to (re)build the world — *from your repo manifests and artifact lists*.  
- Produces a **darksite** with *all* payloads (packages, images, overlays) **included and version‑controlled**.  
- DR angle: if a hypervisor dies 8 months from now, you rebuild it and **replay the exact build** with the **exact files** from 8 months ago.  
  - No “restore to latest” surprises.  
  - No chasing stale mirrors.  
  - It’s not a backup; it’s a **time capsule** you can boot.

### `clonebot.sh` — *Proxmox Clone Orchestrator (cloud‑init aware)*
- Completely automates Proxmox clone creation — no more click‑next‑next‑yes.  
- Clones are **cloud‑init enabled** and **unique** (machine‑id, SSH host keys, instance‑id).  
- Deploys a **fresh** instance by executing `postinstaller.sh` on first boot, i.e., not a brittle “frozen VM,” but a **re‑materialized** deployment.  
- Philosophy: don’t “restore a clone,” just **blow it away and rebuild**; identity and role are asserted on first boot.  
- Ops pattern: detect failure (e.g., “service failed 3 times”), nuke, and replace from the golden recipe — similar to **Kubernetes** reconciliation.

### `deploy.sh` — *(WIP)* Applys all states for the "default example" 
- A staging ground for CKA‑style ops: today it demos simple flows; tomorrow it might be point‑and‑shoot desktops, follow‑the‑sun, or SDN bring‑up.  
- Execution targets: usable across Anaconda‑based installers (CentOS/Rocky/RHEL and cousins), Debian/Ubuntu autoinstall, and cloud images.
- Added "shl" a "example" of a ways to use salt to command 3, 300, or 3M targets to effortlessly conducint day to day operations
- or deploy legions of k8s resources

---

## Usage sketches

- **Cron‑driven fleets:** Upload a golden image at 05:00, run cloning at 05:10, and by 06:30 a **fleet of 100 workstations** appears, each pre‑personalized (per‑user golden image), toss in your favorite xRDP, presto .. remote fleet!
- **Power sanity:** Shut down the damn servers when not in use. Save power, cost, heat — and avoid long‑lived drift. :)
- **Service reliability:** Treat instances as disposable; let health checks trigger **rebuilds** instead of hand‑repair.

---

## DR philosophy — rebuild > restore

- **Rebuild** is deterministic (pinned content + scripted image/materialization).  
- **Restore** often drifts (backups restore into a **newer world** with subtly different dependencies).  
- With optional **ZFS + sanoid** (WIP on Linux), MTTR is:  
  1) revert `/boot` or UEFI entry (boot‑env),  
  2) reboot the fleet, or  
  3) **rebuild the node** and let every hosted VM **recreate itself** from the darksite + postinstall.  
- Worst case: roll back to the last snapshot (~15 minutes ago) or re‑emit the exact image from last release.

> Note on ZFS: on Linux it isn’t in‑kernel; until native integration, some rough edges are expected. It’s WIP here; and Cannonical has had zfs since version 12 its still not "baked-in" but thats another story lol

---

## K8s status (WIP)

I’m new to Kubernetes (CKA studies in progress). FoundryBot borrows the *idea* of reconciliation (cattle, not pets) and applies it to **hypervisor‑level deploy/DR**.  
Goal: “point‑and‑shoot” pods and node bring‑up over private fabrics. **Training starts on the Dec 8th 2025 — can’t wait.**

---

## Compatibility & scope

- **Distros/Installers:** Debian/Ubuntu (preseed/autoinstall), RHEL/Rocky/CentOS (Kickstart/Anaconda), plus cloud images.
- **Targets:** Proxmox templates, VMs, bare metal, cloud AMIs.  
- **Networks:** Multi‑fabric WireGuard hub‑and‑spoke; deterministic addressing (e.g., `10.78.0.0/16`, hubs at `.1`).
- **Identity:** Cloud‑init friendly; uniqueness enforced (machine‑id, SSH host keys, instance‑id).  
- **Keys:** **NOTE: you MUST provide atleast 1 admin public key** user/pw log in is disabled! .. only ADMIN keys are permited, theere is no USER@SSH by default. (feel free to change it if you liek but Im security junky so the ONLY way to access the network internally is from the MASTER) see "shl" command for more along with the a few examples.
    
---

## FAQ

**Why Bash?**  
becasue it has 0 dep's and works with every known linux kernel. Enfact the ENTRE deployment script uses 27 packages and a single bash script. Bash is the right tool for the job.  ie: there is no python in eairly boot when no OS is even installed.. but bash is :)

**The script is a messy”**  
Yes — I know, but its WIP and atomic, and I hate rummaging through files, hah!

**Is this a backup solution?**  
No. It’s a **reproducible build + darksite** approach. You don’t restore mystery tarballs; you **recreate** exact systems using pinned artifacts.

**How does this reduce MTTR?**  
Its a noon-nonsence time capsule.. its not possible to, loose a back up, or have something fail and need to be repaired.. and with linux becasue you RELY on 3rd party repos. You backup process "ASSUMES" that a repo you used way back when. still exists.  All of that can fail, and even when it doesnt fail you can potentially end up like the AWS outage where you fix one thing and break someething else.. that not possible now, you either rever to the last snapshot/bookmark.. or you build from scratch.. hence the power of snapshots/replication and clones with zfs. Its stupid powerful!

**Do I have to change my toolchain?**  
Nope, not at all!!. Enfact it's super easy and works with ANY CIDC pipeline!!.  With a couple of steps.

#1 .. take the "output" / "artifacts/packages" of your existing pipeline and add it to the "darksite directory"
#2 .. modify the postinstall.sh
      - sign and add your darksite repo
      - modify the existing apt install to include what ever you like

once it works as expected, simply use it as the source for Terraform and it will treat it exactly the same as any other image.. The differance is this one has built in kernel support for wireguard and allows to you create as many netowrk fabrics as you like .. And you dont have to change a thing..

granted: as I said before, this is a VERY powerful, "tool" .. but at the same time, not a "magical" bullet, what it does REALLY WELL is .. OFFER ALTERNITIVES and differant ways of doing things.. ie: host your own vault, send your tokens via the L3 tunnel, not hashicorps cloud server. You literally ahve 100% control, and the option to do it with 0 USERLAND/NETWORK.
      

**Is ZFS required?**  
No. It’s a WIP enhancement. The rebuild‑over‑restore ethos stands with or without ZFS.


---

## Quick start (mental model)

1. Put artifacts into `darksite/` (≈2 TB).  
2. Define fabrics: `wg0=bootstrap`, `wg1=control (10.78.0.0/16)`, `wg2=data`, `wg3=storage`.  
3. Run `build.sh` to mint the darksite + payload and repack images.  
4. Use `clonebot.sh` to fan out **cloud‑init** clones with unique identity.  
5. Bind services to `wg*` IPs (e.g., SSH → `10.78.0.1:22`), close public listeners.  
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

# ** Requirements:**

_**1. A build machine where the ./deploy.sh will be executed FROM**_
Any modern Linux box will do (laptop, workstation, or another VM).
Bash + standard tools (curl, xorriso, qemu-img, etc.).
A Debian ISO (Trixie / 13.x works out of the box).
Your SSH key (id_ed25519.pub) for the admin user.

**** THIS SCRIPT IS DESIGNED TO TARGET A REMOTE HOST ****
images are built and stored on the build server

Install Packages to Build Server
```bash
sudo apt-get update && sudo apt-get install -y \
  xorriso syslinux-common isolinux grub-pc-bin grub-efi-amd64-bin \
  debootstrap squashfs-tools genisoimage \
  qemu-utils parted e2fsprogs \
  awscli curl jq rsync
```

_**2. A target HW Hypervisor/Server that will run the instances
Proxmox node (for this example)**_, or
Cloud account (AWS / other KVM-based clouds), or
Bare-metal box that can boot UEFI images.

The script itself is agnostic: 
it just builds signed images and talks to whatever can load them. 
Proxmox is the default “easy path” to show the idea.

# **INSTALL & EXECUTE**

**STEP 1:** _Install the Target Hypervisor/HW_
  - Install proxmox to you TARGET server
  - as root **ssh-copy-id** to **proxmox** && ensure your **BUILD** machine can ssh to proxmox
  - git clone https://github.com/foundrybot-ca/foundryBot.git on your BUILD server
  - config as needed
  - chmod +x deploy.sh
  - sudo su -
  - ./deploy.sh

# **VMS CREATED:**
  -  **master** - preconfigured with Salt/Ansible and optional Semaphore, keys are magically copied to minions (included)
  -  **prometheus** - scrape your logs securely regardless of location, simply allow the udp port (optional)
  -  **grafana** - automatically import your bootstrapped devices into pre-defined dashboards (optional) 
  -  **k8s** - jumphost (optional)
  -  **storage** - storage netowrk backplane (note: 1420 mtu) (optional)
  -  **k8s-lb1** - basic ha proxy loadbalancer x2
  -  **k8s-lb2**
  -  **k8s-cp1** - k8s control nodes x3
  -  **k8s-cp2**
  -  **k8s-cp3**
  -  **k8s-w1** - k8s worker nodes x3
  -  **k8s-w2**
  -  **k8s-w3**

# ** STEP 2: DEPLOY Configuration**
At this point you are left with a MASTER and 12 blank MINIONS, this is by design to allow for existing tools to takeover,build or re-deployments and netwrok meshes

BUT, Ive also included a couplee of tools to get you started.

**# Optional**
The script can also be deployed via EXPORTS and called from cron for "timed" deployments, ie: spin up at 7am, teardown at 4pm .. power off.

**Examples:**
Deploy to proxmox using the script defaults
```bash
ISO_ORIG=/root/debian-13.1.0-amd64-netinst.iso \
TARGET=proxmox-all \
./deploy.sh
```

Proxmox cluster on dragon with custom admin + GNOME
```bash
ISO_ORIG=/root/debian-13.1.0-amd64-netinst.iso \
INPUT=2 \                             # 2|dragon -> 10.100.10.226
TARGET=proxmox-cluster \
ADMIN_USER=admin \
GUI_PROFILE=gnome \
./deploy.sh
```
