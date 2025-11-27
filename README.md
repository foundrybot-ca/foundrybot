# ** Requirements:**

1. **A build machind** AKA where the **./deploy.sh** will be executed **FROM**
Any modern Linux box will do (laptop, workstation, or another VM).
Bash + standard tools (curl, xorriso, qemu-img, etc.).
A Debian ISO (Trixie / 13.x works out of the box).
Your SSH key (id_ed25519.pub) for the admin user.

```bash
sudo apt-get update && sudo apt-get install -y \
  # --- ISO / boot tooling ---
  xorriso \
  syslinux-common isolinux \
  grub-pc-bin grub-efi-amd64-bin \
  squashfs-tools genisoimage \
  mtools dosfstools
```
**Recomended**
```
sudo apt-get update && sudo apt-get install -y \
  # --- filesystem / disk image plumbing ---
  debootstrap \
  parted gdisk e2fsprogs \
  qemu-utils qemu-system-x86 ovmf \
  # --- network / fetch / scripting ---
  curl wget ca-certificates \
  jq \
  rsync pv
```
**Optional**
```
sudo apt-get update && sudo apt-get install -y \
# --- dev / glue ---
  git \
  python3 python3-venv python3-pip \
  unzip zip p7zip-full \
  # --- cloud / automation helpers ---
  awscli \
  packer
```

**2. A target HW Hypervisor/Server** that will run the instances
Proxmox node (this example), or
Cloud account (AWS / other KVM-based clouds), or
Bare-metal box that can boot UEFI images.

The script itself is agnostic: 
it just builds signed images and talks to whatever can load them. 
Proxmox is the default “easy path” to show the idea.

# **How To:**

**STEP 1:** Install the Target Hypervisor/HW
  - Install proxmox using local-zfs
**STEP 2:** build/use a "build" machine &&
  - as root ssh-copy-id <proxmox-ip> && ensure you can ssh to proxmox
**STEP 3:** clone and modify deploy.sh     
  - git clone https://github.com/foundrybot-ca/foundryBot.git && cd foundryBot
  - chmod +x deploy.sh
  - sudo su -
  - vim deploy.sh adjust to taste (the default usees vmid 2000-2010 10.100.10.0/24 and multiple wireguard networks for examples
**STEP 4:** deploy the cluster, obtain coffee
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

At this point you are left with a MASTER and blank 12 MINIONS, this is by design as you may choose to use your own configuration tools.

BUT... I've also "pre-built" the master as a salt MASTER with predefined states that can be applied, and some basic cluster configuration tools and examples so you can build your own without starting from scratch.



additionally: Ive included some sample commands to help you along..
simply type "shl" from thee root terminal for help

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
