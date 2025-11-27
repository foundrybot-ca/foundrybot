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
