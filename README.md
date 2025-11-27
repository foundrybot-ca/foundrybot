## How To:

Step 1: Install proxmox using local-zfs
Step 2: from your "build" machine as root ssh-copy-id <proxmox> select yes to accept, ensure you cah ssh to proxmox
Step 3: https://github.com/foundrybot-ca/foundryBot.git

What you need (2 machines, that’s it)


# Notes:
## 1. A build machine
Any modern Linux box (laptop, workstation, or another VM).
Bash + standard tools (curl, xorriso, qemu-img, etc.).
A Debian ISO (Trixie / 13.x works out of the box).
Your SSH key (id_ed25519.pub) for the admin user.

## 2. A target
Proxmox node (this example), or
Cloud account (AWS / other KVM-based clouds), or
Bare-metal box that can boot UEFI images.

# The script itself is agnostic:

it just builds signed images and talks to whatever can load them.
Proxmox is the default “easy path” to show the idea.

# clonebot.sh - point and shoot template builder/deployment script with cpef and zfs zvols
