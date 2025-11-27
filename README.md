<https://foundrybot.ca>
```
# foundryBot is a one-touch deployment kit.

It’s a single Bash script that takes a stock Debian ISO, builds a small set of secure hardware/VM images, and boots them into a ready-to-manage cluster with a private WireGuard network already online.

## Think of it in two steps:

# Step 1 — Install the cluster: from your build machine, run the script once. It repacks the ISO, deploys the VMs/nodes, and wires up a native encrypted backplane.
# Step 2 — Manage the cluster: once it’s up, manage it with whatever you like: Salt, Ansible, kubectl, or your own tooling. Example Salt states are included but totally optional.

What you need (2 machines, that’s it)

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
```
