## How To:

# STEP 1: Install
  - Install proxmox using local-zfs
  - from your "build" machine as root ssh-copy-id <proxmox> select yes to accept, ensure you cah ssh to proxmox
  - https://github.com/foundrybot-ca/foundryBot.git
  - chmod +x deploy.sh
  - sudo su -
  - vim deploy.sh adjust to taste (the default usees vmid 2000-2010 10.100.10.0/24 and multiple wireguard networks for examples
  - ./deploy.sh

note: defualt vmID's 2000-2012
-master, preconfigured with Salt/Ansible and optional Semaphore, keys are magically copied to minions (included)
-prometheus, scrape your logs securely regardless of location, simply allow the udp port (optional)
-grafana, automatically import your bootstrapped devices into pre-defined dashboards (optional) 
-k8s, optional jumphost
-storage, storage netowrk backplane (note: 1420 mtu) (optional)
-k8s-lb1, basic ha proxy loadbalancer x2
-k8s-lb2
-k8s-cp1, k8s control nodes x3
-k8s-cp2
-k8s-cp3
-k8s-w1, k8s worker nodes x3
-k8s-w2
-k8s-w3

# STEP 2: DEPLOY

At this point you are left with a MASTER and 12 MINIONS, basically blanks. Configure as you like with what ever tool you want to use, simply bind it to the internal wireguard ip and go.

OR:

Ive included the apporiate salt configuraion that will "magically" just build the whole world and also a basic set of tools to get you going.




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
