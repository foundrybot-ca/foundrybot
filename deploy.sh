#!/usr/bin/env bash

: <<'COMMENT'
deploy.sh — Kubernetes cluster builder for an entire VM host

Overview
--------
This script is a full-cluster deployment tool. Instead of configuring one node
at a time, it targets the *entire* VM host and builds a complete Kubernetes
cluster from scratch:

  - Creates the control-plane (master) VM
  - Creates one or more worker (minion) VMs
  - Wires them together into a working cluster

It is designed both for:
  - Fresh deployments (greenfield lab / CKA practice)
  - Rapid rebuilds after critical errors (wipe and re-create the whole cluster)

Base System
-----------
Each VM is built as a clean, reproducible base image. The intent is that any
configuration tool (kubectl, Ansible, Helm, Argo, etc.) can later layer on
workloads and policies without fighting “snowflake” hosts.

The base install includes:

  - A hub-and-spoke network layout
  - Three example point-to-point, Layer-3 WireGuard links
  - Native encryption between nodes at the network layer
  - No dependency on external DNS, DHCP, or other userland services

Because the WireGuard fabrics are brought up early and are logically
separated, every node always has a secure, direct path back to the master.

Motivation
----------
The goal is to model “borg-like”, self-healing infrastructure:

  - Nodes are secure by default (encrypted fabrics, minimal exposure)
  - The cluster can be re-created quickly from a known-good baseline
  - We treat nodes as replaceable "cattle", not fragile "pets"

Instead of spending hours or days trying to repair a broken cluster, you can
re-run this script, rebuild all VMs, and be back to a clean, working state in
minutes.

This makes deploy.sh ideal as:
  - A teaching and practice tool for CKA preparation
  - A reference implementation for immutable, reproducible Kubernetes clusters
  - A starting point for more advanced automation and GitOps workflows
COMMENT

set -euo pipefail

# =============================================================================
# Logging / error helpers
# =============================================================================

log()  { echo "[INFO]  $(date '+%F %T') - $*"; }
warn() { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err()  { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()  { err "$*"; exit 1; }

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found in PATH: $cmd"
}

# =============================================================================
# SSH helpers (build host → Proxmox / remote)
# =============================================================================

SSH_OPTS="-q \
  -o LogLevel=ERROR \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o GlobalKnownHostsFile=/dev/null \
  -o CheckHostIP=no \
  -o ConnectTimeout=6 \
  -o BatchMode=yes"

sssh() { ssh $SSH_OPTS "$@"; }
sscp() { scp -q $SSH_OPTS "$@"; }

# =============================================================================
# Preseed / installer behaviour
# =============================================================================
# These shape how the Debian installer runs inside the VM.

# PRESEED_LOCALE: system locale (POSIX-style).
#   Common: en_US.UTF-8, en_GB.UTF-8, fr_CA.UTF-8, de_DE.UTF-8
PRESEED_LOCALE="${PRESEED_LOCALE:-en_US.UTF-8}"

# PRESEED_KEYMAP: console keymap.
#   Examples: us, uk, de, fr, ca, se, ...
PRESEED_KEYMAP="${PRESEED_KEYMAP:-us}"

# PRESEED_TIMEZONE: system timezone (tzdata name).
#   Examples: America/Vancouver, UTC, Europe/Berlin, America/New_York
PRESEED_TIMEZONE="${PRESEED_TIMEZONE:-America/Vancouver}"

# PRESEED_MIRROR_COUNTRY: Debian mirror country selector.
#   "manual" = use PRESEED_MIRROR_HOST/PRESEED_MIRROR_DIR directly.
#   Otherwise: two-letter country code (e.g. CA, US, DE).
PRESEED_MIRROR_COUNTRY="${PRESEED_MIRROR_COUNTRY:-manual}"

# PRESEED_MIRROR_HOST: Debian HTTP mirror host.
#   Examples: deb.debian.org, ftp.ca.debian.org, mirror.local.lan
PRESEED_MIRROR_HOST="${PRESEED_MIRROR_HOST:-deb.debian.org}"

# PRESEED_MIRROR_DIR: Debian mirror directory path (typically /debian).
PRESEED_MIRROR_DIR="${PRESEED_MIRROR_DIR:-/debian}"

# PRESEED_HTTP_PROXY: HTTP proxy for installer.
#   Empty = no proxy. Example: http://10.0.0.10:3128
PRESEED_HTTP_PROXY="${PRESEED_HTTP_PROXY:-}"

# PRESEED_ROOT_PASSWORD: root password used by preseed.
#   Strongly recommended to override via env/secret.
PRESEED_ROOT_PASSWORD="${PRESEED_ROOT_PASSWORD:-root}"

# PRESEED_BOOTDEV: install target disk inside the VM.
#   Examples: /dev/sda, /dev/vda, /dev/nvme0n1
PRESEED_BOOTDEV="${PRESEED_BOOTDEV:-/dev/sda}"

# PRESEED_EXTRA_PKGS: space-separated list of extra packages installed at install time.
#   Example: "openssh-server curl vim"
PRESEED_EXTRA_PKGS="${PRESEED_EXTRA_PKGS:-openssh-server}"

# =============================================================================
# High-level deployment mode / target
# =============================================================================

# TARGET: what this script should do.
#   Typical values (depends on which functions you wire in):
#     proxmox-all        - full Proxmox flow (build ISO + master + minions)
#     proxmox-cluster    - build & deploy master + core minions
#     proxmox-k8s-ha     - build HA K8s layout on Proxmox
#     image-only         - build role ISOs only
#     export-base-image  - export master disk from Proxmox to qcow2
#     vmdk-export        - convert BASE_DISK_IMAGE → VMDK
#     aws-ami            - import BASE_DISK_IMAGE into AWS as AMI
#     aws-run            - launch EC2 instances from AMI
#     firecracker-bundle - emit Firecracker rootfs/kernel/initrd + helpers
#     firecracker        - run Firecracker microVMs
#     packer-scaffold    - emit Packer QEMU template
TARGET="${TARGET:-proxmox-all}"

# DOMAIN: base DNS domain for all VMs.
DOMAIN="${DOMAIN:-unixbox.net}"

# INPUT: logical Proxmox target selector (maps to PROXMOX_HOST).
INPUT="${INPUT:-1}"

case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *)        die "Unknown INPUT=$INPUT (expected 1|fiend, 2|dragon, 3|lion)" ;;
esac

# =============================================================================
# ISO source / Proxmox storage IDs
# =============================================================================

# ISO_ORIG: source Debian ISO used to build custom images.
#   Typical: netinst or DVD ISO path on the build host.
#ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-netinst.iso}"
ISO_ORIG="${ISO_ORIG:-/root/debian-13.2.0-amd64-netinst.iso}"

# ISO_STORAGE: Proxmox storage ID for ISO upload.
#   Examples: local, local-zfs, iso-store
ISO_STORAGE="${ISO_STORAGE:-local}"

# VM_STORAGE: Proxmox storage ID for VM disks.
#   Examples: local-zfs, ssd-zfs, ceph-data
VM_STORAGE="${VM_STORAGE:-local-zfs}"

# =============================================================================
# Master hub VM (control plane / hub)
# =============================================================================

# MASTER_ID: Proxmox VMID for master node.
MASTER_ID="${MASTER_ID:-2000}"

# MASTER_NAME: VM name in Proxmox.
MASTER_NAME="${MASTER_NAME:-master}"

# MASTER_LAN: master LAN IP (IPv4) on your Proxmox bridge.
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

# NETMASK: LAN netmask (e.g. 255.255.255.0 for /24).
NETMASK="${NETMASK:-255.255.255.0}"

# GATEWAY: default gateway on LAN for master/minions.
GATEWAY="${GATEWAY:-10.100.10.1}"

# NAMESERVER: space-separated list of DNS servers inside guests.
#   Example: "10.100.10.2 10.100.10.3 1.1.1.1"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

# =============================================================================
# Core minion VMs (classic 4-node layout)
# =============================================================================
# prom / graf / k8s / storage – these are the "core" non-K8s nodes.

PROM_ID="${PROM_ID:-2001}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.223}"
GRAF_ID="${GRAF_ID:-2002}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.222}"
K8S_ID="${K8S_ID:-2003}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.221}"
STOR_ID="${STOR_ID:-2004}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.220}"

# =============================================================================
# WireGuard hub addresses (planes / fabrics)
# =============================================================================
# WG0–WG3 live on the master; minions/K8s nodes get /32s carved out of them.
#
# Suggested mapping:
#   wg0 = bootstrap / access
#   wg1 = control / telemetry
#   wg2 = data (K8s, app traffic)
#   wg3 = storage / backup

WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"

# WG_ALLOWED_CIDR: comma-separated CIDRs allowed via WireGuard.
#   Default covers all four 10.77–10.80 /16 networks.
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# =============================================================================
# Per-minion WireGuard /32s (PROM / GRAF / K8S / STOR)
# =============================================================================

# Static /32s per role per fabric. Change only if you want a different scheme.
PROM_WG0="${PROM_WG0:-10.77.0.2/32}"; PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; PROM_WG2="${PROM_WG2:-10.79.0.2/32}"; PROM_WG3="${PROM_WG3:-10.80.0.2/32}"
GRAF_WG0="${GRAF_WG0:-10.77.0.3/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; GRAF_WG2="${GRAF_WG2:-10.79.0.3/32}"; GRAF_WG3="${GRAF_WG3:-10.80.0.3/32}"
K8S_WG0="${K8S_WG0:-10.77.0.4/32}";  K8S_WG1="${K8S_WG1:-10.78.0.4/32}";  K8S_WG2="${K8S_WG2:-10.79.0.4/32}";  K8S_WG3="${K8S_WG3:-10.80.0.4/32}"
STOR_WG0="${STOR_WG0:-10.77.0.5/32}"; STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; STOR_WG2="${STOR_WG2:-10.79.0.5/32}"; STOR_WG3="${STOR_WG3:-10.80.0.5/32}"

# =============================================================================
# Extended K8s HA layout VMs
# =============================================================================
# IDs/IPs assume a contiguous /24; adjust to match your LAN.

K8SLB1_ID="${K8SLB1_ID:-2005}"; K8SLB1_NAME="${K8SLB1_NAME:-k8s-lb1}"; K8SLB1_IP="${K8SLB1_IP:-10.100.10.213}"
K8SLB2_ID="${K8SLB2_ID:-2006}"; K8SLB2_NAME="${K8SLB2_NAME:-k8s-lb2}"; K8SLB2_IP="${K8SLB2_IP:-10.100.10.212}"

K8SCP1_ID="${K8SCP1_ID:-2007}"; K8SCP1_NAME="${K8SCP1_NAME:-k8s-cp1}"; K8SCP1_IP="${K8SCP1_IP:-10.100.10.219}"
K8SCP2_ID="${K8SCP2_ID:-2008}"; K8SCP2_NAME="${K8SCP2_NAME:-k8s-cp2}"; K8SCP2_IP="${K8SCP2_IP:-10.100.10.218}"
K8SCP3_ID="${K8SCP3_ID:-2009}"; K8SCP3_NAME="${K8SCP3_NAME:-k8s-cp3}"; K8SCP3_IP="${K8SCP3_IP:-10.100.10.217}"

K8SW1_ID="${K8SW1_ID:-2010}"; K8SW1_NAME="${K8SW1_NAME:-k8s-w1}"; K8SW1_IP="${K8SW1_IP:-10.100.10.216}"
K8SW2_ID="${K8SW2_ID:-2011}"; K8SW2_NAME="${K8SW2_NAME:-k8s-w2}"; K8SW2_IP="${K8SW2_IP:-10.100.10.215}"
K8SW3_ID="${K8SW3_ID:-2012}"; K8SW3_NAME="${K8SW3_NAME:-k8s-w3}"; K8SW3_IP="${K8SW3_IP:-10.100.10.214}"

# =============================================================================
# Per-node K8s WG /32s (extended layout)
# =============================================================================
# Mostly "don't touch" unless you want a different addressing plan.

K8SLB1_WG0="${K8SLB1_WG0:-10.77.0.101/32}"; K8SLB1_WG1="${K8SLB1_WG1:-10.78.0.101/32}"; K8SLB1_WG2="${K8SLB1_WG2:-10.79.0.101/32}"; K8SLB1_WG3="${K8SLB1_WG3:-10.80.0.101/32}"
K8SLB2_WG0="${K8SLB2_WG0:-10.77.0.102/32}"; K8SLB2_WG1="${K8SLB2_WG1:-10.78.0.102/32}"; K8SLB2_WG2="${K8SLB2_WG2:-10.79.0.102/32}"; K8SLB2_WG3="${K8SLB2_WG3:-10.80.0.102/32}"

K8SCP1_WG0="${K8SCP1_WG0:-10.77.0.110/32}"; K8SCP1_WG1="${K8SCP1_WG1:-10.78.0.110/32}"; K8SCP1_WG2="${K8SCP1_WG2:-10.79.0.110/32}"; K8SCP1_WG3="${K8SCP1_WG3:-10.80.0.110/32}"
K8SCP2_WG0="${K8SCP2_WG0:-10.77.0.111/32}"; K8SCP2_WG1="${K8SCP2_WG1:-10.78.0.111/32}"; K8SCP2_WG2="${K8SCP2_WG2:-10.79.0.111/32}"; K8SCP2_WG3="${K8SCP2_WG3:-10.80.0.111/32}"
K8SCP3_WG0="${K8SCP3_WG0:-10.77.0.112/32}"; K8SCP3_WG1="${K8SCP3_WG1:-10.78.0.112/32}"; K8SCP3_WG2="${K8SCP3_WG2:-10.79.0.112/32}"; K8SCP3_WG3="${K8SCP3_WG3:-10.80.0.112/32}"

K8SW1_WG0="${K8SW1_WG0:-10.77.0.120/32}"; K8SW1_WG1="${K8SW1_WG1:-10.78.0.120/32}"; K8SW1_WG2="${K8SW1_WG2:-10.79.0.120/32}"; K8SW1_WG3="${K8SW1_WG3:-10.80.0.120/32}"
K8SW2_WG0="${K8SW2_WG0:-10.77.0.121/32}"; K8SW2_WG1="${K8SW2_WG1:-10.78.0.121/32}"; K8SW2_WG2="${K8SW2_WG2:-10.79.0.121/32}"; K8SW2_WG3="${K8SW2_WG3:-10.80.0.121/32}"
K8SW3_WG0="${K8SW3_WG0:-10.77.0.122/32}"; K8SW3_WG1="${K8SW3_WG1:-10.78.0.122/32}"; K8SW3_WG2="${K8SW3_WG2:-10.79.0.122/32}"; K8SW3_WG3="${K8SW3_WG3:-10.80.0.122/32}"

# =============================================================================
# VM sizing (resources per role)
# =============================================================================
# Memory in MB, cores as vCPUs, disk in GB.

MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-4}";  MASTER_DISK_GB="${MASTER_DISK_GB:-40}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-32}"

K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

K8S_LB_MEM="${K8S_LB_MEM:-2048}"; K8S_LB_CORES="${K8S_LB_CORES:-2}";  K8S_LB_DISK_GB="${K8S_LB_DISK_GB:-16}"
K8S_CP_MEM="${K8S_CP_MEM:-8192}"; K8S_CP_CORES="${K8S_CP_CORES:-4}";  K8S_CP_DISK_GB="${K8S_CP_DISK_GB:-50}"
K8S_WK_MEM="${K8S_WK_MEM:-8192}"; K8S_WK_CORES="${K8S_WK_CORES:-4}";  K8S_WK_DISK_GB="${K8S_WK_DISK_GB:-60}"

# =============================================================================
# Admin / auth / GUI
# =============================================================================

# ADMIN_USER: primary admin account created in the guest.
ADMIN_USER="${ADMIN_USER:-todd}"

# ADMIN_PUBKEY_FILE: path to an SSH public key file.
#   If set and readable, content overrides SSH_PUBKEY.
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-}"

# SSH_PUBKEY: SSH public key string to authorize for ADMIN_USER.
SSH_PUBKEY="${SSH_PUBKEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgqdaF+C41xwLS41+dOTnpsrDTPkAwo4Zejn4tb0lOt todd@onyx.unixbox.net}"

# ALLOW_ADMIN_PASSWORD: whether password SSH auth is enabled for ADMIN_USER.
#   yes = enable password login (LAN-scoped by your firewall rules)
#   no  = key-only SSH auth
# Backward compat: ALLOW_TODD_PASSWORD also respected.
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-${ALLOW_TODD_PASSWORD:-no}}"

# GUI_PROFILE: what kind of GUI to install (if any).
#   server  = no full desktop; server-friendly bits only
#   gnome   = full GNOME desktop
#   minimal = minimal X/Wayland stack (implementation-specific)
GUI_PROFILE="${GUI_PROFILE:-server}"

# INSTALL_ANSIBLE: whether to install Ansible on master (yes|no).
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"

# INSTALL_SEMAPHORE: whether to install Semaphore (Ansible UI) on master.
#   yes - force install
#   try - attempt install; ignore failures
#   no  - skip
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-no}"

TMUX_CONF="${TMUX_CONF:-/etc/skel/.tmux.conf}"


# =============================================================================
# Build artifacts / disk image paths
# =============================================================================

# BUILD_ROOT: base directory on the build server for all outputs.
BUILD_ROOT="${BUILD_ROOT:-/root/builds}"
mkdir -p "$BUILD_ROOT"

# BASE_DISK_IMAGE: exported “golden” VM disk (qcow2 or raw).
#   Used as input for vmdk-export, aws-ami, etc.
BASE_DISK_IMAGE="${BASE_DISK_IMAGE:-$BUILD_ROOT/base-root.qcow2}"

# BASE_RAW_IMAGE: optional explicit raw image path (for tools needing raw).
BASE_RAW_IMAGE="${BASE_RAW_IMAGE:-$BUILD_ROOT/base-root.raw}"

# BASE_VMDK_IMAGE: default VMDK path (ESXi).
BASE_VMDK_IMAGE="${BASE_VMDK_IMAGE:-$BUILD_ROOT/base-root.vmdk}"

# =============================================================================
# AWS image bake / EC2 run
# =============================================================================

# AWS_REGION: AWS region (e.g. us-east-1, us-west-2, ca-central-1)
AWS_REGION="${AWS_REGION:-us-east-1}"

# AWS_PROFILE: AWS CLI profile to use (from ~/.aws/credentials).
AWS_PROFILE="${AWS_PROFILE:-default}"

# AWS_S3_BUCKET: S3 bucket used during AMI import.
AWS_S3_BUCKET="${AWS_S3_BUCKET:-foundrybot-images}"

# AWS_IMPORT_ROLE: IAM role for VM import (typically 'vmimport').
AWS_IMPORT_ROLE="${AWS_IMPORT_ROLE:-vmimport}"

# AWS_ARCH: AMI architecture (x86_64 | arm64).
AWS_ARCH="${AWS_ARCH:-x86_64}"

# AWS_INSTANCE_TYPE: EC2 instance type for builds / runs.
AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t3.micro}"

# AWS_ASSOC_PUBLIC_IP: whether to associate public IP on run (true|false).
AWS_ASSOC_PUBLIC_IP="${AWS_ASSOC_PUBLIC_IP:-true}"

# AWS_KEY_NAME: Name of EC2 KeyPair to inject.
AWS_KEY_NAME="${AWS_KEY_NAME:-clusterkey}"

# AWS_SECURITY_GROUP_ID: Security Group ID for run (required for aws-run).
AWS_SECURITY_GROUP_ID="${AWS_SECURITY_GROUP_ID:-}"

# AWS_SUBNET_ID: Subnet ID where instances will be launched.
AWS_SUBNET_ID="${AWS_SUBNET_ID:-}"

# AWS_VPC_ID: VPC ID (optional; some flows infer from subnet).
AWS_VPC_ID="${AWS_VPC_ID:-}"

# AWS_AMI_ID: The AMI ID to run (required for aws-run).
AWS_AMI_ID="${AWS_AMI_ID:-}"

# AWS_TAG_STACK: Base tag value for "Stack" or similar.
AWS_TAG_STACK="${AWS_TAG_STACK:-foundrybot}"

# AWS_RUN_ROLE: logical role name for instances launched by aws-run.
#   Examples: master, k8s, generic, worker
AWS_RUN_ROLE="${AWS_RUN_ROLE:-generic}"

# AWS_RUN_COUNT: number of instances to launch in aws-run.
AWS_RUN_COUNT="${AWS_RUN_COUNT:-1}"

# =============================================================================
# Firecracker microVM parameters
# =============================================================================

# FC_IMG_SIZE_MB: rootfs size when creating Firecracker images.
FC_IMG_SIZE_MB="${FC_IMG_SIZE_MB:-2048}"

# FC_VCPUS / FC_MEM_MB: default Firecracker vCPU count and RAM in MB.
FC_VCPUS="${FC_VCPUS:-2}"
FC_MEM_MB="${FC_MEM_MB:-2048}"

# FC_ROOTFS_IMG / FC_KERNEL / FC_INITRD: paths to Firecracker artifacts.
FC_ROOTFS_IMG="${FC_ROOTFS_IMG:-$BUILD_ROOT/firecracker/rootfs.ext4}"
FC_KERNEL="${FC_KERNEL:-$BUILD_ROOT/firecracker/vmlinux}"
FC_INITRD="${FC_INITRD:-$BUILD_ROOT/firecracker/initrd.img}"

# FC_WORKDIR: directory holding Firecracker configs/run scripts.
FC_WORKDIR="${FC_WORKDIR:-$BUILD_ROOT/firecracker}"

# =============================================================================
# Packer output paths
# =============================================================================

# PACKER_OUT_DIR: where Packer templates live.
PACKER_OUT_DIR="${PACKER_OUT_DIR:-$BUILD_ROOT/packer}"

# PACKER_TEMPLATE: path to generated QEMU Packer template.
PACKER_TEMPLATE="${PACKER_TEMPLATE:-$PACKER_OUT_DIR/foundrybot-qemu.json}"

# =============================================================================
# ESXi / VMDK export
# =============================================================================

# VMDK_OUTPUT: target VMDK path when exporting BASE_DISK_IMAGE.
VMDK_OUTPUT="${VMDK_OUTPUT:-$BASE_VMDK_IMAGE}"

# =============================================================================
# Enrollment SSH keypair (for WireGuard / cluster enrollment)
# =============================================================================

# ENROLL_KEY_NAME: filename stem for enroll SSH keypair.
ENROLL_KEY_NAME="${ENROLL_KEY_NAME:-enroll_ed25519}"

# ENROLL_KEY_DIR: directory to store enrollment keys under BUILD_ROOT.
ENROLL_KEY_DIR="$BUILD_ROOT/keys"

# ENROLL_KEY_PRIV / ENROLL_KEY_PUB: private/public key paths.
ENROLL_KEY_PRIV="$ENROLL_KEY_DIR/${ENROLL_KEY_NAME}"
ENROLL_KEY_PUB="$ENROLL_KEY_DIR/${ENROLL_KEY_NAME}.pub"

ensure_enroll_keypair() {
  mkdir -p "$ENROLL_KEY_DIR"
  if [[ ! -f "$ENROLL_KEY_PRIV" || ! -f "$ENROLL_KEY_PUB" ]]; then
    log "Generating cluster enrollment SSH keypair in $ENROLL_KEY_DIR"
    ssh-keygen -t ed25519 -N "" -f "$ENROLL_KEY_PRIV" -C "enroll@cluster" >/dev/null
  else
    log "Using existing cluster enrollment keypair in $ENROLL_KEY_DIR"
  fi
}

# =============================================================================
# Tool sanity checks
# =============================================================================

require_cmd xorriso || true
command -v xorriso >/dev/null || { err "xorriso not installed (needed for ISO build)"; }

SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }

log() { echo "[INFO]  $(date '+%F %T') - $*"; }
warn(){ echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err() { echo "[ERROR] $(date '+%F %T') - $*"; }
die(){ err "$*"; exit 1; }

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found in PATH: $cmd"
}

command -v xorriso >/dev/null || { err "xorriso not installed (needed for ISO build)"; }

# =============================================================================
# PROXMOX HELPERS
# =============================================================================

pmx() { sssh root@"$PROXMOX_HOST" "$@"; }

pmx_vm_state() { pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }

pmx_wait_for_state() {
  local vmid="$1" want="$2" timeout="${3:-2400}" start state
  start=$(date +%s)
  log "Waiting for VM $vmid to be $want ..."
  while :; do
    state="$(pmx_vm_state "$vmid")"
    [[ "$state" == "$want" ]] && { log "VM $vmid is $state"; return 0; }
    (( $(date +%s) - start > timeout )) && { err "Timeout: VM $vmid not $want (state=$state)"; return 1; }
    sleep 5
  done
}

pmx_wait_qga() {
  local vmid="$1" timeout="${2:-1200}" start; start=$(date +%s)
  log "Waiting for QEMU Guest Agent on VM $vmid ..."
  while :; do
    if pmx "qm agent $vmid ping >/dev/null 2>&1 || qm guest ping $vmid >/dev/null 2>&1"; then
      log "QGA ready on VM $vmid"; return 0
    fi
    (( $(date +%s) - start > timeout )) && { err "Timeout waiting for QGA on VM $vmid"; return 1; }
    sleep 3
  done
}

pmx_qga_has_json() {
  if [[ "${PMX_QGA_JSON:-}" == "yes" || "${PMX_QGA_JSON:-}" == "no" ]]; then
    echo "$PMX_QGA_JSON"; return
  fi
  PMX_QGA_JSON="$( pmx "qm guest exec -h 2>&1 | grep -q -- '--output-format' && echo yes || echo no" | tr -d '\r' )"
  echo "$PMX_QGA_JSON"
}

pmx_guest_exec() {
  local vmid="$1"; shift
  pmx "qm guest exec $vmid -- $* >/dev/null 2>&1 || true"
}

pmx_guest_cat() {
  local vmid="$1" path="$2"
  local has_json raw pid status outb64 outplain outjson

  has_json="$(pmx_qga_has_json)"

  if [[ "$has_json" == "yes" ]]; then
    raw="$(pmx "qm guest exec $vmid --output-format json -- /bin/cat '$path' 2>/dev/null || true")"
    pid="$(printf '%s\n' "$raw" | sed -n 's/.*\"pid\"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p')"
    [[ -n "$pid" ]] || return 2
    while :; do
      status="$(pmx "qm guest exec-status $vmid $pid --output-format json 2>/dev/null || true")" || true
      if printf '%s' "$status" | grep -Eq '"exited"[[:space:]]*:[[:space:]]*(true|1)'; then
        outb64="$(printf '%s' "$status" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
        if [[ -n "$outb64" ]]; then
          printf '%s' "$outb64" | base64 -d 2>/dev/null || printf '%b' "${outb64//\\n/$'\n'}"
        else
          outplain="$(printf '%s' "$status" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
          printf '%b' "${outplain//\\n/$'\n'}"
        fi
        break
      fi
      sleep 1
    done
  else
    outjson="$(pmx "qm guest exec $vmid -- /bin/cat '$path' 2>/dev/null || true")"
    outb64="$(printf '%s\n' "$outjson" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
    if [[ -n "$outb64" ]]; then
      printf '%b' "${outb64//\\n/$'\n'}"
    else
      outplain="$(printf '%s\n' "$outjson" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
      [[ -n "$outplain" ]] || return 3
      printf '%b' "${outplain//\\n/$'\n'}"
    fi
  fi
}

pmx_upload_iso() {
  local iso_file="$1" iso_base
  iso_base="$(basename "$iso_file")"
  sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base" || {
    log "ISO upload retry: $iso_base"; sleep 2
    sscp "$iso_file" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$iso_base"
  }
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${iso_base}\" && exit 0; sleep 1; done; exit 1" \
    || warn "pvesm list didn't show ${iso_base} yet—will still try to attach"
  echo "$iso_base"
}

pmx_deploy() {
  local vmid="$1" vmname="$2" iso_file="$3" mem="$4" cores="$5" disk_gb="$6"
  local iso_base
  log "Uploading ISO to Proxmox: $(basename "$iso_file")"
  iso_base="$(pmx_upload_iso "$iso_file")"
  pmx \
    VMID="$vmid" VMNAME="${vmname}.${DOMAIN}-$vmid" FINAL_ISO="$iso_base" \
    VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" \
    DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
qm destroy "$VMID" --purge >/dev/null 2>&1 || true

# Create VM with Secure Boot + TPM2
qm create "$VMID" \
  --name "$VMNAME" \
  --memory "$MEMORY_MB" --cores "$CORES" \
  --cpu host \
  --sockets 1 \
  --machine q35 \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} \
  --serial0 socket \
  --ostype l26 \
  --agent enabled=1,fstrim_cloned_disks=1

# UEFI firmware + Secure Boot keys
qm set "$VMID" --bios ovmf
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=1

# TPM 2.0 state
qm set "$VMID" --tpmstate ${VM_STORAGE}:1,version=v2.0,size=4M

# Attach installer ISO
for i in {1..10}; do
  if qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom 2>/dev/null; then
    break
  fi
  sleep 1
done

if ! qm config "$VMID" | grep -q '^ide2:.*media=cdrom'; then
  echo "[X] failed to attach ISO ${FINAL_ISO} from ${ISO_STORAGE}" >&2
  exit 1
fi

qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}

wait_poweroff() { pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }

boot_from_disk() {
  local vmid="$1"
  pmx "qm set $vmid --delete ide2; qm set $vmid --boot order=scsi0; qm start $vmid"
  pmx_wait_for_state "$vmid" "running" 600
}

seed_tmux_conf() {
  : "${ADMIN_USER:=todd}"
  : "${TMUX_CONF:=/etc/skel/.tmux.conf}"

  log "Writing tmux config to ${TMUX_CONF}"
  install -d -m0755 "$(dirname "$TMUX_CONF")"

  cat >"$TMUX_CONF" <<'EOF'
set -g mouse on
set -g history-limit 100000
setw -g mode-keys vi
bind -n C-Space copy-mode
EOF

  # Copy to root and admin user if they exist
  if id root >/dev/null 2>&1; then
    cp -f "$TMUX_CONF" /root/.tmux.conf
  fi
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    cp -f "$TMUX_CONF" "/home/${ADMIN_USER}/.tmux.conf"
    chown "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.tmux.conf"
  fi
}


# =============================================================================
# ISO BUILDER
# =============================================================================

mk_iso() {
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"

  local build="$BUILD_ROOT/$name"
  local mnt="$build/mnt"
  local cust="$build/custom"
  local dark="$cust/darksite"

  rm -rf "$build" 2>/dev/null || true
  mkdir -p "$mnt" "$cust" "$dark"

  (
    set -euo pipefail
    trap 'umount -f "$mnt" 2>/dev/null || true' EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    cp -a "$mnt/"* "$cust/"
    cp -a "$mnt/.disk" "$cust/" 2>/dev/null || true
  )

  # Darksite payload
  install -m0755 "$postinstall_src" "$dark/postinstall.sh"

  cat > "$dark/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (One-time)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/root/darksite/postinstall.sh
ConditionPathExists=!/root/.bootstrap_done

[Service]
Type=oneshot
Environment=SHELL=/bin/bash
ExecStart=/bin/bash -lc '/root/darksite/postinstall.sh'
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  # Seed env
  {
    echo "DOMAIN=${DOMAIN}"
    echo "MASTER_LAN=${MASTER_LAN}"
    echo "WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}"
    echo "GUI_PROFILE=${GUI_PROFILE}"
    echo "WG0_PORT=${WG0_PORT}"
    echo "WG1_PORT=${WG1_PORT}"
    echo "WG2_PORT=${WG2_PORT}"
    echo "WG3_PORT=${WG3_PORT}"
    echo "ALLOW_ADMIN_PASSWORD=${ALLOW_ADMIN_PASSWORD}"
    echo "ADMIN_USER=${ADMIN_USER}"
    echo "INSTALL_ANSIBLE=${INSTALL_ANSIBLE}"
    echo "INSTALL_SEMAPHORE=${INSTALL_SEMAPHORE}"
  } > "$dark/99-provision.conf"

  # Admin authorized key
  local auth_seed="$dark/authorized_keys.${ADMIN_USER}"
  if [[ -n "${SSH_PUBKEY:-}" ]]; then
    printf '%s\n' "$SSH_PUBKEY" > "$auth_seed"
  elif [[ -n "${ADMIN_PUBKEY_FILE:-}" && -r "$ADMIN_PUBKEY_FILE" ]]; then
    cat "$ADMIN_PUBKEY_FILE" > "$auth_seed"
  else
    : > "$auth_seed"
  fi
  chmod 0644 "$auth_seed"

  # Bake in enrollment keypair if present
  if [[ -f "$ENROLL_KEY_PRIV" && -f "$ENROLL_KEY_PUB" ]]; then
    install -m0600 "$ENROLL_KEY_PRIV" "$dark/enroll_ed25519"
    install -m0644 "$ENROLL_KEY_PUB"  "$dark/enroll_ed25519.pub"
  fi

  # ---------- EXTRA: WireGuard refresher baked into darksite ----------
  cat >"$dark/wg-refresh-planes.py" <<'PY'
#!/usr/bin/env python3
import subprocess, json, shutil, time, os
from pathlib import Path

WG_DIR = Path("/etc/wireguard")
PLANES = ["wg1", "wg2", "wg3"]
SALT_TARGET = "*"
SYSTEMD_UNIT_TEMPLATE = "wg-quick@{iface}.service"

def run(cmd, **kw):
    kw.setdefault("text", True); kw.setdefault("check", True)
    return subprocess.run(cmd, stdout=subprocess.PIPE, **kw).stdout

def salt_cmd(target, shell_cmd):
    out = run(["salt", target, "cmd.run", shell_cmd, "--out=json", "--static", "--no-color"]).strip()
    if not out:
        return {}
    s, e = out.find("{"), out.rfind("}")
    if s == -1 or e == -1 or e <= s:
        return {}
    try:
        return json.loads(out[s:e+1])
    except json.JSONDecodeError:
        return {}

def read_interface_block(conf_path):
    lines=[]
    with open(conf_path,"r") as f:
        for line in f:
            if line.strip().startswith("[Peer]"): break
            lines.append(line.rstrip("\n"))
    return lines

def get_hub_ip(conf_path):
    with open(conf_path,"r") as f:
        for line in f:
            st=line.strip()
            if st.startswith("Address"):
                try:
                    _, rhs = st.split("=",1)
                    ip = rhs.split("#",1)[0].strip().split("/",1)[0].strip()
                    return ip
                except ValueError:
                    pass
    return None

def build_peers_for_plane(iface):
    ips = salt_cmd(SALT_TARGET, f"ip -4 -o addr show dev {iface} 2>/dev/null | awk '{{print $4}}' | cut -d/ -f1")
    pubs = salt_cmd(SALT_TARGET, f"wg show {iface} public-key 2>/dev/null || true")
    peers=[]
    for minion, ip_out in sorted(ips.items()):
        ip=ip_out.strip()
        if not ip: continue
        pub=pubs.get(minion,"").strip()
        if not pub: continue
        peers.append({"minion":minion,"ip":ip,"pubkey":pub})
    return peers

def write_conf_for_plane(iface):
    p = WG_DIR / f"{iface}.conf"
    if not p.exists():
        print(f"[WARN] {p} missing; skip {iface}")
        return
    ts=time.strftime("%Y%m%d%H%M%S")
    shutil.copy2(p, p.with_suffix(p.suffix + f".bak.{ts}"))
    iface_lines = read_interface_block(p)
    hub_ip = get_hub_ip(p)
    peers = build_peers_for_plane(iface)
    newp = p.with_suffix(p.suffix + ".new")
    with open(newp,"w") as f:
        for line in iface_lines: f.write(line+"\n")
        f.write("\n")
        for peer in peers:
            ip=peer["ip"]
            if hub_ip and ip==hub_ip: continue
            f.write("[Peer]\n")
            f.write(f"# {peer['minion']} ({iface})\n")
            f.write(f"PublicKey = {peer['pubkey']}\n")
            f.write(f"AllowedIPs = {ip}/32\n\n")
    os.replace(newp,p)
    print(f"[INFO] Updated {p}")

def restart_plane(iface):
    unit = SYSTEMD_UNIT_TEMPLATE.format(iface=iface)
    try:
        subprocess.run(["systemctl","restart",unit],check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] restart {unit} failed: {e}")

def main():
    for iface in PLANES:
        print(f"=== {iface} ===")
        write_conf_for_plane(iface)
        restart_plane(iface)

if __name__=="__main__":
    main()
PY
  chmod 0755 "$dark/wg-refresh-planes.py"

  # ---------- EXTRA: Ansible seed baked into darksite ----------
  install -d -m0755 "$dark/ansible" "$dark/ansible/group_vars"

  cat >"$dark/ansible/inventory.yaml" <<'YAML'
all:
  vars:
    ansible_user: ansible
    ansible_ssh_private_key_file: /home/ansible/.ssh/id_ed25519
    ansible_python_interpreter: /usr/bin/python3
  children:
    lb:
      hosts:
        k8s-lb1.unixbox.net: { ansible_host: 10.78.0.101 }
        k8s-lb2.unixbox.net: { ansible_host: 10.78.0.102 }
    controlplane:
      hosts:
        k8s-cp1.unixbox.net: { ansible_host: 10.78.0.110 }
        k8s-cp2.unixbox.net: { ansible_host: 10.78.0.111 }
        k8s-cp3.unixbox.net: { ansible_host: 10.78.0.112 }
    workers:
      hosts:
        k8s-w1.unixbox.net:  { ansible_host: 10.78.0.120 }
        k8s-w2.unixbox.net:  { ansible_host: 10.78.0.121 }
        k8s-w3.unixbox.net:  { ansible_host: 10.78.0.122 }
    monitoring:
      hosts:
        grafana.unixbox.net:    { ansible_host: 10.78.0.3 }
        prometheus.unixbox.net: { ansible_host: 10.78.0.2 }
    storage:
      hosts:
        storage.unixbox.net: { ansible_host: 10.78.0.5 }
    misc:
      hosts:
        k8s.unixbox.net: { ansible_host: 10.78.0.4 }
YAML

  cat >"$dark/ansible/ansible.cfg" <<'CFG'
[defaults]
inventory = /etc/ansible/inventory.yaml
host_key_checking = False
retry_files_enabled = False
callbacks_enabled = default
forks = 25
[ssh_connection]
pipelining = True
CFG

  cat >"$dark/ansible/group_vars/all.yml" <<'VARS'
become: true
become_method: sudo
become_user: root

node_exporter_binary_install_dir: /usr/local/bin
node_exporter_web_listen_address: "0.0.0.0:9100"
VARS

  cat >"$dark/ansible/requirements.yml" <<'REQ'
- src: geerlingguy.containerd
  version: "1.4.1"
- src: cloudalchemy.node_exporter
  version: "0.39.0"
- src: geerlingguy.haproxy
  version: "2.9.0"
REQ

  cat >"$dark/ansible/site.yml" <<'SITE'
---
- name: Base platform config
  hosts: all
  gather_facts: yes
  become: yes
  roles:
    - cloudalchemy.node_exporter

- name: Load balancers
  hosts: lb
  gather_facts: yes
  become: yes
  roles:
    - geerlingguy.haproxy

- name: Container runtime
  hosts: controlplane:workers
  gather_facts: yes
  become: yes
  roles:
    - geerlingguy.containerd
SITE

  # ---------- EXTRA: Master-side bootstrap to wire up SSH/Salt/Ansible ----------
  cat >"$dark/seed-ansible.sh" <<'SEED'
#!/usr/bin/env bash
set -euo pipefail

log(){ printf "[INFO] %(%F %T)T - %s\n" -1 "$*"; }
warn(){ printf "[WARN] %(%F %T)T - %s\n" -1 "$*" >&2; }

: "${ADMIN_USER:=admin}"

log "Ensuring ansible user ..."
if ! id -u ansible &>/dev/null; then
  useradd -m -s /bin/bash ansible
fi
install -d -m700 -o ansible -g ansible /home/ansible/.ssh
if [[ ! -s /home/ansible/.ssh/id_ed25519 ]]; then
  sudo -u ansible ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519 >/dev/null
fi
chmod 700 /home/ansible/.ssh
chmod 600 /home/ansible/.ssh/id_ed25519 /home/ansible/.ssh/id_ed25519.pub

log "Passwordless sudo for ansible ..."
printf "ansible ALL=(ALL) NOPASSWD:ALL\n" >/etc/sudoers.d/99-ansible
chmod 440 /etc/sudoers.d/99-ansible

log "SSHD: pubkey only + AllowUsers ansible ..."
sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/; s/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
grep -q '^AllowUsers ' /etc/ssh/sshd_config || printf 'AllowUsers ansible\n' >> /etc/ssh/sshd_config
install -d -m755 /run/sshd
systemctl restart ssh || true

log "Authorize ${ADMIN_USER}'s key for root (if present) ..."
if [[ -s "/root/darksite/authorized_keys.${ADMIN_USER}" ]]; then
  install -d -m700 /root/.ssh
  cat "/root/darksite/authorized_keys.${ADMIN_USER}" >> /root/.ssh/authorized_keys || true
  chmod 600 /root/.ssh/authorized_keys
fi

log "Seed known_hosts for ansible user via Salt roster ..."
install -d -m700 /home/ansible/.ssh
KH="/home/ansible/.ssh/known_hosts"
touch "$KH" && chmod 600 "$KH" && chown -R ansible:ansible /home/ansible/.ssh
if command -v salt &>/dev/null; then
  for h in $(salt --out=newline_values_only '*' grains.get fqdn 2>/dev/null || true); do
    ssh-keygen -R "$h" >/dev/null 2>&1 || true
    ssh-keyscan -T5 -t ed25519,rsa -H "$h" >> "$KH" 2>/dev/null || true
  done
  for ip in $(salt --out=newline_values_only '*' network.ip_addrs cidr=10.78.0.0/16 2>/dev/null || true) \
             $(salt --out=newline_values_only '*' network.ip_addrs cidr=10.100.10.0/24 2>/dev/null || true); do
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
    ssh-keyscan -T5 -t ed25519,rsa -H "$ip" >> "$KH" 2>/dev/null || true
  done
fi
chown ansible:ansible "$KH"

log "Copy Ansible tree into /etc/ansible ..."
install -d -m755 /etc/ansible /etc/ansible/group_vars
cp -f /root/darksite/ansible/inventory.yaml /etc/ansible/inventory.yaml
cp -f /root/darksite/ansible/ansible.cfg    /etc/ansible/ansible.cfg
cp -f /root/darksite/ansible/requirements.yml /etc/ansible/requirements.yml
cp -f /root/darksite/ansible/site.yml /etc/ansible/site.yml
cp -f /root/darksite/ansible/group_vars/all.yml /etc/ansible/group_vars/all.yml
chmod 0644 /etc/ansible/* /etc/ansible/group_vars/*

log "Install Galaxy roles (if Ansible present) ..."
if command -v ansible-galaxy &>/dev/null; then
  ANSIBLE_ROLES_PATH=/etc/ansible/roles ansible-galaxy install -r /etc/ansible/requirements.yml -p /etc/ansible/roles || warn "galaxy failed"
else
  warn "ansible-galaxy not found; skip role install"
fi

log "WireGuard planes refresh (if configs exist) ..."
if command -v python3 &>/dev/null; then
  /usr/bin/env python3 /root/darksite/wg-refresh-planes.py || warn "WG refresh returned non-zero"
fi

log "Quick Ansible smoke ping ..."
if command -v ansible &>/dev/null; then
  ansible -i /etc/ansible/inventory.yaml all -m ping || warn "ansible ping failed"
  ansible-playbook -i /etc/ansible/inventory.yaml /etc/ansible/site.yml || warn "site.yml apply failed"
else
  warn "ansible not installed; skipping applies"
fi

log "seed-ansible.sh done."
SEED
  chmod 0755 "$dark/seed-ansible.sh"

  # Preseed (DHCP vs static)
  local NETBLOCK
  if [[ -z "${static_ip}" ]]; then
    NETBLOCK="d-i netcfg/choose_interface select auto
d-i netcfg/disable_dhcp boolean false
d-i netcfg/get_hostname string ${name}
d-i netcfg/get_domain string ${DOMAIN}"
  else
    NETBLOCK="d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string ${name}
d-i netcfg/get_domain string ${DOMAIN}
d-i netcfg/disable_dhcp boolean true
d-i netcfg/get_ipaddress string ${static_ip}
d-i netcfg/get_netmask string ${NETMASK}
d-i netcfg/get_gateway string ${GATEWAY}
d-i netcfg/get_nameservers string ${NAMESERVER}"
  fi

  cat > "$cust/preseed.cfg" <<'EOF'
d-i debian-installer/locale string ${PRESEED_LOCALE}
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select ${PRESEED_KEYMAP}
$NETBLOCK
d-i mirror/country string ${PRESEED_MIRROR_COUNTRY}
d-i mirror/http/hostname string ${PRESEED_MIRROR_HOST}
d-i mirror/http/directory string ${PRESEED_MIRROR_DIR}
d-i mirror/http/proxy string ${PRESEED_HTTP_PROXY}
d-i passwd/root-login boolean true
d-i passwd/root-password password ${PRESEED_ROOT_PASSWORD}
d-i passwd/root-password-again password ${PRESEED_ROOT_PASSWORD}
d-i passwd/make-user boolean false
d-i time/zone string ${PRESEED_TIMEZONE}
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true
d-i partman-auto/method string lvm
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman/choose_partition select finish
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto-lvm/guided_size string max
d-i pkgsel/run_tasksel boolean false
d-i pkgsel/include string ${PRESEED_EXTRA_PKGS}
d-i pkgsel/upgrade select none
d-i pkgsel/ignore-recommends boolean true
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string ${PRESEED_BOOTDEV}
d-i preseed/late_command string \
  mkdir -p /target/root/darksite ; \
  cp -a /cdrom/darksite/* /target/root/darksite/ ; \
  in-target chmod +x /root/darksite/postinstall.sh ; \
  in-target cp /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service ; \
  in-target mkdir -p /etc/environment.d ; \
  in-target cp /root/darksite/99-provision.conf /etc/environment.d/99-provision.conf ; \
  in-target chmod 0644 /etc/environment.d/99-provision.conf ; \
  in-target systemctl daemon-reload ; \
  in-target systemctl enable bootstrap.service ; \
  in-target /bin/systemctl --no-block poweroff || true
d-i cdrom-detect/eject boolean true
d-i finish-install/reboot_in_progress note
d-i finish-install/exit-installer boolean true
d-i debian-installer/exit/poweroff boolean true
EOF

  # --- Bootloader patching (BIOS + UEFI) -------------------------------------
  local KARGS="auto=true priority=critical vga=788 preseed/file=/cdrom/preseed.cfg ---"

  # BIOS isolinux menu: add an "auto" preseed entry and make it default
  if [[ -f "$cust/isolinux/txt.cfg" ]]; then
    cat >>"$cust/isolinux/txt.cfg" <<'EOF'
label auto
  menu label ^auto (preseed)
  kernel /install.amd/vmlinuz
  append initrd=/install.amd/initrd.gz $KARGS
EOF
    sed -i 's/^default .*/default auto/' "$cust/isolinux/isolinux.cfg" || true
  fi

  # Patch *all* GRUB configs that might be used (BIOS + UEFI), and
  # force them to auto-boot entry 0 with a short timeout.
  local cfg
  for cfg in \
    "$cust/boot/grub/grub.cfg" \
    "$cust/boot/grub/x86_64-efi/grub.cfg" \
    "$cust/EFI/boot/grub.cfg"
  do
    [[ -f "$cfg" ]] || continue

    # Ensure default=0
    if grep -q '^set[[:space:]]\+default=' "$cfg"; then
      sed -i 's/^set[[:space:]]\+default.*/set default="0"/' "$cfg" || true
    else
      sed -i '1i set default="0"' "$cfg" || true
    fi

    # Ensure short timeout (1 second)
    if grep -q '^set[[:space:]]\+timeout=' "$cfg"; then
      sed -i 's/^set[[:space:]]\+timeout.*/set timeout=1/' "$cfg" || true
    else
      sed -i '1i set timeout=1' "$cfg" || true
    fi

    # Inject KARGS right after the kernel path
    sed -i "s#^\([[:space:]]*linux[[:space:]]\+\S\+\)#\1 $KARGS#g" "$cfg" || true
  done

  # --- EFI image detection ----------------------------------------------------
  local efi_img=""
  if [[ -f "$cust/boot/grub/efi.img" ]]; then
    efi_img="boot/grub/efi.img"
  elif [[ -f "$cust/efi.img" ]]; then
    efi_img="efi.img"
  fi

  # --- Final ISO (BIOS+UEFI hybrid if possible, else UEFI-only) --------------
  if [[ -f "$cust/isolinux/isolinux.bin" && -f "$cust/isolinux/boot.cat" && -f /usr/share/syslinux/isohdpfx.bin ]]; then
    log "Repacking ISO (BIOS+UEFI hybrid) -> $iso_out"

    if [[ -n "$efi_img" ]]; then
      xorriso -as mkisofs \
        -o "$iso_out" \
        -r -J -joliet-long -l \
        -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot \
        -e "$efi_img" \
        -no-emul-boot -isohybrid-gpt-basdat \
        "$cust"
    else
      xorriso -as mkisofs \
        -o "$iso_out" \
        -r -J -joliet-long -l \
        -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        "$cust"
    fi
  else
    log "No isolinux BIOS bits found; building UEFI-only ISO"
    if [[ -z "$efi_img" ]]; then
      die "EFI image not found in ISO tree - cannot build bootable ISO"
    fi

    xorriso -as mkisofs \
      -o "$iso_out" \
      -r -J -joliet-long -l \
      -eltorito-alt-boot \
      -e "$efi_img" \
      -no-emul-boot -isohybrid-gpt-basdat \
      "$cust"
  fi
}

# =============================================================================
# MASTER POSTINSTALL
# =============================================================================
emit_postinstall_master() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/postinstall-master.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

# Load seed environment if present (from mk_iso)
if [ -r /etc/environment.d/99-provision.conf ]; then
  # shellcheck disable=SC2046
  export $(grep -E '^[A-Z0-9_]+=' /etc/environment.d/99-provision.conf | xargs -d'\n' || true)
fi

# ---------- Defaults (if not seeded) ----------
DOMAIN="${DOMAIN:-unixbox.net}"

MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"

WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

ADMIN_USER="${ADMIN_USER:-todd}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-yes}"   # yes|try|no

HUB_NAME="${HUB_NAME:-master}"

# ---------- Helpers ----------
ensure_base() {
  log "Configuring APT & base system packages"
  export DEBIAN_FRONTEND=noninteractive

  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF

  for i in 1 2 3; do
    if apt-get update -y; then break; fi
    sleep $((i*3))
  done

  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq xxd unzip tar \
    iproute2 iputils-ping net-tools \
    nftables wireguard-tools \
    python3-venv python3-pip python3-bpfcc python3-psutil \
    libbpfcc llvm libclang-cpp* \
    chrony rsyslog qemu-guest-agent vim || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true

  # Use python3 -m pip so we don’t care about pip vs pip3 name
  if command -v python3 >/dev/null; then
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    python3 -m pip install dnspython requests cryptography pyOpenSSL || true
  fi

  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true

  cat >/etc/sysctl.d/99-master.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF

  sysctl --system || true
}

ensure_users(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"

  mk(){ local u="$1" k="$2";
    id -u "$u" &>/dev/null || useradd -m -s /bin/bash "$u";
    install -d -m700 -o "$u" -g "$u" "/home/$u/.ssh";
    touch "/home/$u/.ssh/authorized_keys"; chmod 600 "/home/$u/.ssh/authorized_keys"
    chown -R "$u:$u" "/home/$u/.ssh"
    [[ -n "$k" ]] && grep -qxF "$k" "/home/$u/.ssh/authorized_keys" || {
      [[ -n "$k" ]] && printf '%s\n' "$k" >> "/home/$u/.ssh/authorized_keys"
    }
    install -d -m755 /etc/sudoers.d
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$u" >"/etc/sudoers.d/90-$u"
    chmod 0440 "/etc/sudoers.d/90-$u"
  }

  mk "$ADMIN_USER" "$PUB"

  # ansible service user
  id -u ansible &>/dev/null || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || \
    runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys
  chmod 600 /home/ansible/.ssh/authorized_keys

  # Allow the cluster enrollment key to log in as ADMIN_USER
  local ENROLL_PUB_SRC="/root/darksite/enroll_ed25519.pub"
  if [[ -s "$ENROLL_PUB_SRC" ]]; then
    local ENROLL_PUB
    ENROLL_PUB="$(head -n1 "$ENROLL_PUB_SRC")"
    if ! grep -qxF "$ENROLL_PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys"; then
      printf '%s\n' "$ENROLL_PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"
    fi
  fi

  # Backplane is wg1
  local BACKPLANE_IF="wg1"
  local BACKPLANE_IP="${WG1_IP%/*}"

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<'EOF'
ListenAddress ${MASTER_LAN}
ListenAddress ${BACKPLANE_IP}
AllowUsers ${ADMIN_USER} ansible
EOF

  cat >/etc/ssh/sshd_config.d/99-hard.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

  if [ "${ALLOW_ADMIN_PASSWORD}" = "yes" ]; then
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<'EOF'
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi

  install -d -m755 /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  (sshd -t && systemctl daemon-reload && systemctl restart ssh) || true
}

wg_setup_planes() {
  log "Configuring WireGuard planes (wg0 reserved, wg1/wg2/wg3 active)"

  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077

  # Generate keys once per interface if missing
  local ifn
  for ifn in wg0 wg1 wg2 wg3; do
    [ -f "/etc/wireguard/${ifn}.key" ] || wg genkey | tee "/etc/wireguard/${ifn}.key" | wg pubkey >"/etc/wireguard/${ifn}.pub"
  done

  # wg0: reserved, NOT started (future use / extra plane)
  cat >/etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address    = ${WG0_IP}
PrivateKey = $(cat /etc/wireguard/wg0.key)
ListenPort = ${WG0_PORT}
MTU        = 1420
EOF

  # wg1: Ansible / SSH plane
  cat >/etc/wireguard/wg1.conf <<'EOF'
[Interface]
Address    = ${WG1_IP}
PrivateKey = $(cat /etc/wireguard/wg1.key)
ListenPort = ${WG1_PORT}
MTU        = 1420
EOF

  # wg2: Metrics plane
  cat >/etc/wireguard/wg2.conf <<'EOF'
[Interface]
Address    = ${WG2_IP}
PrivateKey = $(cat /etc/wireguard/wg2.key)
ListenPort = ${WG2_PORT}
MTU        = 1420
EOF

  # wg3: K8s backend plane
  cat >/etc/wireguard/wg3.conf <<'EOF'
[Interface]
Address    = ${WG3_IP}
PrivateKey = $(cat /etc/wireguard/wg3.key)
ListenPort = ${WG3_PORT}
MTU        = 1420
EOF

  chmod 600 /etc/wireguard/*.conf
  umask "$_old_umask"

  systemctl daemon-reload || true
  systemctl enable --now wg-quick@wg1 || true
  systemctl enable --now wg-quick@wg2 || true
  systemctl enable --now wg-quick@wg3 || true
  # NOTE: wg0 is intentionally NOT enabled
}

nft_firewall() {
  # Try to detect the primary LAN interface (fallback to ens18 if we can't)
  local lan_if
  lan_if="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')" || true
  : "${lan_if:=ens18}"

  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Basic sanity
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept

    # SSH + RDP
    tcp dport 22 accept
    tcp dport 3389 accept

    # WireGuard ports
    udp dport { ${WG0_PORT}, ${WG1_PORT}, ${WG2_PORT}, ${WG3_PORT} } accept

    # Allow traffic arriving over the WG planes
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept

    # Allow WG planes to reach the LAN, and replies back
    iifname "wg1" oifname "${lan_if}" accept
    iifname "wg2" oifname "${lan_if}" accept
    iifname "wg3" oifname "${lan_if}" accept

    iifname "${lan_if}" oifname "wg1" accept
    iifname "${lan_if}" oifname "wg2" accept
    iifname "${lan_if}" oifname "wg3" accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;

    # Masquerade anything leaving via the LAN interface
    oifname "${lan_if}" masquerade
  }
}
EOF

  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

helper_tools() {
  log "Installing wg-add-peer, wg-enrollment, register-minion helpers"

  # wg-add-peer: generic, used for wg1/wg2/wg3 (wg0 if ever needed)
  cat >/usr/local/sbin/wg-add-peer <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFN="${3:-wg1}"
PUB="${1:-}"
ADDR="${2:-}"
FLAG="/srv/wg/ENROLL_ENABLED"

if [[ ! -f "$FLAG" ]]; then
  echo "[X] enrollment closed" >&2
  exit 2
fi
if [[ -z "$PUB" || -z "$ADDR" ]]; then
  echo "usage: wg-add-peer <pubkey> <ip/cidr> [ifname]" >&2
  exit 1
fi

if wg show "$IFN" peers 2>/dev/null | grep -qx "$PUB"; then
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR"
else
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR" persistent-keepalive 25
fi

CONF="/etc/wireguard/${IFN}.conf"
if ! grep -q "$PUB" "$CONF"; then
  printf "\n[Peer]\nPublicKey  = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n" "$PUB" "$ADDR" >> "$CONF"
fi

systemctl reload "wg-quick@${IFN}" 2>/dev/null || true

# TODO: XDP/eBPF hook:
#  - update an eBPF map with peer->plane info here for fast dataplane decisions.

echo "[+] added $PUB $ADDR on $IFN"
EOF
  chmod 0755 /usr/local/sbin/wg-add-peer

  # wg-enrollment: toggle ENROLL_ENABLED flag
  cat >/usr/local/sbin/wg-enrollment <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FLAG="/srv/wg/ENROLL_ENABLED"
case "${1:-}" in
  on)  : >"$FLAG"; echo "enrollment enabled";;
  off) rm -f "$FLAG"; echo "enrollment disabled";;
  *)   echo "usage: wg-enrollment on|off" >&2; exit 1;;
esac
EOF
  chmod 0755 /usr/local/sbin/wg-enrollment

  # register-minion:
  cat >/usr/local/sbin/register-minion <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

GROUP="${1:-}"
HOST="${2:-}"
IP="${3:-}"        # metrics (wg2) IP, port 9100

if [[ -z "$GROUP" || -z "$HOST" || -z "$IP" ]]; then
  echo "usage: $0 <group> <hostname> <metrics-ip>" >&2
  exit 2
fi

ANS_HOSTS="/etc/ansible/hosts"
PROM_DIR="/etc/prometheus/targets.d"
PROM_TGT="${PROM_DIR}/${GROUP}.json"

mkdir -p "$(dirname "$ANS_HOSTS")" "$PROM_DIR"
touch "$ANS_HOSTS"

# Ansible inventory: we use IP as ansible_host for now.
if ! grep -q "^\[${GROUP}\]" "$ANS_HOSTS"; then
  printf "\n[%s]\n" "$GROUP" >> "$ANS_HOSTS"
fi
sed -i "/^${HOST}\b/d" "$ANS_HOSTS"
printf "%s ansible_host=%s\n" "$HOST" "$IP" >> "$ANS_HOSTS"

# Prometheus file_sd target for node_exporter (fixed port 9100)
if [[ ! -s "$PROM_TGT" ]]; then
  echo '[]' > "$PROM_TGT"
fi

tmp="$(mktemp)"
jq --arg target "${IP}:9100" '
  map(select(.targets|index($target)|not)) + [{"targets":[$target]}]
' "$PROM_TGT" > "$tmp" && mv "$tmp" "$PROM_TGT"

if pidof prometheus >/dev/null 2>&1; then
  pkill -HUP prometheus || systemctl reload prometheus || true
fi

echo "[OK] Registered ${HOST} (${IP}) in group ${GROUP}"
EOF
  chmod 0755 /usr/local/sbin/register-minion
}

# --- NEW: drop the enroll script into the master VM --------------------------
install_wg_enroll_script(){
  install -d -m0755 /root
  cat >/root/wg_cluster_enroll.sh <<'EOWG'
#!/usr/bin/env bash
# wg_cluster_enroll.sh — master side, enroll all minions as peers on wg0..wg3
set -euo pipefail
IFACES="${IFACES:-0 1 2 3}"
DRY_RUN="${DRY_RUN:-0}"
LOG="/var/log/wg_cluster_enroll.log"
exec > >(tee -a "$LOG") 2>&1
msg(){ echo "[INFO] $(date '+%F %T') - $*"; }
warn(){ echo "[WARN] $(date '+%F %T') - $*" >&2; }
die(){ echo "[ERROR] $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing: $1"; }
need salt; need wg; need awk; need systemctl; need sed; need grep
get_minions(){ salt-key -L | awk '/Accepted Keys:/{f=1;next} /Denied Keys:|Rejected Keys:|Unaccepted Keys:/{f=0} f&&NF{print $1}' | sort -u; }
salt_cat(){ local m="$1" p="$2"; salt --out=newline_values_only -l quiet "$m" cmd.run "cat $p 2>/dev/null || true"; }
salt_eval(){ local m="$1" c="$2"; salt --out=newline_values_only -l quiet "$m" cmd.run "$c"; }
ensure_iface_up(){ ip link show "$1" >/dev/null 2>&1 || systemctl enable --now "wg-quick@$1" || true; }
ensure_peer_in_conf(){
  local ifn="$1" pub="$2" allowed="$3" conf="/etc/wireguard/${ifn}.conf"
  [[ -r "$conf" ]] || die "missing $conf"
  if grep -qF "$pub" "$conf"; then
    awk -v k="$pub" -v a="$allowed" '
      BEGIN{found=0; inpeer=0}
      /\[Peer\]/ {inpeer=1}
      inpeer && /^PublicKey[[:space:]]*=/ { pk=$0; sub(/^PublicKey[[:space:]]*=[[:space:]]*/,"",pk); if(pk==k){found=1} }
      found && /^AllowedIPs[[:space:]]*=/ { sub(/^AllowedIPs[[:space:]]*=.*/,"AllowedIPs = " a); found=0; print; next }
      {print}
    ' "$conf" > "${conf}.tmp" && mv "${conf}.tmp" "$conf"
  else
    {
      echo ""; echo "[Peer]"; echo "PublicKey  = $pub"; echo "AllowedIPs = $allowed"; echo "PersistentKeepalive = 25"
    } >> "$conf"; chmod 600 "$conf"
  fi
}
apply_conf_live(){ local ifn="$1" conf="/etc/wireguard/${ifn}.conf"; ip link show "$ifn" >/dev/null 2>&1 || systemctl enable --now "wg-quick@$ifn" || true; wg syncconf "$ifn" <(wg-quick strip "$conf") || true; }
msg "Enumerating minions"; readarray -t MINIONS < <(get_minions); [[ ${#MINIONS[@]} -gt 0 ]] || die "no accepted minions"
msg "Collecting pubkeys and desired /32s"
declare -A PEERS
for m in "${MINIONS[@]}"; do
  for i in $IFACES; do
    ifn="wg${i}"
    pub="$(salt_cat "$m" "/etc/wireguard/${ifn}.pub" | head -n1 | tr -d '\r')"; [[ -n "$pub" ]] || { warn "$m $ifn: missing pub"; continue; }
    want="$(salt_eval "$m" "awk -F= '/^WG${i}_WANTED=/{print \$2}' /etc/environment.d/99-provision.conf 2>/dev/null || awk '/^Address/{print \$3}' /etc/wireguard/${ifn}.conf 2>/dev/null | head -n1")"
    [[ -n "$want" ]] || { warn "$m $ifn: missing addr"; continue; }
    PEERS["${ifn}|${pub}"]="$want"; echo "  -> $m $ifn ${pub:0:8}… $want"
  done
done
for i in $IFACES; do [[ -r "/etc/wireguard/wg${i}.conf" ]] || die "missing /etc/wireguard/wg${i}.conf"; ensure_iface_up "wg${i}"; done
for k in "${!PEERS[@]}"; do ifn="${k%%|*}"; pub="${k##*|}"; allowed="${PEERS[$k]}"; ensure_peer_in_conf "$ifn" "$pub" "$allowed"; done
for i in $IFACES; do apply_conf_live "wg${i}"; done
for i in $IFACES; do echo "== $i =="; wg show "wg${i}" peers 2>/dev/null || true; done
EOWG
  chmod +x /root/wg_cluster_enroll.sh
}

telemetry_stack(){  # unchanged
  local wg1_ip; wg1_ip="$(ip -4 addr show dev wg1 | awk '/inet /{print $2}' | cut -d/ -f1)"
  [[ -n "$wg1_ip" ]] || wg1_ip="${WG1_IP%/*}"
  apt-get install -y prometheus prometheus-node-exporter grafana || true
  install -d -m755 /etc/prometheus/targets.d
  cat >/etc/prometheus/prometheus.yml <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 30s
scrape_configs:
  - job_name: 'node'
    file_sd_configs:
      - files:
        - /etc/prometheus/targets.d/*.json
EOF
  install -d -m755 /etc/systemd/system/prometheus.service.d
  cat >/etc/systemd/system/prometheus.service.d/override.conf <<'EOF'
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus --web.listen-address=${wg1_ip}:9090 --config.file=/etc/prometheus/prometheus.yml
EOF
  install -d -m755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<'EOF'
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=${wg1_ip}:9100 --web.disable-exporter-metrics
EOF
  cat >/etc/systemd/system/prometheus.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now prometheus prometheus-node-exporter || true
  install -d /etc/grafana/provisioning/{datasources,dashboards}
  cat >/etc/grafana/provisioning/datasources/prom.yaml <<'EOF'
apiVersion: 1
datasources:
- name: Prometheus
  type: prometheus
  access: proxy
  url: http://${wg1_ip}:9090
  isDefault: true
EOF
  install -d -m755 /var/lib/grafana/dashboards/node
  cat >/etc/grafana/provisioning/dashboards/node.yaml <<'EOF'
apiVersion: 1
providers:
- name: node
  orgId: 1
  folder: "Node"
  type: file
  options:
    path: /var/lib/grafana/dashboards/node
EOF
  cat >/var/lib/grafana/dashboards/node/quick-node.json <<'EOF'
{"annotations":{"list":[{"builtIn":1,"datasource":{"type":"grafana","uid":"grafana"},"enable":true,"hide":true,"iconColor":"rgba(0, 211, 255, 1)","name":"Annotations & Alerts","type":"dashboard"}]},"editable":true,"graphTooltip":0,"panels":[{"type":"stat","title":"Up targets","datasource":"Prometheus","targets":[{"expr":"up"}]}],"schemaVersion":39,"style":"dark","time":{"from":"now-15m","to":"now"},"title":"Quick Node","version":1}
EOF
  systemctl enable --now grafana-server || true
}

control_stack(){  # unchanged
  apt-get install -y --no-install-recommends salt-master salt-api salt-common || true
  install -d -m0755 /etc/salt/master.d
  cat >/etc/salt/master.d/network.conf <<'EOF'
interface: 10.77.0.1
ipv6: False
publish_port: 4505
ret_port: 4506
EOF
  cat >/etc/salt/master.d/api.conf <<'EOF'
rest_cherrypy:
  host: 10.77.0.1
  port: 8000
  disable_ssl: True
EOF
  install -d -m0755 /etc/systemd/system/salt-master.service.d
  cat >/etc/systemd/system/salt-master.service.d/override.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now salt-master salt-api || true

  if [ "${INSTALL_ANSIBLE}" = "yes" ]; then apt-get install -y ansible || true; fi

  if [ "${INSTALL_SEMAPHORE}" != "no" ]; then
    install -d -m755 /etc/semaphore
    if curl -fsSL -o /usr/local/bin/semaphore https://github.com/ansible-semaphore/semaphore/releases/latest/download/semaphore_linux_amd64 2>/dev/null; then
      chmod +x /usr/local/bin/semaphore
      cat >/etc/systemd/system/semaphore.service <<'EOF'
[Unit]
Description=Ansible Semaphore
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service
[Service]
ExecStart=/usr/local/bin/semaphore server --listen 10.77.0.1:3000
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload; systemctl enable --now semaphore || true
    else
      echo "[WARN] Semaphore binary not fetched; install later." >&2
    fi
  fi
}

desktop_gui() {  # unchanged
  case "${GUI_PROFILE}" in
    rdp-minimal)
      apt-get install -y --no-install-recommends xorg xrdp xorgxrdp openbox xterm firefox-esr || true
      if [[ -f /etc/xrdp/xrdp.ini ]]; then
        sed -i 's/^\s*port\s*=.*/; &/' /etc/xrdp/xrdp.ini || true
        if grep -qE '^\s*address=' /etc/xrdp/xrdp.ini; then
          sed -i "s|^\s*address=.*|address=${MASTER_LAN}|" /etc/xrdp/xrdp.ini
        else
          sed -i "1i address=${MASTER_LAN}" /etc/xrdp/xrdp.ini
        fi
        if grep -qE '^\s*;port=' /etc/xrdp/xrdp.ini; then
          sed -i 's|^\s*;port=.*|port=3389|' /etc/xrdp/xrdp.ini
        elif grep -qE '^\s*port=' /etc/xrdp/xrdp.ini; then
          sed -i 's|^\s*port=.*|port=3389|' /etc/xrdp/xrdp.ini
        else
          sed -i '1i port=3389' /etc/xrdp/xrdp.ini
        fi
      fi
      cat >/etc/xrdp/startwm.sh <<'EOSH'
#!/bin/sh
export DESKTOP_SESSION=openbox
export XDG_SESSION_DESKTOP=openbox
export XDG_CURRENT_DESKTOP=openbox
[ -x /usr/bin/openbox-session ] && exec /usr/bin/openbox-session
[ -x /usr/bin/openbox ] && exec /usr/bin/openbox
exec /usr/bin/xterm
EOSH
      chmod +x /etc/xrdp/startwm.sh
      systemctl daemon-reload || true
      systemctl enable --now xrdp || true
      ;;
    wayland-gdm-minimal)
      apt-get install -y --no-install-recommends gdm3 gnome-shell gnome-session-bin firefox-esr || true
      systemctl enable --now gdm3 || true
      ;;
  esac
}

# -----------------------------------------------------------------------------
salt_master_stack() {
  log "Installing and configuring Salt master on LAN"

  install -d -m0755 /etc/apt/keyrings

  # Salt Broadcom repo
  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public \
    -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp \
    >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.gpg || true

  cat >/etc/apt/sources.list.d/salt.sources <<'EOF'
Types: deb
URIs: https://packages.broadcom.com/artifactory/saltproject-deb
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/salt-archive-keyring.pgp
EOF

  cat >/etc/apt/preferences.d/salt-pin-1001 <<'EOF'
Package: salt-*
Pin: version 3006.*
Pin-Priority: 1001
EOF

  apt-get update -y || true
  apt-get install -y --no-install-recommends salt-master salt-api salt-common || true

  cat >/etc/salt/master.d/network.conf <<'EOF'
interface: ${MASTER_LAN}
ipv6: False
publish_port: 4505
ret_port: 4506
EOF

  # For now we keep salt-api without TLS to simplify; harden later.
  cat >/etc/salt/master.d/api.conf <<'EOF'
rest_cherrypy:
  host: ${MASTER_LAN}
  port: 8000
  disable_ssl: True
EOF

  cat >/etc/salt/master.d/bootstrap-autoaccept.conf <<'EOF'
auto_accept: True
EOF

  cat >/etc/salt/master.d/roots.conf <<'EOF'
file_roots:
  base:
    - /srv/salt

pillar_roots:
  base:
    - /srv/pillar
EOF

  install -d -m0755 /etc/systemd/system/salt-master.service.d
  cat >/etc/systemd/system/salt-master.service.d/wg-order.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF

  systemctl daemon-reload
  systemctl enable --now salt-master salt-api || true
}

# -----------------------------------------------------------------------------
pillars_and_states_seed() {
  log "Seeding minimal /srv/pillar and /srv/salt skeleton"

  # ---------------------------------------------------------------------------
  # Ensure directory skeleton exists *before* any redirections
  # ---------------------------------------------------------------------------
  install -d -m0755 /srv/pillar
  install -d -m0755 /srv/salt
  install -d -m0755 /srv/salt/common
  install -d -m0755 /srv/salt/roles

  ###########################################################################
  # VARIABLES
  ###########################################################################

  : "${DOMAIN:=unixbox.net}"
  : "${MASTER_ID:=master}"
  : "${MASTER_LAN:=10.100.10.224}"

  # Load balancers
  : "${K8SLB1_NAME:=k8s-lb1}"
  : "${K8SLB1_IP:=10.100.10.213}"
  : "${K8SLB2_NAME:=k8s-lb2}"
  : "${K8SLB2_IP:=10.100.10.212}"

  # Control planes
  : "${K8SCP1_NAME:=k8s-cp1}"
  : "${K8SCP1_IP:=10.100.10.219}"
  : "${K8SCP2_NAME:=k8s-cp2}"
  : "${K8SCP2_IP:=10.100.10.218}"
  : "${K8SCP3_NAME:=k8s-cp3}"
  : "${K8SCP3_IP:=10.100.10.217}"

  # Workers
  : "${K8SW1_NAME:=k8s-w1}"
  : "${K8SW1_IP:=10.100.10.216}"
  : "${K8SW2_NAME:=k8s-w2}"
  : "${K8SW2_IP:=10.100.10.215}"
  : "${K8SW3_NAME:=k8s-w3}"
  : "${K8SW3_IP:=10.100.10.214}"

  ###########################################################################
  # PILLAR: top.sls
  ###########################################################################
  cat >/srv/pillar/top.sls <<'EOF'
base:
  '*':
    - cluster
    - wireguard
EOF

  ###########################################################################
  # PILLAR: cluster.sls
  ###########################################################################
  cat >/srv/pillar/cluster.sls <<'EOF'
cluster:
  domain: ${DOMAIN}

  master:
    id: ${MASTER_ID}
    lan_ip: ${MASTER_LAN}

  k8s:
    api_vip: ${K8SLB1_IP}
    version_minor: "v1.34"
    pod_subnet: "10.244.0.0/16"
    service_subnet: "10.96.0.0/12"

    lbs:
      - name: ${K8SLB1_NAME}
        ip: ${K8SLB1_IP}
      - name: ${K8SLB2_NAME}
        ip: ${K8SLB2_IP}

    control_planes:
      - name: ${K8SCP1_NAME}
        ip: ${K8SCP1_IP}
      - name: ${K8SCP2_NAME}
        ip: ${K8SCP2_IP}
      - name: ${K8SCP3_NAME}
        ip: ${K8SCP3_IP}

    workers:
      - name: ${K8SW1_NAME}
        ip: ${K8SW1_IP}
      - name: ${K8SW2_NAME}
        ip: ${K8SW2_IP}
      - name: ${K8SW3_NAME}
        ip: ${K8SW3_IP}

    # Filled in dynamically after CP1 init
    token: ""
    ca_hash: ""
EOF

  log "Seeding /srv/pillar and /srv/salt tree"

  ###########################################################################
  # PILLAR: wireguard.sls (empty; will be populated later by generator)
  ###########################################################################
  cat >/srv/pillar/wireguard.sls <<'EOF'
wireguard: {}
EOF

  ###########################################################################
  # /srv/salt/top.sls — map nodes via grains
  ###########################################################################
  cat >/srv/salt/top.sls <<'EOF'
base:
  'role:k8s-lb':
    - match: grain
    - roles.k8s_lb

  'role:k8s-cp':
    - match: grain
    - roles.k8s_control_plane
    - roles.k8s_cp_init

  'role:k8s-cp-join':
    - match: grain
    - roles.k8s_control_plane
    - roles.k8s_cp_join

  'role:k8s-worker':
    - match: grain
    - roles.k8s_worker
    - roles.k8s_worker_join

  'role:k8s':
    - match: grain
    - roles.k8s_admin

  'role:wg':
    - match: grain
    - roles.k8s_wireguard

  '*':
    - common.baseline
EOF

  ###########################################################################
  # COMMON BASELINE
  ###########################################################################
  cat >/srv/salt/common/baseline.sls <<'EOF'
common-baseline:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - vim-tiny
      - jq
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_admin.sls  (K8s toolbox/jumphost)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_admin.sls <<'EOF'
# Kubernetes admin / toolbox node for Debian 13

{% set k8s = pillar.get('cluster', {}).get('k8s', {}) %}
{% set k8s_minor = k8s.get('version_minor', 'v1.34') %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

k8s-admin-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
      - jq
      - git

k8s-admin-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-admin-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-admin-keyrings-dir
      - pkg: k8s-admin-prereqs

k8s-admin-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/kubernetes.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] {{ k8s_repo_url }} /
    - require:
      - cmd: k8s-admin-apt-keyring

# Helm repo
k8s-admin-helm-keyring:
  cmd.run:
    - name: >
        curl -fsSL https://baltocdn.com/helm/signing.asc
        | gpg --dearmor -o /etc/apt/keyrings/helm.gpg
    - creates: /etc/apt/keyrings/helm.gpg
    - require:
      - pkg: k8s-admin-prereqs

k8s-admin-helm-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/helm-stable-debian.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main
    - require:
      - cmd: k8s-admin-helm-keyring

k8s-admin-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-admin-apt-repo
      - file: k8s-admin-helm-repo

k8s-admin-tools:
  pkg.installed:
    - pkgs:
      - kubectl
      - helm
    - require:
      - cmd: k8s-admin-apt-update
EOF

  ###########################################################################
  # --- ALL ROLE FILES ---
  ###########################################################################

  cat >/srv/salt/roles/k8s_control_plane.sls <<'EOF'
# Kubernetes control-plane node role for Debian 13

{% set k8s = pillar.get('cluster', {}).get('k8s', {}) %}
{% set k8s_minor = k8s.get('version_minor', 'v1.34') %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

# APT prerequisites
k8s-cp-prereqs:
  pkg.installed:
    - pkgs:
      - apt-transport-https
      - ca-certificates
      - curl
      - gpg
      - gnupg
      - lsb-release

# Disable swap
k8s-cp-swapoff-fstab:
  file.replace:
    - name: /etc/fstab
    - pattern: '^\S+\s+\S+\s+swap\s+\S+'
    - repl: '# \0'
    - flags:
      - MULTILINE
    - append_if_not_found: False

k8s-cp-swapoff-runtime:
  cmd.run:
    - name: swapoff -a
    - require:
      - file: k8s-cp-swapoff-fstab

# Kernel modules
k8s-cp-modules-load-config:
  file.managed:
    - name: /etc/modules-load.d/k8s.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        overlay
        br_netfilter

k8s-cp-modules-load-now:
  cmd.run:
    - name: |
        modprobe overlay || true
        modprobe br_netfilter || true
    - onchanges:
      - file: k8s-cp-modules-load-config

# Sysctl
k8s-cp-sysctl-config:
  file.managed:
    - name: /etc/sysctl.d/99-kubernetes.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        net.bridge.bridge-nf-call-iptables  = 1
        net.bridge.bridge-nf-call-ip6tables = 1
        net.ipv4.ip_forward                 = 1

k8s-cp-sysctl-apply:
  cmd.run:
    - name: sysctl --system
    - onchanges:
      - file: k8s-cp-sysctl-config

# Kubernetes repo
k8s-cp-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-cp-apt-keyring-deps:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
    - require:
      - pkg: k8s-cp-prereqs

k8s-cp-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-cp-keyrings-dir
      - pkg: k8s-cp-apt-keyring-deps

k8s-cp-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/kubernetes.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] {{ k8s_repo_url }} /
    - require:
      - cmd: k8s-cp-apt-keyring

k8s-cp-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-cp-apt-repo

# containerd
k8s-cp-containerd-pkg:
  pkg.installed:
    - name: containerd
    - require:
      - cmd: k8s-cp-apt-update

k8s-cp-containerd-config-default:
  cmd.run:
    - name: "containerd config default > /etc/containerd/config.toml"
    - creates: /etc/containerd/config.toml
    - require:
      - pkg: k8s-cp-containerd-pkg

k8s-cp-containerd-systemdcgroup:
  file.replace:
    - name: /etc/containerd/config.toml
    - pattern: 'SystemdCgroup = false'
    - repl: 'SystemdCgroup = true'
    - require:
      - cmd: k8s-cp-containerd-config-default

k8s-cp-containerd-service:
  service.running:
    - name: containerd
    - enable: True
    - require:
      - file: k8s-cp-containerd-systemdcgroup

# Kubernetes packages
k8s-cp-packages:
  pkg.installed:
    - pkgs:
      - kubelet
      - kubeadm
      - kubectl
    - require:
      - cmd: k8s-cp-apt-update
      - pkg: k8s-cp-containerd-pkg

k8s-cp-packages-hold:
  cmd.run:
    - name: apt-mark hold kubelet kubeadm kubectl
    - unless: dpkg -l | awk '/kubelet|kubeadm|kubectl/ && /hold/ {found=1} END {exit !found}'
    - require:
      - pkg: k8s-cp-packages

k8s-cp-kubelet-service:
  service.running:
    - name: kubelet
    - enable: True
    - require:
      - pkg: k8s-cp-packages
      - service: k8s-cp-containerd-service
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_worker.sls  (K8s worker prerequisites)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_worker.sls <<'EOF'
# Kubernetes worker node role for Debian 13

{% set k8s = pillar.get('cluster', {}).get('k8s', {}) %}
{% set k8s_minor = k8s.get('version_minor', 'v1.34') %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

k8s-worker-prereqs:
  pkg.installed:
    - pkgs:
      - apt-transport-https
      - ca-certificates
      - curl
      - gpg
      - gnupg
      - lsb-release

k8s-swapoff-fstab:
  file.replace:
    - name: /etc/fstab
    - pattern: '^\S+\s+\S+\s+swap\s+\S+'
    - repl: '# \0'
    - flags:
      - MULTILINE
    - append_if_not_found: False

k8s-swapoff-runtime:
  cmd.run:
    - name: swapoff -a
    - require:
      - file: k8s-swapoff-fstab

k8s-modules-load-config:
  file.managed:
    - name: /etc/modules-load.d/k8s.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        overlay
        br_netfilter

k8s-modules-load-now:
  cmd.run:
    - name: |
        modprobe overlay || true
        modprobe br_netfilter || true
    - onchanges:
      - file: k8s-modules-load-config

k8s-sysctl-config:
  file.managed:
    - name: /etc/sysctl.d/99-kubernetes.conf
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        net.bridge.bridge-nf-call-iptables  = 1
        net.bridge.bridge-nf-call-ip6tables = 1
        net.ipv4.ip_forward                 = 1

k8s-sysctl-apply:
  cmd.run:
    - name: sysctl --system
    - onchanges:
      - file: k8s-sysctl-config

k8s-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-apt-keyring-deps:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
    - require:
      - pkg: k8s-worker-prereqs

k8s-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-keyrings-dir
      - pkg: k8s-apt-keyring-deps

k8s-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/kubernetes.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] {{ k8s_repo_url }} /
    - require:
      - cmd: k8s-apt-keyring

k8s-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-apt-repo

k8s-containerd-pkg:
  pkg.installed:
    - name: containerd
    - require:
      - cmd: k8s-apt-update

k8s-containerd-config-default:
  cmd.run:
    - name: "containerd config default > /etc/containerd/config.toml"
    - creates: /etc/containerd/config.toml
    - require:
      - pkg: k8s-containerd-pkg

k8s-containerd-systemdcgroup:
  file.replace:
    - name: /etc/containerd/config.toml
    - pattern: 'SystemdCgroup = false'
    - repl: 'SystemdCgroup = true'
    - require:
      - cmd: k8s-containerd-config-default

k8s-containerd-service:
  service.running:
    - name: containerd
    - enable: True
    - require:
      - pkg: k8s-containerd-pkg
      - file: k8s-containerd-systemdcgroup

k8s-worker-packages:
  pkg.installed:
    - pkgs:
      - kubelet
      - kubeadm
      - kubectl
    - require:
      - cmd: k8s-apt-update
      - pkg: k8s-containerd-pkg

k8s-worker-packages-hold:
  cmd.run:
    - name: apt-mark hold kubelet kubeadm kubectl
    - unless: dpkg -l | awk '/kubelet|kubeadm|kubectl/ && /hold/ {found=1} END {exit !found}'
    - require:
      - pkg: k8s-worker-packages

k8s-kubelet-service:
  service.running:
    - name: kubelet
    - enable: True
    - require:
      - pkg: k8s-worker-packages
      - service: k8s-containerd-service
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_lb.sls  (HAProxy for K8s API – pillar-driven)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_lb.sls <<'EOF'
# Kubernetes API load balancer (HAProxy) for Debian 13

{% set cluster = pillar.get('cluster', {}) %}
{% set domain = cluster.get('domain', 'cluster.local') %}
{% set k8s = cluster.get('k8s', {}) %}
{% set control_planes = k8s.get('control_planes', []) %}

k8s-lb-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl

k8s-lb-haproxy-pkg:
  pkg.installed:
    - name: haproxy
    - require:
      - pkg: k8s-lb-prereqs

k8s-lb-haproxy-config:
  file.managed:
    - name: /etc/haproxy/haproxy.cfg
    - mode: '0644'
    - user: root
    - group: root
    - require:
      - pkg: k8s-lb-haproxy-pkg
    - contents: |
        global
          log /dev/log  local0
          log /dev/log  local1 notice
          daemon
          maxconn 4096

        defaults
          log     global
          mode    tcp
          option  tcplog
          option  dontlognull
          retries 3
          timeout connect 5s
          timeout client  300s
          timeout server  300s

        frontend k8s_api
          bind *:6443
          default_backend k8s_api_backend

        backend k8s_api_backend
          balance roundrobin
          option tcp-check
          default-server inter 10s fall 3 rise 2
{% for cp in control_planes %}
          server {{ cp.name }} {{ cp.ip }}:6443 check
{% endfor %}
  # If control_planes is empty, backend will be empty until pillar is updated.

k8s-lb-haproxy-service:
  service.running:
    - name: haproxy
    - enable: True
    - require:
      - file: k8s-lb-haproxy-config
EOF

  # ---------------------------------------------------------------------------
  # roles/k8s_flannel.sls (CNI from upstream manifest)
  # ---------------------------------------------------------------------------
  cat >/srv/salt/roles/k8s_flannel.sls <<'EOF'
# Flannel CNI deployment for Kubernetes

k8s-flannel-apply:
  cmd.run:
    - name: |
        export KUBECONFIG=/etc/kubernetes/admin.conf
        kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
    - onlyif: test -f /etc/kubernetes/admin.conf
    - unless: |
        export KUBECONFIG=/etc/kubernetes/admin.conf
        kubectl get daemonset -n kube-flannel kube-flannel -o jsonpath='{.status.numberReady}' 2>/dev/null \
          | grep -Eq '^[1-9]'
EOF
}

###############################################################################
# Seed K8s helper tools on the Salt master
# - gen_wireguard_pillar.py: generate WireGuard keys + /srv/pillar/wireguard.sls
# - update_k8s_join_pillar.sh: set kubeadm token + CA hash in /srv/pillar/cluster.sls
###############################################################################
seed_k8s_support_tools() {
  log "Seeding K8s helper tools (WireGuard generator + join pillar updater)"

  install -d -m0755 /usr/local/sbin
  install -d -m0700 /etc/wireguard/keys

  #############################################################################
  # /usr/local/sbin/gen_wireguard_pillar.py
  # Run on master:
  #   gen_wireguard_pillar.py
  #
  # It will:
  #   - generate private/public keys for each node (if missing)
  #   - drop them in /etc/wireguard/keys/<node>.key/.pub
  #   - write /srv/pillar/wireguard.sls with a "wireguard:" structure
  #
  # You can then have a Salt state (roles.k8s_wireguard) consume this pillar.
  #############################################################################
  cat >/usr/local/sbin/gen_wireguard_pillar.py <<'EOF'
#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Static map of nodes that participate in wg1 for infra/automation
# Adjust as needed.
# ---------------------------------------------------------------------------
NODES = [
    {
        "id": "k8s-cp1.unixbox.net",
        "name": "k8s-cp1",
        "lan_ip": "10.100.10.219",
        "wg_ip": "10.78.0.110/32",
        "listen_port": 51821,
    },
    {
        "id": "k8s-cp2.unixbox.net",
        "name": "k8s-cp2",
        "lan_ip": "10.100.10.218",
        "wg_ip": "10.78.0.111/32",
        "listen_port": 51822,
    },
    {
        "id": "k8s-cp3.unixbox.net",
        "name": "k8s-cp3",
        "lan_ip": "10.100.10.217",
        "wg_ip": "10.78.0.112/32",
        "listen_port": 51823,
    },
    {
        "id": "k8s-w1.unixbox.net",
        "name": "k8s-w1",
        "lan_ip": "10.100.10.216",
        "wg_ip": "10.78.0.120/32",
        "listen_port": 51824,
    },
    {
        "id": "k8s-w2.unixbox.net",
        "name": "k8s-w2",
        "lan_ip": "10.100.10.215",
        "wg_ip": "10.78.0.121/32",
        "listen_port": 51825,
    },
    {
        "id": "k8s-w3.unixbox.net",
        "name": "k8s-w3",
        "lan_ip": "10.100.10.214",
        "wg_ip": "10.78.0.122/32",
        "listen_port": 51826,
    },
    {
        "id": "k8s-lb1.unixbox.net",
        "name": "k8s-lb1",
        "lan_ip": "10.100.10.213",
        "wg_ip": "10.78.0.101/32",
        "listen_port": 51827,
    },
    {
        "id": "k8s-lb2.unixbox.net",
        "name": "k8s-lb2",
        "lan_ip": "10.100.10.212",
        "wg_ip": "10.78.0.102/32",
        "listen_port": 51828,
    },
    {
        "id": "prometheus.unixbox.net",
        "name": "prometheus",
        "lan_ip": "10.100.10.223",
        "wg_ip": "10.78.0.2/32",
        "listen_port": 51829,
    },
    {
        "id": "grafana.unixbox.net",
        "name": "grafana",
        "lan_ip": "10.100.10.222",
        "wg_ip": "10.78.0.3/32",
        "listen_port": 51830,
    },
    {
        "id": "storage.unixbox.net",
        "name": "storage",
        "lan_ip": "10.100.10.220",
        "wg_ip": "10.78.0.5/32",
        "listen_port": 51831,
    },
]

KEY_DIR = Path("/etc/wireguard/keys")
PILLAR_PATH = Path("/srv/pillar/wireguard.sls")


def ensure_keypair(name: str):
    """
    Ensure /etc/wireguard/keys/<name>.key and .pub exist.
    Returns (private_key, public_key, private_key_path).
    """
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    priv_path = KEY_DIR / f"{name}.key"
    pub_path = KEY_DIR / f"{name}.pub"

    if not priv_path.exists():
        priv = (
            subprocess.check_output(["wg", "genkey"], text=True)
            .strip()
        )
        priv_path.write_text(priv + "\n")
        os.chmod(priv_path, 0o600)
    else:
        priv = priv_path.read_text().strip()

    if not pub_path.exists():
        proc = subprocess.run(
            ["wg", "pubkey"],
            input=priv + "\n",
            text=True,
            capture_output=True,
            check=True,
        )
        pub = proc.stdout.strip()
        pub_path.write_text(pub + "\n")
    else:
        pub = pub_path.read_text().strip()

    return priv, pub, str(priv_path)


def main():
    nodes_cfg = {}
    for n in NODES:
        name = n["name"]
        _, pub, priv_path = ensure_keypair(name)
        nodes_cfg[name] = {
            "id": n["id"],
            "lan_ip": n["lan_ip"],
            "wg_ip": n["wg_ip"],
            "listen_port": n["listen_port"],
            "endpoint": f"{n['lan_ip']}:{n['listen_port']}",
            "public_key": pub,
            "private_key_file": priv_path,
        }

    # Emit YAML pillar
    lines = []
    lines.append("wireguard:")
    lines.append("  interface: wg1")
    lines.append(f"  key_dir: {KEY_DIR}")
    lines.append("  nodes:")
    for name, cfg in sorted(nodes_cfg.items()):
        lines.append(f"    {name}:")
        lines.append(f"      id: {cfg['id']}")
        lines.append(f"      lan_ip: {cfg['lan_ip']}")
        lines.append(f"      wg_ip: {cfg['wg_ip']}")
        lines.append(f"      listen_port: {cfg['listen_port']}")
        lines.append(f"      endpoint: {cfg['endpoint']}")
        lines.append(f"      public_key: {cfg['public_key']}")
        lines.append(f"      private_key_file: {cfg['private_key_file']}")

    PILLAR_PATH.parent.mkdir(parents=True, exist_ok=True)
    PILLAR_PATH.write_text("\n".join(lines) + "\n")

    print(f"Wrote WireGuard pillar to {PILLAR_PATH}")
    print(f"Keys are in {KEY_DIR}")


if __name__ == "__main__":
    main()
EOF

  chmod 0755 /usr/local/sbin/gen_wireguard_pillar.py

  #############################################################################
  # /usr/local/sbin/update_k8s_join_pillar.sh
  #
  # Usage (run on master after kubeadm init on k8s-cp1):
  #
  #   update_k8s_join_pillar.sh \
  #     9n3unh.psofte8pbrd5ftro \
  #     sha256:7783031a6f1624a85e0e90049fc4ca701f9fcd009f3f8626b2fb43f6f5e0583f
  #
  # This updates the "token" and "ca_hash" under cluster:k8s: in
  #   /srv/pillar/cluster.sls
  #############################################################################
  cat >/usr/local/sbin/update_k8s_join_pillar.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PILLAR_FILE="/srv/pillar/cluster.sls"

usage() {
  echo "Usage: $0 <kubeadm-token> <ca-hash>" >&2
  echo "Example:" >&2
  echo "  $0 9n3unh.psofte8pbrd5ftro sha256:7783...58f" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 1
fi

TOKEN="$1"
CA_HASH="$2"

if [[ ! -f "$PILLAR_FILE" ]]; then
  echo "ERROR: pillar file $PILLAR_FILE does not exist" >&2
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cp "$PILLAR_FILE" "$TMP"

awk -v token="$TOKEN" -v hash="$CA_HASH" '
/^[[:space:]]*token:/ {
  print "    token: \"" token "\""
  next
}
/^[[:space:]]*ca_hash:/ {
  print "    ca_hash: \"" hash "\""
  next
}
{ print }
' "$TMP" > "$PILLAR_FILE"

echo "Updated token and ca_hash in $PILLAR_FILE"
EOF

  chmod 0755 /usr/local/sbin/update_k8s_join_pillar.sh

  log "K8s support tools installed: gen_wireguard_pillar.py, update_k8s_join_pillar.sh"
}

install_wg_refresh_tool() {
  log "Installing WireGuard plane refresh tool (wg-refresh-planes)"

  install -d -m0755 /usr/local/sbin
  install -d -m0755 /root/darksite || true

  cat >/usr/local/sbin/wg-refresh-planes <<'EOF_WG_REFRESH_PY'
#!/usr/bin/env python3
# Rebuild wg1/wg2/wg3 hub configs from minion state via Salt

import subprocess
import json
import shutil
import time
import os
from pathlib import Path

WG_DIR = Path("/etc/wireguard")
PLANES = ["wg1", "wg2", "wg3"]
SALT_TARGET = "*"          # adjust if you want a subset
SYSTEMD_UNIT_TEMPLATE = "wg-quick@{iface}.service"


def run(cmd, **kwargs):
    """Run a command and return stdout (text)."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("check", True)
    return subprocess.run(cmd, stdout=subprocess.PIPE, **kwargs).stdout


def salt_cmd(target, shell_cmd):
    """
    Run a Salt cmd.run on all matching minions and return a dict:
        {minion_id: "output string"}

    We add --no-color and --static, and defensively extract the JSON
    payload between the first '{' and last '}' to avoid log noise.
    """
    out = run([
        "salt", target, "cmd.run", shell_cmd,
        "--out=json", "--static", "--no-color"
    ])
    out = out.strip()
    if not out:
        return {}

    # Strip anything before the first '{' and after the last '}'
    start = out.find("{")
    end = out.rfind("}")
    if start == -1 or end == -1 or end <= start:
        print(f"[WARN] Could not find JSON object in Salt output for cmd: {shell_cmd}")
        print(f"[WARN] Raw output was:\n{out}")
        return {}

    json_str = out[start:end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON decode failed for Salt output (cmd: {shell_cmd}): {e}")
        print(f"[WARN] Extracted JSON candidate was:\n{json_str}")
        return {}


def read_interface_block(conf_path):
    """
    Read only the [Interface] block from an existing wgX.conf,
    stopping at the first [Peer] (if any).
    Returns list of lines (without trailing newlines).
    """
    lines = []
    with open(conf_path, "r") as f:
        for line in f:
            if line.strip().startswith("[Peer]"):
                break
            lines.append(line.rstrip("\n"))
    return lines


def get_hub_ip(conf_path):
    """
    Parse the 'Address = 10.x.x.x/nn' line from the [Interface] section
    and return just the IP (no CIDR).
    """
    with open(conf_path, "r") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("Address"):
                # e.g. "Address    = 10.78.0.1/16"
                try:
                    _, rhs = stripped.split("=", 1)
                    addr = rhs.split("#", 1)[0].strip()
                    ip = addr.split("/", 1)[0].strip()
                    return ip
                except ValueError:
                    continue
    return None


def build_peers_for_plane(iface):
    """
    For a given interface (wg1, wg2, wg3):
      - ask all minions for IP on that interface
      - ask all minions for public key
    Returns list of dicts: {"minion": ..., "ip": ..., "pubkey": ...}
    """
    # Get IPv4 addr on that interface (one IP per minion)
    ip_cmd = f"ip -4 -o addr show dev {iface} 2>/dev/null | awk '{{print $4}}' | cut -d/ -f1"
    ips = salt_cmd(SALT_TARGET, ip_cmd)

    # Get public key for that interface
    pk_cmd = f"wg show {iface} public-key 2>/dev/null || true"
    pubkeys = salt_cmd(SALT_TARGET, pk_cmd)

    peers = []
    for minion, ip_out in sorted(ips.items()):
        ip = ip_out.strip()
        if not ip:
            continue  # no IP on this iface
        pubkey = pubkeys.get(minion, "").strip()
        if not pubkey:
            continue  # no public key
        peers.append({"minion": minion, "ip": ip, "pubkey": pubkey})
    return peers


def write_conf_for_plane(iface):
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        print(f"[WARN] {conf_path} does not exist, skipping {iface}")
        return

    # Backup existing config
    ts = time.strftime("%Y%m%d%H%M%S")
    backup_path = conf_path.with_suffix(conf_path.suffix + f".bak.{ts}")
    shutil.copy2(conf_path, backup_path)
    print(f"[INFO] Backed up {conf_path} -> {backup_path}")

    # Read interface block and hub IP
    iface_lines = read_interface_block(conf_path)
    hub_ip = get_hub_ip(conf_path)
    if not hub_ip:
        print(f"[WARN] Could not determine hub IP from {conf_path}, continuing anyway")

    # Gather peers via Salt
    peers = build_peers_for_plane(iface)
    if not peers:
        print(f"[WARN] No peers found for {iface}, leaving only [Interface]")
    else:
        print(f"[INFO] Found {len(peers)} peers for {iface}")

    # Write new config
    new_path = conf_path.with_suffix(conf_path.suffix + ".new")
    with open(new_path, "w") as f:
        # [Interface] block
        for line in iface_lines:
            f.write(line + "\n")
        f.write("\n")

        # [Peer] blocks
        for peer in peers:
            ip = peer["ip"]
            # Skip adding self (hub) if it shows up in Salt results
            if hub_ip and ip == hub_ip:
                continue

            f.write("[Peer]\n")
            f.write(f"# {peer['minion']} ({iface})\n")
            f.write(f"PublicKey = {peer['pubkey']}\n")
            f.write(f"AllowedIPs = {ip}/32\n")
            # Uncomment if you want keepalive from clients back to hub
            # f.write("PersistentKeepalive = 25\n")
            f.write("\n")

    # Replace original with new
    os.replace(new_path, conf_path)
    print(f"[INFO] Updated {conf_path}")


def restart_plane(iface):
    unit = SYSTEMD_UNIT_TEMPLATE.format(iface=iface)
    print(f"[INFO] Restarting {unit}")
    try:
        run(["systemctl", "restart", unit])
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to restart {unit}: {e}")


def main():
    for iface in PLANES:
        print(f"=== Processing {iface} ===")
        write_conf_for_plane(iface)
        restart_plane(iface)


if __name__ == "__main__":
    main()
EOF_WG_REFRESH_PY

  chmod 0755 /usr/local/sbin/wg-refresh-planes

  # Optional copy into darksite bundle for traceability
  cp -f /usr/local/sbin/wg-refresh-planes /root/darksite/wg-refresh-planes.py 2>/dev/null || true

  log "wg-refresh-planes installed (Python tool + darksite copy)"
}

ansible_stack() {
  if [ "${INSTALL_ANSIBLE}" != "yes" ]; then
    log "INSTALL_ANSIBLE != yes; skipping Ansible stack"
    return 0
  fi

  log "Installing Ansible and base config"
  apt-get install -y --no-install-recommends ansible || true

  install -d -m0755 /etc/ansible

  cat >/etc/ansible/ansible.cfg <<'EOF'
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
forks = 50
timeout = 30
remote_user = ansible
# We'll use WireGuard plane (wg1) IPs for ansible_host where possible.
EOF

  touch /etc/ansible/hosts
}

semaphore_stack() {
  if [ "${INSTALL_SEMAPHORE}" = "no" ]; then
    log "INSTALL_SEMAPHORE=no; skipping Semaphore"
    return 0
  fi

  log "Installing Semaphore (Ansible UI) - best effort"

  local WG1_ADDR
  WG1_ADDR="$(echo "$WG1_IP" | cut -d/ -f1)"

  install -d -m755 /etc/semaphore

  if curl -fsSL -o /usr/local/bin/semaphore \
      https://github.com/ansible-semaphore/semaphore/releases/latest/download/semaphore_linux_amd64; then
    chmod +x /usr/local/bin/semaphore

    cat >/etc/systemd/system/semaphore.service <<'EOF'
[Unit]
Description=Ansible Semaphore
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target

[Service]
ExecStart=/usr/local/bin/semaphore server --listen ${WG1_ADDR}:3000
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now semaphore || true
  else
    log "WARNING: Failed to fetch Semaphore binary; skipping UI."
  fi
}

hub_seed() {
  log "Seeding /srv/wg/hub.env with master WireGuard metadata"

  mkdir -p /srv/wg

  # Read master public keys (created in wg_setup_planes)
  local wg0_pub wg1_pub wg2_pub wg3_pub
  [ -r /etc/wireguard/wg0.pub ] && wg0_pub="$(cat /etc/wireguard/wg0.pub)" || wg0_pub=""
  [ -r /etc/wireguard/wg1.pub ] && wg1_pub="$(cat /etc/wireguard/wg1.pub)" || wg1_pub=""
  [ -r /etc/wireguard/wg2.pub ] && wg2_pub="$(cat /etc/wireguard/wg2.pub)" || wg2_pub=""
  [ -r /etc/wireguard/wg3.pub ] && wg3_pub="$(cat /etc/wireguard/wg3.pub)" || wg3_pub=""

  cat >/srv/wg/hub.env <<'EOF'
# Master WireGuard Hub metadata – AUTOGENERATED
HUB_NAME=${HUB_NAME}

# This is the IP that minions should use as endpoint for the hub:
HUB_LAN=${MASTER_LAN}
HUB_LAN_GW=10.100.10.1

# High-level WG plane nets
HUB_WG1_NET=10.78.0.0/16    # control/SSH plane
HUB_WG2_NET=10.79.0.0/16    # metrics/prom/graf plane
HUB_WG3_NET=10.80.0.0/16    # k8s/backplane

# Master interface addresses (same values as wg_setup_planes)
WG0_IP=${WG0_IP}
WG1_IP=${WG1_IP}
WG2_IP=${WG2_IP}
WG3_IP=${WG3_IP}

# Master listen ports
WG0_PORT=${WG0_PORT}
WG1_PORT=${WG1_PORT}
WG2_PORT=${WG2_PORT}
WG3_PORT=${WG3_PORT}

# Global allowed CIDR across planes
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}

# Master public keys
WG0_PUB=${wg0_pub}
WG1_PUB=${wg1_pub}
WG2_PUB=${wg2_pub}
WG3_PUB=${wg3_pub}
EOF

  chmod 0644 /srv/wg/hub.env

  mkdir -p /srv/wg/peers
  cat >/srv/wg/README.md <<'EOF'
This directory holds WireGuard hub configuration and enrolled peers.

  * hub.env   – top-level metadata about this hub (IPs, ports, pubkeys)
  * peers/    – per-peer JSON/YAML/whatever we decide later

EOF
}

configure_salt_master_network() {
  echo "[*] Configuring Salt master bind addresses..."

  install -d -m 0755 /etc/salt/master.d

  cat >/etc/salt/master.d/network.conf <<'EOF'
# Bind Salt master on all IPv4 addresses so it’s reachable via:
#  - Public IP
#  - 10.100.x LAN
#  - 10.78.x WireGuard control plane
interface: 0.0.0.0
ipv6: False

# Standard Salt ports
publish_port: 4505
ret_port: 4506
EOF

  systemctl enable --now salt-master salt-api || true
}

configure_nftables_master() {
  echo "[*] Writing /etc/nftables.conf for master..."

  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Allow established/related
    ct state established,related accept

    # Loopback
    iifname "lo" accept

    # Basic ICMP
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    #################################################################
    # SSH (public, LAN, and over WireGuard)
    #################################################################
    tcp dport 22 accept

    #################################################################
    # Salt master (publisher 4505, return 4506)
    # Accessible via:
    #  - public IP
    #  - LAN (10.100.10.0/24)
    #  - WG control plane (10.78.0.0/16)
    #
    # If you want to tighten this later, you can add ip saddr filters.
    #################################################################
    tcp dport { 4505, 4506 } accept

    #################################################################
    # WireGuard UDP ports
    #################################################################
    udp dport { 51820, 51821, 51822, 51823 } accept

    #################################################################
    # Allow all traffic arriving from the WG planes
    # (wg0 = VPN, wg1 = control, wg2 = metrics, wg3 = backup, etc.)
    #################################################################
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept

    #################################################################
    # Default-drop everything else
    #################################################################
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    # Allow forwarding between WG planes and LAN if desired.
    # You can refine this later with explicit rules.
    ct state established,related accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF

  chmod 600 /etc/nftables.conf

  # Enable + apply
  systemctl enable nftables || true
  nft -f /etc/nftables.conf
}

# -----------------------------------------------------------------------------
write_bashrc() {
  log "Writing clean .bashrc for all users (via /etc/skel)..."

  local BASHRC=/etc/skel/.bashrc

  cat > "$BASHRC" <<'EOF'
# ~/.bashrc - foundryBot cluster console

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# -------------------------------------------------------------------
# History, shell options, basic prompt
# -------------------------------------------------------------------
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT='%F %T '
HISTCONTROL=ignoredups:erasedups

shopt -s histappend
shopt -s checkwinsize
shopt -s cdspell

# Basic prompt (will be overridden below with colorized variant)
PS1='\u@\h:\w\$ '

# -------------------------------------------------------------------
# Banner
# -------------------------------------------------------------------
fb_banner() {
  cat << 'FBBANNER'

   oec :                                            dF                        ..
  @88888         u.      x.    .        u.    u.   '88bu.         .u    .    @L
  8"*88%   ...ue888b   .@88k  z88u    x@88k u@88c. '*88888bu    .d88B :@8c  9888i   .dL
  8b.      888R Y888r ~"8888 ^8888   ^"8888""8888"   ^"*8888N  ="8888f8888r `Y888k:*888.
 u888888>  888R I888>   8888  888R     8888  888R   beWE "888L   4888>'88"    888E  888I
  8888R    888R I888>   8888  888R     8888  888R   888E  888E   4888> '      888E  888I
  8888P    888R I888>   8888  888R     8888  888R   888E  888E   4888>        888E  888I
  *888>   u8888cJ888    8888 ,888B .   8888  888R   888E  888F  .d888L .+     888E  888I
  4888     "*888*P"    "8888Y 8888"   "*88*" 8888" .888N..888   ^"8888*"      x888N><888'
  '888       'Y"        `Y"   'YP       ""   'Y"    `"888*""       "Y"        "88"  888
   88R                                                 ""                           88F
   88>                                                                              98" OS
   48         zero trust · borg-like · agnostic platfourms -> everywhere.          ./"
   '8                                                                             ~`

FBBANNER
}

# Only show once per interactive session
if [ -z "$FBNOBANNER" ]; then
  fb_banner
  export FBNOBANNER=1
fi

# -------------------------------------------------------------------
# Colorized prompt (root vs non-root)
# -------------------------------------------------------------------
if [ "$EUID" -eq 0 ]; then
  PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
else
  PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi

# -------------------------------------------------------------------
# Bash completion
# -------------------------------------------------------------------
if [ -f /etc/bash_completion ]; then
  # shellcheck source=/etc/bash_completion
  . /etc/bash_completion
fi

# -------------------------------------------------------------------
# Basic quality-of-life aliases
# -------------------------------------------------------------------
alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'

alias ls='ls --color=auto'
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias e='${EDITOR:-vim}'
alias vi='vim'

# Net & disk helpers
alias ports='ss -tuln'
alias df='df -h'
alias du='du -h'
alias tk='tmux kill-server'

# -------------------------------------------------------------------
# Salt cluster helper commands
# -------------------------------------------------------------------

# Wide minion list as a table
slist() {
  salt --static --no-color --out=json --out-indent=-1 "*" \
    grains.item host os osrelease ipv4 num_cpus mem_total roles \
  | jq -r '
      to_entries[]
      | .key as $id
      | .value as $v
      | ($v.ipv4 // []
         | map(select(. != "127.0.0.1" and . != "0.0.0.0"))
         | join("  ")) as $ips
      | [
          $id,
          $v.host,
          ($v.os + " " + $v.osrelease),
          $ips,
          $v.num_cpus,
          $v.mem_total,
          ($v.roles // "")
        ]
      | @tsv
    ' \
  | sort -k1,1
}

sping()      { salt "*" test.ping; }
ssall()      { salt "*" cmd.run 'ss -tnlp || netstat -tnlp'; }
skservices() { salt "*" service.status kubelet containerd; }
sdfall()     { salt "*" cmd.run 'df -hT --exclude-type=tmpfs --exclude-type=devtmpfs'; }
stop5()      { salt "*" cmd.run 'ps aux --sort=-%cpu | head -n 5'; }
smem5()      { salt "*" cmd.run 'ps aux --sort=-%mem | head -n 5'; }

skvers() {
  echo "== kubelet versions =="
  salt "*" cmd.run 'kubelet --version 2>/dev/null || echo no-kubelet'
  echo
  echo "== kubectl client versions =="
  salt "*" cmd.run 'kubectl version --client --short 2>/dev/null || echo no-kubectl'
}

# "World" apply helpers – tweak state names to your liking
fb_world() {
  echo "Applying 'world' state to all minions..."
  salt "*" state.apply world
}

fb_k8s_cluster() {
  echo "Applying 'k8s.cluster' to role:k8s_cp and role:k8s_worker..."
  salt -C 'G@role:k8s_cp or G@role:k8s_worker' state.apply k8s.cluster
}
# -------------------------------------------------------------------
# Kubernetes helper commands (Salt-powered via role:k8s_cp)
# -------------------------------------------------------------------

# Core cluster info
skcls()   { salt -G "role:k8s_cp" cmd.run 'kubectl cluster-info'; }
sknodes() { salt -G "role:k8s_cp" cmd.run 'kubectl get nodes -o wide'; }
skpods()  { salt -G "role:k8s_cp" cmd.run 'kubectl get pods -A -o wide'; }
sksys()   { salt -G "role:k8s_cp" cmd.run 'kubectl get pods -n kube-system -o wide'; }
sksvc()   { salt -G "role:k8s_cp" cmd.run 'kubectl get svc -A -o wide'; }
sking()   { salt -G "role:k8s_cp" cmd.run 'kubectl get ingress -A -o wide'; }
skapi()   { salt -G "role:k8s_cp" cmd.run 'kubectl api-resources | column -t'; }

# Health & metrics
skready() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get nodes -o json | jq -r ".items[] | [.metadata.name, (.status.conditions[] | select(.type==\"Ready\").status)] | @tsv"'
}

sktop() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl top nodes 2>/dev/null || echo metrics-server-not-installed'
}

sktopp() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl top pods -A --use-protocol-buffers 2>/dev/null || echo metrics-server-not-installed'
}

skevents() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get events -A --sort-by=.lastTimestamp | tail -n 40'
}

skdescribe() {
  if [ -z "$1" ]; then
    echo "Usage: skdescribe <pod> [namespace]"
    return 1
  fi
  local pod="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl describe pod $pod -n $ns"
}

# Workload inventory
skdeploy() { salt -G "role:k8s_cp" cmd.run 'kubectl get deploy -A -o wide'; }
skrs()     { salt -G "role:k8s_cp" cmd.run 'kubectl get rs -A -o wide'; }
sksts()    { salt -G "role:k8s_cp" cmd.run 'kubectl get statefulset -A -o wide'; }
skdaemon() { salt -G "role:k8s_cp" cmd.run 'kubectl get daemonset -A -o wide'; }

# Labels & annotations
sklabel() {
  if [ $# -lt 2 ]; then
    echo "Usage: sklabel <key>=<value> <pod> [namespace]"
    return 1
  fi
  local kv="$1"
  local pod="$2"
  local ns="${3:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl label pod $pod -n $ns $kv --overwrite"
}

skannot() {
  if [ $# -lt 2 ]; then
    echo "Usage: skannot <key>=<value> <pod> [namespace]"
    return 1
  fi
  local kv="$1"
  local pod="$2"
  local ns="${3:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl annotate pod $pod -n $ns $kv --overwrite"
}

# Networking
sknetpol() {
  salt -G "role:k8s_cp" cmd.run 'kubectl get networkpolicies -A -o wide'
}

skcni() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get pods -n kube-flannel -o wide 2>/dev/null || kubectl get pods -n kube-system | grep -i cni'
}

sksvcips() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get svc -A -o json | jq -r ".items[]|[.metadata.namespace,.metadata.name,.spec.clusterIP]|@tsv"'
}

skdns() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide 2>/dev/null || kubectl get pods -n kube-system | grep -i coredns'
}

# Logs
sklog() {
  if [ -z "$1" ]; then
    echo "Usage: sklog <pod> [namespace]"
    return 1
  fi
  local pod="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl logs $pod -n $ns --tail=200"
}

sklogf() {
  if [ -z "$1" ]; then
    echo "Usage: sklogf <pod> [namespace]"
    return 1
  fi
  local pod="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl logs $pod -n $ns -f"
}

sklogs_ns() {
  local ns="${1:-default}"
  salt -G "role:k8s_cp" cmd.run \
    "kubectl get pods -n $ns -o json \
      | jq -r '.items[].metadata.name' \
      | xargs -I {} kubectl logs {} -n $ns --tail=40"
}

# Container runtime & node diag
skcri()   { salt -G "role:k8s_cp" cmd.run 'crictl ps -a 2>/dev/null || echo no-cri-tools'; }
skdmesg() { salt "*" cmd.run 'dmesg | tail -n 25'; }
skoom()   { salt "*" cmd.run 'journalctl -k -g OOM -n 20 --no-pager'; }

# Rollouts & node lifecycle
skroll() {
  if [ -z "$1" ]; then
    echo "Usage: skroll <deployment> [namespace]"
    return 1
  fi
  local deploy="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl rollout restart deploy/$deploy -n $ns"
}

skundo() {
  if [ -z "$1" ]; then
    echo "Usage: skundo <deployment> [namespace]"
    return 1
  fi
  local deploy="$1"
  local ns="${2:-default}"
  salt -G "role:k8s_cp" cmd.run "kubectl rollout undo deploy/$deploy -n $ns"
}

skdrain() {
  if [ -z "$1" ]; then
    echo "Usage: skdrain <node>"
    return 1
  fi
  local node="$1"
  salt -G "role:k8s_cp" cmd.run "kubectl drain $node --ignore-daemonsets --force --delete-emptydir-data"
}

skuncordon() {
  if [ -z "$1" ]; then
    echo "Usage: skuncordon <node>"
    return 1
  fi
  local node="$1"
  salt -G "role:k8s_cp" cmd.run "kubectl uncordon $node"
}

skcordon() {
  if [ -z "$1" ]; then
    echo "Usage: skcordon <node>"
    return 1
  fi
  local node="$1"
  salt -G "role:k8s_cp" cmd.run "kubectl cordon $node"
}

# Security / certs / RBAC
skrbac() {
  salt -G "role:k8s_cp" cmd.run 'kubectl get roles,rolebindings -A -o wide'
}

sksa() {
  salt -G "role:k8s_cp" cmd.run 'kubectl get sa -A -o wide'
}

skcerts() {
  salt -G "role:k8s_cp" cmd.run \
    'for i in /etc/kubernetes/pki/*.crt; do echo "== $(basename "$i") =="; openssl x509 -in "$i" -text -noout | head -n 10; echo; done'
}

# Show-offs
skpodsmap() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl get pods -A -o json | jq -r ".items[] | [.metadata.namespace,.metadata.name,.status.podIP,(.spec.containers|length),.spec.nodeName] | @tsv"'
}

sktopcpu() {
  salt -G "role:k8s_cp" cmd.run \
    'kubectl top pod -A 2>/dev/null | sort -k3 -r | head -n 15'
}

# -------------------------------------------------------------------
# Helper: print cheat sheet of all the good stuff
# -------------------------------------------------------------------
shl() {
  printf "%s\n" \
"Salt / cluster helper commands:" \
"  slist         - List all minions in a wide table (id, host, OS, IPs, CPU, RAM, roles)." \
"  sping         - Ping all minions via Salt (test.ping)." \
"  ssall         - Show listening TCP sockets on all minions (ss/netstat)." \
"  skservices    - Check kubelet and containerd service status on all minions." \
"  skvers        - Show kubelet and kubectl versions on all minions." \
"  sdfall        - Show disk usage (df -hT, no tmpfs/devtmpfs) on all minions." \
"  stop5         - Top 5 CPU-hungry processes on each minion." \
"  smem5         - Top 5 memory-hungry processes on each minion." \
"  fb_world      - Apply top-level 'world' Salt state to all minions." \
"  fb_k8s_cluster- Apply 'k8s.cluster' state to CP + workers." \
"" \
"Kubernetes cluster helpers (via role:k8s_cp):" \
"  skcls         - Show cluster-info." \
"  sknodes       - List nodes (wide)." \
"  skpods        - List all pods (all namespaces, wide)." \
"  sksys         - Show kube-system pods." \
"  sksvc         - List all services." \
"  sking         - List all ingresses." \
"  skapi         - Show API resources." \
"  skready       - Show node Ready status." \
"  sktop         - Node CPU/mem usage (if metrics-server installed)." \
"  sktopp        - Pod CPU/mem usage (if metrics-server installed)." \
"  skevents      - Tail the last cluster events." \
"  skdeploy      - List deployments (all namespaces)." \
"  sksts         - List StatefulSets." \
"  skdaemon      - List DaemonSets." \
"  sknetpol      - List NetworkPolicies." \
"  sksvcips      - Map svc -> ClusterIP." \
"  skdns         - Show cluster DNS pods." \
"  sklog         - Show logs for a pod: sklog <pod> [ns]." \
"  sklogf        - Follow logs for a pod: sklogf <pod> [ns]." \
"  sklogs_ns     - Tail logs for all pods in a namespace." \
"  skroll        - Restart a deployment: skroll <deploy> [ns]." \
"  skundo        - Rollback a deployment: skundo <deploy> [ns]." \
"  skdrain       - Drain a node." \
"  skcordon      - Cordon a node." \
"  skuncordon    - Uncordon a node." \
"  skrbac        - List Roles and RoleBindings." \
"  sksa          - List ServiceAccounts." \
"  skcerts       - Dump brief info about control-plane certs." \
"  skpodsmap     - Pretty map of pods (ns, name, IP, containers, node)." \
"  sktopcpu      - Top 15 CPU-hungry pods." \
"" \
"Other:" \
"  cp/mv/rm      - Interactive (prompt before overwrite/delete)." \
"  ll/la/l       - ls variants." \
"  e, vi         - Open \$EDITOR (vim by default)." \
""
}

# -------------------------------------------------------------------
# Auto-activate BCC virtualenv (if present)
# -------------------------------------------------------------------
VENV_DIR="/root/bccenv"
if [ -d "$VENV_DIR" ] && [ -n "$PS1" ]; then
  if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$VENV_DIR" ]; then
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
  fi
fi

# -------------------------------------------------------------------
# Friendly login line
# -------------------------------------------------------------------
echo "Welcome $USER — connected to $(hostname) on $(date)"
echo "Type 'shl' for the foundryBot helper command list."
EOF
}

# -----------------------------------------------------------------------------
write_tmux_conf() {
  log "Writing tmux.conf to /etc/skel and root"
  apt-get install -y tmux

  local TMUX_CONF="/etc/skel/.tmux.conf"

  cat > "$TMUX_CONF" <<'EOF'
# ~/.tmux.conf — Airline-style theme
set -g mouse on
setw -g mode-keys vi
set -g history-limit 10000
set -g default-terminal "screen-256color"
set-option -ga terminal-overrides ",xterm-256color:Tc"
set-option -g status on
set-option -g status-interval 5
set-option -g status-justify centre
set-option -g status-bg colour236
set-option -g status-fg colour250
set-option -g status-style bold
set-option -g status-left-length 60
set-option -g status-left "#[fg=colour0,bg=colour83] #S #[fg=colour83,bg=colour55,nobold,nounderscore,noitalics]"
set-option -g status-right-length 120
set-option -g status-right "#[fg=colour55,bg=colour236]#[fg=colour250,bg=colour55] %Y-%m-%d  %H:%M #[fg=colour236,bg=colour55]#[fg=colour0,bg=colour236] #H "
set-window-option -g window-status-current-style "fg=colour0,bg=colour83,bold"
set-window-option -g window-status-current-format " #I:#W "
set-window-option -g window-status-style "fg=colour250,bg=colour236"
set-window-option -g window-status-format " #I:#W "
set-option -g pane-border-style "fg=colour238"
set-option -g pane-active-border-style "fg=colour83"
set-option -g message-style "bg=colour55,fg=colour250"
set-option -g message-command-style "bg=colour55,fg=colour250"
set-window-option -g bell-action none
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
bind r source-file ~/.tmux.conf \; display-message "Reloaded!"
bind-key -T copy-mode-vi 'v' send -X begin-selection
bind-key -T copy-mode-vi 'y' send -X copy-selection-and-cancel
EOF

  log ".tmux.conf written to /etc/skel/.tmux.conf"

  # Also set for root:
  cp "$TMUX_CONF" /root/.tmux.conf
  log ".tmux.conf copied to /root/.tmux.conf"
}

# Backwards-compat wrapper (if anything else ever calls this name)
seed_tmux_conf() {
  write_tmux_conf
}

# -----------------------------------------------------------------------------
setup_vim_config() {
  log "Writing standard Vim config..."
  apt-get install -y \
    vim \
    git \
    vim-airline \
    vim-airline-themes \
    vim-ctrlp \
    vim-fugitive \
    vim-gitgutter \
    vim-tabular

  local VIMRC=/etc/skel/.vimrc
  mkdir -p /etc/skel/.vim/autoload/airline/themes

  cat > "$VIMRC" <<'EOF'
syntax on
filetype plugin indent on
set nocompatible
set tabstop=2 shiftwidth=2 expandtab
set autoindent smartindent
set background=dark
set ruler
set showcmd
set cursorline
set wildmenu
set incsearch
set hlsearch
set laststatus=2
set clipboard=unnamedplus
set showmatch
set backspace=indent,eol,start
set ignorecase
set smartcase
set scrolloff=5
set wildmode=longest,list,full
set splitbelow
set splitright
highlight ColorColumn ctermbg=darkgrey guibg=grey
highlight ExtraWhitespace ctermbg=red guibg=red
match ExtraWhitespace /\s\+$/
let g:airline_powerline_fonts = 1
let g:airline_theme = 'custom'
let g:airline#extensions#tabline#enabled = 1
let g:airline_section_z = '%l:%c'
let g:ctrlp_map = '<c-p>'
let g:ctrlp_cmd = 'CtrlP'
nmap <leader>gs :Gstatus<CR>
nmap <leader>gd :Gdiff<CR>
nmap <leader>gc :Gcommit<CR>
nmap <leader>gb :Gblame<CR>
let g:gitgutter_enabled = 1
autocmd FileType python,yaml setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType javascript,typescript,json setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType sh,bash,zsh setlocal tabstop=2 shiftwidth=2 expandtab
nnoremap <leader>w :w<CR>
nnoremap <leader>q :q<CR>
nnoremap <leader>tw :%s/\s\+$//e<CR>
if &term =~ 'xterm'
  let &t_SI = "\e[6 q"
  let &t_EI = "\e[2 q"
endif
EOF

  chmod 644 /etc/skel/.vimrc
  cat > /etc/skel/.vim/autoload/airline/themes/custom.vim <<'EOF'
let g:airline#themes#custom#palette = {}
let s:N1 = [ '#000000' , '#00ff5f' , 0 , 83 ]
let s:N2 = [ '#ffffff' , '#5f00af' , 255 , 55 ]
let s:N3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:I1 = [ '#000000' , '#5fd7ff' , 0 , 81 ]
let s:I2 = [ '#ffffff' , '#5f00d7' , 255 , 56 ]
let s:I3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:V1 = [ '#000000' , '#af5fff' , 0 , 135 ]
let s:V2 = [ '#ffffff' , '#8700af' , 255 , 91 ]
let s:V3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:R1 = [ '#000000' , '#ff5f00' , 0 , 202 ]
let s:R2 = [ '#ffffff' , '#d75f00' , 255 , 166 ]
let s:R3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:IA = [ '#aaaaaa' , '#1c1c1c' , 250 , 234 ]
let g:airline#themes#custom#palette.normal = airline#themes#generate_color_map(s:N1, s:N2, s:N3)
let g:airline#themes#custom#palette.insert = airline#themes#generate_color_map(s:I1, s:I2, s:I3)
let g:airline#themes#custom#palette.visual = airline#themes#generate_color_map(s:V1, s:V2, s:V3)
let g:airline#themes#custom#palette.replace = airline#themes#generate_color_map(s:R1, s:R2, s:R3)
let g:airline#themes#custom#palette.inactive = airline#themes#generate_color_map(s:IA, s:IA, s:IA)
EOF

  mkdir -p /root/.vim/autoload/airline/themes
  cp /etc/skel/.vimrc /root/.vimrc
  chmod 644 /root/.vimrc
  cp /etc/skel/.vim/autoload/airline/themes/custom.vim /root/.vim/autoload/airline/themes/custom.vim
  chmod 644 /root/.vim/autoload/airline/themes/custom.vim
}

# -----------------------------------------------------------------------------
setup_python_env() {
  log "Setting up Python for BCC scripts..."

  # System packages only — no pip bcc!
  apt-get install -y python3-psutil python3-bpfcc

  # Create a virtualenv that sees system site-packages
  local VENV_DIR="/root/bccenv"
  python3 -m venv --system-site-packages "$VENV_DIR"

  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install cryptography pyOpenSSL numba pytest
  deactivate

  log "System Python has psutil + bpfcc. Venv created at $VENV_DIR with system site-packages."

  # Auto-activate for root
  local ROOT_BASHRC="/root/.bashrc"
  if ! grep -q "$VENV_DIR" "$ROOT_BASHRC" 2>/dev/null; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv"
      echo "source \"$VENV_DIR/bin/activate\""
    } >> "$ROOT_BASHRC"
  fi

  # Auto-activate for future users
  local SKEL_BASHRC="/etc/skel/.bashrc"
  if ! grep -q "$VENV_DIR" "$SKEL_BASHRC" 2>/dev/null; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv if available"
      echo "[ -d \"$VENV_DIR\" ] && source \"$VENV_DIR/bin/activate\""
    } >> "$SKEL_BASHRC"
  fi

  log "Virtualenv activation added to root and skel .bashrc"
}

# -----------------------------------------------------------------------------
sync_skel_to_existing_users() {
  log "Syncing skel configs to existing users (root + baked)..."

  local files=".bashrc .vimrc .tmux.conf"
  local homes="/root"
  homes+=" $(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)"

  for home in $homes; do
    for f in $files; do
      if [ -f "/etc/skel/$f" ]; then
        cp -f "/etc/skel/$f" "$home/$f"
      fi
    done
  done
}

  log "Seeding finish-cluster script and systemd unit on Salt master"

  # -------------------------------------------------------------------------
  # /usr/local/sbin/finish-cluster: full cluster bring-up via Salt + kubeadm
  # -------------------------------------------------------------------------

  cat >/usr/local/sbin/finish-cluster <<'EOF_FINISH_CLUSTER'
#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[finish-cluster] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

die() {
  log "ERROR: $*"
  exit 1
}

# ---------------------------------------------------------------------------
# Cluster topology
#   - NODES: list of Salt minion IDs
#   - ROLE_MAP: optional role labels; can be used later for Salt states
# ---------------------------------------------------------------------------
NODES=(
  grafana.unixbox.net
  prometheus.unixbox.net
  k8s.unixbox.net
  storage.unixbox.net
)

declare -A ROLE_MAP=(
  [grafana.unixbox.net]="graf"
  [prometheus.unixbox.net]="prom"
  [k8s.unixbox.net]="k8s"
  [storage.unixbox.net]="storage"
)

# ---------------------------------------------------------------------------
# Helper: ensure Salt is reachable
# ---------------------------------------------------------------------------
check_salt_master() {
  if ! command -v salt >/dev/null 2>&1; then
    die "salt command not found on master; is Salt installed?"
  fi
  if ! systemctl is-active --quiet salt-master; then
    die "salt-master service is not active"
  fi
}

# ---------------------------------------------------------------------------
# Phase 0: ensure local ansible user + key + config on the master
# ---------------------------------------------------------------------------
ensure_local_ansible_user() {
  log "Ensuring local ansible user exists on master"

  if ! id ansible >/dev/null 2>&1; then
    log "Creating ansible user (shell /bin/bash, group sudo)"
    useradd -m -s /bin/bash -G sudo ansible
  fi

  # sudoers
  if [[ ! -f /etc/sudoers.d/ansible ]]; then
    log "Seeding /etc/sudoers.d/ansible (NOPASSWD)"
    echo 'ansible ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/ansible
    chmod 440 /etc/sudoers.d/ansible
  fi

  # SSH keypair
  local ssh_dir="/home/ansible/.ssh"
  if [[ ! -d "$ssh_dir" ]]; then
    log "Creating $ssh_dir"
    mkdir -p "$ssh_dir"
    chown ansible:ansible "$ssh_dir"
    chmod 700 "$ssh_dir"
  fi

  if [[ ! -f "$ssh_dir/id_ed25519" ]]; then
    log "Generating ansible SSH keypair"
    sudo -u ansible ssh-keygen -t ed25519 -N '' -f "$ssh_dir/id_ed25519"
  fi

  # Ansible config
  mkdir -p /etc/ansible

  cat >/etc/ansible/ansible.cfg <<'EOF_CFG'
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
forks = 50
timeout = 30
remote_user = ansible
EOF_CFG

  touch /etc/ansible/hosts
  chmod 644 /etc/ansible/hosts
}

get_ansible_pubkey() {
  sudo -u ansible cat /home/ansible/.ssh/id_ed25519.pub
}

# ---------------------------------------------------------------------------
# Phase 1: wait for Salt minion keys + ping
# ---------------------------------------------------------------------------
wait_for_minion() {
  local node="$1"
  local max_wait="${2:-360}"   # seconds

  log "Waiting for Salt minion key: $node"

  local waited=0
  while (( waited < max_wait )); do
    if salt-key -L | grep -qE "Accepted Keys:\s*(.|\n)*\b${node}\b"; then
      log "Key for ${node} is accepted"
      break
    fi
    if salt-key -L | grep -qE "Unaccepted Keys:\s*(.|\n)*\b${node}\b"; then
      log "Key for ${node} is unaccepted; accepting"
      salt-key -y -a "$node" >/dev/null 2>&1 || true
    fi
    sleep 5
    (( waited += 5 ))
  done

  if ! salt-key -L | grep -qE "Accepted Keys:\s*(.|\n)*\b${node}\b"; then
    die "Salt key for ${node} was not accepted within ${max_wait}s"
  fi

  log "Waiting for $node to respond to salt test.ping"
  waited=0
  while (( waited < max_wait )); do
    if salt "$node" test.ping | grep -q 'True'; then
      log "$node is up (test.ping True)"
      return 0
    fi
    sleep 5
    (( waited += 5 ))
  done

  die "Salt minion ${node} did not respond to test.ping within ${max_wait}s"
}

# ---------------------------------------------------------------------------
# Phase 2: ensure common.baseline on all nodes (idempotent)
# ---------------------------------------------------------------------------
apply_common_baseline() {
  local node="$1"
  log "Applying common.baseline to $node"
  salt "$node" state.apply common.baseline || die "common.baseline failed on $node"
}

# ---------------------------------------------------------------------------
# Phase 3: ensure remote ansible user + sudo + authorized_keys on minions
# ---------------------------------------------------------------------------
ensure_ansible_access() {
  local id="$1"       # FQDN of node
  local wg_ip="$2"    # WireGuard IP we discovered earlier (10.78.0.x)

  log "[finish-cluster] $(date '+%F %T') - finish-cluster Ensuring ansible user + pubkey + inventory for ${id}"

  # 1) Get ansible pubkey from master
  local ANSIBLE_PUB
  if ! ANSIBLE_PUB="$(sudo -u ansible cat /home/ansible/.ssh/id_ed25519.pub 2>/dev/null)"; then
    log "[finish-cluster] $(date '+%F %T') - ERROR: ansible pubkey not found on master; did you create /home/ansible/.ssh/id_ed25519?"
    return 1
  fi

  # 2) Create ansible user + SSH keys + sudo on the minion via Salt
  salt --no-color "${id}" cmd.run \
"set -e
if ! id ansible >/dev/null 2>&1; then
  useradd -m -s /bin/bash ansible || true
  usermod -aG sudo ansible || true
fi
mkdir -p /home/ansible/.ssh
chmod 700 /home/ansible/.ssh
if ! grep -qF '${ANSIBLE_PUB}' /home/ansible/.ssh/authorized_keys 2>/dev/null; then
  echo '${ANSIBLE_PUB}' >> /home/ansible/.ssh/authorized_keys
fi
chown -R ansible:ansible /home/ansible/.ssh
chmod 600 /home/ansible/.ssh/authorized_keys
echo 'ansible ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/90-ansible
chmod 440 /etc/sudoers.d/90-ansible" \
  >/dev/null 2>&1

  if [ $? -ne 0 ]; then
    log "[finish-cluster] $(date '+%F %T') - WARN: Failed to push ansible user/key/sudo to ${id} via Salt"
    return 1
  fi

  # 3) Update /etc/ansible/hosts on the master with WG IP
  update_ansible_inventory "${id}" "${wg_ip}"

  # 4) Prime SSH known_hosts and verify login as ansible
  log "[finish-cluster] $(date '+%F %T') - finish-cluster Testing ansible SSH to ${id}"
  if ! sudo -u ansible ssh -o StrictHostKeyChecking=no "${id}" 'hostname && id' >/dev/null 2>&1; then
    log "[finish-cluster] $(date '+%F %T') - WARN: ansible SSH test failed for ${id}"
    return 1
  fi

  # 5) Optional: ansible ping check
  log "[finish-cluster] $(date '+%F %T') - finish-cluster Testing Ansible ping to ${id}"
  if ! sudo -u ansible ansible "${id}" -m ping >/dev/null 2>&1; then
    log "[finish-cluster] $(date '+%F %T') - WARN: ensure_ansible_access failed on ${id} (Ansible ping)"
    return 1
  fi

  log "[finish-cluster] $(date '+%F %T') - finish-cluster Ansible access OK for ${id}"
  return 0
}

# ---------------------------------------------------------------------------
# Phase 4: build /etc/ansible/hosts using LAN IPs (10.100.10.x)
# ---------------------------------------------------------------------------
discover_lan_ip() {
  local node="$1"
  # Prefer 10.100.10.x from grains.ipv4
  local out
  out=$(salt "$node" grains.get ipv4 --out txt 2>/dev/null || true)
  echo "$out" | sed -n 's/.*-\s*\(10\.100\.10\.[0-9]\+\).*/\1/p' | head -n1
}

ensure_inventory_entry() {
  local node="$1"
  local ip="$2"

  [[ -z "$ip" ]] && die "Could not discover LAN IP for $node"

  local hosts_file="/etc/ansible/hosts"
  local line="${node} ansible_host=${ip}"

  if ! grep -qE "^${node}\b" "$hosts_file"; then
    log "Adding $node to $hosts_file as ${line}"
    echo "$line" >>"$hosts_file"
  else
    log "$node already present in $hosts_file; not duplicating"
  fi
}

# Optional: populate known_hosts for manual SSH use (ansible itself doesn’t need it)
ensure_known_host() {
  local node="$1"
  local ip="$2"
  local kh="/home/ansible/.ssh/known_hosts"

  mkdir -p "$(dirname "$kh")"
  touch "$kh"
  chown ansible:ansible "$kh"
  chmod 644 "$kh"

  # Avoid duplicates
  if ! sudo -u ansible ssh-keygen -F "$ip" >/dev/null 2>&1; then
    log "Adding SSH host key for $node ($ip) to ansible known_hosts"
    sudo -u ansible ssh-keyscan -H "$ip" >>"$kh" 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------
# Phase 5: (optional) per-role Salt states
#   NOTE: roles.prometheus / roles.grafana must be created as states to use.
# ---------------------------------------------------------------------------
apply_role_states() {
  local node="$1"
  local role="${ROLE_MAP[$node]:-}"

  [[ -z "$role" ]] && {
    log "No role mapped for $node; skipping role-specific states"
    return 0
  }

  case "$role" in
    k8s)
      # Example: control plane / worker / flannel, etc.
      # salt "$node" state.apply roles.k8s_control_plane
      # salt "$node" state.apply roles.k8s_flannel
      log "Role 'k8s' for $node – TODO: add concrete Salt states here"
      ;;
    prom)
      # Uncomment once you create roles.prometheus.sls
      # salt "$node" state.apply roles.prometheus
      log "Role 'prom' for $node – TODO: add roles.prometheus Salt state"
      ;;
    graf)
      # Uncomment once you create roles.grafana.sls
      # salt "$node" state.apply roles.grafana
      log "Role 'graf' for $node – TODO: add roles.grafana Salt state"
      ;;
    storage)
      log "Role 'storage' for $node – TODO: add storage Salt states"
      ;;
    *)
      log "Unknown role '$role' for $node – skipping role-specific states"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Phase 6: verify ansible connectivity
# ---------------------------------------------------------------------------
test_ansible_ping() {
  local node="$1"
  log "Testing Ansible ping to $node"
  if ! sudo -u ansible ansible "$node" -m ping >/tmp/ansible-ping-"$node".log 2>&1; then
    log "WARN: Ansible ping failed for $node; see /tmp/ansible-ping-$node.log"
    return 1
  fi
  log "Ansible ping succeeded for $node"
}
# --- Helper: update /etc/ansible/hosts with WG IPs ---
update_ansible_inventory() {
  local id="$1"     # e.g. prometheus.unixbox.net
  local wg_ip="$2"  # e.g. 10.78.0.2

  local inv="/etc/ansible/hosts"

  mkdir -p /etc/ansible
  touch "$inv"

  # Add or update the host line (simple static inventory)
  if grep -qE "^${id}[[:space:]]" "$inv"; then
    # Update existing line
    sed -i "s|^${id}.*|${id} ansible_host=${wg_ip}|" "$inv"
  else
    echo "${id} ansible_host=${wg_ip}" >> "$inv"
  fi

  # Minimal group support for monitoring (prom + graf)
  case "$id" in
    prometheus.unixbox.net|grafana.unixbox.net)
      if ! grep -q "^\[monitoring\]" "$inv"; then
        printf "\n[monitoring]\n" >> "$inv"
      fi
      if ! awk -v h="$id" '
        BEGIN{in_group=0; found=0}
        /^\[monitoring\]/{in_group=1; next}
        /^\[/{in_group=0}
        in_group && $1==h{found=1}
        END{exit(found?0:1)}
      ' "$inv"; then
        echo "$id" >> "$inv"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  log "=== finish-cluster starting ==="
  check_salt_master
  ensure_local_ansible_user
  update_ansible_inventory

  local pubkey
  pubkey="$(get_ansible_pubkey)"

  for node in "${NODES[@]}"; do
    log "--- Processing node ${node} ---"

    wait_for_minion "$node" 360
    apply_common_baseline "$node"
    ensure_ansible_access "$node" "$pubkey"

    local ip
    ip="$(discover_lan_ip "$node")"
    ensure_inventory_entry "$node" "$ip"
    ensure_known_host "$node" "$ip"

    apply_role_states "$node" || true
    test_ansible_ping "$node" || true
  done

  log "=== finish-cluster completed successfully ==="
}

main "$@"
EOF_FINISH_CLUSTER
  chmod +x /usr/local/sbin/finish-cluster

  # -------------------------------------------------------------------------
  # Systemd unit to run finish-cluster once on first boot
  # -------------------------------------------------------------------------

  cat >/etc/systemd/system/finish-cluster.service <<'EOF_FINISH_CLUSTER_UNIT'
[Unit]
Description=Finalize K8s cluster via Salt and kubeadm
After=network-online.target salt-master.service
Wants=network-online.target salt-master.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/finish-cluster
# We want retries if something transient fails (e.g. minion is still rebooting)
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF_FINISH_CLUSTER_UNIT

  systemctl daemon-reload || true
  systemctl enable finish-cluster.service || true

  # Convenience alias for interactive root shells
  if ! grep -q 'finish-cluster' /root/.bashrc 2>/dev/null; then
    echo "alias finish-cluster='/usr/local/sbin/finish-cluster'" >> /root/.bashrc
  fi

  log "finish-cluster script + service installed on master"

main_master() {
  log "BEGIN postinstall (master control hub)"

  ensure_base
  ensure_users
  wg_setup_planes
  nft_firewall
  hub_seed
  helper_tools
  salt_master_stack
telemetry_stack
  control_stack
  desktop_gui
  pillars_and_states_seed
  seed_k8s_support_tools
  install_wg_refresh_tool
  ansible_stack
  semaphore_stack
  configure_salt_master_network
  configure_nftables_master
  write_bashrc
  write_tmux_conf
  setup_vim_config
  setup_python_env
  sync_skel_to_existing_users

  # Clean up unnecessary services
  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Master hub ready."

  # Mark bootstrap as done for this VM
  touch /root/.bootstrap_done
  sync || true

  # Disable bootstrap.service so it won't be wanted on next boot
  systemctl disable bootstrap.service 2>/dev/null || true
  systemctl daemon-reload || true

  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}

main_master
EOS
}

# =============================================================================
# MINION POSTINSTALL
# =============================================================================
emit_postinstall_minion() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/minion-postinstall.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR

log(){ echo "[INFO] $(date '+%F %T') - $*"; }

# ---------------------------------------------------------------------------
# Import environment seeded by mk_iso / wrapper
# ---------------------------------------------------------------------------
if [ -r /etc/environment.d/99-provision.conf ]; then
  # shellcheck disable=SC2046
  export $(grep -E '^[A-Z0-9_]+=' /etc/environment.d/99-provision.conf | xargs -d'\n' || true)
fi

ADMIN_USER="${ADMIN_USER:-todd}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
MY_GROUP="${MY_GROUP:-prom}"

# Per-minion WireGuard IPs (seeded by wrapper / mk_iso)
WG0_WANTED="${WG0_WANTED:-10.77.0.2/32}"  # reserved plane
WG1_WANTED="${WG1_WANTED:-10.78.0.2/32}"  # control / SSH / Salt
WG2_WANTED="${WG2_WANTED:-10.79.0.2/32}"  # metrics plane
WG3_WANTED="${WG3_WANTED:-10.80.0.2/32}"  # k8s side/backplane

# Where hub.env might live (wrapper or manual copy)
HUB_ENV_CANDIDATES=(
  "/root/darksite/cluster-seed/hub.env"
  "/root/cluster-seed/hub.env"
  "/srv/wg/hub.env"
)

# =============================================================================
# BASE OS
# =============================================================================
ensure_base() {
  log "Configuring APT & base OS packages"
  export DEBIAN_FRONTEND=noninteractive

  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF

  for i in 1 2 3; do
    if apt-get update -y; then break; fi
    sleep $((i*3))
  done

  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq xxd unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    nftables wireguard-tools \
    chrony rsyslog qemu-guest-agent vim \
    prometheus-node-exporter || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true

  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true

  cat >/etc/sysctl.d/99-minion.conf <<'EOF'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
  sysctl --system || true
}

# =============================================================================
# ADMIN USER + SSH
# =============================================================================
ensure_admin_user() {
  log "Ensuring admin user ${ADMIN_USER}"

  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [ -s "$SEED" ] && PUB="$(head -n1 "$SEED")"

  if ! id -u "${ADMIN_USER}" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "${ADMIN_USER}"
  fi

  install -d -m700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  touch "/home/${ADMIN_USER}/.ssh/authorized_keys"
  chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"

  if [ -n "$PUB" ] && ! grep -qxF "$PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys"; then
    echo "$PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"
  fi

  install -d -m755 /etc/sudoers.d
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${ADMIN_USER}" >"/etc/sudoers.d/90-${ADMIN_USER}"
  chmod 0440 "/etc/sudoers.d/90-${ADMIN_USER}"
}

install_enroll_key() {
  log "Installing cluster enrollment SSH key (for auto-enroll & registration)"

  local SRC_PRIV="/root/darksite/enroll_ed25519"
  local SRC_PUB="/root/darksite/enroll_ed25519.pub"
  local DST_DIR="/root/.ssh"
  local DST_PRIV="${DST_DIR}/enroll_ed25519"
  local DST_PUB="${DST_DIR}/enroll_ed25519.pub"

  if [[ ! -r "$SRC_PRIV" || ! -r "$SRC_PUB" ]]; then
    log "No enroll_ed25519 keypair found in /root/darksite; skipping install"
    return 0
  fi

  install -d -m700 "$DST_DIR"
  install -m600 "$SRC_PRIV" "$DST_PRIV"
  install -m644 "$SRC_PUB" "$DST_PUB"
}

ssh_hardening_static() {
  log "Applying static SSH hardening"

  install -d -m755 /etc/ssh/sshd_config.d

  cat >/etc/ssh/sshd_config.d/99-hard.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

  if [ "${ALLOW_ADMIN_PASSWORD}" = "yes" ]; then
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<'EOF'
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi

  install -d -m755 /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service wg-quick@wg2.service wg-quick@wg3.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  if sshd -t; then
    systemctl daemon-reload
    systemctl restart ssh || true
  else
    log "WARNING: sshd config test failed (pre-WG); will retry after WG1 setup"
  fi
}

ssh_bind_lan_and_wg1() {
  log "Configuring SSH ListenAddress for LAN + wg1"

  local LAN_IP WG1_ADDR
  LAN_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  WG1_ADDR="$(echo "${WG1_WANTED}" | cut -d/ -f1)"

  if [ -z "$LAN_IP" ]; then
    log "WARNING: could not detect LAN IP; leaving ListenAddress unchanged"
    return 0
  fi

  cat >/etc/ssh/sshd_config.d/00-listen.conf <<'EOF'
ListenAddress ${LAN_IP}
ListenAddress ${WG1_ADDR}
EOF

  if sshd -t; then
    systemctl daemon-reload
    systemctl restart ssh || true
  else
    log "WARNING: sshd config test failed; keeping previous sshd config"
  fi
}

# =============================================================================
# HUB METADATA (hub.env)
# =============================================================================
read_hub() {
  log "Searching for hub.env"

  local f
  for f in "${HUB_ENV_CANDIDATES[@]}"; do
    if [ -r "$f" ]; then
      log "Loading hub env from $f"
      # shellcheck disable=SC1090
      . "$f"
      break
    fi
  done

  : "${HUB_LAN:?missing HUB_LAN in hub.env}"
  : "${WG1_PUB:?missing WG1_PUB in hub.env}"
  : "${WG2_PUB:?missing WG2_PUB in hub.env}"
  : "${WG3_PUB:?missing WG3_PUB in hub.env}"
  : "${WG1_PORT:?missing WG1_PORT in hub.env}"
  : "${WG2_PORT:?missing WG2_PORT in hub.env}"
  : "${WG3_PORT:?missing WG3_PORT in hub.env}"

  : "${HUB_WG1_NET:?missing HUB_WG1_NET in hub.env}"
  : "${HUB_WG2_NET:?missing HUB_WG2_NET in hub.env}"
  : "${HUB_WG3_NET:?missing HUB_WG3_NET in hub.env}"

  : "${WG_ALLOWED_CIDR:?missing WG_ALLOWED_CIDR in hub.env}"
}

# =============================================================================
# WIREGUARD PLANES
# =============================================================================
wg_setup_all() {
  log "Configuring WireGuard planes on minion"

  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077

  local ifn
  for ifn in wg0 wg1 wg2 wg3; do
    [ -f "/etc/wireguard/${ifn}.key" ] || wg genkey | tee "/etc/wireguard/${ifn}.key" | wg pubkey >"/etc/wireguard/${ifn}.pub"
  done

  # wg0: reserved
  cat >/etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address    = ${WG0_WANTED}
PrivateKey = $(cat /etc/wireguard/wg0.key)
ListenPort = 0
MTU        = 1420
EOF

  # wg1: control / SSH / Salt
  cat >/etc/wireguard/wg1.conf <<'EOF'
[Interface]
Address    = ${WG1_WANTED}
PrivateKey = $(cat /etc/wireguard/wg1.key)
ListenPort = 0
MTU        = 1420

[Peer]
PublicKey  = ${WG1_PUB}
Endpoint   = ${HUB_LAN}:${WG1_PORT}
AllowedIPs = ${HUB_WG1_NET}
PersistentKeepalive = 25
EOF

  # wg2: metrics plane
  cat >/etc/wireguard/wg2.conf <<'EOF'
[Interface]
Address    = ${WG2_WANTED}
PrivateKey = $(cat /etc/wireguard/wg2.key)
ListenPort = 0
MTU        = 1420

[Peer]
PublicKey  = ${WG2_PUB}
Endpoint   = ${HUB_LAN}:${WG2_PORT}
AllowedIPs = ${HUB_WG2_NET}
PersistentKeepalive = 25
EOF

  # wg3: k8s side/backplane
  cat >/etc/wireguard/wg3.conf <<'EOF'
[Interface]
Address    = ${WG3_WANTED}
PrivateKey = $(cat /etc/wireguard/wg3.key)
ListenPort = 0
MTU        = 1420

[Peer]
PublicKey  = ${WG3_PUB}
Endpoint   = ${HUB_LAN}:${WG3_PORT}
AllowedIPs = ${HUB_WG3_NET}
PersistentKeepalive = 25
EOF

  chmod 600 /etc/wireguard/*.conf
  umask "$_old_umask"

  systemctl daemon-reload || true
  systemctl enable --now wg-quick@wg1 || true
  systemctl enable --now wg-quick@wg2 || true
  systemctl enable --now wg-quick@wg3 || true
}

auto_enroll_with_hub() {
  log "Attempting auto-enrollment with hub via wg-add-peer"

  local ENROLL_KEY="/root/.ssh/enroll_ed25519"
  if [[ ! -r "$ENROLL_KEY" ]]; then
    log "Enrollment SSH key ${ENROLL_KEY} missing; skipping auto-enroll"
    return 0
  fi

  local SSHOPTS="-i ${ENROLL_KEY} -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=6"

  # Check if enrollment is open
  local check_cmd='[ -f /srv/wg/ENROLL_ENABLED ]'
  if ! ssh $SSHOPTS "${ADMIN_USER}@${HUB_LAN}" "$check_cmd" 2>/dev/null; then
    log "Hub enrollment flag not present or unreachable; skipping wg-add-peer"
    return 0
  fi

  local iface wanted pub success any_success=0
  for iface in wg1 wg2 wg3; do
    case "$iface" in
      wg1) wanted="${WG1_WANTED}" ;;
      wg2) wanted="${WG2_WANTED}" ;;
      wg3) wanted="${WG3_WANTED}" ;;
    esac
    pub="$(cat "/etc/wireguard/${iface}.pub" 2>/dev/null || true)"
    if [[ -z "$pub" || -z "$wanted" ]]; then
      log "Skipping ${iface}: missing pubkey or wanted IP"
      continue
    fi

    success=0
    if ssh $SSHOPTS "${ADMIN_USER}@${HUB_LAN}" \
         "sudo /usr/local/sbin/wg-add-peer '$pub' '$wanted' '$iface'" 2>/dev/null; then
      success=1
    fi

    if [[ "$success" -eq 1 ]]; then
      log "[OK] Enrolled ${iface} (${wanted}) with hub"
      any_success=1
    else
      log "[WARN] Failed to enroll ${iface} with hub"
    fi
  done

  if [[ "$any_success" -ne 1 ]]; then
    log "[WARN] No WG interfaces enrolled with hub; continuing anyway"
  fi
}

# =============================================================================
# NFTABLES
# =============================================================================
nft_min() {
  log "Installing nftables rules on minion"

  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Established/related
    ct state { established, related } accept

    # Loopback
    iif "lo" accept

    # ICMP
    ip protocol icmp accept

    # SSH
    tcp dport 22 accept

    # WireGuard UDP hints (ports are from hub.env)
    udp dport { ${WG1_PORT:-51821}, ${WG2_PORT:-51822}, ${WG3_PORT:-51823} } accept

    # Any traffic from WG planes (control, metrics, k8s)
    ip saddr { 10.78.0.0/16, 10.79.0.0/16, 10.80.0.0/16 } accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state { established, related } accept

    # Allow forwarding within WG planes
    ip saddr { 10.78.0.0/16, 10.79.0.0/16, 10.80.0.0/16 } accept
    ip daddr { 10.78.0.0/16, 10.79.0.0/16, 10.80.0.0/16 } accept
  }
}
EOF

  systemctl enable --now nftables || true
}

# =============================================================================
# SALT MINION
# =============================================================================
install_salt_minion() {
  log "Installing Salt minion"

  install -d -m0755 /etc/apt/keyrings

  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public \
    -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp \
    >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.gpg || true

  cat >/etc/apt/sources.list.d/salt.sources <<'EOF'
Types: deb
URIs: https://packages.broadcom.com/artifactory/saltproject-deb
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/salt-archive-keyring.pgp
EOF

  cat >/etc/apt/preferences.d/salt-pin-1001 <<'EOF'
Package: salt-*
Pin: version 3006.*
Pin-Priority: 1001
EOF

  apt-get update -y || true
  apt-get install -y --no-install-recommends salt-minion salt-common || true

  mkdir -p /etc/salt/minion.d

  # Master is the hub LAN IP from hub.env
  cat >/etc/salt/minion.d/master.conf <<'EOF'
master: ${HUB_LAN}
ipv6: False
EOF

  # Grains: role + LAN/WG IPs
  local LAN_IP WG1_ADDR WG2_ADDR WG3_ADDR
  LAN_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  WG1_ADDR="$(echo "${WG1_WANTED}" | cut -d/ -f1)"
  WG2_ADDR="$(echo "${WG2_WANTED}" | cut -d/ -f1)"
  WG3_ADDR="$(echo "${WG3_WANTED}" | cut -d/ -f1)"

  cat >/etc/salt/minion.d/role.conf <<EOF
grains:
  role: ${MY_GROUP}
  lan_ip: ${LAN_IP}
  wg1_ip: ${WG1_ADDR}
  wg2_ip: ${WG2_ADDR}
  wg3_ip: ${WG3_ADDR}
EOF

  install -d -m0755 /etc/systemd/system/salt-minion.service.d
  cat >/etc/systemd/system/salt-minion.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  systemctl daemon-reload
  systemctl enable --now salt-minion || true
}

# =============================================================================
# METRICS (node_exporter on wg2)
# =============================================================================
bind_node_exporter() {
  log "Binding node_exporter to wg2 IP"

  local WG2_ADDR
  WG2_ADDR="$(echo "${WG2_WANTED}" | cut -d/ -f1)"

  install -d -m755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<'EOF'
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=${WG2_ADDR}:9100 --web.disable-exporter-metrics
EOF

  cat >/etc/systemd/system/prometheus-node-exporter.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg2.service network-online.target
Wants=wg-quick@wg2.service network-online.target
EOF

  systemctl daemon-reload
  systemctl enable --now prometheus-node-exporter || true
}

# =============================================================================
# REGISTER WITH MASTER (PROM + ANSIBLE)
# =============================================================================
register_with_master() {
  log "Registering minion with master via register-minion"

  local ENROLL_KEY="/root/.ssh/enroll_ed25519"
  if [[ ! -r "$ENROLL_KEY" ]]; then
    log "Enrollment SSH key ${ENROLL_KEY} missing; skipping register-minion"
    return 0
  fi

  local WG2_ADDR
  WG2_ADDR="$(echo "${WG2_WANTED}" | cut -d/ -f1)"
  local HOST_SHORT
  HOST_SHORT="$(hostname -s)"

  local SSHOPTS="-i ${ENROLL_KEY} -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=6"

  if ssh $SSHOPTS "${ADMIN_USER}@${HUB_LAN}" \
       "sudo /usr/local/sbin/register-minion '${MY_GROUP}' '${HOST_SHORT}' '${WG2_ADDR}'" 2>/dev/null; then
    log "[OK] Registered ${HOST_SHORT} (${WG2_ADDR}) in group ${MY_GROUP}"
    return 0
  fi

  log "[WARN] Failed to register minion with master; Prom/Ansible inventories will miss this node until fixed"
}

# =============================================================================
# ROLE-SPECIFIC HOOKS
# =============================================================================
maybe_role_specific() {
  case "${MY_GROUP}" in
    storage)
      log "Role=storage: installing minimal storage tooling (placeholder)"
      apt-get install -y --no-install-recommends zfsutils-linux || true
      modprobe zfs 2>/dev/null || true
      ;;
    # prom / graf / k8s-* etc. handled by Salt
  esac
}

write_bashrc() {
  log "Writing clean .bashrc for all users (via /etc/skel)..."
  local BASHRC=/etc/skel/.bashrc
  cat > "$BASHRC" <<'EOF'
# ~/.bashrc - foundryBot cluster console

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# -------------------------------------------------------------------
# History, shell options, basic prompt
# -------------------------------------------------------------------
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT='%F %T '
HISTCONTROL=ignoredups:erasedups

shopt -s histappend
shopt -s checkwinsize
shopt -s cdspell

# Basic prompt (will be overridden below with colorized variant)
PS1='\u@\h:\w\$ '

# -------------------------------------------------------------------
# Banner
# -------------------------------------------------------------------
fb_banner() {
  cat << 'FBBANNER'

   oec :                                            dF                        ..
  @88888         u.      x.    .        u.    u.   '88bu.         .u    .    @L
  8"*88%   ...ue888b   .@88k  z88u    x@88k u@88c. '*88888bu    .d88B :@8c  9888i   .dL
  8b.      888R Y888r ~"8888 ^8888   ^"8888""8888"   ^"*8888N  ="8888f8888r `Y888k:*888.
 u888888>  888R I888>   8888  888R     8888  888R   beWE "888L   4888>'88"    888E  888I
  8888R    888R I888>   8888  888R     8888  888R   888E  888E   4888> '      888E  888I
  8888P    888R I888>   8888  888R     8888  888R   888E  888E   4888>        888E  888I
  *888>   u8888cJ888    8888 ,888B .   8888  888R   888E  888F  .d888L .+     888E  888I
  4888     "*888*P"    "8888Y 8888"   "*88*" 8888" .888N..888   ^"8888*"      x888N><888'
  '888       'Y"        `Y"   'YP       ""   'Y"    `"888*""       "Y"        "88"  888
   88R                                                 ""                           88F
   88>                                                                              98" OS
   48         zero trust · borg-like · agnostic platfourms -> everywhere.          ./"
   '8                                                                             ~`

FBBANNER
}

# Only show once per interactive session
if [ -z "$FBNOBANNER" ]; then
  fb_banner
  export FBNOBANNER=1
fi

# -------------------------------------------------------------------
# Colorized prompt (root vs non-root)
# -------------------------------------------------------------------
if [ "$EUID" -eq 0 ]; then
  PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
else
  PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi

# -------------------------------------------------------------------
# Bash completion
# -------------------------------------------------------------------
if [ -f /etc/bash_completion ]; then
  # shellcheck source=/etc/bash_completion
  . /etc/bash_completion
fi

# -------------------------------------------------------------------
# Basic quality-of-life aliases
# -------------------------------------------------------------------
alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'

alias ls='ls --color=auto'
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias e='${EDITOR:-vim}'
alias vi='vim'

# Net & disk helpers
alias ports='ss -tuln'
alias df='df -h'
alias du='du -h'
alias tk='tmux kill-server'

# -------------------------------------------------------------------
# Auto-activate BCC virtualenv (if present)
# -------------------------------------------------------------------
VENV_DIR="/root/bccenv"
if [ -d "$VENV_DIR" ] && [ -n "$PS1" ]; then
  if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$VENV_DIR" ]; then
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
  fi
fi

# -------------------------------------------------------------------
# Friendly login line
# -------------------------------------------------------------------
echo "Welcome $USER — connected to $(hostname) on $(date)"
echo "Type 'shl' for the foundryBot helper command list."
EOF
}

# -----------------------------------------------------------------------------
write_tmux_conf() {
  log "Writing tmux.conf to /etc/skel and root"
  apt-get install -y tmux

  local TMUX_CONF="/etc/skel/.tmux.conf"

  cat > "$TMUX_CONF" <<'EOF'
# ~/.tmux.conf — Airline-style theme
set -g mouse on
setw -g mode-keys vi
set -g history-limit 10000
set -g default-terminal "screen-256color"
set-option -ga terminal-overrides ",xterm-256color:Tc"
set-option -g status on
set-option -g status-interval 5
set-option -g status-justify centre
set-option -g status-bg colour236
set-option -g status-fg colour250
set-option -g status-style bold
set-option -g status-left-length 60
set-option -g status-left "#[fg=colour0,bg=colour83] #S #[fg=colour83,bg=colour55,nobold,nounderscore,noitalics]"
set-option -g status-right-length 120
set-option -g status-right "#[fg=colour55,bg=colour236]#[fg=colour250,bg=colour55] %Y-%m-%d  %H:%M #[fg=colour236,bg=colour55]#[fg=colour0,bg=colour236] #H "
set-window-option -g window-status-current-style "fg=colour0,bg=colour83,bold"
set-window-option -g window-status-current-format " #I:#W "
set-window-option -g window-status-style "fg=colour250,bg=colour236"
set-window-option -g window-status-format " #I:#W "
set-option -g pane-border-style "fg=colour238"
set-option -g pane-active-border-style "fg=colour83"
set-option -g message-style "bg=colour55,fg=colour250"
set-option -g message-command-style "bg=colour55,fg=colour250"
set-window-option -g bell-action none
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
bind r source-file ~/.tmux.conf \; display-message "Reloaded!"
bind-key -T copy-mode-vi 'v' send -X begin-selection
bind-key -T copy-mode-vi 'y' send -X copy-selection-and-cancel
EOF

  log ".tmux.conf written to /etc/skel/.tmux.conf"

  # Also set for root:
  cp "$TMUX_CONF" /root/.tmux.conf
  log ".tmux.conf copied to /root/.tmux.conf"
}

# Backwards-compat wrapper (if anything else ever calls this name)
seed_tmux_conf() {
  write_tmux_conf
}

# -----------------------------------------------------------------------------
setup_vim_config() {
  log "Writing standard Vim config..."
  apt-get install -y \
    vim \
    git \
    vim-airline \
    vim-airline-themes \
    vim-ctrlp \
    vim-fugitive \
    vim-gitgutter \
    vim-tabular

  local VIMRC=/etc/skel/.vimrc
  mkdir -p /etc/skel/.vim/autoload/airline/themes

  cat > "$VIMRC" <<'EOF'
syntax on
filetype plugin indent on
set nocompatible
set tabstop=2 shiftwidth=2 expandtab
set autoindent smartindent
set background=dark
set ruler
set showcmd
set cursorline
set wildmenu
set incsearch
set hlsearch
set laststatus=2
set clipboard=unnamedplus
set showmatch
set backspace=indent,eol,start
set ignorecase
set smartcase
set scrolloff=5
set wildmode=longest,list,full
set splitbelow
set splitright
highlight ColorColumn ctermbg=darkgrey guibg=grey
highlight ExtraWhitespace ctermbg=red guibg=red
match ExtraWhitespace /\s\+$/
let g:airline_powerline_fonts = 1
let g:airline_theme = 'custom'
let g:airline#extensions#tabline#enabled = 1
let g:airline_section_z = '%l:%c'
let g:ctrlp_map = '<c-p>'
let g:ctrlp_cmd = 'CtrlP'
nmap <leader>gs :Gstatus<CR>
nmap <leader>gd :Gdiff<CR>
nmap <leader>gc :Gcommit<CR>
nmap <leader>gb :Gblame<CR>
let g:gitgutter_enabled = 1
autocmd FileType python,yaml setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType javascript,typescript,json setlocal tabstop=2 shiftwidth=2 expandtab
autocmd FileType sh,bash,zsh setlocal tabstop=2 shiftwidth=2 expandtab
nnoremap <leader>w :w<CR>
nnoremap <leader>q :q<CR>
nnoremap <leader>tw :%s/\s\+$//e<CR>
if &term =~ 'xterm'
  let &t_SI = "\e[6 q"
  let &t_EI = "\e[2 q"
endif
EOF

  chmod 644 /etc/skel/.vimrc
  cat > /etc/skel/.vim/autoload/airline/themes/custom.vim <<'EOF'
let g:airline#themes#custom#palette = {}
let s:N1 = [ '#000000' , '#00ff5f' , 0 , 83 ]
let s:N2 = [ '#ffffff' , '#5f00af' , 255 , 55 ]
let s:N3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:I1 = [ '#000000' , '#5fd7ff' , 0 , 81 ]
let s:I2 = [ '#ffffff' , '#5f00d7' , 255 , 56 ]
let s:I3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:V1 = [ '#000000' , '#af5fff' , 0 , 135 ]
let s:V2 = [ '#ffffff' , '#8700af' , 255 , 91 ]
let s:V3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:R1 = [ '#000000' , '#ff5f00' , 0 , 202 ]
let s:R2 = [ '#ffffff' , '#d75f00' , 255 , 166 ]
let s:R3 = [ '#ffffff' , '#303030' , 255 , 236 ]
let s:IA = [ '#aaaaaa' , '#1c1c1c' , 250 , 234 ]
let g:airline#themes#custom#palette.normal = airline#themes#generate_color_map(s:N1, s:N2, s:N3)
let g:airline#themes#custom#palette.insert = airline#themes#generate_color_map(s:I1, s:I2, s:I3)
let g:airline#themes#custom#palette.visual = airline#themes#generate_color_map(s:V1, s:V2, s:V3)
let g:airline#themes#custom#palette.replace = airline#themes#generate_color_map(s:R1, s:R2, s:R3)
let g:airline#themes#custom#palette.inactive = airline#themes#generate_color_map(s:IA, s:IA, s:IA)
EOF

  mkdir -p /root/.vim/autoload/airline/themes
  cp /etc/skel/.vimrc /root/.vimrc
  chmod 644 /root/.vimrc
  cp /etc/skel/.vim/autoload/airline/themes/custom.vim /root/.vim/autoload/airline/themes/custom.vim
  chmod 644 /root/.vim/autoload/airline/themes/custom.vim
}

# -----------------------------------------------------------------------------
setup_python_env() {
  log "Setting up Python for BCC scripts..."

  # System packages only — no pip bcc!
  apt-get install -y python3-psutil python3-bpfcc python3-venv

  # Create a virtualenv that sees system site-packages
  local VENV_DIR="/root/bccenv"
  python3 -m venv --system-site-packages "$VENV_DIR"

  source "$VENV_DIR/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install cryptography pyOpenSSL numba pytest
  deactivate

  log "System Python has psutil + bpfcc. Venv created at $VENV_DIR with system site-packages."

  # Auto-activate for root
  local ROOT_BASHRC="/root/.bashrc"
  if ! grep -q "$VENV_DIR" "$ROOT_BASHRC" 2>/dev/null; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv"
      echo "source \"$VENV_DIR/bin/activate\""
    } >> "$ROOT_BASHRC"
  fi

  # Auto-activate for future users
  local SKEL_BASHRC="/etc/skel/.bashrc"
  if ! grep -q "$VENV_DIR" "$SKEL_BASHRC" 2>/dev/null; then
    {
      echo ""
      echo "# Auto-activate BCC virtualenv if available"
      echo "[ -d \"$VENV_DIR\" ] && source \"$VENV_DIR/bin/activate\""
    } >> "$SKEL_BASHRC"
  fi

  log "Virtualenv activation added to root and skel .bashrc"
}

# -----------------------------------------------------------------------------
sync_skel_to_existing_users() {
  log "Syncing skel configs to existing users (root + baked)..."

  local files=".bashrc .vimrc .tmux.conf"
  local homes="/root"
  homes+=" $(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)"

  for home in $homes; do
    for f in $files; do
      if [ -f "/etc/skel/$f" ]; then
        cp -f "/etc/skel/$f" "$home/$f"
      fi
    done
  done
}

# =============================================================================
# MAIN
# =============================================================================
main() {
  log "BEGIN postinstall (minion)"

  ensure_base
  ensure_admin_user
  install_enroll_key
  ssh_hardening_static
  read_hub
  wg_setup_all
  ssh_bind_lan_and_wg1
  auto_enroll_with_hub
  nft_min
  install_salt_minion
  bind_node_exporter
  register_with_master
  maybe_role_specific
  write_bashrc
  write_tmux_conf
  setup_vim_config
  setup_python_env
  sync_skel_to_existing_users

  # Cleanup noisy/unneeded services
  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Minion ready."

  # Disable bootstrap.service for next boot
  systemctl disable bootstrap.service 2>/dev/null || true
  systemctl daemon-reload || true

  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}

main
EOS
}

# =========================
# MINION WRAPPER
# =========================

emit_minion_wrapper() {
  # Usage: emit_minion_wrapper <outfile> <group> <wg0/32> <wg1/32> <wg2/32> <wg3/32>
  local out="$1" group="$2" wg0="$3" wg1="$4" wg2="$5" wg3="$6"
  local hub_src="$BUILD_ROOT/hub/hub.env"
  [[ -s "$hub_src" ]] || { err "emit_minion_wrapper: missing hub.env at $hub_src"; return 1; }

  cat >"$out" <<'EOSH'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/minion-wrapper.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Wrapper failed at line $LINENO" >&2' ERR
EOSH

  {
    echo 'mkdir -p /root/darksite/cluster-seed'
    echo 'cat > /root/darksite/cluster-seed/hub.env <<HUBEOF'
    cat "$hub_src"
    echo 'HUBEOF'
    echo 'chmod 0644 /root/darksite/cluster-seed/hub.env'
  } >>"$out"

  cat >>"$out" <<EOSH
install -d -m0755 /etc/environment.d
{
  echo "ADMIN_USER=\${ADMIN_USER:-$ADMIN_USER}"
  echo "MY_GROUP=${group}"
  echo "WG0_WANTED=${wg0}"
  echo "WG1_WANTED=${wg1}"
  echo "WG2_WANTED=${wg2}"
  echo "WG3_WANTED=${wg3}"
} >> /etc/environment.d/99-provision.conf
chmod 0644 /etc/environment.d/99-provision.conf
EOSH

  cat >>"$out" <<'EOSH'
install -d -m0755 /root/darksite
cat >/root/darksite/postinstall-minion.sh <<'EOMINION'
EOSH

  local __tmp_minion
  __tmp_minion="$(mktemp)"
  emit_postinstall_minion "$__tmp_minion"
  cat "$__tmp_minion" >>"$out"
  rm -f "$__tmp_minion"

  cat >>"$out" <<'EOSH'
EOMINION
chmod +x /root/darksite/postinstall-minion.sh
bash -lc '/root/darksite/postinstall-minion.sh'
EOSH
  chmod +x "$out"
}

# =============================================================================
# GENERIC: ensure hub enrollment seed exists
# =============================================================================

ensure_master_enrollment_seed() {
  local vmid="$1"
  pmx_guest_exec "$vmid" /bin/bash -lc 'set -euo pipefail
mkdir -p /srv/wg
: > /srv/wg/ENROLL_ENABLED'
}

# =============================================================================
# minion deploy helper
# =============================================================================

deploy_minion_vm() {
  # deploy_minion_vm <vmid> <name> <lan_ip> <group> <wg0/32> <wg1/32> <wg2/32> <wg3/32> <mem_mb> <cores> <disk_gb>
  local id="$1" name="$2" ip="$3" group="$4"
  local wg0="$5" wg1="$6" wg2="$7" wg3="$8"
  local mem="$9" cores="${10}" disk="${11}"

  local payload iso
  payload="$(mktemp)"
  emit_minion_wrapper "$payload" "$group" "$wg0" "$wg1" "$wg2" "$wg3"

  iso="$BUILD_ROOT/${name}.iso"
  mk_iso "$name" "$payload" "$iso" "$ip"
  pmx_deploy "$id" "$name" "$iso" "$mem" "$cores" "$disk"

  wait_poweroff "$id" 2400
  boot_from_disk "$id"
  wait_poweroff "$id" 2400
  pmx "qm start $id"
  pmx_wait_for_state "$id" "running" 600
}

# =============================================================================
# ORIGINAL: base proxmox_cluster
# =============================================================================

proxmox_cluster() {
  log "=== Building base Proxmox cluster (master + prom + graf + k8s-jump + storage) ==="

  # --- Master (hub) ---
  log "Emitting postinstall-master.sh"
  MASTER_PAYLOAD="$(mktemp)"
  emit_postinstall_master "$MASTER_PAYLOAD"

  MASTER_ISO="$BUILD_ROOT/master.iso"
  mk_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"
  pmx_deploy "$MASTER_ID" "$MASTER_NAME" "$MASTER_ISO" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"

  wait_poweroff "$MASTER_ID" 1800
  boot_from_disk "$MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  pmx "qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900

  ensure_master_enrollment_seed "$MASTER_ID"

  log "Fetching hub.env from master via QGA..."
  mkdir -p "$BUILD_ROOT/hub"
  DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "hub.env saved to ${DEST}"
  else
    err "QGA fetch failed; fallback to SSH probe"
    for u in "${ADMIN_USER}" ansible root; do
      if sssh "$u@${MASTER_LAN}" "test -r /srv/wg/hub.env" 2>/dev/null; then
        sscp "$u@${MASTER_LAN}:/srv/wg/hub.env" "${DEST}"
        break
      fi
    done
    [[ -s "$DEST" ]] || { err "Failed to retrieve hub.env"; exit 1; }
  fi

  pmx_guest_exec "$MASTER_ID" /bin/bash -lc ": >/srv/wg/ENROLL_ENABLED" || \
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment on || true' || \
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'wg-enrollment on || true' || true

  deploy_minion_vm "$PROM_ID"  "$PROM_NAME"  "$PROM_IP"  "prom" \
    "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3" \
    "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$GRAF_ID"  "$GRAF_NAME"  "$GRAF_IP"  "graf" \
    "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3" \
    "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$K8S_ID"   "$K8S_NAME"   "$K8S_IP"   "k8s"  \
    "$K8S_WG0"  "$K8S_WG1" "$K8S_WG2" "$K8S_WG3" \
    "$K8S_MEM"  "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$STOR_ID"  "$STOR_NAME"  "$STOR_IP"  "storage" \
    "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3" \
    "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"

  pmx_wait_qga(){ local id="$1" t="${2:-900}" s=$(date +%s); while :; do pmx "qm agent $id ping >/dev/null 2>&1 || qm guest ping $id >/dev/null 2>&1" && return 0; (( $(date +%s)-s > t )) && return 1; sleep 3; done; }
  pmx_wait_qga "$MASTER_ID" 900 || warn "master QGA not ready; skipping wg enroll"
  pmx "qm guest exec $MASTER_ID --output-format json -- /bin/bash -lc '/usr/bin/env IFACES=\"0 1 2 3\" bash /root/wg_cluster_enroll.sh'" \
    >/dev/null || warn "WireGuard enroll exec failed (see /var/log/wg_cluster_enroll.log inside master)"

  log "Done. Master + minions deployed (LIVE ISO → ZFS root with BE + Sanoid + signed UKI)."
}

# =============================================================================
# Proxmox K8s node VMs
# =============================================================================

proxmox_k8s_ha() {
  log "=== Deploying K8s node VMs (LBs + CPs + workers) with unified pipeline ==="

  pmx "qm start $MASTER_ID" >/dev/null 2>&1 || true
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900
  ensure_master_enrollment_seed "$MASTER_ID"

  mkdir -p "$BUILD_ROOT/hub"
  DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "hub.env refreshed at ${DEST}"
  else
    [[ -s "$DEST" ]] || die "Could not get hub.env for K8s nodes."
  fi

  pmx_guest_exec "$MASTER_ID" /bin/bash -lc ": >/srv/wg/ENROLL_ENABLED" || true

  # LBs
  deploy_minion_vm "$K8SLB1_ID" "$K8SLB1_NAME" "$K8SLB1_IP" "k8s-lb" \
    "$K8SLB1_WG0" "$K8SLB1_WG1" "$K8SLB1_WG2" "$K8SLB1_WG3" \
    "$K8S_LB_MEM" "$K8S_LB_CORES" "$K8S_LB_DISK_GB"

  deploy_minion_vm "$K8SLB2_ID" "$K8SLB2_NAME" "$K8SLB2_IP" "k8s-lb" \
    "$K8SLB2_WG0" "$K8SLB2_WG1" "$K8SLB2_WG2" "$K8SLB2_WG3" \
    "$K8S_LB_MEM" "$K8S_LB_CORES" "$K8S_LB_DISK_GB"

  # Control planes
  deploy_minion_vm "$K8SCP1_ID" "$K8SCP1_NAME" "$K8SCP1_IP" "k8s-cp" \
    "$K8SCP1_WG0" "$K8SCP1_WG1" "$K8SCP1_WG2" "$K8SCP1_WG3" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  deploy_minion_vm "$K8SCP2_ID" "$K8SCP2_NAME" "$K8SCP2_IP" "k8s-cp" \
    "$K8SCP2_WG0" "$K8SCP2_WG1" "$K8SCP2_WG2" "$K8SCP2_WG3" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  deploy_minion_vm "$K8SCP3_ID" "$K8SCP3_NAME" "$K8SCP3_IP" "k8s-cp" \
    "$K8SCP3_WG0" "$K8SCP3_WG1" "$K8SCP3_WG2" "$K8SCP3_WG3" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  # Workers
  deploy_minion_vm "$K8SW1_ID" "$K8SW1_NAME" "$K8SW1_IP" "k8s-worker" \
    "$K8SW1_WG0" "$K8SW1_WG1" "$K8SW1_WG2" "$K8SW1_WG3" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  deploy_minion_vm "$K8SW2_ID" "$K8SW2_NAME" "$K8SW2_IP" "k8s-worker" \
    "$K8SW2_WG0" "$K8SW2_WG1" "$K8SW2_WG2" "$K8SW2_WG3" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  deploy_minion_vm "$K8SW3_ID" "$K8SW3_NAME" "$K8SW3_IP" "k8s-worker" \
    "$K8SW3_WG0" "$K8SW3_WG1" "$K8SW3_WG2" "$K8SW3_WG3" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  pmx_guest_exec "$MASTER_ID" /bin/bash -lc "rm -f /srv/wg/ENROLL_ENABLED" || true

  # Finalize: WireGuard + Ansible bootstrap + cluster apply
  post_rebuild_finalize

  log "==> K8s cluster bootstrap is complete"
}

proxmox_all() {
  log "=== Running full Proxmox deployment: base cluster + K8s node VMs ==="
  proxmox_cluster
  proxmox_k8s_ha
  log "=== Proxmox ALL complete. ==="
}

# =============================================================================
# Packer scaffold (optional)
# =============================================================================

packer_scaffold() {
  require_cmd packer
  mkdir -p "$PACKER_OUT_DIR"

  local iso="${MASTER_ISO:-${ISO_ORIG:-}}"
  [[ -n "${iso:-}" ]] || die "packer_scaffold: MASTER_ISO or ISO_ORIG must be set"

  log "Emitting Packer QEMU template at: $PACKER_TEMPLATE (iso=$iso)"

  cat >"$PACKER_TEMPLATE" <<EOF
{
  "variables": {
    "image_name": "foundrybot-debian13",
    "iso_url": "${iso}",
    "iso_checksum": "none"
  },
  "builders": [
    {
      "type": "qemu",
      "name": "foundrybot-qemu",
      "iso_url": "{{user \"iso_url\"}}",
      "iso_checksum": "{{user \"iso_checksum\"}}",
      "output_directory": "${PACKER_OUT_DIR}/output",
      "shutdown_command": "sudo shutdown -P now",
      "ssh_username": "${ADMIN_USER:-admin}",
      "ssh_password": "disabled",
      "ssh_timeout": "45m",
      "headless": true,
      "disk_size": 20480,
      "format": "qcow2",
      "accelerator": "kvm",
      "http_directory": "${PACKER_OUT_DIR}/http",
      "boot_wait": "5s",
      "boot_command": [
        "<esc><wait>",
        "auto priority=critical console=ttyS0,115200n8 ",
        "preseed/file=/cdrom/preseed.cfg ",
        "debian-installer=en_US ",
        "language=en ",
        "country=US ",
        "locale=en_US.UTF-8 ",
        "hostname=packer ",
        "domain=${DOMAIN:-example.com} ",
        "<enter>"
      ]
    }
  ],
  "provisioners": [
    { "type": "shell", "inline": [ "echo 'Packer provisioner hook - handoff to foundryBot bootstrap if desired.'" ] }
  ]
}
EOF

  log "Packer scaffold ready."
}

# =============================================================================
# Export VMDK (optional)
# =============================================================================

export_vmdk() {
  require_cmd qemu-img
  [[ -f "$BASE_DISK_IMAGE" ]] || die "export_vmdk: BASE_DISK_IMAGE not found"
  mkdir -p "$(dirname "$VMDK_OUTPUT")"
  log "Converting $BASE_DISK_IMAGE -> $VMDK_OUTPUT"
  qemu-img convert -O vmdk "$BASE_DISK_IMAGE" "$VMDK_OUTPUT"
  log "VMDK export complete: $VMDK_OUTPUT"
}

# =============================================================================
# Firecracker bundle/flow (optional)
# =============================================================================

firecracker_bundle() {
  mkdir -p "$FC_WORKDIR"
  [[ -f "$FC_ROOTFS_IMG" ]] || die "firecracker_bundle: FC_ROOTFS_IMG missing"
  [[ -f "$FC_KERNEL"    ]] || die "firecracker_bundle: FC_KERNEL missing"
  [[ -f "$FC_INITRD"    ]] || die "firecracker_bundle: FC_INITRD missing"

  local cfg="$FC_WORKDIR/fc-config.json"
  log "Emitting Firecracker config: $cfg"

  cat >"$cfg" <<'EOF'
{
  "boot-source": {
    "kernel_image_path": "${FC_KERNEL}",
    "initrd_path": "${FC_INITRD}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=dhcp"
  },
  "drives": [
    { "drive_id": "rootfs", "path_on_host": "${FC_ROOTFS_IMG}", "is_root_device": true, "is_read_only": false }
  ],
  "machine-config": { "vcpu_count": ${FC_VCPUS}, "mem_size_mib": ${FC_MEM_MB}, "ht_enabled": false },
  "network-interfaces": []
}
EOF

  local run="$FC_WORKDIR/run-fc.sh"
  cat >"$run" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FC_BIN="${FC_BIN:-firecracker}"
FC_SOCKET="${FC_SOCKET:-/tmp/firecracker.sock}"
FC_CONFIG="${FC_CONFIG:-/dev/null}"
rm -f "$FC_SOCKET"
$FC_BIN --api-sock "$FC_SOCKET" &
FC_PID=$!
cleanup() { kill "$FC_PID" 2>/dev/null || true; }
trap cleanup EXIT
curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' -d @"$FC_CONFIG" /machine-config >/dev/null
curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' -d @"$FC_CONFIG" /boot-source >/dev/null
curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' -d @"$FC_CONFIG" /drives/rootfs >/dev/null
curl -sS -X PUT --unix-socket "$FC_SOCKET" -H 'Content-Type: application/json' -d '{"action_type": "InstanceStart"}' /actions >/dev/null
wait "$FC_PID"
EOF
  chmod +x "$run"

  log "Firecracker bundle ready in $FC_WORKDIR"
  log "Run with: FC_CONFIG='$cfg' $run"
}

firecracker_flow() {
  firecracker_bundle
  log "Launching Firecracker microVM..."
  FC_CONFIG="$FC_WORKDIR/fc-config.json" "$FC_WORKDIR/run-fc.sh"
}

# =============================================================================
# AWS (optional)
# =============================================================================

aws_bake_ami() {
  require_cmd aws
  require_cmd qemu-img
  [[ -n "${AWS_S3_BUCKET:-}" ]]   || die "aws_bake_ami: AWS_S3_BUCKET must be set"
  [[ -n "${AWS_REGION:-}"   ]]   || die "aws_bake_ami: AWS_REGION must be set"
  [[ -n "${AWS_IMPORT_ROLE:-}" ]]|| die "aws_bake_ami: AWS_IMPORT_ROLE must be set"

  [[ -f "$BASE_DISK_IMAGE" ]] || die "aws_bake_ami: BASE_DISK_IMAGE not found"

  mkdir -p "$BUILD_ROOT/aws"
  local raw="$BASE_RAW_IMAGE"
  local key="foundrybot/${AWS_ARCH}/$(date +%Y%m%d-%H%M%S)-root.raw"

  log "Converting $BASE_DISK_IMAGE -> raw: $raw"
  qemu-img convert -O raw "$BASE_DISK_IMAGE" "$raw"

  log "Uploading raw image to s3://$AWS_S3_BUCKET/$key"
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" s3 cp "$raw" "s3://$AWS_S3_BUCKET/$key"

  log "Starting EC2 import-image task"
  local task_id
  task_id=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 import-image \
    --description "foundryBot Debian 13 $AWS_ARCH" \
    --disk-containers "FileFormat=RAW,UserBucket={S3Bucket=$AWS_S3_BUCKET,S3Key=$key}" \
    --role-name "$AWS_IMPORT_ROLE" --query 'ImportTaskId' --output text)

  log "Import task: $task_id (polling until completed...)"
  local status ami
  while :; do
    sleep 30
    status=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 describe-import-image-tasks \
      --import-task-ids "$task_id" --query 'ImportImageTasks[0].Status' --output text)
    log "Import status: $status"
    if [[ "$status" == "completed" ]]; then
      ami=$(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 describe-import-image-tasks \
        --import-task-ids "$task_id" --query 'ImportImageTasks[0].ImageId' --output text)
      break
    elif [[ "$status" =~ ^(deleted|deleting|cancelling)$ ]]; then
      die "aws_bake_ami: import task $task_id failed with status=$status"
    fi
  done

  log "AMI created: $ami"
  echo "$ami" >"$BUILD_ROOT/aws/last-ami-id"
}

aws_run_from_ami() {
  require_cmd aws
  local ami="${AWS_AMI_ID:-}"
  if [[ -z "$ami" ]] && [[ -f "$BUILD_ROOT/aws/last-ami-id" ]]; then
    ami=$(<"$BUILD_ROOT/aws/last-ami-id")
  fi
  [[ -n "$ami" ]] || die "aws_run_from_ami: AWS_AMI_ID not set and no last-ami-id found"
  [[ -n "${AWS_SUBNET_ID:-}" ]] || die "aws_run_from_ami: AWS_SUBNET_ID must be set"
  [[ -n "${AWS_SECURITY_GROUP_ID:-}" ]] || die "aws_run_from_ami: AWS_SECURITY_GROUP_ID must be set"

  log "Launching $AWS_RUN_COUNT x $AWS_INSTANCE_TYPE in $AWS_REGION from AMI $ami"
  aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2 run-instances \
    --image-id "$ami" \
    --count "${AWS_RUN_COUNT:-1}" \
    --instance-type "${AWS_INSTANCE_TYPE:-t3.medium}" \
    --key-name "$AWS_KEY_NAME" \
    --subnet-id "$AWS_SUBNET_ID" \
    --security-group-ids "$AWS_SECURITY_GROUP_ID" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=stack,Value=${AWS_TAG_STACK:-foundrybot}},{Key=role,Value=${AWS_RUN_ROLE:-generic}}]" \
    --output table
}

# =============================================================================
# MAIN
# =============================================================================

TARGET="${TARGET:-proxmox-all}"

case "$TARGET" in
  proxmox-all)        proxmox_all        ;;
  proxmox-cluster)    proxmox_cluster    ;;
  proxmox-k8s-ha)     proxmox_k8s_ha     ;;
  packer-scaffold)    packer_scaffold    ;;
  aws-ami|aws_ami)    aws_bake_ami       ;;
  aws-run|aws_run)    aws_run_from_ami   ;;
  firecracker-bundle) firecracker_bundle ;;
  firecracker)        firecracker_flow   ;;
  vmdk-export)        export_vmdk        ;;
  *)
    die "Unknown TARGET '$TARGET'. Expected: proxmox-all | proxmox-cluster | proxmox-k8s-ha | packer-scaffold | aws-ami | aws-run | firecracker-bundle | firecracker | vmdk-export"
    ;;
esac
