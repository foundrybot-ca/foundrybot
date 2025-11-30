#!/usr/bin/env bash
# zfs-live/env.sh - Environment for Debian 13 ZFS-on-root live installer builder

set -euo pipefail

# -----------------------------------------------------------------------------
# Repo roots
# -----------------------------------------------------------------------------
ZFS_LIVE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FOUNDRY_ROOT="$(cd "$ZFS_LIVE_ROOT/.." && pwd)"

# Optionally source cluster/env.sh so we can reuse PROXMOX_HOST, ISO_STORAGE, VM_STORAGE, DOMAIN, etc.
if [[ -f "$FOUNDRY_ROOT/cluster/env.sh" ]]; then
  # shellcheck source=/dev/null
  source "$FOUNDRY_ROOT/cluster/env.sh"
fi

# -----------------------------------------------------------------------------
# Debian live ISO selection
# -----------------------------------------------------------------------------
# Debian codename for this installer. We explicitly target Debian 13 (Trixie).
ZFS_DEBIAN_CODENAME="${ZFS_DEBIAN_CODENAME:-trixie}"

# Base Debian *live* ISO path. This is the image we customize.
# You can point this at:
#   - debian-live-13.2.0-amd64-standard.iso
#   - debian-live-13.2.0-amd64-lxde.iso
#   - any official live with /live/filesystem.squashfs
ZFS_BASE_ISO_PATH="${ZFS_BASE_ISO_PATH:-/root/debian-live-13.2.0-amd64-standard.iso}"

# Optional checksum for safety. Leave empty to skip verification.
ZFS_BASE_ISO_SHA256="${ZFS_BASE_ISO_SHA256:-}"

# -----------------------------------------------------------------------------
# Build directories (all under zfs-live/build by default)
# -----------------------------------------------------------------------------
ZFS_BUILD_DIR="${ZFS_BUILD_DIR:-$ZFS_LIVE_ROOT/build}"
ZFS_ISO_WORK_DIR="${ZFS_ISO_WORK_DIR:-$ZFS_BUILD_DIR/iso}"
ZFS_SQUASHFS_WORK_DIR="${ZFS_SQUASHFS_WORK_DIR:-$ZFS_BUILD_DIR/squashfs-root}"
ZFS_OUTPUT_DIR="${ZFS_OUTPUT_DIR:-$ZFS_BUILD_DIR/output}"
ZFS_LOG_DIR="${ZFS_LOG_DIR:-$ZFS_BUILD_DIR/logs}"

mkdir -p "$ZFS_BUILD_DIR" "$ZFS_ISO_WORK_DIR" "$ZFS_SQUASHFS_WORK_DIR" "$ZFS_OUTPUT_DIR" "$ZFS_LOG_DIR"

# Paths inside ISO
ZFS_LIVE_DIR="${ZFS_LIVE_DIR:-$ZFS_ISO_WORK_DIR/live}"
ZFS_SQUASHFS_IMAGE="${ZFS_SQUASHFS_IMAGE:-$ZFS_LIVE_DIR/filesystem.squashfs}"

# Output ISO name (what we’ll upload to Proxmox / PXE / USB etc.)
ZFS_OUTPUT_ISO_NAME="${ZFS_OUTPUT_ISO_NAME:-debian-13-zfs-live-amd64.iso}"
ZFS_OUTPUT_ISO_PATH="${ZFS_OUTPUT_DIR}/${ZFS_OUTPUT_ISO_NAME}"

# -----------------------------------------------------------------------------
# ZFS-on-root layout (root + future multi-disk storage)
# -----------------------------------------------------------------------------
# Default INSTALL target disk inside the installer VM or bare metal.
# For Proxmox VirtIO this is often /dev/vda instead of /dev/sda.
ZFS_ROOT_DISK="${ZFS_ROOT_DISK:-/dev/sda}"

# Future: additional data disks that the production installer can fold into
# pool(s) for storage nodes, Ceph-like layouts, etc.
# Example:
#   export ZFS_DATA_DISKS="/dev/sdb /dev/sdc /dev/sdd"
ZFS_DATA_DISKS="${ZFS_DATA_DISKS:-}"

# ZFS pool name for root.
ZFS_POOL_NAME="${ZFS_POOL_NAME:-rpool}"

# ZFS root dataset naming convention.
# The live-config hook will create:
#   rpool/ROOT/<ZFS_DEBIAN_CODENAME>
ZFS_ROOT_DATASET_PREFIX="${ZFS_ROOT_DATASET_PREFIX:-ROOT}"
ZFS_ROOT_DATASET_NAME="${ZFS_ROOT_DATASET_NAME:-${ZFS_ROOT_DATASET_PREFIX}/${ZFS_DEBIAN_CODENAME}}"

# Default hostname / user / timezone used by the installer
# (overridable via kernel cmdline: zfs-hostname=, zfs-user=, zfs-timezone=, zfs-pass=)
ZFS_DEFAULT_HOSTNAME="${ZFS_DEFAULT_HOSTNAME:-debian-zfs}"
ZFS_DEFAULT_USERNAME="${ZFS_DEFAULT_USERNAME:-debian}"
ZFS_DEFAULT_PASSWORD="${ZFS_DEFAULT_PASSWORD:-debian}"
ZFS_DEFAULT_TIMEZONE="${ZFS_DEFAULT_TIMEZONE:-Etc/UTC}"

# Debian suite + mirror for debootstrap inside the live-config script
ZFS_DEBIAN_SUITE="${ZFS_DEBIAN_SUITE:-$ZFS_DEBIAN_CODENAME}"
ZFS_DEBOOTSTRAP_MIRROR="${ZFS_DEBOOTSTRAP_MIRROR:-http://deb.debian.org/debian}"

# -----------------------------------------------------------------------------
# Darksite / offline APT repo (optional)
# -----------------------------------------------------------------------------
# If you have an offline repo, put it here before build; we’ll copy into
# the live filesystem at /opt/darksite.
ZFS_DARKSITE_DIR="${ZFS_DARKSITE_DIR:-$ZFS_BUILD_DIR/darksite}"

# When true, the autoinstall script will try to add /opt/darksite as an
# APT source inside the target system.
ZFS_USE_DARKSITE_IN_TARGET="${ZFS_USE_DARKSITE_IN_TARGET:-false}"

# -----------------------------------------------------------------------------
# Auto-install boot menu behaviour
# -----------------------------------------------------------------------------
# Label shown in isolinux/GRUB menus for the destructive ZFS installer entry.
ZFS_BOOT_MENU_LABEL="${ZFS_BOOT_MENU_LABEL:-Auto ZFS Install (DESTROYS DISK)}"

# Kernel parameters toggling the live-config hook:
#   zfs-auto-install=1  → arm the installer
#   zfs-disk=/dev/sda   → which disk to destroy/install onto
ZFS_KERNEL_FLAG_ENABLE="${ZFS_KERNEL_FLAG_ENABLE:-zfs-auto-install=1}"
ZFS_KERNEL_FLAG_DISK_PARAM="${ZFS_KERNEL_FLAG_DISK_PARAM:-zfs-disk}"

# Optional kernel param for extra data disks (future multi-disk support):
#   zfs-data-disks=/dev/sdb,/dev/sdc,/dev/sdd
ZFS_KERNEL_FLAG_DATA_PARAM="${ZFS_KERNEL_FLAG_DATA_PARAM:-zfs-data-disks}"

# Whether to add console=ttyS0 to the auto entry (nice for headless/QEMU/Proxmox)
ZFS_ADD_SERIAL_CONSOLE="${ZFS_ADD_SERIAL_CONSOLE:-true}"

# -----------------------------------------------------------------------------
# Proxmox integration (reuses cluster/env.sh where possible)
# -----------------------------------------------------------------------------
# Storage to which we upload the built ISO on Proxmox.
ZFS_ISO_STORAGE="${ZFS_ISO_STORAGE:-${ISO_STORAGE:-local}}"

# Storage for VM disks used in the test/deploy VM.
ZFS_VM_STORAGE="${ZFS_VM_STORAGE:-${VM_STORAGE:-local-zfs}}"

# Default VMID for the ZFS live test VM in Proxmox.
ZFS_TEST_VM_ID="${ZFS_TEST_VM_ID:-13000}"

# Default name/FQDN for the ZFS live test VM.
ZFS_TEST_VM_NAME="${ZFS_TEST_VM_NAME:-debian13-zfs}"
ZFS_TEST_VM_FQDN="${ZFS_TEST_VM_FQDN:-${ZFS_TEST_VM_NAME}.${DOMAIN:-unixbox.net}-${ZFS_TEST_VM_ID}}"

# VM sizing for the ZFS live installer test VM.
ZFS_TEST_VM_MEM_MB="${ZFS_TEST_VM_MEM_MB:-4096}"
ZFS_TEST_VM_CORES="${ZFS_TEST_VM_CORES:-4}"
ZFS_TEST_VM_DISK_GB="${ZFS_TEST_VM_DISK_GB:-40}"

# Root disk device *inside* that VM (often VirtIO)
ZFS_TEST_VM_ROOT_DISK="${ZFS_TEST_VM_ROOT_DISK:-/dev/vda}"

# -----------------------------------------------------------------------------
# Local QEMU smoke test settings
# -----------------------------------------------------------------------------
# Whether to run the QEMU smoke test module by default (07_test_qemu.sh).
# You can override at runtime: ZFS_QEMU_SKIP=1 ./run.sh
ZFS_QEMU_SKIP="${ZFS_QEMU_SKIP:-0}"

# Disk image path for local QEMU test (qcow2).
ZFS_QEMU_DISK_IMG="${ZFS_QEMU_DISK_IMG:-$ZFS_BUILD_DIR/test-disk.img}"
ZFS_QEMU_DISK_SIZE_GB="${ZFS_QEMU_DISK_SIZE_GB:-40}"

# -----------------------------------------------------------------------------
# Helper: environment summary (useful when debugging builds)
# -----------------------------------------------------------------------------
zfs_live_env_summary() {
  cat <<EOF
[zfs-live] Environment summary
  ZFS_DEBIAN_CODENAME         = $ZFS_DEBIAN_CODENAME
  ZFS_BASE_ISO_PATH           = $ZFS_BASE_ISO_PATH
  ZFS_OUTPUT_ISO_PATH         = $ZFS_OUTPUT_ISO_PATH

  ZFS_ROOT_DISK               = $ZFS_ROOT_DISK
  ZFS_DATA_DISKS              = $ZFS_DATA_DISKS
  ZFS_POOL_NAME               = $ZFS_POOL_NAME
  ZFS_ROOT_DATASET_NAME       = $ZFS_ROOT_DATASET_NAME

  ZFS_DEFAULT_HOSTNAME        = $ZFS_DEFAULT_HOSTNAME
  ZFS_DEFAULT_USERNAME        = $ZFS_DEFAULT_USERNAME
  ZFS_DEFAULT_TIMEZONE        = $ZFS_DEFAULT_TIMEZONE

  ZFS_DEBOOTSTRAP_MIRROR      = $ZFS_DEBOOTSTRAP_MIRROR
  ZFS_DARKSITE_DIR            = $ZFS_DARKSITE_DIR
  ZFS_USE_DARKSITE_IN_TARGET  = $ZFS_USE_DARKSITE_IN_TARGET

  PROXMOX_HOST                = ${PROXMOX_HOST:-<unset>}
  ZFS_ISO_STORAGE             = $ZFS_ISO_STORAGE
  ZFS_VM_STORAGE              = $ZFS_VM_STORAGE
  ZFS_TEST_VM_ID              = $ZFS_TEST_VM_ID
  ZFS_TEST_VM_FQDN            = $ZFS_TEST_VM_FQDN
EOF
}

