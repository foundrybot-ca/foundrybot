#!/usr/bin/env bash
# build.sh — Debian 13 universal SB+TPM ZFS image builder (Proxmox + AWS)
# UEFI-only, ZFS-on-root with Boot Environments, UKI signing, Secure Boot, Sanoid
# Modes: proxmox-cluster | image-only | aws | packer-scaffold | firecracker-bundle
set -Eeuo pipefail
shopt -s extglob
trap 'rc=$?; echo; echo "[X] ${BASH_COMMAND@Q} failed at line ${LINENO} (rc=${rc})";
      { command -v nl >/dev/null && nl -ba "$0" | sed -n "$((LINENO-6)),$((LINENO+6))p"; } || true; exit $rc' ERR

# ==============================================================================
# 0) DRIVER MODE (env or positional)
# ==============================================================================
TARGET="${TARGET:-proxmox-cluster}"  # default; can be overridden by $1
if [ "${1:-}" ]; then TARGET="$1"; shift; fi  # allow ./build.sh image-only, etc.

# ==============================================================================
# 1) GLOBAL CONFIG
# ==============================================================================
INPUT="${INPUT:-1}"  # 1|fiend, 2|dragon, 3|lion
DOMAIN="${DOMAIN:-unixbox.net}"
case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) echo "[ERROR] Unknown INPUT=$INPUT" >&2; exit 1 ;;
esac

BUILD_ROOT="${BUILD_ROOT:-/root/builds}"; mkdir -p "$BUILD_ROOT"
DARKSITE_SUITE="${DARKSITE_SUITE:-trixie}"     # Debian 13
ARCH="${ARCH:-amd64}"

# Secure Boot keys (db.key/db.crt) — real keys preferred; temp keys auto-generated if missing
SB_KEY="${SB_KEY:-$BUILD_ROOT/keys/db.key}"
SB_CRT="${SB_CRT:-$BUILD_ROOT/keys/db.crt}"
UEFI_BLOB="${UEFI_BLOB:-$BUILD_ROOT/keys/blob.bin}"  # optional: UEFI var-store blob for AWS --uefi-data

# AWS
AWS_S3_BUCKET="${AWS_S3_BUCKET:-}"
AWS_AMI_NAME="${AWS_AMI_NAME:-debian13-sb-zfs-$(date +%F)}"
AWS_LT_NAME="${AWS_LT_NAME:-debian13-sb-zfs-lt}"
UNIVERSAL_QCOW2="${UNIVERSAL_QCOW2:-$BUILD_ROOT/universal.qcow2}"
UNIVERSAL_RAW="${UNIVERSAL_RAW:-$BUILD_ROOT/universal.raw}"

# ISO input/output
ISO_ORIG="${ISO_ORIG:-/var/lib/libvirt/boot/debian-13.1.0-amd64-netinst.iso}"
ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"
ROOT_SCHEME="${ROOT_SCHEME:-zfs}"

# Network (site)
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3}"

# WireGuard hub subnets/ports (master on .1; minions start at .10)
WG0_IP="${WG0_IP:-10.77.0.1/16}";  WG0_PORT="${WG0_PORT:-51820}"   # control
WG1_IP="${WG1_IP:-10.78.0.1/16}";  WG1_PORT="${WG1_PORT:-51821}"   # telemetry
WG2_IP="${WG2_IP:-10.79.0.1/16}";  WG2_PORT="${WG2_PORT:-51822}"   # build
WG3_IP="${WG3_IP:-10.80.0.1/16}";  WG3_PORT="${WG3_PORT:-51823}"   # storage
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# Role IDs/IPs
MASTER_ID="${MASTER_ID:-5010}"; MASTER_NAME="${MASTER_NAME:-master}"; MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
PROM_ID="${PROM_ID:-5011}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.123}"
GRAF_ID="${GRAF_ID:-5012}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.122}"
K8S_ID="${K8S_ID:-5013}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.121}"
STOR_ID="${STOR_ID:-5014}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.120}"

# Sizing
MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-8}"; MASTER_DISK_GB="${MASTER_DISK_GB:-20}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-20}"
K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

# Admin / ops
ADMIN_USER="${ADMIN_USER:-debian}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-/home/debian/.ssh/id_ed25519.pub}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
GUI_PROFILE="${GUI_PROFILE:-server}"   # server by default (no fluxbox)
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
ZFS_MOUNTPOINT="${ZFS_MOUNTPOINT:-/mnt/share}"

# ==============================================================================
# 2) UTILS + SANITY
# ==============================================================================
log()  { echo "[INFO]  $(date '+%F %T') - $*"; }
warn() { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err()  { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()  { err "$*"; exit 1; }

SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }
retry(){ local n="$1" s="$2"; shift 2; local i; for ((i=1;i<=n;i++)); do "$@" && return 0; sleep "$s"; done; return 1; }

validate_env_or_die() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
  case "$TARGET" in
    image-only|packer-scaffold|firecracker-bundle) local -a req=(BUILD_ROOT ISO_ORIG) ;;
    proxmox-cluster)                               local -a req=(BUILD_ROOT ISO_ORIG PROXMOX_HOST VM_STORAGE ISO_STORAGE) ;;
    aws)                                           local -a req=(BUILD_ROOT AWS_S3_BUCKET) ;;
    *)                                             local -a req=(BUILD_ROOT ISO_ORIG) ;;
  esac
  local -a miss=(); for v in "${req[@]}"; do [[ -n "${!v:-}" ]] || miss+=("$v"); done
  ((${#miss[@]}==0)) || die "missing: ${miss[*]}"
  [[ -r "$ISO_ORIG" ]] || { [[ "$TARGET" == aws ]] || die "ISO_ORIG not readable: $ISO_ORIG"; }
  mkdir -p "$BUILD_ROOT" "$BUILD_ROOT/keys"
}
validate_env_or_die

mask_to_cidr(){ awk -v m="$1" 'BEGIN{split(m,a,".");c=0;for(i=1;i<=4;i++){x=a[i]+0;for(j=7;j>=0;j--) if((x>>j)&1) c++; else break}print c}'; }

# ----------------------------------------------------------------------
# PROXMOX VM: q35 + OVMF (UEFI), EFI vars in Setup Mode, TPM v2 ON
# ----------------------------------------------------------------------
pmx(){ sssh root@"${PROXMOX_HOST}" "$@"; }
pmx_vm_state(){ pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }
pmx_wait_for_state(){ local id="$1" want="$2" t="${3:-2400}" s=$(date +%s) st; while :; do st="$(pmx_vm_state "$id")"; [[ "$st" == "$want" ]] && return 0; (( $(date +%s)-s > t )) && return 1; sleep 5; done; }
pmx_upload_iso(){ local iso="$1" base; base="$(basename "$iso")"
  sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base" || { sleep 2; sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base"; }
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${base}\" && exit 0; sleep 1; done; exit 0" || true
  echo "$base"; }
pmx_deploy_uefi(){ # id name iso mem cores disk_gb
  local vmid="$1" name="$2" iso="$3" mem="$4" cores="$5" disk_gb="$6"
  local base; base="$(pmx_upload_iso "$iso")"
  pmx VMID="$vmid" VMNAME="${name}.${DOMAIN}-$vmid" FINAL_ISO="$base" VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
qm destroy "$VMID" --purge >/dev/null 2>&1 || true
qm create "$VMID" --name "$VMNAME" --machine q35 --bios ovmf --ostype l26 \
  --agent enabled=1,fstrim_cloned_disks=1 --memory "$MEMORY_MB" --cores "$CORES" \
  --scsihw virtio-scsi-single --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB},ssd=1,discard=on,iothread=1 \
  --net0 virtio,bridge=vmbr0,firewall=1 --serial0 socket --rng0 source=/dev/urandom
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0
qm set "$VMID" --tpmstate0 ${VM_STORAGE}:1,version=v2.0
for i in {1..10}; do qm set "$VMID" --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom && break || sleep 1; done
qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH
}
wait_poweroff(){ pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }
boot_from_disk_uefi(){ local id="$1"; pmx "qm set $id --delete ide2; qm set $id --boot order=scsi0; qm start $id"; pmx_wait_for_state "$id" "running" 600; }

# ==============================================================================
# DARKSITE REPO (APT + offline extras)
# ==============================================================================
: "${ARCH:=amd64}"
: "${DARKSITE_SUITE:=trixie}"
: "${DARKSITE:=/root/builds/darksite}"

build_dark_repo() {
  local out="$1" arch="${2:-$ARCH}" suite="${3:-$DARKSITE_SUITE}"
  [[ -n "$out" ]] || { echo "[X] build_dark_repo: outdir required" >&2; return 2; }
  rm -f "$out/.stamp" 2>/dev/null || true
  rm -rf "$out"; mkdir -p "$out" "$out/extras" "$out/45wg"
  docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive -e SUITE="$suite" -e ARCH="$arch" \
    -e BASE_PACKAGES="apt apt-utils openssh-server wireguard-tools nftables qemu-guest-agent \
dracut systemd-boot-efi systemd-ukify sbsigntool tpm2-tools mokutil efitools efivar \
zfsutils-linux zfs-dkms zfs-dracut dkms build-essential linux-headers-amd64 linux-image-amd64 \
sudo ca-certificates curl wget jq unzip tar xz-utils iproute2 iputils-ping ethtool tcpdump net-tools chrony rsyslog \
bpftrace bpfcc-tools perf-tools-unstable sysstat strace lsof xorriso syslinux ansible nginx \
sanoid syncoid debsums" \
    -v "$out:/repo" "debian:${suite}" bash -lc '
set -euo pipefail
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${SUITE} main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${SUITE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free non-free-firmware
EOF
echo "Acquire::Languages \"none\";" >/etc/apt/apt.conf.d/99nolangs
apt-get update -y
apt-get install -y --no-install-recommends apt apt-utils dpkg-dev apt-rdepends gnupg
tmp_list=$(mktemp)
apt-rdepends $BASE_PACKAGES 2>/dev/null | awk "/^[A-Za-z0-9][A-Za-z0-9+.-]*$/{print}" | sort -u >"$tmp_list"
: > /tmp/want.lock
while read -r pkg; do cand=$(apt-cache policy "$pkg" | awk "/Candidate:/{print \$2}"); if [ -n "${cand:-}" ] && [ "$cand" != "(none)" ]; then echo "$pkg=$cand" >> /tmp/want.lock; fi; done <"$tmp_list"
work=/tmp/aptdownload; install -d -m0777 "$work"; chown _apt:_apt "$work" 2>/dev/null || true
runuser -u _apt -- bash -lc "cd \"$work\"; while read -r pv; do apt-get download \"\$pv\" || apt-get download \"\${pv%%=*}\"; done </tmp/want.lock"
mkdir -p /repo/pool/main
mv -f "$work"/*.deb /repo/pool/main/ 2>/dev/null || true
for sec in main extra; do mkdir -p /repo/dists/${SUITE}/${sec}/binary-${ARCH} /repo/dists/${SUITE}/${sec}/binary-all; done
apt-ftparchive packages /repo/pool/main > /repo/dists/${SUITE}/main/binary-${ARCH}/Packages
gzip -9fk  /repo/dists/${SUITE}/main/binary-${ARCH}/Packages
xz   -T0 -9e -f /repo/dists/${SUITE}/main/binary-${ARCH}/Packages
cp -a /repo/dists/${SUITE}/main/binary-${ARCH}/Packages* /repo/dists/${SUITE}/main/binary-all/ || : > /repo/dists/${SUITE}/main/binary-all/Packages
cat > /tmp/aptconf <<APTCONF
Dir { ArchiveDir "/repo"; };
Default { Packages::Compress ". gz xz"; };
APTCONF
apt-ftparchive -c /tmp/aptconf release /repo/dists/${SUITE} > /repo/dists/${SUITE}/Release
chmod -R a+rX /repo
echo "[OK] Dark repo ready"
'
  echo "[OK] built APT darksite at: $out"
}

darksite_stage_extras() {
  local out="$1"; shift || true
  [[ -n "${out:-}" ]] || { echo "[X] darksite_stage_extras: outdir required" >&2; return 2; }
  mkdir -p "$out/extras"
  [ "$#" -gt 0 ] || { echo "[i] darksite_stage_extras: no extras provided; skipping"; return 0; }
  for src in "$@"; do
    if [ -d "$src" ]; then rsync -a --delete "$src"/ "$out/extras/$(basename "$src")"/
    elif [ -f "$src" ]; then install -D -m0644 "$src" "$out/extras/$(basename "$src")"
    else echo "[WARN] darksite_stage_extras: missing path: $src" >&2; fi
  done
  chmod -R a+rX "$out/extras"
  echo "[OK] staged extras into: $out/extras"
}

darksite_fetch_repos() {
  local out="$1"; shift || true
  [[ -n "${out:-}" ]] || { echo "[X] darksite_fetch_repos: outdir required" >&2; return 2; }
  local vend="$out/extras/vendor"; mkdir -p "$vend"
  local manifest="$vend/_manifest.tsv"; : > "$manifest"
  while [ "$#" -gt 0 ]; do
    local spec="$1"; shift
    local url="${spec%@*}"; local ref=""; [[ "$spec" == *@* ]] && ref="${spec##*@}"
    local name="$(basename "${url%.git}")"; local tmpd; tmpd="$(mktemp -d)"
    echo "[*] Fetching $url ${ref:+(@ $ref)}"
    git clone --depth 1 ${ref:+--branch "$ref"} "$url" "$tmpd/$name"
    ( cd "$tmpd/$name" && git rev-parse HEAD ) > "$tmpd/$name/.git-rev"
    tar -C "$tmpd" -czf "$vend/${name}.tar.gz" "$name"
    echo -e "$name\t$url\t${ref:-HEAD}\t$(cat "$tmpd/$name/.git-rev")\t$(date -u +%F)" >> "$manifest"
    rm -rf "$tmpd"
  done
  chmod -R a+rX "$vend"
  echo "[OK] vendored repos -> $vend (manifest: $(wc -l < "$manifest") entries)"
}

# ==============================================================================
# Secure Boot keys (db.key/db.crt) & UEFI blob placeholders
# ==============================================================================
emit_sb_keys_if_missing(){
  mkdir -p "$(dirname "$SB_KEY")"
  if [[ ! -s "$SB_KEY" || ! -s "$SB_CRT" ]]; then
    log "[*] Generating TEMP Secure Boot signing keypair (db.key/db.crt) — replace with real keys!"
    openssl req -new -x509 -newkey rsa:3072 -keyout "$SB_KEY" -out "$SB_CRT" -days 3650 -nodes -subj "/CN=unixbox-db/"
    chmod 600 "$SB_KEY"; chmod 644 "$SB_CRT"
  fi
  if [[ ! -s "$UEFI_BLOB" ]]; then
    warn "[!] No UEFI var-store blob at $UEFI_BLOB. You can still boot with platform keys or shim+MOK."
  fi
}

# ==============================================================================
# Dracut module: WireGuard pre-mount (Stage-0) — optional
# ==============================================================================
emit_wg_dracut(){
  local out="$1"; mkdir -p "$out/45wg"
  cat >"$out/45wg/module-setup.sh" <<'__WGSETUP__'
#!/bin/bash
check(){ return 0; }
depends(){ echo "zfs network"; }
install(){
  inst_multiple wg wg-quick ip jq curl awk sed tpm2_unseal
  inst_simple "$moddir/wg-pre-mount.sh" /sbin/wg-pre-mount.sh
  mkdir -p "$initdir/etc/dracut/hooks/pre-mount"
  printf '%s\n' '/sbin/wg-pre-mount.sh' > "$initdir/etc/dracut/hooks/pre-mount/10-wg.sh"
}
__WGSETUP__
  chmod +x "$out/45wg/module-setup.sh"
  cat >"$out/45wg/wg-pre-mount.sh" <<'__WGPRERUN__'
#!/bin/sh
set -eu
TOKEN="$(curl -sX PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token || true)"
IID="$(curl -sH "X-aws-ec2-metadata-token: ${TOKEN:-}" http://169.254.169.254/latest/dynamic/instance-identity/document || true)" || true
if [ -s /etc/wireguard/wg0.key.sealed ]; then
  tpm2_unseal -c /etc/wireguard/wg0.key.sealed -o /run/wg.key || true
fi
PRIV=""
[ -s /run/wg.key ] && PRIV="$(cat /run/wg.key)" || PRIV="$(cat /etc/wireguard/wg0.key 2>/dev/null || echo '')"
mkdir -p /etc/wireguard
cat >/etc/wireguard/wg0.conf <<CFG
[Interface]
PrivateKey = ${PRIV}
Address    = 10.77.0.10/32
DNS        = 1.1.1.1
MTU        = 1420
SaveConfig = false
[Peer]
PublicKey  = REPLACE_HUB_PUBKEY
Endpoint   = hub.example:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CFG
wg-quick up wg0 || true
exit 0
__WGPRERUN__
  chmod +x "$out/45wg/wg-pre-mount.sh"
}

# ==============================================================================
# ZFS boot-environment toolkit & hooks (installed in target by late.sh)
# ==============================================================================
emit_zfs_be_toolkit(){
  local out_dir="$1"; mkdir -p "$out_dir/be"
  # zfs-bectl
  cat >"$out_dir/be/zfs-bectl" <<'__BECTL__'
#!/usr/bin/env bash
# zfs-bectl — tiny ZFS boot environment manager for systemd-boot + UKI
set -euo pipefail
SB_KEY="${SB_KEY:-/root/darksite/db.key}"
SB_CRT="${SB_CRT:-/root/darksite/db.crt}"

pool_bootfs() { zpool get -H -o value bootfs rpool; }
current_be()  { pool_bootfs | awk -F/ '{print $3}'; }
rootds_of()   { echo "rpool/ROOT/$1"; }

build_sign_uki() {
  local be="$1" rootds="rpool/ROOT/$1"
  local kver
  kver="$(uname -r || ls /lib/modules | sort -V | tail -1)"
  local out="/boot/efi/EFI/Linux/${be}-${kver}.efi"
  mkdir -p /boot/efi/EFI/Linux
  ukify build \
    --linux "/usr/lib/kernel/vmlinuz-${kver}" \
    --initrd "/boot/initrd.img-${kver}" \
    --cmdline "root=ZFS=${rootds} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${out}"
  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then
    sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${out}" "${out}"
  fi
  cat >/boot/loader/entries/debian.conf <<EOF
title   Debian ${be}
linux   ${out#/boot/efi}
EOF
  bootctl update || true
}

cmd="${1:-}"; shift || true
case "${cmd}" in
  list)
    zfs list -H -o name | awk '/^rpool\/ROOT\//'
    ;;
  create)
    be="${1:?usage: zfs-bectl create <be-name>}"
    cur="$(current_be)"
    snap="pre-clone-$(date +%Y%m%d%H%M%S)"
    zfs snapshot "rpool/ROOT/${cur}@${snap}"
    zfs clone   "rpool/ROOT/${cur}@${snap}" "$(rootds_of "$be")"
    zfs set canmount=noauto "$(rootds_of "$be")"
    build_sign_uki "$be"
    echo "[OK] created $be"
    ;;
  activate)
    be="${1:?usage: zfs-bectl activate <be>}"
    zpool set bootfs="$(rootds_of "$be")" rpool
    build_sign_uki "$be"
    echo "[OK] activated $be"
    ;;
  destroy)
    be="${1:?usage: zfs-bectl destroy <be>}"
    zfs destroy -r "$(rootds_of "$be")"
    echo "[OK] destroyed $be"
    ;;
  rollback)
    spec="${1:?usage: zfs-bectl rollback <be@snap>}"
    be="${spec%@*}"; snap="${spec##*@}"
    zfs rollback -r "$(rootds_of "$be")@${snap}"
    build_sign_uki "$be"
    echo "[OK] rolled back ${be} to @${snap}"
    ;;
  *)
    echo "Usage: zfs-bectl {list|create|activate|destroy|rollback}" >&2
    exit 2
    ;;
esac
__BECTL__
  chmod +x "$out_dir/be/zfs-bectl"

  # APT snapshot hook
  cat >"$out_dir/be/90-zfs-snapshots" <<'__SNAPHK__'
DPKg::Pre-Invoke  { "if command -v zfs >/dev/null 2>&1; then root=$(zpool get -H -o value bootfs rpool 2>/dev/null); ts=$(date +%Y%m%d%H%M%S); [ -n \"$root\" ] && zfs snapshot ${root}@apt-pre-${ts} || true; fi"; };
DPkg::Post-Invoke { "if command -v zfs >/dev/null 2>&1; then root=$(zpool get -H -o value bootfs rpool 2>/dev/null); ts=$(date +%Y%m%d%H%M%S); [ -n \"$root\" ] && zfs snapshot ${root}@apt-post-${ts} || true; fi"; };
__SNAPHK__

  # Kernel postinst UKI builder/sign
  cat >"$out_dir/be/zz-uki-sign" <<'__UKIHOOK__'
#!/bin/sh
set -eu
SB_KEY="${SB_KEY:-/root/darksite/db.key}"
SB_CRT="${SB_CRT:-/root/darksite/db.crt}"
POOL="${POOL:-rpool}"
BE="$(zpool get -H -o value bootfs "${POOL}" | awk -F/ '{print $3}')"
KVER="${1:-$(uname -r)}"
OUT="/boot/efi/EFI/Linux/${BE}-${KVER}.efi"

if command -v ukify >/dev/null 2>&1; then
  ukify build \
    --linux "/usr/lib/kernel/vmlinuz-${KVER}" \
    --initrd "/boot/initrd.img-${KVER}" \
    --cmdline "root=ZFS=${POOL}/ROOT/${BE} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${OUT}" || true
  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then
    sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${OUT}" "${OUT}" || true
  fi
  cat >/boot/loader/entries/debian.conf <<EOF2
title   Debian ${BE}
linux   ${OUT#/boot/efi}
EOF2
  bootctl update || true
fi
exit 0
__UKIHOOK__
  chmod +x "$out_dir/be/zz-uki-sign"
}

# ==============================================================================
# *** EARLY INSTALLER (RUNS INSIDE d-i) — minimal ext4; ZFS migration after 1st boot ***
# ==============================================================================
emit_early_zfs_install_be_script() {
  local out="$1"; install -D -m0755 /dev/null "$out"
  cat >"$out" <<"__EARLYZFS__"
#!/bin/sh
# d-i partman/early_command script — temporary ext4 root; convert to ZFS at first boot
# Safe for BusyBox (no lsblk/apt-get in this phase)
set -eu

# ----- logging (works in d-i) -----
LOG=/var/log/10-zfs.log
umask 022
mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
# shellcheck disable=SC2069
exec > >(busybox tee -a "$LOG") 2>&1

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export DEBIAN_FRONTEND=noninteractive

log(){ printf '[EARLY] %s\n' "$*" >&2; }
die(){ printf '[EARLY][X] %s\n' "$*" >&2; exit 1; }

# Mini helpers (d-i safe)
has(){ command -v "$1" >/dev/null 2>&1; }
wait_for_block(){
  dev="$1"; tries="${2:-120}"; i=0
  while [ ! -b "$dev" ] && [ $i -lt "$tries" ]; do
    sleep 0.25
    has udevadm && udevadm settle || true
    i=$((i+1))
  done
  [ -b "$dev" ] || die "block device did not appear: $dev"
}

# Make udebs available for parted/mkfs/debootstrap
echo "deb [trusted=yes] file:/cdrom/darksite-udeb trixie main" > /etc/apt/sources.list
# anna-install is present in d-i
anna-install kmod-udeb parted-udeb util-linux-udeb e2fsprogs-udeb dosfstools-udeb debootstrap-udeb || true

# Required tools in d-i
PARTED="$(command -v parted || true)"; [ -n "$PARTED" ] || die "parted not available"
MKFS_EXT4="$(command -v mkfs.ext4 || true)"; [ -n "$MKFS_EXT4" ] || die "mkfs.ext4 not available"
MKFS_VFAT="$(command -v mkfs.vfat || true)"   # we’ll format ESP inside chroot where dosfstools exists

# Pick the install disk (avoid lsblk)
pick_disk() {
  if has list-devices; then
    list-devices disk | head -n1
  else
    for d in /dev/vda /dev/sda /dev/nvme0n1; do [ -b "$d" ] && { echo "$d"; return; }; done
    # last resort: first “disk” entry in /proc/partitions
    awk '/^ *[0-9]+ +[0-9]+ +[0-9]+ +[a-z]$/{print "/dev/"$4; exit}' /proc/partitions
  fi
}
DISK="$(pick_disk)"
[ -n "$DISK" ] || die "no disk found"
log "Using disk: $DISK"

# Ensure nothing mounted/used
swapoff -a 2>/dev/null || true
umount -l /target 2>/dev/null || true
for p in 1 2 3 4; do umount -l "${DISK}${p}" 2>/dev/null || true; done

# Wipe stale metadata & partition table (no sgdisk in d-i; use dd + wipefs if present)
if has wipefs; then wipefs -a "$DISK" || true; fi
dd if=/dev/zero of="$DISK" bs=1M count=8 conv=fsync 2>/dev/null || true
sync
has partprobe && partprobe "$DISK" || true
has udevadm && udevadm settle || true
sleep 1

# Create GPT: 1) ESP 1GiB, 2) root (rest)
$PARTED -s "$DISK" mklabel gpt
# use MiB alignment and avoid 0-MiB rounding issues
$PARTED -s "$DISK" mkpart ESP fat32 1MiB 1025MiB
$PARTED -s "$DISK" set 1 esp on
$PARTED -s "$DISK" mkpart root ext4 1025MiB 100%
has partprobe && partprobe "$DISK" || true
has udevadm && udevadm settle || true
sleep 1

ESP="${DISK}1"
ROOT="${DISK}2"
wait_for_block "$ESP" 120
wait_for_block "$ROOT" 120

# Make ext4 root (skip FAT here; do it in chroot with full dosfstools)
modprobe ext4 2>/dev/null || true
"$MKFS_EXT4" -F -L root "$ROOT"

# Mount target root
mkdir -p /target
mount -t ext4 "$ROOT" /target || die "mount root failed"
mkdir -p /target/root
echo "$ESP" > /target/root/.esp-device

# Minimal debootstrap (full apt is available inside the target)
CODENAME=trixie
debootstrap --arch=amd64 "$CODENAME" /target http://deb.debian.org/debian

# Bind mounts for chroot phase
mount --rbind /dev  /target/dev
mount --rbind /proc /target/proc
mount --rbind /sys  /target/sys

# Do the “real” work inside the target (apt, bootctl, ESP format, one-shot ZFS conversion)
chroot /target /usr/bin/env bash -eu <<'CHROOT'
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# APT sources
cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free-firmware
EOF
apt-get update -y
apt-get install -y --no-install-recommends \
  linux-image-amd64 linux-headers-amd64 \
  openssh-server qemu-guest-agent \
  systemd-boot-efi ca-certificates gnupg curl wget jq xz-utils \
  efivar efitools sbsigntool mokutil systemd-ukify dracut dosfstools rsync

# Format + mount the ESP
ESP="$(cat /root/.esp-device)"
mkfs.vfat -F 32 -n EFI "$ESP"
mkdir -p /boot/efi
mount -t vfat "$ESP" /boot/efi

# Hostname and hosts
echo master >/etc/hostname
printf "127.0.0.1\tlocalhost\n127.0.1.1\tmaster\n" >/etc/hosts

# Bootloader (temporary ext4 entry; ZFS later on first boot)
bootctl install || true
install -d -m755 /boot/loader/entries
cat >/boot/loader/entries/ext4-temp.conf <<'EOF'
title   Temporary ext4 root
linux   /vmlinuz
initrd  /initrd.img
options root=LABEL=root rw
EOF
printf "default ext4-temp.conf\ntimeout 1\n" > /boot/loader/loader.conf

# First-boot ZFS conversion (same as you had, kept intact & slightly hardened)
install -d /usr/local/sbin
cat >/usr/local/sbin/convert-to-zfs.sh <<'EOSH'
#!/usr/bin/env bash
set -euo pipefail
LOG=/var/log/convert-to-zfs.log; exec > >(tee -a "$LOG") 2>&1
echo "[C2Z] start"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends dkms zfs-dkms zfsutils-linux zfs-dracut dracut systemd-ukify rsync

# Detect the disk without lsblk (fallback to /proc/cmdline root=LABEL=root)
ROOTSRC="$(findmnt -no SOURCE / || true)"
DISK=""
if [[ "$ROOTSRC" =~ ^/dev/(sd.|vd.|nvme[0-9]+n1)p?2$ ]]; then
  DISK="/dev/${BASH_REMATCH[1]%p?}"
else
  # simple heuristic if findmnt is unhelpful
  for d in /dev/vda /dev/sda /dev/nvme0n1; do [ -b "$d" ] && DISK="$d" && break; done
fi
[ -n "$DISK" ] || { echo "[C2Z] could not determine base disk"; exit 1; }

ESP="${DISK}1"
ZPART="${DISK}2"
POOL="rpool"

mkdir -p /mnt/newroot /mnt/oldroot
mount -t tmpfs -o size=2G tmpfs /mnt/newroot
rsync -aHx --exclude=/proc/* --exclude=/sys/* --exclude=/dev/* --exclude=/run/* / /mnt/newroot/
mount --rbind /dev  /mnt/newroot/dev
mount --rbind /proc /mnt/newroot/proc
mount --rbind /sys  /mnt/newroot/sys
pivot_root /mnt/newroot /mnt/newroot/mnt/oldroot || chroot /mnt/newroot /usr/bin/env bash -lc 'pivot_root /mnt/newroot /mnt/newroot/mnt/oldroot'

chroot / /usr/bin/env bash -eux <<'EOT'
umount -l /mnt/oldroot || true
sleep 1

zpool create -f \
  -o ashift=12 \
  -O compression=zstd \
  -O acltype=posixacl -O xattr=sa \
  -O atime=off -O relatime=on \
  -O dnodesize=auto \
  -O mountpoint=none rpool ${ZPART}

zfs create -o mountpoint=none   rpool/ROOT
zfs create -o canmount=noauto -o mountpoint=/ rpool/ROOT/debian
zfs mount  rpool/ROOT/debian

rsync -aHx --delete --exclude=/proc/* --exclude=/sys/* --exclude=/dev/* --exclude=/run/* / /rpool/ROOT/debian/

mkdir -p /rpool/ROOT/debian/boot/efi
mount ${ESP} /rpool/ROOT/debian/boot/efi
ESP_UUID="$(blkid -s UUID -o value ${ESP})"
echo "UUID=${ESP_UUID} /boot/efi vfat umask=0077 0 1" > /rpool/ROOT/debian/etc/fstab

zpool set bootfs=rpool/ROOT/debian rpool

chroot /rpool/ROOT/debian /usr/bin/env bash -eux <<'EOCH'
KVER="$(uname -r || ls /lib/modules | sort -V | tail -1)"
dracut --force "/boot/initrd.img-${KVER}" "${KVER}"
mkdir -p /boot/efi/EFI/Linux
ukify build \
  --linux "/usr/lib/kernel/vmlinuz-${KVER}" \
  --initrd "/boot/initrd.img-${KVER}" \
  --cmdline "root=ZFS=rpool/ROOT/debian module.sig_enforce=1" \
  --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
  --output "/boot/efi/EFI/Linux/debian-${KVER}.efi" || true
bootctl update || true
EOCH
EOT

echo "[C2Z] done; rebooting"
systemctl --no-block reboot
EOSH
chmod +x /usr/local/sbin/convert-to-zfs.sh

cat >/etc/systemd/system/convert-to-zfs.service <<'EOF'
[Unit]
Description=Convert temporary ext4 install to ZFS-on-root with Boot Environments
After=network-online.target
Wants=network-online.target
ConditionFirstBoot=yes

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/convert-to-zfs.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable convert-to-zfs.service
systemctl enable ssh || true
systemctl enable qemu-guest-agent || true
CHROOT

log "Temporary ext4 base installed; convert-to-zfs will run on first boot"
exit 0

__EARLYZFS__
}

# ==============================================================================
# Installer boot menu + preseed
# ==============================================================================
write_bootloader_entries(){
  local cust="$1"; local K="/install.amd/vmlinuz"; local I="/install.amd/initrd.gz"
  [[ -f "$cust$K" ]] || { K="/debian-installer/amd64/linux"; I="/debian-installer/amd64/initrd.gz"; }
  cat >"$cust/boot/grub/grub.cfg" <<GRUB
set default=0
set timeout=2
menuentry "Install (auto, ZFS-on-root early, UEFI, BE-aware)" {
    linux ${K} auto=true priority=critical \
      preseed/file=/cdrom/preseed.cfg \
      debconf/frontend=noninteractive \
      locale=en_US.UTF-8 keyboard-configuration/xkb-keymap=us \
      netcfg/choose_interface=auto --- quiet
    initrd ${I}
}
GRUB
}

emit_preseed_minimal() {
  local cust="${1:?custom-iso-root-required}"
  local hostname="${2:-debian}"
  local domain="${DOMAIN:-unixbox.net}"
  {
    echo '### Preseed — minimal; we do ZFS+bootstrap inside /cdrom/extras/10-zfs.sh'
    echo 'd-i debian-installer/locale string en_US.UTF-8'
    echo 'd-i console-setup/ask_detect boolean false'
    echo 'd-i keyboard-configuration/xkb-keymap select us'
    if [[ -z "${STATIC_IP:-}" ]]; then
      cat <<'EOFNET'
d-i netcfg/choose_interface select auto
d-i netcfg/disable_autoconfig boolean false
EOFNET
    else
      cat <<EOFNET
d-i netcfg/choose_interface select auto
d-i netcfg/disable_dhcp boolean true
d-i netcfg/get_hostname string ${hostname}
d-i netcfg/get_domain string ${domain}
d-i netcfg/get_ipaddress string ${STATIC_IP}
d-i netcfg/get_netmask string ${NETMASK:-255.255.255.0}
d-i netcfg/get_gateway string ${GATEWAY:-10.100.10.1}
d-i netcfg/get_nameservers string ${NAMESERVER:-1.1.1.1}
EOFNET
    fi
    cat <<'EOFCOMMON'
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/disable_autoconfig boolean false
d-i time/zone string Etc/UTC
d-i clock-setup/ntp boolean true
d-i apt-setup/use_mirror boolean false
d-i passwd/root-login boolean false
d-i passwd/user-fullname string debian
d-i passwd/username string debian
d-i passwd/user-password-crypted password *
d-i user-setup/allow-password-weak boolean true
d-i passwd/user-default-groups string sudo
# Run our early partition/bootstrap script
d-i partman/early_command string /bin/sh /cdrom/extras/10-zfs.sh
tasksel tasksel/first multiselect standard
# Keep the target tiny; ZFS arrives after first boot
d-i pkgsel/include string openssh-server qemu-guest-agent
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/skip boolean true
d-i partman/confirm_write_new_label boolean true
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i finish-install/reboot_in_progress note
EOFCOMMON
  } > "$cust/preseed.cfg"
}

# ==============================================================================
# mk_iso — builds custom ISO (UEFI-only) with preseed + darksite + dracut + early ZFS(BE)
# ==============================================================================
mk_iso(){  # mk_iso <name> <postinstall_src> <iso_out> [static_ip]
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"
  local build="$BUILD_ROOT/$name"
  local mnt="$build/mnt"
  local cust="$build/custom"
  local dark="$cust/darksite"
  local suite="${DARKSITE_SUITE:-trixie}" arch="${ARCH:-amd64}"
  rm -rf "$build"; mkdir -p "$mnt" "$cust" "$dark" "$cust/extras"

  emit_sb_keys_if_missing
  emit_wg_dracut  "$dark"
  emit_zfs_be_toolkit "$dark"

  (
    set -euo pipefail
    trap "umount -f '$mnt' 2>/dev/null || true" EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    cp -a "$mnt/"* "$cust/"
    cp -a "$mnt/.disk" "$cust/" 2>/dev/null || true
  )

  install -m0755 "$postinstall_src" "$dark/postinstall.sh"

  cat >"$dark/bootstrap.service" <<'__BOOTSTRAPUNIT__'
[Unit]
Description=Initial Bootstrap Script (one-time)
After=local-fs.target network-online.target
Wants=network-online.target
ConditionPathExists=/root/darksite/postinstall.sh
ConditionPathIsExecutable=/root/darksite/postinstall.sh
[Service]
Type=oneshot
Environment=DEBIAN_FRONTEND=noninteractive
WorkingDirectory=/root/darksite
ExecStart=/usr/bin/env bash -lc '/root/darksite/postinstall.sh'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
__BOOTSTRAPUNIT__

  cat >"$dark/late.sh" <<'__LATE__'
#!/bin/sh
set -eux
mkdir -p /target/root/darksite
cp -a /cdrom/darksite/. /target/root/darksite/ 2>/dev/null || true
in-target install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch || true
in-target install -D -m0755 /root/darksite/postinstall.sh /root/darksite/postinstall.sh || true
in-target install -D -m0644 /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service || true
in-target systemctl daemon-reload || true
in-target systemctl enable bootstrap.service || true
in-target apt-get purge -y grub-pc grub-efi-amd64 grub-common || true
in-target bootctl install || true
in-target install -D -m0755 /root/darksite/be/zfs-bectl /usr/local/sbin/zfs-bectl
in-target install -D -m0644 /root/darksite/be/90-zfs-snapshots /etc/apt/apt.conf.d/90-zfs-snapshots
in-target install -D -m0755 /root/darksite/be/zz-uki-sign /etc/kernel/postinst.d/zz-uki-sign
in-target mkdir -p /usr/lib/dracut/modules.d/45wg
in-target cp -a /root/darksite/45wg/. /usr/lib/dracut/modules.d/45wg/
in-target dracut --force || true
in-target /bin/systemctl --no-block poweroff || true
exit 0
__LATE__
  chmod +x "$dark/late.sh"

  mkdir -p "$dark/repo"
  build_dark_repo "$dark/repo" "$arch" "$suite"
  darksite_stage_extras "$dark/repo" "./scripts" "./patches"

  cat >"$dark/apt-arch.conf" <<'__APTARCH__'
APT::Architectures { "amd64"; };
DPkg::Architectures { "amd64"; };
Acquire::Languages "none";
__APTARCH__

  emit_preseed_minimal "$cust" "$name"
  emit_early_zfs_install_be_script "$cust/extras/10-zfs.sh"
  write_bootloader_entries "$cust"
    write_bootloader_entries "$cust"

  echo "======== /preseed.cfg ========";  sed -n '1,999p' "$cust/preseed.cfg"
  echo "======== /extras/10-zfs.sh ==="; sed -n '1,999p' "$cust/extras/10-zfs.sh"

  # >>> add udeb staging here <<<
    # --- stage d-i udebs onto the ISO (offline, reproducible) ---
  # --- stage d-i udebs onto the ISO (offline, reproducible, quiet) ---
stage_di_udebs() {
  local iso_root="$1" suite="${2:-trixie}" arch="${3:-amd64}"
  local out="$iso_root/darksite-udeb"
  echo "[udeb] staging udebs → $out (suite=$suite arch=$arch)"
  rm -rf "$out"; mkdir -p "$out"

  docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -e SUITE="$suite" -e ARCH="$arch" \
    -v "$out:/out" "debian:${suite}" bash -lc '
set -euo pipefail

# Keep apt quiet and single-sourced
echo "Acquire::Languages \"none\";" >/etc/apt/apt.conf.d/99nolangs
rm -f /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${SUITE} main
deb http://deb.debian.org/debian ${SUITE} main/debian-installer
EOF

# Use root as the sandbox user to avoid the “unsandboxed as root” warning
echo "APT::Sandbox::User \"root\";" >/etc/apt/apt.conf.d/00nosandbox

apt-get -qq update
apt-get -qq install -y --no-install-recommends apt-utils dpkg-dev ca-certificates >/dev/null

mkdir -p /out/pool/main /out/dists/${SUITE}/main/debian-installer/binary-${ARCH}
work=/tmp/w; mkdir -p "$work"
cd "$work"

pkgs="busybox-udeb kmod-udeb udev-udeb parted-udeb util-linux-udeb e2fsprogs-udeb dosfstools-udeb debootstrap-udeb"

# Fetch udebs (quiet)
for p in $pkgs; do apt-get -qq download "$p"; done

shopt -s nullglob
mv ./*.udeb /out/pool/main/

# Minimal index for anna/apt in d-i
apt-ftparchive packages /out/pool/main > /out/dists/${SUITE}/main/debian-installer/binary-${ARCH}/Packages
gzip -9f /out/dists/${SUITE}/main/debian-installer/binary-${ARCH}/Packages

chmod -R a+rX /out
echo "[udeb] done"
'
}


  stage_di_udebs "$cust" "trixie" "amd64"

  stage_di_udebs "$cust"
  # <<< end udeb staging >>>

  local have_uefi=0 efi_img=""
  [[ -f "$cust/boot/grub/efi.img" ]] && { efi_img="boot/grub/efi.img"; have_uefi=1; }
  [[ -f "$cust/efi.img" ]] &&        { efi_img="efi.img";            have_uefi=1; }
  [[ $have_uefi -eq 1 ]] || die "No UEFI image found inside ISO tree."

  local args=( -as mkisofs -o "$iso_out" -r -J -joliet-long -l )
  args+=( -eltorito-alt-boot -e "$efi_img" -no-emul-boot -isohybrid-gpt-basdat "$cust" )
  echo "[mk_iso] Building (UEFI-only) → $iso_out"
  xorriso "${args[@]}"
  stat -c '[mk_iso] ISO size: %s bytes' "$iso_out" || true
  sha256sum "$iso_out" || true
}


# ==============================================================================
# MASTER POSTINSTALL — hardened base, WG hub, Sanoid/Syncoid, UKI signing
# ==============================================================================
emit_postinstall_master(){
  local out="$1"
  cat >"$out" <<'__MASTER__'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/postinstall-master.log"; exec > >(tee -a "$LOG") 2>&1
log(){ echo "[INFO] $(date '+%F %T') - $*"; }
die(){ echo "[ERROR] $*" >&2; exit 1; }
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
GUI_PROFILE="${GUI_PROFILE:-server}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
ADMIN_USER="${ADMIN_USER:-todd}"
DOMAIN="${DOMAIN:-unixbox.net}"
MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
WG0_IP="${WG0_IP:-10.77.0.1/16}";  WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}";  WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}";  WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}";  WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"
SB_KEY="/root/darksite/db.key"
SB_CRT="/root/darksite/db.crt"
dpkg_script_sanity_fix(){ shopt -s nullglob; for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
  [ -f "$f" ] || continue; head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"; sed -i 's/\r$//' "$f" 2>/dev/null || true; chmod +x "$f" || true; done; dpkg --configure -a || true; }
ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  install -d -m0755 /var/lib/apt/lists; install -d -m0700 -o _apt -g root /var/lib/apt/lists/partial || true
  dpkg_script_sanity_fix
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo trixie main
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    build-essential dkms linux-headers-$(uname -r) \
    zfs-dkms zfsutils-linux zfs-dracut dracut systemd-boot-efi systemd-ukify sbsigntool tpm2-tools efitools efivar mokutil \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar iproute2 iputils-ping ethtool tcpdump net-tools \
    wireguard-tools nftables chrony rsyslog qemu-guest-agent nfs-common \
    bpftrace bpfcc-tools perf-tools-unstable sysstat strace lsof debsums \
    sanoid syncoid prometheus prometheus-node-exporter grafana nginx || true
  # (Re)build initrd with dracut to ensure zfs modules included
  dracut --force "/boot/initrd.img-$(uname -r)" "$(uname -r)" || true
  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}
secureboot_enroll_and_enable() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y --no-install-recommends efitools efivar mokutil || true
  local WORK=/root/sbwork; mkdir -p "$WORK"
  cp -f "$SB_CRT" "$WORK/db.crt"; cp -f "$SB_KEY" "$WORK/db.key"
  cert-to-efi-sig-list -g "$(uuidgen)" "$WORK/db.crt" "$WORK/db.esl"
  openssl req -new -x509 -newkey rsa:3072 -subj "/CN=unixbox-KEK/" -keyout "$WORK/kek.key" -out "$WORK/kek.crt" -days 3650 -nodes
  cert-to-efi-sig-list -g "$(uuidgen)" "$WORK/kek.crt" "$WORK/kek.esl"
  openssl req -new -x509 -newkey rsa:3072 -subj "/CN=unixbox-PK/"  -keyout "$WORK/pk.key"  -out "$WORK/pk.crt"  -days 3650 -nodes
  cert-to-efi-sig-list -g "$(uuidgen)" "$WORK/pk.crt"  "$WORK/pk.esl"
  sign-efi-sig-list -k "$WORK/pk.key"  -c "$WORK/pk.crt"  PK  "$WORK/pk.esl"  "$WORK/pk.auth"
  sign-efi-sig-list -k "$WORK/pk.key"  -c "$WORK/pk.crt"  KEK "$WORK/kek.esl" "$WORK/kek.auth"
  sign-efi-sig-list -k "$WORK/kek.key" -c "$WORK/kek.crt" db  "$WORK/db.esl"  "$WORK/db.auth"
  efi-updatevar -f "$WORK/pk.auth"  PK; efi-updatevar -f "$WORK/kek.auth" KEK; efi-updatevar -f "$WORK/db.auth"  db
  mokutil --sb-state || true; echo -n -e '\x01' > "$WORK/sbon"; efi-updatevar -f "$WORK/sbon" SecureBoot || true
  build_sign_current_uki; echo "[SB] PK/KEK/DB enrolled; Secure Boot ON; UKI signed."
}
ensure_users_harden(){
  local PUB=""; [ -s "/root/darksite/authorized_keys.${ADMIN_USER}" ] && PUB="$(head -n1 "/root/darksite/authorized_keys.${ADMIN_USER}")"
  id -u "$ADMIN_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$ADMIN_USER"
  install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
  touch "/home/$ADMIN_USER/.ssh/authorized_keys"; chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
  [[ -n "$PUB" ]] && grep -qxF "$PUB" "/home/$ADMIN_USER/.ssh/authorized_keys" || { [[ -n "$PUB" ]] && printf '%s\n' "$PUB" >> "/home/$ADMIN_USER/.ssh/authorized_keys"; }
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" >"/etc/sudoers.d/90-$ADMIN_USER"; chmod 0440 "/etc/sudoers.d/90-$ADMIN_USER"
  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress ${MASTER_LAN}
ListenAddress $(echo "${WG0_IP}" | cut -d/ -f1)
AllowUsers ${ADMIN_USER}
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
cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi
  systemctl restart ssh || true
}
wg_hub(){
  install -d -m700 /etc/wireguard
  for IFN in wg0 wg1 wg2 wg3; do
    [ -f /etc/wireguard/${IFN}.key ] || wg genkey | tee /etc/wireguard/${IFN}.key | wg pubkey >/etc/wireguard/${IFN}.pub
  done
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${WG0_IP}
ListenPort = ${WG0_PORT}
PrivateKey = $(cat /etc/wireguard/wg0.key)
SaveConfig = true
MTU        = 1420
EOF
  for n in 1 2 3; do
  cat >/etc/wireguard/wg${n}.conf <<EOF
[Interface]
Address    = $(eval echo \${WG${n}_IP})
ListenPort = $(eval echo \${WG${n}_PORT})
PrivateKey = $(cat /etc/wireguard/wg${n}.key)
SaveConfig = true
MTU        = 1420
EOF
  done
  systemctl enable --now wg-quick@wg0 wg-quick@wg1 wg-quick@wg2 wg-quick@wg3 || true
}
nft_firewall(){
  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    tcp dport 22 accept
    udp dport { 51820,51821,51822,51823 } accept
    tcp dport { 80, 443, 9090, 9100 } accept
    iifname { "wg0","wg1","wg2","wg3" } accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}
sanoid_baseline(){
  mkdir -p /etc/sanoid
  cat >/etc/sanoid/sanoid.conf <<'EOC'
[rpool/ROOT/*]
  use_template = be
[rpool/home]
  use_template = user

[template_be]
  daily = 7
  autosnap = yes
  autoprune = yes

[template_user]
  daily = 7
  autosnap = yes
  autoprune = yes
EOC
  systemctl enable --now sanoid.timer || true
}
syncoid_stub(){ install -d -m755 /etc/syncoid; cat >/etc/syncoid/targets.conf <<'EOF'
# Example:
# syncoid rpool/ROOT/debian remotehost:rpool/backup/debian
EOF
}
seal_wg_key(){
  command -v tpm2_createprimary >/dev/null 2>&1 || return 0
  umask 077
  [ -s /etc/wireguard/wg0.key ] || (wg genkey > /etc/wireguard/wg0.key && chmod 600 /etc/wireguard/wg0.key)
  tpm2_createprimary -C o -G rsa -c /root/wg_prim.ctx
  tpm2_create -G aes -u /root/wg_key.pub -r /root/wg_key.priv -i /etc/wireguard/wg0.key -C /root/wg_prim.ctx -L sha256:0,2,7
  tpm2_load -C /root/wg_prim.ctx -u /root/wg_key.pub -r /root/wg_key.priv -c /etc/wireguard/wg0.key.sealed
}
build_sign_current_uki(){
  local kver="$(uname -r)"
  local rootds="$(zpool get -H -o value bootfs rpool 2>/dev/null || echo 'rpool/ROOT/debian')"
  local out="/boot/efi/EFI/Linux/debian-${kver}.efi"
  ukify build \
    --linux /usr/lib/kernel/vmlinuz-${kver} \
    --initrd /boot/initrd.img-${kver} \
    --cmdline "root=ZFS=${rootds} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${out}" || true
  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${out}" "${out}"; fi
  bootctl update || true
}
prom_graf_stub(){
  local ip="$(ip -4 addr show dev wg1 | awk '/inet /{print $2}' | cut -d/ -f1)"; [ -n "$ip" ] || ip="${WG1_IP%/*}"
  install -d -m755 /etc/prometheus/targets.d
  cat >/etc/prometheus/prometheus.yml <<'EOF'
global: { scrape_interval: 15s, evaluation_interval: 30s }
scrape_configs: [{ job_name: "node", file_sd_configs: [{ files: ["/etc/prometheus/targets.d/*.json"] }] }]
EOF
  install -d -m755 /etc/systemd/system/{prometheus.service.d,prometheus-node-exporter.service.d}
  cat >/etc/systemd/system/prometheus.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus --web.listen-address=${ip}:9090 --config.file=/etc/prometheus/prometheus.yml
EOF
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=${ip}:9100 --web.disable-exporter-metrics
EOF
  systemctl daemon-reload
  systemctl enable --now prometheus prometheus-node-exporter || true
  install -d /etc/grafana/provisioning/{datasources,dashboards} /var/lib/grafana/dashboards/node
  cat >/etc/grafana/provisioning/datasources/prom.yaml <<EOF
apiVersion: 1
datasources: [{ name: Prometheus, type: prometheus, access: proxy, url: http://${ip}:9090, isDefault: true }]
EOF
  cat >/etc/grafana/provisioning/dashboards/node.yaml <<'EOF'
apiVersion: 1
providers: [{ name: node, orgId: 1, folder: "Node", type: file, options: { path: /var/lib/grafana/dashboards/node } }]
EOF
  cat >/var/lib/grafana/dashboards/node/quick-node.json <<'EOF'
{"panels":[{"type":"stat","title":"Up targets","datasource":"Prometheus","targets":[{"expr":"up"}]}],"title":"Quick Node","schemaVersion":39}
EOF
  systemctl enable --now grafana-server || true
}
verify_uefi_only(){ test -d /sys/firmware/efi || die "System is not booted via UEFI (no /sys/firmware/efi)"; bootctl status || true; ls -l /boot/efi/EFI || true; }
main(){
  log "BEGIN master postinstall"
  ensure_base; ensure_users_harden; wg_hub; nft_firewall; sanoid_baseline; syncoid_stub; seal_wg_key
  secureboot_enroll_and_enable; prom_graf_stub; verify_uefi_only
  systemctl disable bootstrap.service || true
  log "Master ready; poweroff in 2s"; (sleep 2; systemctl --no-block poweroff) & disown
}
main
__MASTER__
}

# ==============================================================================
# MINION POSTINSTALL
# ==============================================================================
emit_postinstall_minion(){
  local out="$1"
  cat >"$out" <<'__MINION__'
#!/usr/bin/env bash
# minion postinstall (UEFI-only, dracut + UKI, ZFS utils from darksite when present)
set -Eeuo pipefail
LOG="/var/log/minion-postinstall.log"; exec > >(tee -a "$LOG") 2>&1

log(){ echo "[INFO] $(date '+%F %T') - $*"; }
die(){ echo "[ERROR] $*" >&2; exit 1; }

# ---- tunables via env or /etc/environment.d/99-provision.conf ----
ADMIN_USER="${ADMIN_USER:-todd}"
MY_GROUP="${MY_GROUP:-prom}"

# Secure Boot signing materials staged by ISO (optional but preferred)
SB_KEY="/root/darksite/db.key"
SB_CRT="/root/darksite/db.crt"

# --- helpers -------------------------------------------------------
dpkg_script_sanity_fix(){
  shopt -s nullglob
  for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
    [ -f "$f" ] || continue
    head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"
    sed -i 's/\r$//' "$f" 2>/dev/null || true
    chmod +x "$f" || true
  done
  dpkg --configure -a || true
}

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive

  dpkg_script_sanity_fix

  # Prefer local darksite if present; fall back to Debian online (harmless on an offline darksite).
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo trixie main
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch || true

  for i in 1 2 3; do
    apt-get update -y && break || sleep $((i*3))
  done

  # NOTE: dkms + zfs-dkms + headers needed to build ZFS for the *running* kernel
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar xz-utils \
    iproute2 iputils-ping ethtool tcpdump net-tools wireguard-tools nftables \
    chrony rsyslog qemu-guest-agent debsums \
    build-essential dkms linux-headers-$(uname -r) \
    zfsutils-linux zfs-dkms zfs-initramfs dracut systemd-boot-efi systemd-ukify-efi \
    efitools efivar mokutil sbsigntool ukify \
    sanoid syncoid || true

  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

ensure_users(){
  local PUB=""
  if [ -s "/root/darksite/authorized_keys.${ADMIN_USER}" ]; then
    PUB="$(head -n1 "/root/darksite/authorized_keys.${ADMIN_USER}")"
  fi

  id -u "${ADMIN_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${ADMIN_USER}"

  install -d -m700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  touch "/home/${ADMIN_USER}/.ssh/authorized_keys"
  if [ -n "$PUB" ] && ! grep -qxF "$PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys"; then
    echo "$PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"
  fi
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"

  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" >/etc/sudoers.d/90-${ADMIN_USER}
  chmod 0440 /etc/sudoers.d/90-${ADMIN_USER}
}

# ---------- hub bootstrap (wg, ports, allowlist) ----------
read_hub(){
  for f in \
    /root/cluster-seed/hub.env \
    /srv/wg/hub.env \
    /root/darksite/cluster-seed/hub.env \
    /root/darksite/hub.env
  do
    if [ -r "$f" ]; then HUB_ENV="$f"; break; fi
  done
  [ -n "${HUB_ENV:-}" ] || die "missing hub.env (looked in: /root/cluster-seed, /srv/wg, /root/darksite/cluster-seed, /root/darksite)"

  # Safe-ish env import (key=val; ignore comments/blank)
  eval "$(
    awk -F= '
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      /^[A-Za-z0-9_]+=/ {
        key=$1; $1=""; sub(/^=/,"");
        val=$0; gsub(/^[ \t]+|[ \t]+$/,"",val);
        gsub(/"/,"\\\"",val);
        print key "=\"" val "\""
      }' "$HUB_ENV"
  )"

  : "${WG0_PORT:?missing WG0_PORT}"
  : "${WG_ALLOWED_CIDR:?missing WG_ALLOWED_CIDR}"
  : "${HUB_LAN:?missing HUB_LAN}"
  : "${WG0_PUB:?missing WG0_PUB}"
}

wg_setup(){
  install -d -m700 /etc/wireguard
  umask 077
  [ -f /etc/wireguard/wg0.key ] || wg genkey | tee /etc/wireguard/wg0.key | wg pubkey >/etc/wireguard/wg0.pub

  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/wg0.key)
Address    = ${WG0_WANTED:-10.77.0.10/32}
DNS        = 1.1.1.1
MTU        = 1420

[Peer]
PublicKey  = ${WG0_PUB}
Endpoint   = ${HUB_LAN}:${WG0_PORT}
AllowedIPs = ${WG_ALLOWED_CIDR}
PersistentKeepalive = 25
EOF

  systemctl enable --now wg-quick@wg0 || true
}

nft_base(){
  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    tcp dport 22 accept
    iifname "wg0" accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

sanoid_minion(){
  mkdir -p /etc/sanoid
  cat >/etc/sanoid/sanoid.conf <<'EOC'
[rpool/ROOT/*]
  use_template = be
[rpool/home]
  use_template = user

[template_be]
  daily = 7
  autosnap = yes
  autoprune = yes

[template_user]
  daily = 7
  autosnap = yes
  autoprune = yes
EOC
  systemctl enable --now sanoid.timer || true
}

# -------- UKI build/sign for ZFS root (dracut handles initrd) --------
build_sign_uki(){
  local kver
  kver="$(uname -r || ls /lib/modules | sort -V | tail -1)"
  local rootds
  rootds="$(zpool get -H -o value bootfs rpool 2>/dev/null || echo 'rpool/ROOT/debian')"
  local out="/boot/efi/EFI/Linux/debian-${kver}.efi"

  # Ensure dracut initramfs exists for this kernel
  dracut --force "/boot/initrd.img-${kver}" "${kver}" || true

  mkdir -p /boot/efi/EFI/Linux
  ukify build \
    --linux "/usr/lib/kernel/vmlinuz-${kver}" \
    --initrd "/boot/initrd.img-${kver}" \
    --cmdline "root=ZFS=${rootds} module.sig_enforce=1" \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --output "${out}" || true

  if [ -s "$SB_KEY" ] && [ -s "$SB_CRT" ]; then
    sbsign --key "$SB_KEY" --cert "$SB_CRT" --output "${out}" "${out}" || true
  fi

  install -d -m755 /boot/loader/entries
  cat >/boot/loader/entries/debian.conf <<EOF
title   Debian (ZFS, ${kver})
linux   ${out#/boot/efi}
EOF
  printf "default debian.conf\ntimeout 1\n" >/boot/loader/loader.conf
  bootctl update || true
}

verify_uefi_only(){
  test -d /sys/firmware/efi || die "System not booted via UEFI (no /sys/firmware/efi)"
  bootctl status || true
  ls -l /boot/efi/EFI || true
}

main(){
  log "minion bootstrap start"
  ensure_base
  ensure_users
  read_hub
  wg_setup
  nft_base
  sanoid_minion
  build_sign_uki
  verify_uefi_only
  log "minion bootstrap done; poweroff in 2s"
  (sleep 2; systemctl --no-block poweroff) & disown
}
main
__MINION__
}

# ==============================================================================
# MINION WRAPPER — embeds hub.env + env vars + drops/minion postinstall & runs it
# ==============================================================================
emit_minion_wrapper(){
  local out="$1" group="$2" wg0="$3" wg1="$4" wg2="$5" wg3="$6"
  local hub_src="$BUILD_ROOT/hub/hub.env"
  if [[ ! -s "$hub_src" ]]; then
    err "emit_minion_wrapper: missing hub.env at $hub_src"
    return 1
  fi

  cat >"$out" <<'__WRAPHEAD__'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/minion-wrapper.log"; exec > >(tee -a "$LOG") 2>&1
trap 'echo "[WRAP] failed: ${BASH_COMMAND@Q}  (line ${LINENO})" >&2' ERR
__WRAPHEAD__

  {
    echo 'mkdir -p /root/darksite/cluster-seed'
    echo 'cat > /root/darksite/cluster-seed/hub.env <<HUBEOF'
    cat "$hub_src"
    echo 'HUBEOF'
    echo 'chmod 0644 /root/darksite/cluster-seed/hub.env'
  } >>"$out"

  cat >>"$out" <<__WRAPENV__
install -d -m0755 /etc/environment.d
cat >/etc/environment.d/99-provision.conf <<EOF
ADMIN_USER=$ADMIN_USER
MY_GROUP=${group}
WG0_WANTED=${wg0}
WG1_WANTED=${wg1}
WG2_WANTED=${wg2}
WG3_WANTED=${wg3}
EOF
chmod 0644 /etc/environment.d/99-provision.conf
__WRAPENV__

  cat >>"$out" <<'__WRAPBODY__'
install -d -m0755 /root/darksite
cat >/root/darksite/postinstall-minion.sh <<'EOMINION'
__WRAPBODY__

  local tmp; tmp="$(mktemp)"
  emit_postinstall_minion "$tmp"
  cat "$tmp" >>"$out"
  rm -f "$tmp"

  cat >>"$out" <<'__WRAPTAIL__'
EOMINION
perl -0777 -pe 's/\r\n/\n/g; s/\r/\n/g' -i /root/darksite/postinstall-minion.sh
sed -i '1s|.*|#!/usr/bin/env bash|' /root/darksite/postinstall-minion.sh
chmod +x /root/darksite/postinstall-minion.sh
/usr/bin/env bash /root/darksite/postinstall-minion.sh
__WRAPTAIL__

  chmod +x "$out"
}

# ==============================================================================
# BUILD ALL ISOS — master first (to harvest hub.env), then minions
# ==============================================================================
build_all_isos(){
  log "[*] Building all ISOs into $BUILD_ROOT"
  mkdir -p "$BUILD_ROOT/hub"

  # ---- master ISO: produces hub.env on first boot ----
  local master_payload master_iso
  master_payload="$(mktemp)"; emit_postinstall_master "$master_payload"
  master_iso="$BUILD_ROOT/master.iso"
  mk_iso "master" "$master_payload" "$master_iso" "$MASTER_LAN"
  log "[OK] master ISO: $master_iso"

  # Boot master twice (install → convert → poweroff), then capture hub.env via QGA
  pmx_deploy_uefi "$MASTER_ID" "$MASTER_NAME" "$master_iso" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"
  wait_poweroff "$MASTER_ID" 2400
  boot_from_disk_uefi "$MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  pmx "qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600

  pmx_wait_qga(){ local id="$1" t="${2:-900}" s=$(date +%s); while :; do
    pmx "qm agent $id ping >/dev/null 2>&1 || qm guest ping $id >/dev/null 2>&1" && return 0
    (( $(date +%s)-s > t )) && return 1
    sleep 3
  done; }
  pmx_wait_qga "$MASTER_ID" 900

  local DEST="$BUILD_ROOT/hub/hub.env"
  if pmx "qm guest exec $MASTER_ID --output-format json -- /bin/cat /srv/wg/hub.env" | \
     sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | base64 -d > "${DEST}.tmp" 2>/dev/null \
     && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "[OK] captured hub.env → $DEST"
  else
    err "Failed to retrieve hub.env via QGA"; exit 1
  fi

  # ---- minion ISOs (prom, graf, k8s, storage) ----
  local pld iso
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "prom"    "10.77.0.10/32" "10.78.0.10/32" "10.79.0.10/32" "10.80.0.10/32"; iso="$BUILD_ROOT/prom.iso";    mk_iso "$PROM_NAME" "$pld" "$iso" "$PROM_IP"; log "[OK] prom ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "graf"    "10.77.0.11/32" "10.78.0.11/32" "10.79.0.11/32" "10.80.0.11/32"; iso="$BUILD_ROOT/graf.iso";    mk_iso "$GRAF_NAME" "$pld" "$iso" "$GRAF_IP"; log "[OK] graf ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "k8s"     "10.77.0.12/32" "10.78.0.12/32" "10.79.0.12/32" "10.80.0.12/32"; iso="$BUILD_ROOT/k8s.iso";     mk_iso "$K8S_NAME"  "$pld" "$iso" "$K8S_IP";  log "[OK] k8s ISO:     $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "storage" "10.77.0.13/32" "10.78.0.13/32" "10.79.0.13/32" "10.80.0.13/32"; iso="$BUILD_ROOT/storage.iso"; mk_iso "$STOR_NAME" "$pld" "$iso" "$STOR_IP";  log "[OK] storage ISO: $iso"
}

# ==============================================================================
# PROXMOX CLUSTER DEPLOY — UEFI-ONLY path; ZFS root with BE + signed UKI
# ==============================================================================
proxmox_cluster(){
  build_all_isos

  pmx_deploy_uefi "$PROM_ID" "$PROM_NAME" "$BUILD_ROOT/prom.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$PROM_ID" 2400; boot_from_disk_uefi "$PROM_ID"; wait_poweroff "$PROM_ID" 2400; pmx "qm start $PROM_ID"; pmx_wait_for_state "$PROM_ID" "running" 600

  pmx_deploy_uefi "$GRAF_ID" "$GRAF_NAME" "$BUILD_ROOT/graf.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$GRAF_ID" 2400; boot_from_disk_uefi "$GRAF_ID"; wait_poweroff "$GRAF_ID" 2400; pmx "qm start $GRAF_ID"; pmx_wait_for_state "$GRAF_ID" "running" 600

  pmx_deploy_uefi "$K8S_ID"  "$K8S_NAME"  "$BUILD_ROOT/k8s.iso"  "$K8S_MEM"    "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$K8S_ID"  2400; boot_from_disk_uefi "$K8S_ID";  wait_poweroff "$K8S_ID"  2400; pmx "qm start $K8S_ID";  pmx_wait_for_state "$K8S_ID"  "running" 600

  pmx_deploy_uefi "$STOR_ID" "$STOR_NAME" "$BUILD_ROOT/storage.iso" "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"
  wait_poweroff "$STOR_ID" 2400; boot_from_disk_uefi "$STOR_ID"; wait_poweroff "$STOR_ID" 2400; pmx "qm start $STOR_ID"; pmx_wait_for_state "$STOR_ID" "running" 600

  log "Done. Master + minions deployed (UEFI-only, ZFS root with BE + Sanoid + signed UKI)."
}

# ==============================================================================
# AWS IMPORT — qcow2/raw → S3 → import-image → register UEFI+TPM
# ==============================================================================
aws_import_register_launch(){
  command -v aws >/dev/null || die "aws cli required"
  [[ -n "$AWS_S3_BUCKET" ]] || die "Set AWS_S3_BUCKET to an S3 bucket you control"

  if [[ -s "$UNIVERSAL_QCOW2" ]]; then
    log "[*] Converting qcow2 → raw"
    qemu-img convert -p -O raw "$UNIVERSAL_QCOW2" "$UNIVERSAL_RAW"
  fi
  [[ -s "$UNIVERSAL_RAW" ]] || die "Provide UNIVERSAL_QCOW2 or UNIVERSAL_RAW"

  log "[*] Upload RAW to s3://${AWS_S3_BUCKET}/import/${AWS_AMI_NAME}.raw"
  aws s3 cp "$UNIVERSAL_RAW" "s3://${AWS_S3_BUCKET}/import/${AWS_AMI_NAME}.raw"

  log "[*] Start import-image"
  IID=$(aws ec2 import-image \
          --description "$AWS_AMI_NAME import" \
          --disk-containers "Format=raw,UserBucket={S3Bucket=${AWS_S3_BUCKET},S3Key=import/${AWS_AMI_NAME}.raw}" \
          --query 'ImportImageTasks[0].ImportTaskId' --output text)

  log "[*] Waiting for import ($IID)"
  while :; do
    ST=$(aws ec2 describe-import-image-tasks --import-task-ids "$IID" --query 'ImportImageTasks[0].Status' --output text)
    [[ "$ST" == "completed" ]] && break
    [[ "$ST" == "deleted" || "$ST" == "deleting" ]] && die "Import failed ($ST)"
    sleep 15
  done

  SRC_AMI=$(aws ec2 describe-import-image-tasks --import-task-ids "$IID" --query 'ImportImageTasks[0].ImageId' --output text)
  SNAP=$(aws ec2 describe-images --image-ids "$SRC_AMI" --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)

  log "[*] Register image with UEFI+TPM ${UEFI_BLOB:+and your UEFI var-store}"
  AMI=$(aws ec2 register-image \
          --name "$AWS_AMI_NAME" \
          --architecture x86_64 \
          --root-device-name /dev/xvda \
          --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${SNAP},DeleteOnTermination=true}" \
          --virtualization-type hvm --ena-support \
          --boot-mode uefi --tpm-support v2.0 \
          ${UEFI_BLOB:+--uefi-data fileb://${UEFI_BLOB}} \
          --query 'ImageId' --output text)

  log "[OK] AMI: $AMI"

  set +e
  aws ec2 create-launch-template --launch-template-name "$AWS_LT_NAME" \
      --launch-template-data "{\"ImageId\":\"$AMI\",\"InstanceType\":\"c6a.large\",\"EbsOptimized\":true}" >/dev/null 2>&1
  set -e

  aws ec2 create-launch-template-version --launch-template-name "$AWS_LT_NAME" --source-version '$Latest' \
      --launch-template-data "{\"ImageId\":\"$AMI\"}" >/dev/null
  aws ec2 modify-launch-template --launch-template-name "$AWS_LT_NAME" --default-version '$Latest' >/devnull 2>&1 || true

  IID2=$(aws ec2 run-instances --launch-template "LaunchTemplateName=${AWS_LT_NAME},Version=\$Default" --count 1 --query 'Instances[0].InstanceId' --output text)
  log "[OK] Instance: $IID2"
}

# ==============================================================================
# PACKER + FIRECRACKER SCAFFOLDS (unchanged)
# ==============================================================================
emit_packer_scaffold(){
  local out="${PACKER_OUT:-${BUILD_ROOT}/packer}"
  mkdir -p "$out"
  cat >"$out/README.txt" <<'EOF'
Packer scaffold:
packer {
  required_plugins { qemu = { source = "github.com/hashicorp/qemu", version = ">=1.1.0" } }
}
variable "iso_path" { type=string }
variable "vm_name" { type=string default="debian-guest" }
source "qemu" "debian" {
  iso_url = var.iso_path
  output_directory = "output-${var.vm_name}"
  headless = true
  accelerator = "kvm"
  cpus = 2
  memory = 2048
  disk_size = "20G"
  ssh_username = "root"
  ssh_password = "root"
  ssh_timeout  = "30m"
  boot_wait    = "5s"
}
build { name = var.vm_name sources = ["source.qemu.debian"] }
EOF
  log "[OK] packer scaffold at: $out"
}

emit_firecracker_scaffold(){
  local out="${FIRECRACKER_OUT:-${BUILD_ROOT}/firecracker}"
  install -d "$out"
  cat >"$out/extract-kernel-initrd.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
RAW_IMG="${1:-}"; OUT_DIR="${2:-.}"
[[ -n "$RAW_IMG" && -s "$RAW_IMG" ]] || { echo "usage: $0 <rootfs.raw> [outdir]" >&2; exit 2; }
mkdir -p "$OUT_DIR"
command -v guestmount >/dev/null || { echo "[X] apt install libguestfs-tools"; exit 1; }
mnt="$(mktemp -d)"
trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' EXIT
guestmount -a "$RAW_IMG" -i "$mnt"
cp -Lf "$mnt"/boot/vmlinuz* "$OUT_DIR/kernel"
cp -Lf "$mnt"/boot/initrd*  "$OUT_DIR/initrd"
echo "[OK] kernel/initrd -> $OUT_DIR"
EOF
  chmod +x "$out/extract-kernel-initrd.sh"
  log "[OK] Firecracker scaffold in $out"
}

# ==============================================================================
# DISPATCHER
# ==============================================================================
case "$TARGET" in
  proxmox-cluster)     proxmox_cluster ;;
  image-only)
    log "[*] Building role ISOs only…"
    emit_sb_keys_if_missing
    MASTER_PAYLOAD="$(mktemp)"; emit_postinstall_master "$MASTER_PAYLOAD"
    MASTER_ISO="$BUILD_ROOT/master.iso"; mk_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"

    mkdir -p "$BUILD_ROOT/hub"
    # Seed placeholder hub.env (real one overwritten after master boots)
    cat >"$BUILD_ROOT/hub/hub.env" <<EOF
WG0_IP=${WG0_IP}
WG1_IP=${WG1_IP}
WG2_IP=${WG2_IP}
WG3_IP=${WG3_IP}
WG0_PORT=${WG0_PORT}
WG1_PORT=${WG1_PORT}
WG2_PORT=${WG2_PORT}
WG3_PORT=${WG3_PORT}
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR}
HUB_LAN=${MASTER_LAN}
WG0_PUB=
WG1_PUB=
WG2_PUB=
WG3_PUB=
EOF

    P="$(mktemp)"; emit_minion_wrapper "$P" "prom"    "10.77.0.10/32" "10.78.0.10/32" "10.79.0.10/32" "10.80.0.10/32"; mk_iso "$PROM_NAME" "$P" "$BUILD_ROOT/prom.iso"    "$PROM_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "graf"    "10.77.0.11/32" "10.78.0.11/32" "10.79.0.11/32" "10.80.0.11/32"; mk_iso "$GRAF_NAME" "$P" "$BUILD_ROOT/graf.iso"    "$GRAF_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "k8s"     "10.77.0.12/32" "10.78.0.12/32" "10.79.0.12/32" "10.80.0.12/32"; mk_iso "$K8S_NAME"  "$P" "$BUILD_ROOT/k8s.iso"     "$K8S_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "storage" "10.77.0.13/32" "10.78.0.13/32" "10.79.0.13/32" "10.80.0.13/32"; mk_iso "$STOR_NAME" "$P" "$BUILD_ROOT/storage.iso" "$STOR_IP"
    log "[DONE] ISOs in $BUILD_ROOT"
    ;;
  aws)                 emit_sb_keys_if_missing; aws_import_register_launch ;;
  packer-scaffold)     emit_packer_scaffold ;;
  firecracker-bundle)  emit_firecracker_scaffold ;;
  *)                   die "Unknown TARGET=$TARGET" ;;
esac
