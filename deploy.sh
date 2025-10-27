#!/usr/bin/env bash
# =====================================================================
# Unified Deployer — Ubuntu 24.04 LTS (Noble)
# Targets: Proxmox • QEMU/KVM • AWS • Firecracker
# Features: Darksite repo • Autoinstall • ZFS-on-root pivot • WireGuard
#           Secure Boot (MOK autosign) • Master + Minion roles
# 
# This version of the script builds and deploys 5 servers to proxmox by default
# its designed to be a "starter" template with a few examples
# =====================================================================

set -Eeuo pipefail
trap 'rc=$?; echo; echo "[X] ${BASH_COMMAND@Q} failed at line ${LINENO} (rc=${rc})";
      { command -v nl >/dev/null && nl -ba "$0" | sed -n "$((LINENO-5)),$((LINENO+5))p"; } || true; exit $rc' ERR

# =====================================================================
# DRIVER MODE
# =====================================================================
TARGET="${TARGET:-proxmox-cluster}"   # proxmox-cluster | image-only | packer-scaffold | firecracker-bundle | firecracker | aws-ami | aws-run

# =====================================================================
# GLOBAL CONFIG
# =====================================================================
INPUT="${INPUT:-1}"   # 1|fiend, 2|dragon, 3|lion
DOMAIN="${DOMAIN:-unixbox.net}"
case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) echo "[ERROR] Unknown INPUT=$INPUT" >&2; exit 1 ;;
esac

BUILD_ROOT="${BUILD_ROOT:-/root/builds}"; mkdir -p "$BUILD_ROOT"
log()  { echo "[INFO]  $(date '+%F %T') - $*"; }
warn() { echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err()  { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------
# SSH helpers (quiet, non-interactive)
# ---------------------------------------------------------------------
SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }

# ---------------------------------------------------------------------
# Paths / storage
# ---------------------------------------------------------------------
IMAGE_FORMATS="${IMAGE_FORMATS:-iso,qcow2,raw}"
DISK_GB_DEFAULT="${DISK_GB_DEFAULT:-10}"
PACKER_OUT="${PACKER_OUT:-${BUILD_ROOT}/packer}"
FIRECRACKER_OUT="${FIRECRACKER_OUT:-${BUILD_ROOT}/firecracker}"

# Base Ubuntu Live ISO (24.04.x)
ISO_ORIG="${ISO_ORIG:-/var/lib/libvirt/boot/ubuntu-24.04.3-live-server-amd64.iso}"
ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"
ROOT_SCHEME="${ROOT_SCHEME:-zfs}"

# ---------------------------------------------------------------------
# Role VM IDs/Names/IPs
# ---------------------------------------------------------------------
MASTER_ID="${MASTER_ID:-5010}"; MASTER_NAME="${MASTER_NAME:-master}"; MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
PROM_ID="${PROM_ID:-5011}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.123}"
GRAF_ID="${GRAF_ID:-5012}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.122}"
K8S_ID="${K8S_ID:-5013}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.121}"
STOR_ID="${STOR_ID:-5014}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.120}"

NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3}"

# ---------------------------------------------------------------------
# WireGuard hub (master) subnets/ports
# ---------------------------------------------------------------------
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# Minion per-plane IPs (/32)
PROM_WG0="${PROM_WG0:-10.77.0.2/32}"; PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; PROM_WG2="${PROM_WG2:-10.79.0.2/32}"; PROM_WG3="${PROM_WG3:-10.80.0.2/32}"
GRAF_WG0="${GRAF_WG0:-10.77.0.3/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; GRAF_WG2="${GRAF_WG2:-10.79.0.3/32}"; GRAF_WG3="${GRAF_WG3:-10.80.0.3/32}"
K8S_WG0="${K8S_WG0:-10.77.0.4/32}";  K8S_WG1="${K8S_WG1:-10.78.0.4/32}";  K8S_WG2="${K8S_WG2:-10.79.0.4/32}";  K8S_WG3="${K8S_WG3:-10.80.0.4/32}"
STOR_WG0="${STOR_WG0:-10.77.0.5/32}"; STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; STOR_WG2="${STOR_WG2:-10.79.0.5/32}"; STOR_WG3="${STOR_WG3:-10.80.0.5/32}"

# ---------------------------------------------------------------------
# Kubernetes / Cilium
# ---------------------------------------------------------------------
K8S_ENABLE="${K8S_ENABLE:-yes}"
K8S_VERSION="${K8S_VERSION:-1.29}"
K8S_POD_CIDR="${K8S_POD_CIDR:-10.244.0.0/16}"
K8S_SVC_CIDR="${K8S_SVC_CIDR:-10.96.0.0/12}"
K8S_API_ADVERTISE_IFACE="${K8S_API_ADVERTISE_IFACE:-wg2}"
K8S_NODE_IP_IFACE="${K8S_NODE_IP_IFACE:-wg2}"
K8S_RUNTIME="${K8S_RUNTIME:-containerd}"

CILIUM_VERSION="${CILIUM_VERSION:-1.14.6}"
CILIUM_ENCRYPTION="${CILIUM_ENCRYPTION:-disabled}"
CILIUM_WG_INTERFACE="${CILIUM_WG_INTERFACE:-wg2}"
CILIUM_KPR="${CILIUM_KPR:-strict}"
CILIUM_TUNNEL_MODE="${CILIUM_TUNNEL_MODE:-disabled}"
CILIUM_AUTO_DIRECT_ROUTES="${CILIUM_AUTO_DIRECT_ROUTES:-true}"
CILIUM_BPF_MASQ="${CILIUM_BPF_MASQ:-true}"

METALLB_POOL_CIDRS="${METALLB_POOL_CIDRS:-10.100.10.111-10.100.10.130}"
METALLB_NAMESPACE="${METALLB_NAMESPACE:-metallb-system}"

# ---------------------------------------------------------------------
# Sizing
# ---------------------------------------------------------------------
MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-8}"; MASTER_DISK_GB="${MASTER_DISK_GB:-20}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-20}"
K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

# ---------------------------------------------------------------------
# Admin / Extras
# ---------------------------------------------------------------------
ADMIN_USER="${ADMIN_USER:-todd}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-/home/todd/.ssh/id_ed25519.pub}"
SSH_PUBKEY="${SSH_PUBKEY:-}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
GUI_PROFILE="${GUI_PROFILE:-rdp-minimal}"

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
ZFS_MOUNTPOINT="${ZFS_MOUNTPOINT:-/mnt/share}"

# ---------------------------------------------------------------------
# AWS (unchanged)
# ---------------------------------------------------------------------
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_VPC_ID="${AWS_VPC_ID:-}"
AWS_SUBNET_ID="${AWS_SUBNET_ID:-}"
AWS_SG_ID="${AWS_SG_ID:-}"
AWS_KEY_NAME="${AWS_KEY_NAME:-clusterkey}"
AWS_PUBLIC_KEY_PATH="${AWS_PUBLIC_KEY_PATH:-}"
AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-m5.large}"
AWS_ARCH="${AWS_ARCH:-x86_64}"
AWS_ENABLE_SSH="${AWS_ENABLE_SSH:-true}"
AWS_SSH_CIDR="${AWS_SSH_CIDR:-}"
AWS_ASSOC_PUBLIC_IP="${AWS_ASSOC_PUBLIC_IP:-true}"
AWS_AMI_NAME_PREFIX="${AWS_AMI_NAME_PREFIX:-unixbox-ubuntu2404}"
AWS_TAG_STACK="${AWS_TAG_STACK:-ucluster}"
AWS_RUN_COUNT="${AWS_RUN_COUNT:-5}"
AWS_PRIVATE_IP_BASE="${AWS_PRIVATE_IP_BASE:-10.0.1.5}"
AWS_RUN_ROLE="${AWS_RUN_ROLE:-k8s}"

# =====================================================================
# EARLY VALIDATION + SMALL HELPERS
# =====================================================================
validate_env_or_die() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
  local -a req=(BUILD_ROOT ISO_ORIG)
  local -a miss=(); for v in "${req[@]}"; do [[ -n "${!v:-}" ]] || miss+=("$v"); done
  ((${#miss[@]}==0)) || die "missing: ${miss[*]}"
  [[ -r "$ISO_ORIG" ]] || die "ISO_ORIG not readable: $ISO_ORIG"
  mkdir -p "$BUILD_ROOT"
  log "[OK] environment validated"
}
validate_env_or_die

retry(){ local n="$1" s="$2"; shift 2; local i; for ((i=1;i<=n;i++)); do "$@" && return 0; sleep "$s"; done; return 1; }
mask_to_cidr(){ python3 - "$1" <<'PY'
import ipaddress, sys
print(ipaddress.IPv4Network(f"0.0.0.0/{sys.argv[1]}", strict=False).prefixlen)
PY
}
inc_ip(){ local ip="$1" inc="${2:-1}"; python3 - "$ip" "$inc" <<'PY'
import ipaddress,sys
ip=ipaddress.IPv4Address(sys.argv[1]); inc=int(sys.argv[2]); print(str(ip+inc))
PY
}

# =====================================================================
# PROXMOX HELPERS
# =====================================================================
pmx(){ sssh root@"$PROXMOX_HOST" "$@"; }
pmx_vm_state(){ pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }
pmx_wait_for_state(){ local id="$1" want="$2" t="${3:-2400}" s="$(date +%s)" st; while :; do st="$(pmx_vm_state "$id")"; [[ "$st" == "$want" ]] && return 0; (( $(date +%s) - s > t )) && return 1; sleep 5; done; }
pmx_wait_qga(){ local id="$1" t="${2:-1200}" s=$(date +%s); while :; do pmx "qm agent $id ping >/dev/null 2>&1 || qm guest ping $id >/dev/null 2>&1" && return 0; (( $(date +%s) - s > t )) && return 1; sleep 3; done; }
pmx_qga_has_json(){ PMX_QGA_JSON="${PMX_QGA_JSON:-$(pmx "qm guest exec -h 2>&1 | grep -q -- '--output-format' && echo yes || echo no" | tr -d '\r')}"; echo "$PMX_QGA_JSON"; }
pmx_guest_exec(){ local id="$1"; shift; local q=(); for a in "$@"; do q+=("$(printf '%q' "$a")"); done; pmx "qm guest exec $id -- ${q[*]} >/dev/null 2>&1 || true"; }
pmx_guest_cat(){ local id="$1" path="$2" has_json out pid st data
  has_json="$(pmx_qga_has_json)"
  if [[ "$has_json" == "yes" ]]; then
    out="$(pmx "qm guest exec $id --output-format json -- /bin/cat '$path' 2>/dev/null || true")"
    pid="$(printf '%s\n' "$out" | sed -n 's/.*\"pid\"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p')"
    [[ -n "$pid" ]] || return 2
    while :; do
      st="$(pmx "qm guest exec-status $id $pid --output-format json 2>/dev/null || true")" || true
      if printf '%s' "$st" | grep -Eq '"exited"[[:space:]]*:[[:space:]]*(true|1)'; then
        data="$(printf '%s' "$st" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
        [[ -n "$data" ]] && { printf '%s' "$data" | base64 -d 2>/dev/null; return 0; }
        data="$(printf '%s' "$st" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p')"
        printf '%b' "${data//\\n/$'\n'}"; return 0
      fi; sleep 1; done
  else
    out="$(pmx "qm guest exec $id -- /bin/cat '$path' 2>/dev/null || true")"
    data="$(printf '%s\n' "$out" | sed -n 's/.*\"out-data\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
    [[ -n "$data" ]] && { printf '%s' "$data" | base64 -d 2>/dev/null; return 0; }
    data="$(printf '%s\n' "$out" | sed -n 's/.*\"out\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/p')"
    [[ -n "$data" ]] || return 3
    printf '%b' "${data//\\n/$'\n'}"
  fi
}
pmx_upload_iso(){ local iso="$1" base; base="$(basename "$iso")"; sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base" || { log "retry ISO upload $base"; sleep 2; sscp "$iso" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/$base"; }
  pmx "for i in {1..30}; do pvesm list ${ISO_STORAGE} | awk '{print \$5}' | grep -qx \"${base}\" && exit 0; sleep 1; done; exit 0" || true; echo "$base"; }

pmx_deploy(){ local vmid="$1" name="$2" iso="$3" mem="$4" cores="$5" disk_gb="$6"
  local base; base="$(pmx_upload_iso "$iso")"
  pmx VMID="$vmid" VMNAME="${name}.${DOMAIN}-$vmid" FINAL_ISO="$base" VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail

qm destroy "$VMID" --purge >/dev/null 2>&1 || true
qm create "$VMID" --name "$VMNAME" --memory "$MEMORY_MB" --cores "$CORES" \
  --net0 virtio,bridge=vmbr0,firewall=1 --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} --serial0 socket --ostype l26

# UEFI + Secure Boot (correct 4M vars store)
qm set "$VMID" --bios ovmf
qm set "$VMID" --delete efidisk0 || true
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=1

# Attach ISO on SATA (better with OVMF than IDE)
for i in {1..10}; do qm set "$VMID" --sata0 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom && break || sleep 1; done

# Boot from CD first, then disk (NOTE: quote the semicolon)
qm set "$VMID" --boot order='sata0;scsi0'

qm start "$VMID"
EOSSH
}

wait_poweroff(){ pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }
boot_from_disk(){ local id="$1"; pmx "qm set $id --delete ide2; qm set $id --boot order=scsi0; qm start $id"; pmx_wait_for_state "$id" "running" 600; }

# =====================================================================
# DARKSITE REPO (Ubuntu Noble)
# =====================================================================
build_dark_repo(){
  local out="$1" arch="${2:-amd64}" suite="${3:-noble}"
  [[ -n "$out" ]] || { echo "[X] build_dark_repo: outdir required" >&2; return 2; }
  rm -rf "$out"; mkdir -p "$out"
  docker run --rm -e DEBIAN_FRONTEND=noninteractive -e SUITE="$suite" -e ARCH="$arch" \
    -e BASE_PACKAGES="ubuntu-minimal ca-certificates curl gnupg jq unzip tar \
      sudo openssh-server chrony rsyslog wireguard-tools nftables qemu-guest-agent \
      zfsutils-linux zfs-dkms dkms build-essential linux-headers-generic mokutil kmod \
      iproute2 iputils-ping ethtool tcpdump net-tools \
      bpftrace linux-tools-generic sysstat strace lsof" \
    -v "$out:/repo" ubuntu:noble bash -lc '
set -euo pipefail
apt-get update -y
apt-get install -y --no-install-recommends apt apt-utils ca-certificates curl wget gnupg xz-utils dpkg-dev apt-rdepends apt-transport-https
tmp_list=$(mktemp)
apt-rdepends $BASE_PACKAGES 2>/dev/null | awk "/^[A-Za-z0-9][A-Za-z0-9+.-]*$/{print}" | sort -u >"$tmp_list"
: > /tmp/want.lock
while read -r pkg; do cand=$(apt-cache policy "$pkg" | awk "/Candidate:/{print \$2}"); [ -n "$cand" ] && [ "$cand" != "(none)" ] && echo "$pkg=$cand" >> /tmp/want.lock || true; done <"$tmp_list"
work=/tmp/aptdownload; install -d -m0777 "$work"; chown _apt:_apt "$work" 2>/dev/null || true
runuser -u _apt -- bash -lc "cd \"$work\"; while read -r pv; do apt-get download \"\$pv\" || apt-get download \"\${pv%%=*}\"; done </tmp/want.lock"
mkdir -p /repo/pool/main
mv -f "$work"/*.deb /repo/pool/main/ 2>/dev/null || true
mkdir -p /repo/dists/${SUITE}/{main,extra}/binary-${ARCH} /repo/dists/${SUITE}/{main,extra}/binary-all
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
echo "[OK] Dark repo (Ubuntu noble) ready"
'
}

# =====================================================================
# ZFS PIVOT (runs first boot inside guest)
# =====================================================================
emit_zfs_rootify(){
  local out_dir="$1"; mkdir -p "$out_dir"
  cat >"$out_dir/zfs-rootify.service" <<'EOF'
[Unit]
Description=Pivot to ZFS on first boot (one-time)
DefaultDependencies=no
After=local-fs.target
Before=bootstrap.service
ConditionPathExists=/root/darksite/zfs-rootify.sh
[Service]
Type=oneshot
ExecStart=/usr/bin/env bash -lc '/root/darksite/zfs-rootify.sh'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

  cat >"$out_dir/zfs-rootify.sh" <<'EOSH'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG=/var/log/zfs-rootify.log
exec > >(tee -a "$LOG") 2>&1
[ -f /var/lib/zfs-rootify.done ] && exit 0

DISK="$(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print "/dev/"$1; exit}')"; [ -n "$DISK" ] || exit 1
case "$DISK" in /dev/nvme*|/dev/mmcblk*|/dev/loop*|/dev/md*|/dev/dm-*) p="p";; *) p="";; esac
EFI=${DISK}${p}1; ROOT=${DISK}${p}2; ZP=${DISK}${p}3
if [ ! -b "$ZP" ]; then echo -e ",,\n" | sfdisk -N 3 "$DISK" >/dev/null; partprobe "$DISK" || true; udevadm settle || true; fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y --no-install-recommends build-essential dkms linux-headers-$(uname -r) zfs-dkms zfsutils-linux zfs-initramfs mokutil kmod || true
modprobe zfs || true

zpool create -f -o ashift=12 -O acltype=posixacl -O atime=off -O xattr=sa -O compression=zstd -O normalization=formD -O mountpoint=none -R /mnt/zfsroot rpool "$ZP"
zfs create -o mountpoint=none rpool/ROOT
zfs create -o mountpoint=/ rpool/ROOT/ubuntu
for d in home var var/log var/tmp root usr-local; do zfs create -o mountpoint=/${d//usr-local/usr/local} rpool/${d//\//-}; done

rsync -aHAX --info=progress2 --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} / /mnt/zfsroot/
install -d -m1777 /mnt/zfsroot/tmp; install -d -m0755 /mnt/zfsroot/{proc,sys,dev,run}
mount --bind /dev  /mnt/zfsroot/dev; mount --bind /proc /mnt/zfsroot/proc; mount --bind /sys  /mnt/zfsroot/sys

chroot /mnt/zfsroot /usr/bin/env bash -lc '
blkid -o export '"$EFI"' | awk -F= "/^UUID=/{print \$2}" | xargs -I{} bash -lc "printf \"UUID=%s /boot/efi vfat umask=0077 0 1\n\" \"{}\" >> /etc/fstab"
printf "ZFS=rpool/ROOT/ubuntu\n" > /etc/initramfs-tools/conf.d/zfs; update-initramfs -u
sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"root=ZFS=rpool\\/ROOT\\/ubuntu\"/" /etc/default/grub || true
update-grub
apt-get install -y --no-install-recommends grub-efi-amd64 shim-signed || true
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id="ubuntu" --recheck || true
update-grub
'
zpool set bootfs=rpool/ROOT/ubuntu rpool
touch /var/lib/zfs-rootify.done
(sleep 2; systemctl --no-block reboot) & disown
EOSH
  chmod +x "$out_dir/zfs-rootify.sh"
}

# =====================================================================
# AUTOINSTALL ISO (UEFI)  — preserves original boot images
# =====================================================================
mk_ubuntu_iso(){
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"
  local build="$BUILD_ROOT/$name"; local mnt="$build/mnt"; local cust="$build/custom"; local dark="$cust/darksite"
  rm -rf "$build"; mkdir -p "$mnt" "$cust" "$dark"

  # ---- Payloads placed under /darksite on the ISO ---------------------------------
  emit_zfs_rootify "$dark"
  install -m0755 "$postinstall_src" "$dark/postinstall.sh"

  # One-shot bootstrap unit
  cat >"$dark/bootstrap.service" <<'EOF'
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
EOF

  # Local apt pin + dark repo (for airgapped installs)
  cat >"$dark/apt-arch.conf" <<'EOF'
APT::Architectures { "amd64"; };
DPKg::Architectures { "amd64"; };
Acquire::Languages "none";
EOF
  mkdir -p "$dark/repo"
  build_dark_repo "$dark/repo" "amd64" "noble"

  # ---- NoCloud autoinstall seed ---------------------------------------------------
  mkdir -p "$cust/nocloud"
  local USERDATA="$cust/nocloud/user-data"
  local METADATA="$cust/nocloud/meta-data"
  : > "$METADATA"; echo "instance-id: iid-$name" > "$METADATA"

  # Network config (DHCP vs static)
  local NETYAML
  if [[ -z "$static_ip" ]]; then
    NETYAML=$(cat <<'YAML'
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
      dhcp6: false
YAML
)
  else
    NETYAML=$(cat <<YAML
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      addresses: [ ${static_ip}/$(mask_to_cidr "$NETMASK") ]
      gateway4: ${GATEWAY}
      nameservers:
        addresses: [ ${NAMESERVER// /, } ]
YAML
)
  fi

  cat > "$USERDATA" <<EOF
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  ssh:
    install-server: true
    authorized-keys:
      - ${SSH_PUBKEY:-$(test -r "$ADMIN_PUBKEY_FILE" && cat "$ADMIN_PUBKEY_FILE" || echo "")}
    allow-pw: false
  identity:
    hostname: ${name}
    username: root
    password: "\$6\$salt\$X8y1cY8o3wZxR3bR7JqQhX0D2u0pF3XnblZqHj7e2d7G3b7b5gL9h" # dummy, SSH keys only
  apt:
    preserve_sources_list: false
    sources:
      darksite:
        source: "deb [trusted=yes] file:/root/darksite/repo noble main extra"
  packages:
    - ubuntu-minimal
    - qemu-guest-agent
    - wireguard-tools
    - nftables
    - zfsutils-linux
    - zfs-dkms
    - mokutil
    - dkms
  storage:
    config:
      - {id: disk0, type: disk, match: {size: largest}, ptable: gpt}
      - {id: part-efi, type: partition, device: disk0, size: 512M, flag: boot, number: 1}
      - {id: part-root-tmp, type: partition, device: disk0, size: 8G,  number: 2}
      - {id: part-free,     type: partition, device: disk0, size: -1, number: 3}
      - {id: fs-efi,  type: format, fstype: fat32, volume: part-efi}
      - {id: fs-root, type: format, fstype: ext4,   volume: part-root-tmp}
      - {id: mp-efi,  type: mount,  path: /boot/efi, device: fs-efi}
      - {id: mp-root, type: mount,  path: /,        device: fs-root}
  user-data:
${NETYAML//^/}
  late-commands:
    - curtin in-target -- bash -c 'mkdir -p /root/darksite'
    - cp -a /cdrom/darksite/. /target/root/darksite/
    - curtin in-target -- bash -c 'install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch || true'
    - curtin in-target -- bash -c 'install -D -m0644 /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service && systemctl enable bootstrap.service'
    - curtin in-target -- bash -c 'test -f /root/darksite/zfs-rootify.sh && install -D -m0755 /root/darksite/zfs-rootify.sh /root/darksite/zfs-rootify.sh && install -D -m0644 /root/darksite/zfs-rootify.service /etc/systemd/system/zfs-rootify.service && systemctl enable zfs-rootify.service || true'
    - curtin in-target -- bash -c 'systemctl --no-block poweroff || true'
EOF

  # Also make it available under /autoinstall (mirrors /nocloud)
  mkdir -p "$cust/autoinstall"
  cp -a "$cust/nocloud" "$cust/autoinstall/"

  # ---- Copy original ISO and patch boot entries for autoinstall ---------------
  (
    set -euo pipefail
    trap "umount -f '$mnt' 2>/dev/null || true" EXIT
    mount -o loop,ro "$ISO_ORIG" "$mnt"
    rsync -aHAX --delete "$mnt/" "$cust/"
  )

  # GRUB (UEFI): append autoinstall + NoCloud seed path
  if [[ -f "$cust/boot/grub/grub.cfg" ]]; then
    sed -ri 's#(^[[:space:]]*linux[[:space:]]+/casper/[^[:space:]]+[[:space:]].*)$#\1 autoinstall ds=nocloud\\;s=/cdrom/nocloud/#' \
      "$cust/boot/grub/grub.cfg" || true
  fi
  # SYSLINUX (BIOS; usually absent on live-server, patch if present)
  if [[ -f "$cust/isolinux/txt.cfg" ]]; then
    sed -ri 's#(^[[:space:]]*append[[:space:]].*)$#\1 autoinstall ds=nocloud\\;s=/cdrom/nocloud/#' \
      "$cust/isolinux/txt.cfg" || true
  fi

  # Ensure the destination is fresh/blank
  mkdir -p "$(dirname "$iso_out")"
  [ -e "$iso_out" ] && rm -f "$iso_out"

  # Sanitize VOLID: ISO9660 allows 32 chars [A-Z0-9_]
  VOLID_RAW="${name^^}-AUTOINSTALL"
  VOLID_CLEAN="$(printf '%s' "$VOLID_RAW" | tr -c 'A-Z0-9_' '_' | cut -c1-32)"

  xorriso \
    -indev  "$ISO_ORIG" \
    -outdev "$BUILD_ROOT/master.iso" \
    -map    "$cust" / \
    -boot_image any replay

  echo "[OK] ISO rebuilt with original UEFI boot structure → $iso_out"
}

# =====================================================================
# SECURE BOOT / MOK AUTOSIGN (payload placed inside guests)
# =====================================================================
secure_boot_mok_autosign(){
  cat >"$1" <<'EOSH'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/mok-autosign.log"; exec > >(tee -a "$LOG") 2>&1 || true
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y --no-install-recommends mokutil openssl kmod dkms || true

KEYDIR=/etc/secureboot/keys
KEY=$KEYDIR/MOK.key
CRT=$KEYDIR/MOK.crt
DER=$KEYDIR/MOK.der

mkdir -p "$KEYDIR"
if [ ! -s "$KEY" ] || [ ! -s "$CRT" ]; then
  openssl req -new -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CRT" -days 36500 -nodes -subj "/CN=foundrybot MOK/"
  openssl x509 -in "$CRT" -outform DER -out "$DER"
  chmod 600 "$KEY"
fi

if mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'; then
  mokutil --list-enrolled | grep -q "foundrybot MOK" || mokutil --import "$DER" --password "changeme" || true
fi

cat >/etc/dkms/sign_helper.sh <<'EOK'
#!/bin/sh
KOBJ="$1"
KEY=/etc/secureboot/keys/MOK.key
CRT=/etc/secureboot/keys/MOK.crt
[ -s "$KOBJ" ] && /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 "$KEY" "$CRT" "$KOBJ" || true
EOK
chmod +x /etc/dkms/sign_helper.sh

cat >/etc/dkms/framework.conf <<'EOK'
sign_tool=/etc/dkms/sign_helper.sh
EOK

for m in zfs zunicode zzstd zcommon zlua zavl icp spl; do
  K=$(modinfo -n $m 2>/dev/null || true)
  [ -n "$K" ] && /etc/dkms/sign_helper.sh "$K" || true
done
EOSH
  chmod +x "$1"
}

# =====================================================================
# MASTER PAYLOAD (runs inside master after install)
# =====================================================================
emit_postinstall_master(){
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/postinstall-master.log"; exec > >(tee -a "$LOG") 2>&1
log(){ echo "[INFO] $(date '+%F %T') - $*"; }
warn(){ echo "[WARN] $(date '+%F %T') - $*" >&2; }
err(){ echo "[ERROR] $(date '+%F %T') - $*" >&2; }

dpkg_script_sanity_fix(){
  shopt -s nullglob
  for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
    [ -f "$f" ] || continue
    head -c 4 "$f" | grep -q $'^\x7fELF' && continue
    sed -i 's/\r$//' "$f" 2>/dev/null || true
    head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"
    chmod +x "$f" || true
  done
  dpkg --configure -a || true
}

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"
GUI_PROFILE="${GUI_PROFILE:-rdp-minimal}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
ADMIN_USER="${ADMIN_USER:-todd}"
DOMAIN="${DOMAIN:-unixbox.net}"
MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"
ZFS_MOUNTPOINT="${ZFS_MOUNTPOINT:-/mnt/share}"

EXTRAS_DIR="/root/darksite/extras"
CLUSTER_DEPLOY="${CLUSTER_DEPLOY:-$EXTRAS_DIR/cluster-deploy.sh}"
SCC_SCRIPT="${SCC_SCRIPT:-$EXTRAS_DIR/scc.sh}"
NEW_SCRIPT="${NEW_SCRIPT:-$EXTRAS_DIR/new.sh}"

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  dpkg_script_sanity_fix
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo noble main extra
deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    build-essential dkms linux-headers-generic \
    zfs-dkms zfsutils-linux zfs-initramfs shim-signed grub-efi-amd64-signed mokutil kmod \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    wireguard-tools nftables chrony rsyslog qemu-guest-agent nfs-common \
    bpftrace linux-tools-generic sysstat strace lsof || true
  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

ensure_users_harden(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"
  id -u "$ADMIN_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$ADMIN_USER"
  install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
  touch "/home/$ADMIN_USER/.ssh/authorized_keys"; chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
  [[ -n "$PUB" ]] && grep -qxF "$PUB" "/home/$ADMIN_USER/.ssh/authorized_keys" || { [[ -n "$PUB" ]] && printf '%s\n' "$PUB" >> "/home/$ADMIN_USER/.ssh/authorized_keys"; }
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" >"/etc/sudoers.d/90-$ADMIN_USER"; chmod 0440 "/etc/sudoers.d/90-$ADMIN_USER"

  id -u ansible >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys; chmod 600 /home/ansible/.ssh/authorized_keys

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress ${MASTER_LAN}
ListenAddress $(echo "${WG1_IP}" | cut -d/ -f1)
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
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
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

wg_prepare_conf(){
  local ifn="$1" ipcidr="$2" port="$3"
  install -d -m700 /etc/wireguard
  umask 077; [[ -f /etc/wireguard/${ifn}.key ]] || wg genkey | tee /etc/wireguard/${ifn}.key | wg pubkey >/etc/wireguard/${ifn}.pub
  cat >/etc/wireguard/${ifn}.conf <<EOF
[Interface]
Address    = ${ipcidr}
ListenPort = ${port}
PrivateKey = $(cat /etc/wireguard/${ifn}.key)
SaveConfig = true
MTU = 1420
EOF
  chmod 600 /etc/wireguard/${ifn}.conf
}
wg_try_systemd(){ systemctl daemon-reload || true; systemctl enable --now "wg-quick@${1}" || return 1; }
wg_bringup_manual(){ local ifn="$1" ipcidr="$2" port="$3"; ip link add "$ifn" type wireguard 2>/dev/null || true; ip addr add "$ipcidr" dev "$ifn" 2>/dev/null || true; wg set "$ifn" listen-port "$port" private-key /etc/wireguard/${ifn}.key || true; ip link set "$ifn" mtu 1420 up || true; }
wg_up_all(){ wg_prepare_conf wg0 "$WG0_IP" "$WG0_PORT"; wg_try_systemd wg0 || wg_bringup_manual wg0 "$WG0_IP" "$WG0_PORT"; wg_prepare_conf wg1 "$WG1_IP" "$WG1_PORT"; wg_try_systemd wg1 || wg_bringup_manual wg1 "$WG1_IP" "$WG1_PORT"; wg_prepare_conf wg2 "$WG2_IP" "$WG2_PORT"; wg_try_systemd wg2 || wg_bringup_manual wg2 "$WG2_IP" "$WG2_PORT"; wg_prepare_conf wg3 "$WG3_IP" "$WG3_PORT"; wg_try_systemd wg3 || wg_bringup_manual wg3 "$WG3_IP" "$WG3_PORT"; }

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
    tcp dport 3389 accept
    iifname { "wg0","wg1","wg2","wg3" } accept
  }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
  nft -f /etc/nftables.conf || true
  systemctl enable --now nftables || true
}

hub_seed(){
  install -d -m0755 /srv/wg
  local _wg0pub _wg1pub _wg2pub _wg3pub _anspub _adminpub
  _wg0pub="$(cat /etc/wireguard/wg0.pub 2>/dev/null || true)"
  _wg1pub="$(cat /etc/wireguard/wg1.pub 2>/dev/null || true)"
  _wg2pub="$(cat /etc/wireguard/wg2.pub 2>/dev/null || true)"
  _wg3pub="$(cat /etc/wireguard/wg3.pub 2>/dev/null || true)"
  _anspub="$(cat /home/ansible/.ssh/id_ed25519.pub 2>/dev/null || true)"
  _adminpub="$( [ -n "${ADMIN_USER:-}" ] && cat "/home/${ADMIN_USER}/.ssh/authorized_keys" 2>/dev/null | head -n1 || true )"
  cat >/srv/wg/hub.env <<EOF
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
WG0_PUB="${_wg0pub}"
WG1_PUB="${_wg1pub}"
WG2_PUB="${_wg2pub}"
WG3_PUB="${_wg3pub}"
ANSIBLE_PUB="${_anspub}"
ADMIN_PUB="${_adminpub}"
EOF
  chmod 0644 /srv/wg/hub.env
  : >/srv/wg/ENROLL_ENABLED
}

helper_tools(){
  cat >/usr/local/sbin/wg-add-peer <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
PUB="${1:-}"; ADDR="${2:-}"; IFN="${3:-wg0}"
FLAG="/srv/wg/ENROLL_ENABLED"
[[ -f "$FLAG" ]] || { echo "[X] enrollment closed"; exit 2; }
[[ -n "$PUB" && -n "$ADDR" ]] || { echo "usage: wg-add-peer <pubkey> <ip/cidr> [ifname]"; exit 1; }
if wg show "$IFN" peers | grep -qx "$PUB"; then
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR"
else
  wg set "$IFN" peer "$PUB" allowed-ips "$ADDR" persistent-keepalive 25
fi
CONF="/etc/wireguard/${IFN}.conf"
if ! grep -q "$PUB" "$CONF"; then
  printf "\n[Peer]\nPublicKey  = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n" "$PUB" "$ADDR" >> "$CONF"
fi
systemctl reload "wg-quick@${IFN}" 2>/dev/null || true
echo "[+] added $PUB $ADDR on $IFN"
EOF
  chmod 0755 /usr/local/sbin/wg-add-peer

  cat >/usr/local/sbin/wg-enrollment <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
FLAG="/srv/wg/ENROLL_ENABLED"
case "${1:-}" in
  on)  : >"$FLAG"; echo "enrollment enabled";;
  off) rm -f "$FLAG"; echo "enrollment disabled";;
  *) echo "usage: wg-enrollment on|off"; exit 1;;
esac
EOF
  chmod 0755 /usr/local/sbin/wg-enrollment

  cat >/usr/local/sbin/register-minion <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
GROUP="${1:-}"; HOST="${2:-}"; IP="${3:-}"
[[ -z "$GROUP" || -z "$HOST" || -z "$IP" ]] && { echo "usage: $0 <group> <hostname> <wg1-ip>"; exit 2; }
ANS_HOSTS="/etc/ansible/hosts"
mkdir -p "$(dirname "$ANS_HOSTS")"; touch "$ANS_HOSTS"
if ! grep -q "^\[${GROUP}\]" "$ANS_HOSTS"; then echo -e "\n[${GROUP}]" >> "$ANS_HOSTS"; fi
sed -i "/^${HOST}\b/d" "$ANS_HOSTS"
echo "${HOST} ansible_host=${IP}" >> "$ANS_HOSTS"
mkdir -p /etc/prometheus/targets.d
TGT="/etc/prometheus/targets.d/${GROUP}.json"
[[ -s "$TGT" ]] || echo '[]' > "$TGT"
tmp="$(mktemp)"; jq --arg target "${IP}:9100" 'map(select(.targets|index($target)|not)) + [{"targets":[$target]}]' "$TGT" > "$tmp" && mv "$tmp" "$TGT"
if pidof prometheus >/dev/null 2>&1; then pkill -HUP prometheus || systemctl reload prometheus || true; fi
echo "[OK] Registered ${HOST} (${IP}) in group ${GROUP}"
EOF
  chmod 0755 /usr/local/sbin/register-minion
}

telemetry_stack(){
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
  cat >/etc/systemd/system/prometheus.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus --web.listen-address=${wg1_ip}:9090 --config.file=/etc/prometheus/prometheus.yml
EOF
  install -d -m755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<EOF
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
  cat >/etc/grafana/provisioning/datasources/prom.yaml <<EOF
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

control_stack(){
  local CONTROL_IF="wg1"; local CONTROL_IP; CONTROL_IP="$(echo "${WG1_IP}" | cut -d/ -f1)"
  apt-get install -y --no-install-recommends salt-master salt-api salt-common || true
  install -d -m0755 /etc/salt/master.d
  cat >/etc/salt/master.d/network.conf <<EOF
interface: ${CONTROL_IP}
ipv6: False
publish_port: 4505
ret_port: 4506
EOF
  cat >/etc/salt/master.d/api.conf <<EOF
rest_cherrypy:
  host: ${CONTROL_IP}
  port: 8000
  disable_ssl: True
EOF
  install -d -m0755 /etc/systemd/system/salt-master.service.d
  cat >/etc/systemd/system/salt-master.service.d/override.conf <<EOF
[Unit]
After=wg-quick@${CONTROL_IF}.service network-online.target
Wants=wg-quick@${CONTROL_IF}.service network-online.target
EOF
  install -d -m0755 /etc/systemd/system/salt-api.service.d
  cat >/etc/systemd/system/salt-api.service.d/override.conf <<EOF
[Unit]
After=wg-quick@${CONTROL_IF}.service network-online.target
Wants=wg-quick@${CONTROL_IF}.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now salt-master salt-api || true

  if [ "${INSTALL_ANSIBLE}" = "yes" ]; then apt-get install -y ansible || true; fi
  if [ "${INSTALL_SEMAPHORE}" != "no" ]; then
    install -d -m755 /etc/semaphore
    if curl -fsSL -o /usr/local/bin/semaphore https://github.com/ansible-semaphore/semaphore/releases/latest/download/semaphore_linux_amd64 2>/dev/null; then
      chmod +x /usr/local/bin/semaphore
      cat >/etc/systemd/system/semaphore.service <<EOF
[Unit]
Description=Ansible Semaphore
After=wg-quick@${CONTROL_IF}.service network-online.target
Wants=wg-quick@${CONTROL_IF}.service
[Service]
ExecStart=/usr/local/bin/semaphore server --listen ${CONTROL_IP}:3000
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now semaphore || true
    else
      warn "Semaphore binary not fetched; install later."
    fi
  fi
}

desktop_gui() {
  case "${GUI_PROFILE}" in
    rdp-minimal)
      apt-get install -y --no-install-recommends xorg xrdp openbox xterm firefox || true
      local INI="/etc/xrdp/xrdp.ini"
      if [ -f "$INI" ]; then
        sed -i 's/^[[:space:]]*port[[:space:]]*=.*/; &/' "$INI" || true
        if grep -qE '^[[:space:]]*address=' "$INI"; then
          sed -i "s|^[[:space:]]*address=.*|address=${MASTER_LAN}|" "$INI"
        else
          sed -i "1i address=${MASTER_LAN}" "$INI"
        fi
        if grep -qE '^[[:space:]]*;port=' "$INI" || grep -qE '^[[:space:]]*port=' "$INI"; then
          sed -ri 's|^[[:space:]]*;?port=.*|port=3389|' "$INI"
        else
          sed -i '1i port=3389' "$INI"
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
  esac
}

storage_share_setup(){
  local share="${ZFS_MOUNTPOINT:-/mnt/share}"
  apt-get install -y --no-install-recommends nfs-kernel-server >/dev/null 2>&1 || true
  install -d -m0755 "$share"
  grep -q "^[[:space:]]*${share}[[:space:]]" /etc/exports 2>/dev/null || \
    echo "${share} 10.80.0.0/16(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
  echo 'RPCMOUNTDOPTS="--port 20048"' >/etc/default/nfs-kernel-server
  echo 'STATDOPTS="--port 32765 --outgoing-port 32766"' >/etc/default/nfs-common
  install -d -m0755 /etc/systemd/system/nfs-server.service.d
  cat >/etc/systemd/system/nfs-server.service.d/override.conf <<'EOF'
[Service]
Environment=RPCMOUNTDOPTS=--port=20048
EOF
  systemctl daemon-reload || true
  exportfs -ra || true
  systemctl enable --now nfs-server || true
  log "NFS share ${share} exported on wg3."
}

main_master(){
  log "BEGIN postinstall (master hub)"
  ensure_base

  # Secure Boot / MOK automation (sign DKMS like ZFS)
  /bin/true
  cat >/root/mok-autosign.sh <<"EOM"
PLACEHOLDER
EOM
  sed -i '1,$d' /root/mok-autosign.sh
  printf '%s\n' "#!/usr/bin/env bash" >> /root/mok-autosign.sh
  printf '%s\n' "$(cat /root/darksite/mok-autosign.sh)" >> /root/mok-autosign.sh
  chmod +x /root/mok-autosign.sh
  /root/mok-autosign.sh || true

  ensure_users_harden
  wg_up_all
  nft_firewall
  hub_seed
  helper_tools
  storage_share_setup
  telemetry_stack
  control_stack
  desktop_gui

  systemctl disable --now openipmi.service 2>/div/null || true
  systemctl mask openipmi.service 2>/div/null || true

  log "Master hub ready."
  systemctl disable bootstrap.service || true
  systemctl daemon-reload || true
  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}
main_master
EOS
}

# =====================================================================
# MINION PAYLOAD (runs inside minions after install)
# =====================================================================
emit_postinstall_minion(){
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/minion-postinstall.log"; exec > >(tee -a "$LOG") 2>&1
log(){ echo "[INFO] $(date '+%F %T') - $*"; }
warn(){ echo "[WARN] $(date '+%F %T') - $*" >&2; }
err(){ echo "[ERROR] $(date '+%F %T') - $*" >&2; }

dpkg_script_sanity_fix() {
  set +u
  shopt -s nullglob
  for f in /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm,config}; do
    [ -f "$f" ] || continue
    head -c 4 "$f" | grep -q $'^\x7fELF' && continue
    sed -i 's/\r$//' "$f" 2>/dev/null || true
    head -n1 "$f" | grep -q '^#!' || sed -i '1s|.*|#!/bin/sh|' "$f"
    chmod +x "$f" || true
  done
  dpkg --configure -a || true
  set -u
}

ADMIN_USER="${ADMIN_USER:-todd}"
MY_GROUP="${MY_GROUP:-prom}"

WG0_WANTED="${WG0_WANTED:-10.77.0.2/32}"
WG1_WANTED="${WG1_WANTED:-10.78.0.2/32}"
WG2_WANTED="${WG2_WANTED:-10.79.0.2/32}"
WG3_WANTED="${WG3_WANTED:-10.80.0.2/32}"

K8S_ENABLE="${K8S_ENABLE:-yes}"
K8S_VERSION="${K8S_VERSION:-1.29}"
K8S_POD_CIDR="${K8S_POD_CIDR:-10.244.0.0/16}"
K8S_SVC_CIDR="${K8S_SVC_CIDR:-10.96.0.0/12}"
K8S_API_ADVERTISE_IFACE="${K8S_API_ADVERTISE_IFACE:-wg2}"
K8S_NODE_IP_IFACE="${K8S_NODE_IP_IFACE:-wg2}"
K8S_RUNTIME="${K8S_RUNTIME:-containerd}"

CILIUM_VERSION="${CILIUM_VERSION:-1.14.6}"
CILIUM_ENCRYPTION="${CILIUM_ENCRYPTION:-disabled}"
CILIUM_WG_INTERFACE="${CILIUM_WG_INTERFACE:-wg2}"
CILIUM_KPR="${CILIUM_KPR:-strict}"
CILIUM_TUNNEL_MODE="${CILIUM_TUNNEL_MODE:-disabled}"
CILIUM_AUTO_DIRECT_ROUTES="${CILIUM_AUTO_DIRECT_ROUTES:-true}"
CILIUM_BPF_MASQ="${CILIUM_BPF_MASQ:-true}"

METALLB_POOL_CIDRS="${METALLB_POOL_CIDRS:-10.100.10.111-10.100.10.130}"
METALLB_NAMESPACE="${METALLB_NAMESPACE:-metallb-system}"

EXTRAS_DIR="/root/darksite/extras"
CLUSTER_DEPLOY="${CLUSTER_DEPLOY:-$EXTRAS_DIR/cluster-deploy.sh}"
SCC_SCRIPT="${SCC_SCRIPT:-$EXTRAS_DIR/scc.sh}"
NEW_SCRIPT="${NEW_SCRIPT:-$EXTRAS_DIR/new.sh}"

HUB_ENV_CANDIDATES=(/root/cluster-seed/hub.env /srv/wg/hub.env /root/darksite/cluster-seed/hub.env /root/darksite/hub.env)

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  dpkg_script_sanity_fix
  cat >/etc/apt/sources.list <<'EOF'
deb [trusted=yes] file:/root/darksite/repo noble main extra
deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
EOF
  install -D -m0644 /root/darksite/apt-arch.conf /etc/apt/apt.conf.d/00local-arch
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    wireguard-tools nftables chrony rsyslog qemu-guest-agent \
    build-essential dkms linux-headers-generic \
    zfsutils-linux zfs-dkms zfs-initramfs nfs-common mokutil kmod \
    bpftrace linux-tools-generic sysstat strace lsof || true
  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

ensure_admin_user(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"; local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"
  id -u "${ADMIN_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${ADMIN_USER}"
  install -d -m700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  touch "/home/${ADMIN_USER}/.ssh/authorized_keys"
  [[ -n "$PUB" ]] && ! grep -qxF "$PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys" && echo "$PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys" || true
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
}
ensure_ansible_user(){
  id -u ansible >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -n "${ANSIBLE_PUB:-}" ]] && { printf '%s\n' "$ANSIBLE_PUB" >> /home/ansible/.ssh/authorized_keys; sort -u -o /home/ansible/.ssh/authorized_keys /home/ansible/.ssh/authorized_keys; chown -R ansible:ansible /home/ansible/.ssh; chmod 600 /home/ansible/.ssh/authorized_keys; }
}

read_hub(){
  local f; for f in "${HUB_ENV_CANDIDATES[@]}"; do [[ -r "$f" ]] && { HUB_ENV_FILE="$f"; break; }; done
  [[ -n "${HUB_ENV_FILE:-}" ]] || { err "missing hub.env"; return 1; }
  eval "$(
    awk -F= '
      /^[[:space:]]*#/ {next}
      /^[A-Za-z0-9_]+=/ {key=$1; $1=""; sub(/^=/,""); val=$0; gsub(/^[ \t]+|[ \t]+$/,"",val); gsub(/"/,"\\\"",val); print key "=\"" val "\""}' "$HUB_ENV_FILE"
  )"
  : "${HUB_LAN:?missing HUB_LAN}"
  : "${WG0_PORT:?missing WG0_PORT}"
  : "${WG_ALLOWED_CIDR:?missing WG_ALLOWED_CIDR}"
}

wg_setup_all(){
  install -d -m700 /etc/wireguard; umask 077
  for IFN in wg0 wg1 wg2 wg3; do [[ -f /etc/wireguard/${IFN}.key ]] || wg genkey | tee /etc/wireguard/${IFN}.key | wg pubkey >/etc/wireguard/${IFN}.pub; done
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${WG0_WANTED}
PrivateKey = $(cat /etc/wireguard/wg0.key)
ListenPort = 0
DNS        = 1.1.1.1
MTU        = 1420
SaveConfig = true
[Peer]
PublicKey  = ${WG0_PUB}
Endpoint   = ${HUB_LAN}:${WG0_PORT}
AllowedIPs = ${WG_ALLOWED_CIDR}
PersistentKeepalive = 25
EOF
  for n in 1 2 3; do
    cat >/etc/wireguard/wg${n}.conf <<EOF
[Interface]
Address    = $(eval echo \${WG${n}_WANTED})
PrivateKey = $(cat /etc/wireguard/wg${n}.key)
ListenPort = 0
MTU        = 1420
SaveConfig = true
EOF
  done
  chmod 600 /etc/wireguard/*.conf
  install -d -m755 /etc/systemd/system/wg-quick@wg0.service.d
  cat >/etc/systemd/system/wg-quick@wg0.service.d/override.conf <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target
EOF
  for ifn in wg1 wg2 wg3; do
    install -d -m755 /etc/systemd/system/wg-quick@${ifn}.service.d
    cat >/etc/systemd/system/wg-quick@${ifn}.service.d/override.conf <<EOF
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  done
  systemctl daemon-reload || true
  systemctl enable --now wg-quick@wg0 || true
  for ifn in wg1 wg2 wg3; do systemctl enable --now "wg-quick@${ifn}" || true; done
}

secure_boot_mok(){
  if command -v mokutil >/dev/null 2>&1; then
    bash /root/darksite/mok-autosign.sh || true
  fi
}

main(){
  log "minion bootstrap start (group=${MY_GROUP})"
  ensure_base
  read_hub
  ensure_admin_user
  ensure_ansible_user
  secure_boot_mok
  wg_setup_all
  if [[ "$MY_GROUP" == "k8s" && "${K8S_ENABLE}" == "yes" ]]; then
    :
  fi
  log "minion bootstrap done; powering off in 2s"
  (sleep 2; systemctl --no-block poweroff) & disown
}
main
EOS
}

# =====================================================================
# MINION WRAPPER (builds per-role payload, embeds hub.env)
# =====================================================================
emit_minion_wrapper(){
  local out="$1" group="$2" wg0="$3" wg1="$4" wg2="$5" wg3="$6"
  local hub_src="$BUILD_ROOT/hub/hub.env"; [[ -s "$hub_src" ]] || { err "emit_minion_wrapper: missing hub.env at $hub_src"; return 1; }

  cat >"$out" <<'EOSH'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/minion-wrapper.log"; exec > >(tee -a "$LOG") 2>&1
trap 'echo "[WRAP] failed: ${BASH_COMMAND@Q}  (line ${LINENO})" >&2' ERR
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
cat >/etc/environment.d/99-provision.conf <<EOF
ADMIN_USER=$ADMIN_USER
MY_GROUP=${group}
WG0_WANTED=${wg0}
WG1_WANTED=${wg1}
WG2_WANTED=${wg2}
WG3_WANTED=${wg3}
K8S_ENABLE=${K8S_ENABLE}
K8S_VERSION=${K8S_VERSION}
K8S_POD_CIDR=${K8S_POD_CIDR}
K8S_SVC_CIDR=${K8S_SVC_CIDR}
K8S_API_ADVERTISE_IFACE=${K8S_API_ADVERTISE_IFACE}
K8S_NODE_IP_IFACE=${K8S_NODE_IP_IFACE}
K8S_RUNTIME=${K8S_RUNTIME}
CILIUM_VERSION=${CILIUM_VERSION}
CILIUM_ENCRYPTION=${CILIUM_ENCRYPTION}
CILIUM_WG_INTERFACE=${CILIUM_WG_INTERFACE}
CILIUM_KPR=${CILIUM_KPR}
CILIUM_TUNNEL_MODE=${CILIUM_TUNNEL_MODE}
CILIUM_AUTO_DIRECT_ROUTES=${CILIUM_AUTO_DIRECT_ROUTES}
CILIUM_BPF_MASQ=${CILIUM_BPF_MASQ}
METALLB_POOL_CIDRS=${METALLB_POOL_CIDRS}
METALLB_NAMESPACE=${METALLB_NAMESPACE}
EOF
chmod 0644 /etc/environment.d/99-provision.conf
EOSH

  # Bundle minion payload + MOK helper and run it
  cat >>"$out" <<'EOSH'
install -d -m0755 /root/darksite
cat >/root/darksite/postinstall-minion.sh <<'EOMINION'
EOSH
  local tmp; tmp="$(mktemp)"; emit_postinstall_minion "$tmp"; cat "$tmp" >>"$out"; rm -f "$tmp"
  cat >>"$out" <<'EOSH'
EOMINION
EOSH

  local moktmp; moktmp="$(mktemp)"; secure_boot_mok_autosign "$moktmp"
  echo "cat >/root/darksite/mok-autosign.sh <<'EOMOK'" >> "$out"
  cat "$moktmp" >> "$out"
  echo "EOMOK" >> "$out"
  rm -f "$moktmp"

  cat >>"$out" <<'EOSH'
perl -0777 -pe 's/\r\n/\n/g; s/\r/\n/g' -i /root/darksite/postinstall-minion.sh
chmod +x /root/darksite/postinstall-minion.sh
/usr/bin/env bash /root/darksite/postinstall-minion.sh
EOSH
  chmod +x "$out"
}

# =====================================================================
# MASTER ENROLLMENT SEED (ensures minimal hub.env exists)
# =====================================================================
ensure_master_enrollment_seed(){
  local vmid="$1"
  pmx_guest_exec "$vmid" /bin/bash -lc "$(cat <<'EOS'
set -euo pipefail
. /etc/environment.d/99-provision.conf 2>/dev/null || true
mkdir -p /srv/wg
if [ ! -s /srv/wg/hub.env ]; then
  cat > /srv/wg/hub.env <<'EOF'
WG0_IP=${WG0_IP:-10.77.0.1/16}
WG1_IP=${WG1_IP:-10.78.0.1/16}
WG2_IP=${WG2_IP:-10.79.0.1/16}
WG3_IP=${WG3_IP:-10.80.0.1/16}
WG0_PORT=${WG0_PORT:-51820}
WG1_PORT=${WG1_PORT:-51821}
WG2_PORT=${WG2_PORT:-51822}
WG3_PORT=${WG3_PORT:-51823}
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}
HUB_LAN=${MASTER_LAN:-10.100.10.224}
WG0_PUB=
WG1_PUB=
WG2_PUB=
WG3_PUB=
EOF
  chmod 0644 /srv/wg/hub.env
fi
: > /srv/wg/ENROLL_ENABLED
EOS
)"
}

# =====================================================================
# BUILD ALL ROLE ISOs + CAPTURE hub.env
# =====================================================================
build_all_isos(){
  log "[*] Building all ISOs into $BUILD_ROOT"
  mkdir -p "$BUILD_ROOT/hub" "$BUILD_ROOT/extras"

  for f in /mnt/data/cluster-deploy.sh /mnt/data/scc.sh /mnt/data/new.sh; do
    [[ -s "$f" ]] && cp -f "$f" "$BUILD_ROOT/extras/$(basename "$f")" || true
  done

  local master_payload master_iso
  master_payload="$(mktemp)"
  emit_postinstall_master "$master_payload"

  local moktmp; moktmp="$(mktemp)"; secure_boot_mok_autosign "$moktmp"
  mkdir -p "$BUILD_ROOT/mok"; cp -f "$moktmp" "$BUILD_ROOT/mok/mok-autosign.sh"; rm -f "$moktmp"
  echo >>"$master_payload"; echo "# MOK helper included via darksite" >>"$master_payload"

  master_iso="$BUILD_ROOT/master.iso"
  mk_ubuntu_iso "master" "$master_payload" "$master_iso" "$MASTER_LAN"
  log "[OK] master ISO: $master_iso"

  pmx_deploy "$MASTER_ID" "$MASTER_NAME" "$master_iso" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"
  wait_poweroff "$MASTER_ID" 1800
  pmx "qm set $MASTER_ID --boot order=scsi0; qm start $MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  pmx "qm set $MASTER_ID --delete ide2; qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900
  ensure_master_enrollment_seed "$MASTER_ID"

  log "Fetching hub.env from master via QGA…"
  local DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "[OK] captured hub.env → $DEST"
  else
    err "Failed to retrieve hub.env via QGA"; exit 1
  fi

  local pld iso
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "prom"    "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3"; iso="$BUILD_ROOT/prom.iso";    mk_ubuntu_iso "$PROM_NAME"    "$pld" "$iso" "$PROM_IP"; log "[OK] prom ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "graf"    "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3"; iso="$BUILD_ROOT/graf.iso";    mk_ubuntu_iso "$GRAF_NAME"    "$pld" "$iso" "$GRAF_IP"; log "[OK] graf ISO:    $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "k8s"     "$K8S_WG0"  "$K8S_WG1"  "$K8S_WG2"  "$K8S_WG3";  iso="$BUILD_ROOT/k8s.iso";     mk_ubuntu_iso "$K8S_NAME"     "$pld" "$iso" "$K8S_IP";  log "[OK] k8s ISO:     $iso"
  pld="$(mktemp)"; emit_minion_wrapper "$pld" "storage" "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3"; iso="$BUILD_ROOT/storage.iso"; mk_ubuntu_iso "$STOR_NAME"     "$pld" "$iso" "$STOR_IP"; log "[OK] storage ISO: $iso"
}

# =====================================================================
# PROXMOX FANOUT
# =====================================================================
proxmox_cluster(){
  build_all_isos

  pmx_deploy "$PROM_ID" "$PROM_NAME" "$BUILD_ROOT/prom.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$PROM_ID" 2400; pmx "qm set $PROM_ID --boot order=scsi0; qm start $PROM_ID"; wait_poweroff "$PROM_ID" 2400; pmx "qm set $PROM_ID --delete ide2; qm start $PROM_ID"; pmx_wait_for_state "$PROM_ID" "running" 600

  pmx_deploy "$GRAF_ID" "$GRAF_NAME" "$BUILD_ROOT/graf.iso" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$GRAF_ID" 2400; pmx "qm set $GRAF_ID --boot order=scsi0; qm start $GRAF_ID"; wait_poweroff "$GRAF_ID" 2400; pmx "qm set $GRAF_ID --delete ide2; qm start $GRAF_ID"; pmx_wait_for_state "$GRAF_ID" "running" 600

  pmx_deploy "$K8S_ID"  "$K8S_NAME"  "$BUILD_ROOT/k8s.iso"  "$K8S_MEM"    "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$K8S_ID"  2400; pmx "qm set $K8S_ID --boot order=scsi0; qm start $K8S_ID";  wait_poweroff "$K8S_ID"  2400; pmx "qm set $K8S_ID --delete ide2; qm start $K8S_ID";  pmx_wait_for_state "$K8S_ID"  "running" 600

  pmx_deploy "$STOR_ID" "$STOR_NAME" "$BUILD_ROOT/storage.iso" "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"
  wait_poweroff "$STOR_ID" 2400; pmx "qm set $STOR_ID --boot order=scsi0; qm start $STOR_ID"; wait_poweroff "$STOR_ID" 2400; pmx "qm set $STOR_ID --delete ide2; qm start $STOR_ID"; pmx_wait_for_state "$STOR_ID" "running" 600

  log "Closing WireGuard enrollment on master…"
  pmx_guest_exec "$MASTER_ID" /bin/bash -lc "rm -f /srv/wg/ENROLL_ENABLED" || true

  log "Done. Master + minions deployed on Ubuntu 24.04 (ZFS pivot handled on first boot, MOK autosign ready)."
}

# =====================================================================
# OPTIONAL SCAFFOLDS / ENTRYPOINT
# =====================================================================
emit_packer_scaffold(){ mkdir -p "$PACKER_OUT"; cat >"$PACKER_OUT/README.txt" <<'EOF'
Starter Packer scaffold (QEMU/KVM). Adjust to point at your Ubuntu ISO.
EOF
log "[OK] packer scaffold at: $PACKER_OUT"; }

emit_firecracker_scaffold(){ install -d "$FIRECRACKER_OUT"; cat >"$FIRECRACKER_OUT/extract-kernel-initrd.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
RAW_IMG="${1:-}"; OUT_DIR="${2:-.}"
[[ -n "$RAW_IMG" && -s "$RAW_IMG" ]] || { echo "usage: $0 <rootfs.raw> [outdir]" >&2; exit 2; }
mkdir -p "$OUT_DIR"
command -v guestmount >/dev/null || { echo "[X] apt install libguestfs-tools"; exit 1; }
mnt="$(mktemp -d)"; trap 'umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true' EXIT
guestmount -a "$RAW_IMG" -i "$mnt"
cp -Lf "$mnt"/boot/vmlinuz* "$OUT_DIR/kernel"
cp -Lf "$mnt"/boot/initrd*  "$OUT_DIR/initrd"
echo "[OK] kernel/initrd -> $OUT_DIR"
EOF
chmod +x "$FIRECRACKER_OUT/extract-kernel-initrd.sh"; log "[OK] Firecracker scaffold in $FIRECRACKER_OUT"; }

firecracker_flow(){ log "[hint] Firecracker flow unchanged from Debian edition; adapt your rootfs path as needed."; }

# ----------------- Entrypoint -----------------
case "$TARGET" in
  proxmox-cluster) proxmox_cluster ;;
  image-only)
    log "[*] Building role ISOs only…"
    MASTER_PAYLOAD="$(mktemp)"; emit_postinstall_master "$MASTER_PAYLOAD"
    mkdir -p "$BUILD_ROOT/hub"
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
    MASTER_ISO="$BUILD_ROOT/master.iso"; mk_ubuntu_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"
    P="$(mktemp)"; emit_minion_wrapper "$P" "prom"    "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3"; mk_ubuntu_iso "$PROM_NAME" "$P" "$BUILD_ROOT/prom.iso"    "$PROM_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "graf"    "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3"; mk_ubuntu_iso "$GRAF_NAME" "$P" "$BUILD_ROOT/graf.iso"    "$GRAF_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "k8s"     "$K8S_WG0"  "$K8S_WG1"  "$K8S_WG2"  "$K8S_WG3";  mk_ubuntu_iso "$K8S_NAME" "$P" "$BUILD_ROOT/k8s.iso"     "$K8S_IP"
    P="$(mktemp)"; emit_minion_wrapper "$P" "storage" "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3"; mk_ubuntu_iso "$STOR_NAME" "$P" "$BUILD_ROOT/storage.iso" "$STOR_IP"
    log "[DONE] ISOs in $BUILD_ROOT"
    ;;
  packer-scaffold)     emit_packer_scaffold ;;
  firecracker-bundle)  emit_firecracker_scaffold ;;
  firecracker)         firecracker_flow ;;
  aws-ami)             log "[note] Ubuntu AMI bake flow compatible; use base ubuntu-24.04 images." ;;
  aws-run)             log "[note] aws-run unchanged; set AWS_AMI_ID from Ubuntu AMI." ;;
  *) die "Unknown TARGET=$TARGET" ;;
esac


[bpfenv] root@onyx:~/deploy/v7# 
