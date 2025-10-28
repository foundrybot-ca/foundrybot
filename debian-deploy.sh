#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2155,SC2086

set -euo pipefail

# =========================
# DRIVER MODE & GLOBAL CONFIG
# =========================

TARGET="${TARGET:-proxmox-cluster}"   # proxmox-cluster | proxmox-clones | aws-ami | aws-run | firecracker
INPUT="${INPUT:-1}"                   # 1|fiend, 2|dragon, 3|lion
DOMAIN="${DOMAIN:-unixbox.net}"

case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) echo "[ERROR] Unknown INPUT=$INPUT" >&2; exit 1 ;;
esac

# ---- Proxmox storage knobs ----
# ISO_STORAGE / VM_STORAGE refer to Proxmox storage IDs.
#  - local directory:         ISO_STORAGE=local          VM_STORAGE=local
#  - ZFS pool (common):       ISO_STORAGE=local          VM_STORAGE=local-zfs
#  - ZFS pool (custom name):  VM_STORAGE=zpool-vmdata
#  - Ceph/RBD (default pool): VM_STORAGE=void
#  - Ceph/RBD (custom pool):  VM_STORAGE=void-vm

ISO_ORIG="${ISO_ORIG:-/var/lib/libvirt/boot/debian-13.1.0-amd64-netinst.iso}"
ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"

# ---- Optional: Ceph/ZFS tuning for disks ----
# CEPH_RBD_FEATURES can be set on the storage definition in Proxmox GUI; this script uses storage ID only.
# ZFS THIN vs THICK: Proxmox 'scsi0 ${VM_STORAGE}:${SIZE}' honors storage config (thin on ZFS by default).
# To attach disks to specific ZFS datasets/pools, ensure the storage ID maps to that pool/dataset.

# ===== Master VM (ISO flow) =====
MASTER_ID="${MASTER_ID:-7010}"; MASTER_NAME="${MASTER_NAME:-master}"
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

# ===== Minion VMs (ISO flow) =====
PROM_ID="${PROM_ID:-7011}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.223}"
GRAF_ID="${GRAF_ID:-7012}"; GRAF_NAME="${GRAF_NAME:-grafana}";   GRAF_IP="${GRAF_IP:-10.100.10.222}"
K8S_ID="${K8S_ID:-7013}";  K8S_NAME="${K8S_NAME:-k8s}";          K8S_IP="${K8S_IP:-10.100.10.221}"
STOR_ID="${STOR_ID:-7014}"; STOR_NAME="${STOR_NAME:-storage}";   STOR_IP="${STOR_IP:-10.100.10.220}"

# ===== WireGuard planes (master addresses) =====
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

# ===== Per-minion WG IPs (ISO flow; /32) =====
PROM_WG0="${PROM_WG0:-10.77.0.2/32}"; PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; PROM_WG2="${PROM_WG2:-10.79.0.2/32}"; PROM_WG3="${PROM_WG3:-10.80.0.2/32}"
GRAF_WG0="${GRAF_WG0:-10.77.0.3/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; GRAF_WG2="${GRAF_WG2:-10.79.0.3/32}"; GRAF_WG3="${GRAF_WG3:-10.80.0.3/32}"
K8S_WG0="${K8S_WG0:-10.77.0.4/32}";  K8S_WG1="${K8S_WG1:-10.78.0.4/32}";  K8S_WG2="${K8S_WG2:-10.79.0.4/32}";  K8S_WG3="${K8S_WG3:-10.80.0.4/32}"
STOR_WG0="${STOR_WG0:-10.77.0.5/32}"; STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; STOR_WG2="${STOR_WG2:-10.79.0.5/32}"; STOR_WG3="${STOR_WG3:-10.80.0.5/32}"

# ===== VM sizing (ISO flow) =====
MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-4}"; MASTER_DISK_GB="${MASTER_DISK_GB:-40}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-32}"
K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

# ===== Admin =====
ADMIN_USER="${ADMIN_USER:-todd}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-/home/todd/.ssh/id_ed25519.pub}"   # path to a pubkey to inject
SSH_PUBKEY="${SSH_PUBKEY:-}"                 # literal public key string
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-${ALLOW_TODD_PASSWORD:-no}}"
GUI_PROFILE="${GUI_PROFILE:-server}"    # rdp-minimal, server

# Optional
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"   # yes|try|no

# ===== Proxmox Cloud-Init Clone Flow =====
# Enable this with TARGET=proxmox-clones
# TEMPLATE_ID: Proxmox VM template ID with cloud-init installed (Ubuntu/Debian cloud images or your own).
TEMPLATE_ID="${TEMPLATE_ID:-9000}"             # Cloud-init template VM
CLONES="${CLONES:-0}"                          # Number of clones to create (e.g., 50)
CLONE_NAME_PREFIX="${CLONE_NAME_PREFIX:-minion}" # Resulting names: minion-001 .. minion-050
STARTING_VMID="${STARTING_VMID:-12000}"        # First VMID to assign; will increment
LAN_BRIDGE="${LAN_BRIDGE:-vmbr0}"              # Proxmox bridge for NIC
LAN_MASK="${LAN_MASK:-24}"                     # e.g., 24 for /24
LAN_GW="${LAN_GW:-10.100.10.1}"                # Default gateway on LAN
LAN_IP_BASE="${LAN_IP_BASE:-10.100.10.50}"     # First LAN static IP (increments)
LAN_DNS="${LAN_DNS:-10.100.10.1}"              # DNS for netplan (or set multiple: 10.100.10.1,1.1.1.1)
SNIPPETS_STORAGE="${SNIPPETS_STORAGE:-local}"  # Proxmox storage ID that has snippets enabled (e.g., 'local')

# WG fabric (minions get incremented /32s on wg0; Salt binds to wg0)
WG_HOST_BASE="${WG_HOST_BASE:-10.16.1.10}"     # First minion WG /32 (increments)
WG_ENDPOINT_HOST="${WG_ENDPOINT_HOST:-wg.unixbox.net}" # public hub endpoint (FQDN or IP)
WG_ENDPOINT_PORT="${WG_ENDPOINT_PORT:-51820}"
SALT_MASTER_WG_IP="${SALT_MASTER_WG_IP:-10.16.1.1}"    # hub/master IP on wg0
WG_ALLOWED_MASTER="${WG_ALLOWED_MASTER:-10.16.1.1/32}" # narrow allowed-ips (avoid default route steal)
WG_DNS="${WG_DNS:-}"                          # optional DNS over WG (empty = none)
WG_MTU="${WG_MTU:-1420}"

# Optionally tag each clone with a role/group (prom/graf/k8s/storage) in a round-robin or fixed mapping
# Default: all 'minion'. You can override dynamically via CLONE_GROUP_CYCLE="prom,graf,k8s,storage"
CLONE_GROUP_DEFAULT="${CLONE_GROUP_DEFAULT:-minion}"
CLONE_GROUP_CYCLE="${CLONE_GROUP_CYCLE:-}"    # e.g., "prom,graf,k8s,storage"

# ===== Paths / SSH =====
BUILD_ROOT="${BUILD_ROOT:-/root/builds}"
mkdir -p "$BUILD_ROOT"

SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@" ; }

log() { echo "[INFO]  $(date '+%F %T') - $*"; }
warn(){ echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err() { echo "[ERROR] $(date '+%F %T') - $*" >&2; }
die(){ err "$*"; exit 1; }

command -v xorriso >/dev/null || { err "xorriso not installed (needed for ISO build)"; }

# =========
# UTILITIES
# =========

# Increment an IPv4 address by N (default 1)
ip_inc() {
  local ip=$1 inc=${2:-1}
  IFS=. read -r a b c d <<< "$ip"
  local x=$(( (a<<24) + (b<<16) + (c<<8) + d + inc ))
  printf "%d.%d.%d.%d\n" $(( (x>>24)&255 )) $(( (x>>16)&255 )) $(( (x>>8)&255 )) $(( x&255 ))
}

require_ip_headroom() {
  local start_ip=$1 count=$2
  local last_ip
  last_ip=$(ip_inc "$start_ip" $((count-1)))
  [[ -n "$last_ip" ]] || { echo "IP headroom calc failed for $start_ip x $count"; exit 1; }
}

# =================
# PROXMOX HELPERS
# =================

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
  iso_base="$(pmx_upload_iso "$iso_file")"
  pmx \
    VMID="$vmid" VMNAME="${vmname}.${DOMAIN}-$vmid" FINAL_ISO="$iso_base" \
    VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" \
    DISK_SIZE_GB="$disk_gb" MEMORY_MB="$mem" CORES="$cores" 'bash -s' <<'EOSSH'
set -euo pipefail
qm destroy "$VMID" --purge >/dev/null 2>&1 || true
qm create "$VMID" \
  --name "$VMNAME" \
  --memory "$MEMORY_MB" --cores "$CORES" \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} \
  --serial0 socket --ostype l26 --agent enabled=1
qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0

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

: <<'COMMENT'
ISO BUILDER (CLUSTER-SPECIFIC)

 mk_iso <name> <postinstall_src> <iso_out> [static_ip]
   - Loop-mounts ISO_ORIG read-only, copies content to a staging dir,
     injects:
       * darksite payload (postinstall.sh + bootstrap.service)
       * environment seed (99-provision.conf + authorized_keys)
       * Debian preseed (DHCP or static IP)
       * boot entries for automated install (isolinux/grub)
   - Builds a hybrid BIOS/UEFI ISO with xorriso.

 Preseed Notes:
   - Minimal package set (openssh-server), LVM atomic scheme, UTC, Pacific TZ.
   - late_command copies darksite into target, enables bootstrap, then
     initiates poweroff for the first postinstall run on next boot.

 Security Notes:
   - SSH hardening is applied in postinstall scripts (not here).
   - IPv6 disabled in master postinstall unless changed.
COMMENT

mk_iso() {
  local name="$1" postinstall_src="$2" iso_out="$3" static_ip="${4:-}"

  local build="$BUILD_ROOT/$name"
  local mnt="$build/mnt"
  local cust="$build/custom"
  local dark="$cust/darksite"

  rm -rf "$build" 2>/dev/null || true
  mkdir -p "$mnt" "$cust" "$dark"

  # Do the mount/copy inside a subshell with a *local* EXIT trap.
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

  # Seed provision env + authorized key
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
  } > "$dark/99-provision.conf"

  local auth_seed="$dark/authorized_keys.${ADMIN_USER}"
  if [[ -n "${SSH_PUBKEY:-}" ]]; then
    printf '%s\n' "$SSH_PUBKEY" > "$auth_seed"
  elif [[ -n "${ADMIN_PUBKEY_FILE:-}" && -r "$ADMIN_PUBKEY_FILE" ]]; then
    cat "$ADMIN_PUBKEY_FILE" > "$auth_seed"
  else
    : > "$auth_seed"
  fi
  chmod 0644 "$auth_seed"

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

  cat > "$cust/preseed.cfg" <<EOF
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us
$NETBLOCK
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
d-i passwd/root-login boolean true
d-i passwd/root-password password root
d-i passwd/root-password-again password root
d-i passwd/make-user boolean false
d-i time/zone string America/Vancouver
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
d-i pkgsel/include string openssh-server
d-i pkgsel/upgrade select none
d-i pkgsel/ignore-recommends boolean true
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/sda
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

  # Boot entries
  local KARGS="auto=true priority=critical vga=788 preseed/file=/cdrom/preseed.cfg ---"
  if [[ -f "$cust/isolinux/txt.cfg" ]]; then
    cat >> "$cust/isolinux/txt.cfg" <<EOF
label auto
  menu label ^auto (preseed)
  kernel /install.amd/vmlinuz
  append initrd=/install.amd/initrd.gz $KARGS
EOF
    sed -i 's/^default .*/default auto/' "$cust/isolinux/isolinux.cfg" || true
  fi
  [[ -f "$cust/boot/grub/grub.cfg" ]] && \
    sed -i "s#^\(\s*linux\s\+\S\+\s*\)#\1$KARGS #g" "$cust/boot/grub/grub.cfg" || true

  # Build ISO
  xorriso -as mkisofs -o "$iso_out" -r -J -joliet-long -l \
    -b isolinux/isolinux.bin -c isolinux/boot.cat \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
    -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat "$cust"
}

: <<'COMMENT'
MASTER POSTINSTALL PAYLOAD
--------------------------

 emit_postinstall_master <outfile>
   Writes /root/darksite/postinstall-master.sh for the hub node.
   Responsibilities:
     - Base OS enablement (repos, guest agent, modules).
     - Admin user creation and SSH hardening (LAN-scoped fallback optional).
     - WireGuard wg0..wg3 hub bring-up (keys, systemd or manual).
     - nftables baseline firewall (drop-by-default; permit SSH/WG/RDP).
     - Hub seed (/srv/wg/hub.env + ENROLL_ENABLED flag).
     - Helper tools:
         * wg-add-peer: add/update peer entries + config persistence.
         * wg-enrollment: gate auto-enrollment window on/off.
         * register-minion: inventory to Ansible + Prometheus file_sd.
     - Telemetry stack: Prometheus + node_exporter + Grafana, pinned to wg1 IP.
     - Control stack: Salt master + API on wg0; optional Ansible/Semaphore.
     - Optional GUI: xrdp/openbox or minimal GNOME; service bound to MASTER_LAN.
     - Final: disable bootstrap, cleanly power off.

Idempotency:
   Safe to re-run; key files are only created when absent; services reloaded.
COMMENT

emit_postinstall_master() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
[ -r /etc/environment.d/99-provision.conf ] && . /etc/environment.d/99-provision.conf

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"

GUI_PROFILE="${GUI_PROFILE:-rdp-minimal}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
ADMIN_USER="${ADMIN_USER:-todd}"

DOMAIN="${DOMAIN:-unixbox.net}"
MASTER_LAN="${MASTER_LAN:-10.100.10.224}"

# WG planes
WG0_IP="${WG0_IP:-10.77.0.1/16}"; WG0_PORT="${WG0_PORT:-51820}"
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG2_IP="${WG2_IP:-10.79.0.1/16}"; WG2_PORT="${WG2_PORT:-51822}"
WG3_IP="${WG3_IP:-10.80.0.1/16}"; WG3_PORT="${WG3_PORT:-51823}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"

LOG="/var/log/postinstall-master.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  for i in 1 2 3; do apt-get update -y && break || sleep $((i*3)); done
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq xxd unzip tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    nftables wireguard-tools vim \
    chrony rsyslog qemu-guest-agent dbus-x11 || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true
  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true

  cat >/etc/sysctl.d/99-wg.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
  sysctl --system || true
}

ensure_users_harden(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"

  mk(){ local u="$1" k="$2";
    id -u "$u" &>/dev/null || useradd -m -s /bin/bash "$u";
    install -d -m700 -o "$u" -g "$u" "/home/$u/.ssh";
    touch "/home/$u/.ssh/authorized_keys"; chmod 600 "/home/$u/.ssh/authorized_keys"
    chown -R "$u:$u" "/home/$u/.ssh"
    [[ -n "$k" ]] && grep -qxF "$k" "/home/$u/.ssh/authorized_keys" || { [[ -n "$k" ]] && printf '%s\n' "$k" >> "/home/$u/.ssh/authorized_keys"; }
    install -d -m755 /etc/sudoers.d; printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$u" >"/etc/sudoers.d/90-$u"; chmod 0440 "/etc/sudoers.d/90-$u";
  }
  mk "$ADMIN_USER" "$PUB"

  id -u ansible &>/dev/null || useradd -m -s /bin/bash -G sudo ansible
  install -d -m700 -o ansible -g ansible /home/ansible/.ssh
  [[ -s /home/ansible/.ssh/id_ed25519 ]] || runuser -u ansible -- ssh-keygen -t ed25519 -N "" -f /home/ansible/.ssh/id_ed25519
  install -m0644 /home/ansible/.ssh/id_ed25519.pub /home/ansible/.ssh/authorized_keys
  chown ansible:ansible /home/ansible/.ssh/authorized_keys; chmod 600 /home/ansible/.ssh/authorized_keys

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress ${MASTER_LAN}
ListenAddress $(echo "${WG0_IP}" | cut -d/ -f1)
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
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  (sshd -t && systemctl daemon-reload && systemctl restart ssh) || true
}

wg_prepare_conf(){
  local ifn="$1" ipcidr="$2" port="$3"
  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077
  [[ -f /etc/wireguard/${ifn}.key ]] || wg genkey | tee /etc/wireguard/${ifn}.key | wg pubkey >/etc/wireguard/${ifn}.pub
  cat >/etc/wireguard/${ifn}.conf <<EOF
[Interface]
Address    = ${ipcidr}
ListenPort = ${port}
PrivateKey = $(cat /etc/wireguard/${ifn}.key)
SaveConfig = true
MTU = 1420
EOF
  chmod 600 /etc/wireguard/${ifn}.conf
  umask "$_old_umask"
}
wg_try_systemd(){ systemctl daemon-reload || true; systemctl enable --now "wg-quick@${1}" || return 1; }
wg_bringup_manual(){
  local ifn="$1" ipcidr="$2" port="$3"
  ip link show "$ifn" >/dev/null 2>&1 || ip link add "$ifn" type wireguard || true
  ip -4 addr show dev "$ifn" | grep -q "${ipcidr%/*}" || ip addr add "$ipcidr" dev "$ifn" || true
  wg set "$ifn" listen-port "$port" private-key /etc/wireguard/${ifn}.key || true
  ip link set "$ifn" mtu 1420 up || true
}
wg_up_all(){
  wg_prepare_conf wg0 "$WG0_IP" "$WG0_PORT"; wg_try_systemd wg0 || wg_bringup_manual wg0 "$WG0_IP" "$WG0_PORT"
  wg_prepare_conf wg1 "$WG1_IP" "$WG1_PORT"; wg_try_systemd wg1 || wg_bringup_manual wg1 "$WG1_IP" "$WG1_PORT"
  wg_prepare_conf wg2 "$WG2_IP" "$WG2_PORT"; wg_try_systemd wg2 || wg_bringup_manual wg2 "$WG2_IP" "$WG2_PORT"
  wg_prepare_conf wg3 "$WG3_IP" "$WG3_PORT"; wg_try_systemd wg3 || wg_bringup_manual wg3 "$WG3_IP" "$WG3_PORT"
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
    tcp dport 3389 accept
    iifname "wg0" accept
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
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
WG0_PUB=$(cat /etc/wireguard/wg0.pub 2>/dev/null || echo "")
WG1_PUB=$(cat /etc/wireguard/wg1.pub 2>/dev/null || echo "")
WG2_PUB=$(cat /etc/wireguard/wg2.pub 2>/dev/null || echo "")
WG3_PUB=$(cat /etc/wireguard/wg3.pub 2>/dev/null || echo "")
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

desktop_gui() {
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

main_master(){
  log "BEGIN postinstall (master hub)"
  export DEBIAN_FRONTEND=noninteractive
  ensure_base
  ensure_users_harden

  # Salt/Grafana repos
  install -d -m0755 /etc/apt/keyrings
  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.gpg || true
  curl -fsSL https://github.com/saltstack/salt-install-guide/releases/latest/download/salt.sources -o /etc/apt/sources.list.d/salt.sources || true
  sed -i 's#/etc/apt/keyrings/salt-archive-keyring\.pgp#/etc/apt/keyrings/salt-archive-keyring.pgp#' /etc/apt/sources.list.d/salt.sources || true
  cat >/etc/apt/preferences.d/salt-pin-1001 <<'EOF'
Package: salt-*
Pin: version 3006.*
Pin-Priority: 1001
EOF
  curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg || true
  chmod 0644 /etc/apt/keyrings/grafana.gpg || true
  cat >/etc/apt/sources.list.d/grafana.sources <<'EOF'
Types: deb
URIs: https://apt.grafana.com
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/grafana.gpg
EOF
  apt-get update -y || true

  wg_up_all
  nft_firewall
  hub_seed
  helper_tools
  telemetry_stack
  control_stack
  desktop_gui

  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Master hub ready."
  systemctl disable bootstrap.service || true
  systemctl daemon-reload || true
  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) & disown
}
main_master
EOS
}

: <<'COMMENT'
MINION POSTINSTALL
------------------
 emit_postinstall_minion <outfile>
   Writes /root/darksite/postinstall-minion.sh for a minion VM.
   Responsibilities:
     - Base OS + admin user + guest agent.
     - Discover hub.env (multiple candidate paths) and assert required vars.
     - Generate wg0..wg3 keys/configs:
         * wg0 peers the hub (allowed-ips = WG_ALLOWED_CIDR).
         * wg1..wg3 local addresses only; peers added by hub during enroll.
     - Auto-enrollment:
         Calls wg-add-peer on the hub for each interface if ENROLL_ENABLED.
     - nftables baseline, node_exporter bound to wg1, Salt minion to wg0 hub.
     - Register into master (Ansible inventory + Prometheus file_sd).
     - Storage profile (ZFS/iSCSI) if group == storage.
     - Final: disable bootstrap, power off.

Security:
   - No password auth; ListenAddress binds to wg0 IP; 'AllowUsers $ADMIN_USER'.
COMMENT

emit_postinstall_minion() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
ADMIN_USER="${ADMIN_USER:-todd}"
MY_GROUP="${MY_GROUP:-prom}"

WG0_WANTED="${WG0_WANTED:-10.77.0.2/32}"
WG1_WANTED="${WG1_WANTED:-10.78.0.2/32}"
WG2_WANTED="${WG2_WANTED:-10.79.0.2/32}"
WG3_WANTED="${WG3_WANTED:-10.80.0.2/32}"

LOG="/var/log/minion-postinstall.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

HUB_ENV_CANDIDATES=(/root/cluster-seed/hub.env /srv/wg/hub.env /root/darksite/cluster-seed/hub.env)

ensure_base(){
  export DEBIAN_FRONTEND=noninteractive
  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF
  apt-get update -y || true
  apt-get install -y --no-install-recommends \
    sudo openssh-server curl wget ca-certificates gnupg jq unzip xxd tar \
    iproute2 iputils-ping ethtool tcpdump net-tools \
    wireguard wireguard-tools nftables vim \
    prometheus-node-exporter chrony rsyslog qemu-guest-agent || true
  systemctl enable --now ssh chrony rsyslog qemu-guest-agent || true
}

ensure_admin_user(){
  local SEED="/root/darksite/authorized_keys.${ADMIN_USER}"
  local PUB=""; [[ -s "$SEED" ]] && PUB="$(head -n1 "$SEED")"
  id -u "${ADMIN_USER}" >/dev/null 2>&1 || useradd -m -s /bin/bash "${ADMIN_USER}"
  install -d -m700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  touch "/home/${ADMIN_USER}/.ssh/authorized_keys"
  [[ -n "$PUB" ]] && grep -qxF "$PUB" "/home/${ADMIN_USER}/.ssh/authorized_keys" || { [[ -n "$PUB" ]] && echo "$PUB" >> "/home/${ADMIN_USER}/.ssh/authorized_keys"; }
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.ssh"
  chmod 600 "/home/${ADMIN_USER}/.ssh/authorized_keys"
}

read_hub(){
  for F in "${HUB_ENV_CANDIDATES[@]}"; do [[ -r "$F" ]] && . "$F"; done
  : "${HUB_LAN:?missing HUB_LAN in hub.env}"
  : "${WG0_PUB:=}"
  : "${WG0_PORT:?missing WG0_PORT in hub.env}"
  : "${WG_ALLOWED_CIDR:?missing WG_ALLOWED_CIDR in hub.env}"
}

wg_setup_all(){
  install -d -m700 /etc/wireguard
  umask 077
  for IFN in wg0 wg1 wg2 wg3; do
    [[ -f /etc/wireguard/${IFN}.key ]] || wg genkey | tee /etc/wireguard/${IFN}.key | wg pubkey >/etc/wireguard/${IFN}.pub
  done
  # wg0 peers the hub (control plane)
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${WG0_WANTED}
PrivateKey = $(cat /etc/wireguard/wg0.key)
ListenPort = 0
DNS = 1.1.1.1
MTU = 1420
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
MTU = 1420
EOF
  done
  chmod 600 /etc/wireguard/*.conf
  systemctl enable --now wg-quick@wg0 || true
  for ifn in wg1 wg2 wg3; do systemctl enable --now "wg-quick@${ifn}" || true; done

  install -d -m755 /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
ListenAddress $(echo "${WG0_WANTED}" | cut -d/ -f1)
EOF
  cat >/etc/ssh/sshd_config.d/99-hard.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowTcpForwarding no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${ADMIN_USER}
EOF
  install -d -m755 /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  (sshd -t && systemctl daemon-reload && systemctl restart ssh) || true
}

auto_enroll_with_hub(){
  log "Auto-enrolling this node on hub (wg0..wg3)..."
  local SSHOPTS="-o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=6"
  local ifn wanted pub ok any_ok=0
  for ifn in wg0 wg1 wg2 wg3; do
    case "$ifn" in
      wg0) wanted="${WG0_WANTED:-}";; wg1) wanted="${WG1_WANTED:-}";;
      wg2) wanted="${WG2_WANTED:-}";; wg3) wanted="${WG3_WANTED:-}";;
    esac
    pub="$(cat "/etc/wireguard/${ifn}.pub" 2>/dev/null || true)"
    if [[ -z "$pub" || -z "$wanted" ]]; then log "[WARN] skip ${ifn}: missing pubkey/wanted"; continue; fi
    ok=0
    for u in "${ADMIN_USER}" root; do
      if ssh $SSHOPTS "$u@${HUB_LAN}" "sudo /usr/local/sbin/wg-add-peer '$pub' '$wanted' '$ifn'" 2>/dev/null; then ok=1; break; fi
    done
    [[ "$ok" -eq 1 ]] && { log "[OK] enrolled ${ifn} (${wanted})"; any_ok=1; } || log "[WARN] ${ifn} enrollment failed"
  done
  [[ "$any_ok" -eq 1 ]] || log "[WARN] No interfaces enrolled; continuing"
}

nft_min(){
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
    iifname "wg1" accept
    iifname "wg2" accept
    iifname "wg3" accept
    udp dport { 51820,51821,51822,51823 } accept
  }
  chain output  { type filter hook output  priority 0; policy accept; }
  chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }
}
EOF
  nft -f /etc/nftables.conf
  systemctl enable --now nftables
}

install_salt_minion(){
  install -d -m0755 /etc/apt/keyrings
  curl -fsSL https://packages.broadcom.com/artifactory/api/security/keypair/SaltProjectKey/public -o /etc/apt/keyrings/salt-archive-keyring.pgp || true
  chmod 0644 /etc/apt/keyrings/salt-archive-keyring.pgp || true
  gpg --dearmor </etc/apt/keyrings/salt-archive-keyring.pgp >/etc/apt/keyrings/salt-archive-keyring.gpg 2>/dev/null || true
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
  apt-get install -y salt-minion salt-common || true

  local hub_ip; hub_ip="$(echo "${WG0_WANTED}" | cut -d/ -f1)"; hub_ip="${hub_ip%.*}.1"
  mkdir -p /etc/salt/minion.d
  cat >/etc/salt/minion.d/master.conf <<EOF
master: ${hub_ip}
ipv6: False
source_interface_name: wg0
EOF
  install -d -m0755 /etc/systemd/system/salt-minion.service.d
  cat >/etc/systemd/system/salt-minion.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now salt-minion || true
}

bind_node_exporter(){
  local ip; ip="$(ip -4 addr show dev wg1 | awk '/inet /{print $2}' | cut -d/ -f1)"
  install -d -m755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=${ip}:9100 --web.disable-exporter-metrics
EOF
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF
  systemctl daemon-reload
  systemctl enable --now prometheus-node-exporter || true
}

register_with_master(){
  local ip host
  ip="$(ip -4 addr show dev wg1 | awk '/inet /{print $2}' | cut -d/ -f1)"
  host="$(hostname -s)"
  ssh -q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "${ADMIN_USER}@${HUB_LAN}" \
    "sudo /usr/local/sbin/register-minion '${MY_GROUP}' '${host}' '${ip}'" \
    || ssh -q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null root@"${HUB_LAN}" \
    "/usr/local/sbin/register-minion '${MY_GROUP}' '${host}' '${ip}'" || true
}

maybe_storage_bits(){
  if [[ "${MY_GROUP}" == "storage" ]]; then
    apt-get install -y zfsutils-linux targetcli-fb || true
    modprobe zfs 2>/dev/null || true
  fi
}

main(){
  log "BEGIN postinstall (minion)"
  ensure_base
  ensure_admin_user
  read_hub
  wg_setup_all
  auto_enroll_with_hub
  nft_min
  bind_node_exporter
  install_salt_minion
  register_with_master
  maybe_storage_bits
  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true
  log "minion ready."
  systemctl disable bootstrap.service || true
  systemctl daemon-reload || true
  log "Powering off in 2s..."
  (sleep 2; systemctl --no-block poweroff) &
}
main
EOS
}

: <<'COMMENT'
MINION WRAPPER EMITTER
----------------------
 emit_minion_wrapper <outfile> <group> <wg0/32> <wg1/32> <wg2/32> <wg3/32>
   - Embeds hub.env captured from the master into the ISO's darksite seed.
   - Persists wanted WG addresses and group into /etc/environment.d.
   - Drops the minion postinstall script and executes it immediately during
     first boot (via darksite bootstrap).

Rationale:
   Decouples the master build from minion specifics while avoiding race
   conditions (hub.env fetch) and preventing cross-plane address drift.
COMMENT

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

: <<'COMMENT'
MASTER ENROLLMENT SEED
----------------------
ensure_master_enrollment_seed <vmid>
   - Via QGA, ensures /srv/wg/hub.env exists (with defaults) and opens the
     enrollment flag ENROLL_ENABLED before minions boot.
   - Protects against races where hub.env is not yet persisted on disk.
COMMENT


ensure_master_enrollment_seed() {
  local vmid="$1"
  pmx_guest_exec "$vmid" /bin/bash -lc "$(cat <<'EOS'
set -euo pipefail
# Pull in any provision variables if present
. /etc/environment.d/99-provision.conf 2>/dev/null || true

mkdir -p /srv/wg
# Create hub.env if missing (include current env defaults)
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

# Ensure enrollment flag exists (open)
: > /srv/wg/ENROLL_ENABLED
EOS
)"
}

: <<'COMMENT'
PROXMOX CLUSTER FLOW
--------------------
 proxmox_cluster()
   1) Build master ISO with postinstall payload, deploy VM, let installer power
      off, reboot from disk for postinstall, then wait for clean shutdown.
   2) Start master, wait for QGA, seed hub.env + ENROLL_ENABLED.
   3) Fetch hub.env (QGA cat preferred, SSH fallback).
   4) Build and deploy minions (prom, graf, k8s, storage), each with wrapper:
        - static LAN IPs, WG wanted /32’s, group tags.
        - waits for installer shutdown, boots from disk.
   5) Close WireGuard enrollment window on the master.

Exit Conditions:
   - Any fatal error aborts with non-zero exit code (controller side).
   - Timeouts are generous; adjust to your infra speed profile.
COMMENT

proxmox_cluster() {
  # --- Build & deploy master ---
  log "Emitting postinstall-master.sh"
  MASTER_PAYLOAD="$(mktemp)"
  emit_postinstall_master "$MASTER_PAYLOAD"

  MASTER_ISO="$BUILD_ROOT/master.iso"
  mk_iso "master" "$MASTER_PAYLOAD" "$MASTER_ISO" "$MASTER_LAN"
  pmx_deploy "$MASTER_ID" "$MASTER_NAME" "$MASTER_ISO" "$MASTER_MEM" "$MASTER_CORES" "$MASTER_DISK_GB"

  # 1) Wait installer shutdown
  wait_poweroff "$MASTER_ID" 1800
  # 2) Boot from disk (bootstrap runs, powers off)
  boot_from_disk "$MASTER_ID"
  wait_poweroff "$MASTER_ID" 2400
  # 3) Bring it up normally
  pmx "qm start $MASTER_ID"
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900

  # Ensure hub env + enroll flag exist (avoid race), then fetch hub.env
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

  # Ensure enrollment flag ON
  pmx_guest_exec "$MASTER_ID" /bin/bash -lc ": >/srv/wg/ENROLL_ENABLED" || \
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment on || true' || \
    sssh root@"$MASTER_LAN" 'wg-enrollment on || true' || true

  # --- Build & deploy minions ---
  # PROM
  PROM_PAYLOAD="$(mktemp)"; emit_minion_wrapper "$PROM_PAYLOAD" "prom" "$PROM_WG0" "$PROM_WG1" "$PROM_WG2" "$PROM_WG3"
  PROM_ISO="$BUILD_ROOT/prom.iso"
  mk_iso "$PROM_NAME" "$PROM_PAYLOAD" "$PROM_ISO" "$PROM_IP"
  pmx_deploy "$PROM_ID" "$PROM_NAME" "$PROM_ISO" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$PROM_ID" 2400
  pmx "qm set $PROM_ID --delete ide2; qm set $PROM_ID --boot order=scsi0; qm start $PROM_ID"
  pmx_wait_for_state "$PROM_ID" "running" 600

  # GRAF
  GRAF_PAYLOAD="$(mktemp)"; emit_minion_wrapper "$GRAF_PAYLOAD" "graf" "$GRAF_WG0" "$GRAF_WG1" "$GRAF_WG2" "$GRAF_WG3"
  GRAF_ISO="$BUILD_ROOT/graf.iso"
  mk_iso "$GRAF_NAME" "$GRAF_PAYLOAD" "$GRAF_ISO" "$GRAF_IP"
  pmx_deploy "$GRAF_ID" "$GRAF_NAME" "$GRAF_ISO" "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$GRAF_ID" 2400
  pmx "qm set $GRAF_ID --delete ide2; qm set $GRAF_ID --boot order=scsi0; qm start $GRAF_ID"
  pmx_wait_for_state "$GRAF_ID" "running" 600

  # K8S
  K8S_PAYLOAD="$(mktemp)"; emit_minion_wrapper "$K8S_PAYLOAD" "k8s" "$K8S_WG0" "$K8S_WG1" "$K8S_WG2" "$K8S_WG3"
  K8S_ISO="$BUILD_ROOT/k8s.iso"
  mk_iso "$K8S_NAME" "$K8S_PAYLOAD" "$K8S_ISO" "$K8S_IP"
  pmx_deploy "$K8S_ID" "$K8S_NAME" "$K8S_ISO" "$K8S_MEM" "$MINION_CORES" "$MINION_DISK_GB"
  wait_poweroff "$K8S_ID" 2400
  pmx "qm set $K8S_ID --delete ide2; qm set $K8S_ID --boot order=scsi0; qm start $K8S_ID"
  pmx_wait_for_state "$K8S_ID" "running" 600

  # STORAGE
  STOR_PAYLOAD="$(mktemp)"; emit_minion_wrapper "$STOR_PAYLOAD" "storage" "$STOR_WG0" "$STOR_WG1" "$STOR_WG2" "$STOR_WG3"
  STOR_ISO="$BUILD_ROOT/storage.iso"
  mk_iso "$STOR_NAME" "$STOR_PAYLOAD" "$STOR_ISO" "$STOR_IP"
  pmx_deploy "$STOR_ID" "$STOR_NAME" "$STOR_ISO" "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"
  wait_poweroff "$STOR_ID" 2400
  pmx "qm set $STOR_ID --delete ide2; qm set $STOR_ID --boot order=scsi0; qm start $STOR_ID"
  pmx_wait_for_state "$STOR_ID" "running" 600

  # Close enrollment
  log "Closing WireGuard enrollment on master..."
  pmx_guest_exec "$MASTER_ID" /bin/bash -lc "rm -f /srv/wg/ENROLL_ENABLED" || \
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment off || true' || \
    sssh root@"$MASTER_LAN" 'wg-enrollment off || true' || true

  log "Done. Master + minions deployed; wg0..wg3 up; SSH/Salt/Ansible(+Semaphore*) on wg0; Prom/Grafana+exporters on wg1; wg2 for k8s; wg3 for storage."
}

: <<'COMMENT'
AWS DARKSITE PREPARATION (SHARED)
---------------------------------
prepare_darksite_generic()
   - Constructs a generic darksite payload with postinstall + bootstrap.service
     and a small /etc/environment.d seed (DOMAIN, USE_CLOUD_INIT, PROFILE).
   - Used by both aws-ami and firecracker flows to centralize guest setup.

AWS HELPERS
-----------
 aws_cli(): region/profile wrapper around 'aws' CLI.
 resolve_debian13_ami(<arch>): queries owner 136693071363 for latest Debian 13.
 wait_for_ssh(<host> <user> [pem] [timeout]): poll for SSH reachability.

AWS AMI BAKE / RUN
------------------
 aws_bake_ami():
   - Resolves base Debian 13 AMI (or uses AWS_BASE_AMI), brings up a "builder"
     instance, ships darksite, triggers bootstrap (which powers off), snapshots
     to a named AMI, and terminates the builder.
   - Security group/ingress is created as needed; SSH ingress is optional and
     can be auto-scoped to the controller’s public /32.

aws_run_from_ami():
   - Launches an instance from AWS_AMI_ID into default VPC/subnet unless
     AWS_SUBNET_ID provided. Optional public IP association and keypair import.
COMMENT

prepare_darksite_generic() {
  local BUILD_DIR="${BUILD_DIR:-/root/build}"
  local CUSTOM_DIR="$BUILD_DIR/custom"
  local DARKSITE_DIR="$CUSTOM_DIR/darksite"
  local INSTALL_PROFILE="${INSTALL_PROFILE:-server}"
  local USE_CLOUD_INIT="${USE_CLOUD_INIT:-true}"

  rm -rf "$BUILD_DIR" 2>/dev/null || true
  mkdir -p "$CUSTOM_DIR" "$DARKSITE_DIR" /mnt/build || true

  cat > "$DARKSITE_DIR/postinstall.sh" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/postinstall.log"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[POST] $(date '+%F %T') - $*"; }
[ -f /etc/environment.d/99-provision.conf ] && . /etc/environment.d/99-provision.conf
: "${DOMAIN:=localdomain}"
: "${USE_CLOUD_INIT:=false}"
: "${INSTALL_PROFILE:=server}"
wait_for_network(){ for i in {1..60}; do ip route show default &>/dev/null && ping -c1 -W1 1.1.1.1 &>/dev/null && return 0; sleep 2; done; }
update_and_upgrade(){ export DEBIAN_FRONTEND=noninteractive; apt-get update -y || true; apt-get -y upgrade || true; }
install_base_packages(){ apt-get install -y --no-install-recommends \
  dbus polkitd pkexec curl wget ca-certificates gnupg lsb-release unzip \
  net-tools traceroute tcpdump sysstat strace lsof rsync rsyslog cron chrony \
  sudo git ethtool jq qemu-guest-agent openssh-server ngrep nmap tmux htop; \
  systemctl enable qemu-guest-agent rsyslog ssh chrony || true; }
maybe_install_desktop(){
  case "${INSTALL_PROFILE}" in
    gnome-min) apt-get install -y --no-install-recommends gnome-core gdm3 gnome-terminal network-manager; systemctl enable --now NetworkManager gdm3 || true;;
    gnome-full) apt-get install -y task-gnome-desktop;;
    xfce-min) apt-get install -y --no-install-recommends xfce4 xfce4-terminal lightdm xorg network-manager; systemctl enable --now NetworkManager lightdm || true;;
    kde-min) apt-get install -y --no-install-recommends plasma-desktop sddm plasma-workspace-wayland kwin-wayland konsole network-manager; systemctl enable --now NetworkManager sddm || true;;
    *) ;;
  esac
}
configure_ssh_basics(){
  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/99-custom.conf <<EOF
Port 22
Protocol 2
PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF
  chmod 600 /etc/ssh/sshd_config.d/99-custom.conf
  systemctl restart ssh || true
}
configure_hostname(){
  VM="$(hostname --short)"; FQDN="${VM}.${DOMAIN}"
  hostnamectl set-hostname "$FQDN"
  cat >/etc/hosts <<EOF
127.0.0.1 localhost
127.0.1.1 ${FQDN} ${VM}
EOF
}
install_custom_scripts(){
  if [[ -d /root/darksite/scripts ]] && compgen -G "/root/darksite/scripts/*" >/dev/null; then
    cp -a /root/darksite/scripts/* /usr/local/bin/
    chmod +x /usr/local/bin/* || true
  fi
}
final_cleanup(){ apt-get autoremove -y || true; apt-get clean || true; find /var/log -type f -exec truncate -s 0 {} \; || true; }
log "BEGIN postinstall"
wait_for_network; update_and_upgrade; install_base_packages; maybe_install_desktop; configure_ssh_basics; configure_hostname; install_custom_scripts; final_cleanup
systemctl disable bootstrap.service || true; rm -f /etc/systemd/system/bootstrap.service; systemctl daemon-reload || true
log "Postinstall complete. Powering off..."
/sbin/poweroff -f
EOS
  chmod +x "$DARKSITE_DIR/postinstall.sh"

  cat > "$DARKSITE_DIR/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (One-time)
After=network.target
Wants=network.target
ConditionPathExists=/root/darksite/postinstall.sh
[Service]
Type=oneshot
ExecStart=/bin/bash -lc '/root/darksite/postinstall.sh'
TimeoutStartSec=0
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
EOF

  mkdir -p "$DARKSITE_DIR"
  mkdir -p /etc/environment.d || true
  cat > "$DARKSITE_DIR/99-provision.conf" <<EOF
DOMAIN=$DOMAIN
USE_CLOUD_INIT=${USE_CLOUD_INIT:-true}
INSTALL_PROFILE=${INSTALL_PROFILE:-server}
EOF
}

# -------- AWS knobs & helpers --------
AWS_REGION="${AWS_REGION:-ca-central-1}"
AWS_PROFILE="${AWS_PROFILE:-}"
AWS_INSTANCE_NAME="${AWS_INSTANCE_NAME:-k8s-node}"
AWS_INSTANCE_TYPE="${AWS_INSTANCE_TYPE:-t2.micro}"
AWS_SUBNET_ID="${AWS_SUBNET_ID:-}"
AWS_ASSOC_PUBLIC_IP="${AWS_ASSOC_PUBLIC_IP:-auto}" # auto|true|false
AWS_SG_NAME="${AWS_SG_NAME:-${AWS_INSTANCE_NAME}-sg}"
AWS_ENABLE_SSH="${AWS_ENABLE_SSH:-true}"
AWS_SSH_CIDR="${AWS_SSH_CIDR:-}"
AWS_KEY_NAME="${AWS_KEY_NAME:-${AWS_INSTANCE_NAME}-key}"
AWS_PUBLIC_KEY_PATH="${AWS_PUBLIC_KEY_PATH:-}"
AWS_SAVE_PEM="${AWS_SAVE_PEM:-${AWS_KEY_NAME}.pem}"
AWS_SSH_USER="${AWS_SSH_USER:-admin}"
AWS_EXTRA_TAGS="${AWS_EXTRA_TAGS:-Owner=ops,Env=dev}"
AWS_BASE_AMI="${AWS_BASE_AMI:-}"
AWS_AMI_ID="${AWS_AMI_ID:-}"
AWS_ARCH="${AWS_ARCH:-x86_64}"

aws_cli(){ if [[ -n "${AWS_PROFILE:-}" ]]; then aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"; else aws --region "$AWS_REGION" "$@"; fi }
resolve_debian13_ami(){
  local arch="${1:-x86_64}"
  local name_filter; if [[ "$arch" == "arm64" ]]; then name_filter="debian-13-arm64-*"; else name_filter="debian-13-amd64-*"; fi
  aws_cli ec2 describe-images \
    --owners 136693071363 \
    --filters "Name=name,Values=${name_filter}" "Name=architecture,Values=${arch}" \
              "Name=virtualization-type,Values=hvm" "Name=root-device-type,Values=ebs" \
    --query 'reverse(sort_by(Images,&CreationDate))[0].ImageId' --output text
}
wait_for_ssh(){ local host="$1" user="$2" key="${3:-}" timeout="${4:-600}" start; start=$(date +%s)
  while :; do
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new ${key:+-i "$key"} "$user@$host" "true" 2>/dev/null; then return 0; fi
    (( $(date +%s)-start > timeout )) && return 1
    sleep 5
  done
}

aws_bake_ami(){
  local BUILD_DIR="${BUILD_DIR:-/root/build}"
  local DARKSITE_DIR="$BUILD_DIR/custom/darksite"
  prepare_darksite_generic
  [[ -z "$AWS_BASE_AMI" || "$AWS_BASE_AMI" == "auto" ]] && AWS_BASE_AMI="$(resolve_debian13_ami "$AWS_ARCH")"
  [[ -n "$AWS_BASE_AMI" && "$AWS_BASE_AMI" != "None" ]] || die "Could not resolve Debian 13 AMI."

  aws_cli sts get-caller-identity >/dev/null || die "AWS auth failed."
  vpc_id="$(aws_cli ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  [[ -n "$AWS_SUBNET_ID" ]] || AWS_SUBNET_ID="$(aws_cli ec2 describe-subnets --filters Name=vpc-id,Values="$vpc_id" --query 'Subnets[0].SubnetId' --output text)"

  sg_id="$(aws_cli ec2 describe-security-groups --filters Name=group-name,Values="$AWS_SG_NAME" Name=vpc-id,Values="$vpc_id" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
  if [[ -z "$sg_id" || "$sg_id" == "None" ]]; then
    sg_id="$(aws_cli ec2 create-security-group --vpc-id "$vpc_id" --group-name "$AWS_SG_NAME" --description "SG for $AWS_INSTANCE_NAME" --query 'GroupId' --output text)"
  fi
  myip="$(curl -fsSL https://checkip.amazonaws.com || true)"; myip="${myip//$'\n'/}"
  if [[ "$AWS_ENABLE_SSH" == "true" ]]; then
    cidr="${AWS_SSH_CIDR:-${myip:+${myip}/32}}"
    [[ -n "$cidr" ]] && aws_cli ec2 authorize-security-group-ingress --group-id "$sg_id" \
      --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=\"${cidr}\"}]" >/dev/null 2>&1 || true
  fi

  if [[ -n "$AWS_PUBLIC_KEY_PATH" && -r "$AWS_PUBLIC_KEY_PATH" ]]; then
    exists="$(aws_cli ec2 describe-key-pairs --key-names "$AWS_KEY_NAME" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null || true)"
    [[ "$exists" == "$AWS_KEY_NAME" ]] || aws_cli ec2 import-key-pair --key-name "$AWS_KEY_NAME" --public-key-material "fileb://$AWS_PUBLIC_KEY_PATH" >/dev/null
    PEM_PATH=""
  else
    exists="$(aws_cli ec2 describe-key-pairs --key-names "$AWS_KEY_NAME" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null || true)"
    if [[ "$exists" != "$AWS_KEY_NAME" ]]; then
      aws_cli ec2 create-key-pair --key-name "$AWS_KEY_NAME" --key-type rsa --key-format pem --query 'KeyMaterial' --output text > "$AWS_SAVE_PEM"
      chmod 600 "$AWS_SAVE_PEM"; PEM_PATH="$AWS_SAVE_PEM"
    else PEM_PATH=""; fi
  fi

  if [[ "$AWS_ASSOC_PUBLIC_IP" == "true" ]]; then
    ni="[{\"DeviceIndex\":0,\"SubnetId\":\"${AWS_SUBNET_ID}\",\"Groups\":[\"${sg_id}\"],\"AssociatePublicIpAddress\":true}]"
  elif [[ "$AWS_ASSOC_PUBLIC_IP" == "false" ]]; then
    ni="[{\"DeviceIndex\":0,\"SubnetId\":\"${AWS_SUBNET_ID}\",\"Groups\":[\"${sg_id}\"],\"AssociatePublicIpAddress\":false}]"
  else
    ni="[{\"DeviceIndex\":0,\"SubnetId\":\"${AWS_SUBNET_ID}\",\"Groups\":[\"${sg_id}\"]}]"
  fi

  log "Launching builder from $AWS_BASE_AMI..."
  tags="ResourceType=instance,Tags=[{Key=Name,Value=${AWS_INSTANCE_NAME}-builder},{Key=Owner,Value=ops},{Key=Env,Value=dev}]"
  iid="$(aws_cli ec2 run-instances --image-id "$AWS_BASE_AMI" --instance-type "$AWS_INSTANCE_TYPE" --key-name "$AWS_KEY_NAME" --network-interfaces "$ni" --tag-specifications "$tags" --query 'Instances[0].InstanceId' --output text)"
  [[ -n "$iid" && "$iid" != "None" ]] || die "run-instances failed."
  aws_cli ec2 wait instance-running --instance-ids "$iid"
  pub_ip="$(aws_cli ec2 describe-instances --instance-ids "$iid" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  log "Builder instance: $iid  PublicIP=$pub_ip"

  log "Waiting for SSH..."
  wait_for_ssh "$pub_ip" "$AWS_SSH_USER" "${PEM_PATH:-}" 900 || die "SSH not reachable."

  log "Copying darksite..."
  scp -r -o StrictHostKeyChecking=accept-new ${PEM_PATH:+-i "$PEM_PATH"} "$DARKSITE_DIR" "$AWS_SSH_USER@$pub_ip:/home/$AWS_SSH_USER/"
  ssh ${PEM_PATH:+-i "$PEM_PATH"} "$AWS_SSH_USER@$pub_ip" "sudo mkdir -p /root/darksite && sudo cp -a /home/$AWS_SSH_USER/darksite/* /root/darksite/ && sudo mkdir -p /etc/environment.d && echo 'DOMAIN=$DOMAIN' | sudo tee /etc/environment.d/99-provision.conf >/dev/null && echo 'USE_CLOUD_INIT=true' | sudo tee -a /etc/environment.d/99-provision.conf >/dev/null && echo 'INSTALL_PROFILE=${INSTALL_PROFILE:-server}' | sudo tee -a /etc/environment.d/99-provision.conf >/dev/null && echo OK"

  log "Activate bootstrap (will power off)..."
  ssh ${PEM_PATH:+-i "$PEM_PATH"} "$AWS_SSH_USER@$pub_ip" "sudo cp /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service && sudo systemctl daemon-reload && sudo systemctl enable --now bootstrap.service || true"

  log "Waiting for builder to stop..."
  aws_cli ec2 wait instance-stopped --instance-ids "$iid"

  ami_name="${AWS_INSTANCE_NAME}-$(date +%Y%m%d-%H%M%S)"
  log "Creating AMI: $ami_name"
  new_ami="$(aws_cli ec2 create-image --instance-id "$iid" --name "$ami_name" --description "Baked by unified deployer" --no-reboot --query 'ImageId' --output text)"
  aws_cli ec2 create-tags --resources "$new_ami" --tags Key=Name,Value="$ami_name" >/dev/null
  log "AMI_ID=$new_ami"

  log "Terminating builder..."
  aws_cli ec2 terminate-instances --instance-ids "$iid" >/dev/null || true

  echo; echo "=== AMI CREATED ==="; echo "AMI_ID: $new_ami"; echo "Name  : $ami_name"
}

aws_run_from_ami(){
  [[ -n "$AWS_AMI_ID" ]] || die "Set AWS_AMI_ID to the AMI you want to launch."
  aws_cli sts get-caller-identity >/dev/null || die "AWS auth failed."

  vpc_id="$(aws_cli ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
  [[ -n "$AWS_SUBNET_ID" ]] || AWS_SUBNET_ID="$(aws_cli ec2 describe-subnets --filters Name=vpc-id,Values="$vpc_id" --query 'Subnets[0].SubnetId' --output text)"

  sg_id="$(aws_cli ec2 describe-security-groups --filters Name=group-name,Values="$AWS_SG_NAME" Name=vpc-id,Values="$vpc_id" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)"
  if [[ -z "$sg_id" || "$sg_id" == "None" ]]; then
    sg_id="$(aws_cli ec2 create-security-group --vpc-id "$vpc_id" --group-name "$AWS_SG_NAME" --description "SG for $AWS_INSTANCE_NAME" --query 'GroupId' --output text)"
  fi
  myip="$(curl -fsSL https://checkip.amazonaws.com || true)"; myip="${myip//$'\n'/}"
  if [[ "$AWS_ENABLE_SSH" == "true" ]]; then
    cidr="${AWS_SSH_CIDR:-${myip:+${myip}/32}}"
    [[ -n "$cidr" ]] && aws_cli ec2 authorize-security-group-ingress --group-id "$sg_id" \
      --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=\"${cidr}\"}]" >/dev/null 2>&1 || true
  fi

  if [[ -n "$AWS_PUBLIC_KEY_PATH" && -r "$AWS_PUBLIC_KEY_PATH" ]]; then
    exists="$(aws_cli ec2 describe-key-pairs --key-names "$AWS_KEY_NAME" --query 'KeyPairs[0].KeyName' --output text 2>/dev/null || true)"
    [[ "$exists" == "$AWS_KEY_NAME" ]] || aws_cli ec2 import-key-pair --key-name "$AWS_KEY_NAME" --public-key-material "fileb://$AWS_PUBLIC_KEY_PATH" >/dev/null
  fi

  if [[ "$AWS_ASSOC_PUBLIC_IP" == "true" ]]; then
    ni="[{\"DeviceIndex\":0,\"SubnetId\":\"${AWS_SUBNET_ID}\",\"Groups\":[\"${sg_id}\"],\"AssociatePublicIpAddress\":true}]"
  elif [[ "$AWS_ASSOC_PUBLIC_IP" == "false" ]]; then
    ni="[{\"DeviceIndex\":0,\"SubnetId\":\"${AWS_SUBNET_ID}\",\"Groups\":[\"${sg_id}\"],\"AssociatePublicIpAddress\":false}]"
  else
    ni="[{\"DeviceIndex\":0,\"SubnetId\":\"${AWS_SUBNET_ID}\",\"Groups\":[\"${sg_id}\"]}]"
  fi

  tags="ResourceType=instance,Tags=[{Key=Name,Value=${AWS_INSTANCE_NAME}},{Key=Owner,Value=ops},{Key=Env,Value=dev}]"
  iid="$(aws_cli ec2 run-instances --image-id "$AWS_AMI_ID" --instance-type "$AWS_INSTANCE_TYPE" --key-name "$AWS_KEY_NAME" --network-interfaces "$ni" --tag-specifications "$tags" --query 'Instances[0].InstanceId' --output text)"
  [[ -n "$iid" && "$iid" != "None" ]] || die "run-instances failed."
  aws_cli ec2 wait instance-running --instance-ids "$iid"
  pub_ip="$(aws_cli ec2 describe-instances --instance-ids "$iid" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  log "Launched: $iid  PublicIP=$pub_ip"
}

: <<'COMMENT'
FIRECRACKER FLOW
----------------
 firecracker_flow()
   - Debootstrap minimal Debian rootfs into $FC_ROOTFS_DIR.
   - Inject darksite (postinstall + env), enable systemd-networkd (static IP),
     and first-boot service to run postinstall once inside the micro-VM.
   - Assemble ext4 image, pick a vmlinux, generate Firecracker config JSON,
     emit a runnable wrapper (run-fc.sh) that creates a TAP iface and
     configures simple NAT via nftables.

Outputs:
   $FC_OUTPUT_VMLINUX, $FC_IMG (ext4), $FC_CONFIG_JSON, $FC_RUN_SCRIPT

Notes:
   - TAP provisioning assumes host has CAP_NET_ADMIN; NAT is best-effort.
   - Seccomp disabled by default (--seccomp-level=0) for bootstrap convenience.
COMMENT

firecracker_flow(){
  local BUILD_DIR="${BUILD_DIR:-/root/build}"
  local FC_ROOTFS_DIR="${FC_ROOTFS_DIR:-$BUILD_DIR/fcroot}"
  local FC_IMG="${FC_IMG:-$BUILD_DIR/rootfs.ext4}"
  local FC_IMG_SIZE_MB="${FC_IMG_SIZE_MB:-2048}"
  local FC_VMLINUX_PATH="${FC_VMLINUX_PATH:-/boot/vmlinux-$(uname -r)}"
  local FC_OUTPUT_VMLINUX="${FC_OUTPUT_VMLINUX:-$BUILD_DIR/vmlinux}"
  local FC_RUN_SCRIPT="${FC_RUN_SCRIPT:-$BUILD_DIR/run-fc.sh}"
  local FC_CONFIG_JSON="${FC_CONFIG_JSON:-$BUILD_DIR/fc.json}"
  local FC_TAP_IF="${FC_TAP_IF:-fc-tap0}"
  local FC_GUEST_IP="${FC_GUEST_IP:-172.20.0.2/24}"
  local FC_GW_IP="${FC_GW_IP:-172.20.0.1}"
  local FC_VCPUS="${FC_VCPUS:-2}"
  local FC_MEM_MB="${FC_MEM_MB:-2048}"

  prepare_darksite_generic

  log "Building Firecracker rootfs (Debian minimal)..."
  rm -rf "$FC_ROOTFS_DIR"; mkdir -p "$FC_ROOTFS_DIR"
  debootstrap --variant=minbase trixie "$FC_ROOTFS_DIR" http://deb.debian.org/debian
  cp -a "$BUILD_DIR/custom/darksite" "$FC_ROOTFS_DIR/root/darksite"
  mkdir -p "$FC_ROOTFS_DIR/etc/environment.d"
  cp -a "$BUILD_DIR/custom/darksite/99-provision.conf" "$FC_ROOTFS_DIR/etc/environment.d/99-provision.conf"

  chroot "$FC_ROOTFS_DIR" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends systemd-sysv ca-certificates curl wget iproute2 iputils-ping openssh-server net-tools rsyslog
    systemctl enable ssh rsyslog
    cat >/etc/systemd/system/fc-firstboot.service <<EOF
[Unit]
Description=Firecracker first boot bootstrap
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash -lc "/root/darksite/postinstall.sh || true"
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable fc-firstboot.service
    apt-get install -y --no-install-recommends systemd-networkd
    systemctl enable systemd-networkd
  '

  mkdir -p "$FC_ROOTFS_DIR/etc/systemd/network"
  cat > "$FC_ROOTFS_DIR/etc/systemd/network/10-eth0.network" <<EOF
[Match]
Name=eth0
[Network]
Address=${FC_GUEST_IP}
Gateway=${FC_GW_IP}
DNS=1.1.1.1
EOF

  log "Assembling ext4 image..."
  mkdir -p "$BUILD_DIR/mntimg"
  fallocate -l "${FC_IMG_SIZE_MB}M" "$FC_IMG"
  mkfs.ext4 -F "$FC_IMG"
  mount -o loop "$FC_IMG" "$BUILD_DIR/mntimg"
  rsync -aHAX --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/tmp --exclude=/run "$FC_ROOTFS_DIR"/ "$BUILD_DIR/mntimg"/
  mkdir -p "$BUILD_DIR/mntimg"/{proc,sys,dev,run,tmp}; chmod 1777 "$BUILD_DIR/mntimg/tmp"
  umount "$BUILD_DIR/mntimg"

  if [[ -f "$FC_VMLINUX_PATH" ]]; then cp -f "$FC_VMLINUX_PATH" "$FC_OUTPUT_VMLINUX"
  else vmlin="$(find /boot -maxdepth 1 -type f -name "vmlinux-*" | head -n1 || true)"; [[ -n "$vmlin" ]] && cp -f "$vmlin" "$FC_OUTPUT_VMLINUX" || die "No vmlinux found"; fi

  cat > "$FC_CONFIG_JSON" <<EOF
{
  "boot-source": { "kernel_image_path": "$(realpath "$FC_OUTPUT_VMLINUX")", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off nomodules random.trust_cpu=on" },
  "drives": [ { "drive_id": "rootfs", "path_on_host": "$(realpath "$FC_IMG")", "is_root_device": true, "is_read_only": false } ],
  "network-interfaces": [ { "iface_id": "eth0", "guest_mac": "02:FC:00:00:00:01", "host_dev_name": "${FC_TAP_IF}" } ],
  "machine-config": { "vcpu_count": ${FC_VCPUS}, "mem_size_mib": ${FC_MEM_MB}, "smt": false }
}
EOF

  cat > "$FC_RUN_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
FC_BIN="${FC_BIN:-/usr/local/bin/firecracker}"
CFG="${CFG:-__CFG__}"
TAP="__TAP__"
GW="__GW__"
if ! command -v "$FC_BIN" >/dev/null 2>&1; then echo "firecracker binary not found at $FC_BIN" >&2; exit 1; fi
if ! ip link show "$TAP" >/dev/null 2>&1; then
  sudo ip tuntap add dev "$TAP" mode tap
  sudo ip addr add "$GW" dev "$TAP"
  sudo ip link set "$TAP" up
  if command -v nft >/dev/null 2>&1; then
    sudo nft add table inet fc 2>/dev/null || true
    sudo nft add chain inet fc post { type nat hook postrouting priority 100 \; } 2>/dev/null || true
    sudo nft add rule inet fc post oifname != "$TAP" masquerade 2>/dev/null || true
  fi
fi
exec "$FC_BIN" --no-api --config-file "$CFG" --seccomp-level=0
EOS
  sed -i "s|__CFG__|$(realpath "$FC_CONFIG_JSON")|g" "$FC_RUN_SCRIPT"
  sed -i "s|__TAP__|$FC_TAP_IF|g" "$FC_RUN_SCRIPT"
  sed -i "s|__GW__|$FC_GW_IP|g" "$FC_RUN_SCRIPT"
  chmod +x "$FC_RUN_SCRIPT"

  log "Firecracker outputs:"
  log " - Kernel : $FC_OUTPUT_VMLINUX"
  log " - Rootfs : $FC_IMG"
  log " - Config : $FC_CONFIG_JSON"
  log " - Runner : $FC_RUN_SCRIPT"
}


# MAIN

case "$TARGET" in
  proxmox-cluster) proxmox_cluster ;;
  aws-ami)         aws_bake_ami ;;
  aws-run)         aws_run_from_ami ;;
  firecracker)     firecracker_flow ;;
  *)               die "Unknown TARGET '$TARGET' (use proxmox-cluster | aws-ami | aws-run | firecracker)" ;;
esac
[bpfenv] root@onyx:~/deploy/v5# 
