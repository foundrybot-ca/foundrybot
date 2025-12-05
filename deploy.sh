#!/usr/bin/env bash
#
# Unified Proxmox Deployer (hub + minions + K8s node VMs)
# -------------------------------------------------------#
# Targets:
#   TARGET=proxmox-cluster  → master + prom + graf + k8s-jump + storage
#   TARGET=proxmox-k8s-ha   → only K8s node VMs (requires master already built)
#   TARGET=proxmox-all      → cluster + K8s node VMs
#

set -euo pipefail

# Preseed config
PRESEED_LOCALE="${PRESEED_LOCALE:-en_US.UTF-8}"
PRESEED_KEYMAP="${PRESEED_KEYMAP:-us}"
PRESEED_TIMEZONE="${PRESEED_TIMEZONE:-America/Vancouver}"
PRESEED_MIRROR_COUNTRY="${PRESEED_MIRROR_COUNTRY:-manual}"
PRESEED_MIRROR_HOST="${PRESEED_MIRROR_HOST:-deb.debian.org}"
PRESEED_MIRROR_DIR="${PRESEED_MIRROR_DIR:-/debian}"
PRESEED_HTTP_PROXY="${PRESEED_HTTP_PROXY:-}"
PRESEED_ROOT_PASSWORD="${PRESEED_ROOT_PASSWORD:-root}"
PRESEED_BOOTDEV="${PRESEED_BOOTDEV:-/dev/sda}"
PRESEED_EXTRA_PKGS="${PRESEED_EXTRA_PKGS:-openssh-server}"

TARGET="${TARGET:-proxmox-all}"   # proxmox-all | proxmox-cluster | proxmox-k8s-ha
INPUT="${INPUT:-1}"              # 1|fiend, 2|dragon, 3|lion
DOMAIN="${DOMAIN:-unixbox.net}"

case "$INPUT" in
  1|fiend)  PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.225}" ;;
  2|dragon) PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.226}" ;;
  3|lion)   PROXMOX_HOST="${PROXMOX_HOST:-10.100.10.227}" ;;
  *) echo "[ERROR] Unknown INPUT=$INPUT" >&2; exit 1 ;;
esac

#ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-DVD-1.iso}"
ISO_ORIG="${ISO_ORIG:-/root/debian-13.1.0-amd64-netinst.iso}"
ISO_STORAGE="${ISO_STORAGE:-local}"
VM_STORAGE="${VM_STORAGE:-local-zfs}"

# ===== Master hub VM =====
MASTER_ID="${MASTER_ID:-1000}"
MASTER_NAME="${MASTER_NAME:-master}"
MASTER_LAN="${MASTER_LAN:-10.100.10.124}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

# ===== Existing minion VMs =====
PROM_ID="${PROM_ID:-1001}"; PROM_NAME="${PROM_NAME:-prometheus}"; PROM_IP="${PROM_IP:-10.100.10.123}"
GRAF_ID="${GRAF_ID:-1002}"; GRAF_NAME="${GRAF_NAME:-grafana}"; GRAF_IP="${GRAF_IP:-10.100.10.122}"
K8S_ID="${K8S_ID:-1003}"; K8S_NAME="${K8S_NAME:-k8s}"; K8S_IP="${K8S_IP:-10.100.10.121}"
STOR_ID="${STOR_ID:-1004}"; STOR_NAME="${STOR_NAME:-storage}"; STOR_IP="${STOR_IP:-10.100.10.120}"
K8SLB1_ID="${K8SLB1_ID:-1005}"; K8SLB1_NAME="${K8SLB1_NAME:-k8s-lb1}"; K8SLB1_IP="${K8SLB1_IP:-10.100.10.113}"
K8SLB2_ID="${K8SLB2_ID:-1006}"; K8SLB2_NAME="${K8SLB2_NAME:-k8s-lb2}"; K8SLB2_IP="${K8SLB2_IP:-10.100.10.112}"
K8SCP1_ID="${K8SCP1_ID:-1007}"; K8SCP1_NAME="${K8SCP1_NAME:-k8s-cp1}"; K8SCP1_IP="${K8SCP1_IP:-10.100.10.119}"
K8SCP2_ID="${K8SCP2_ID:-1008}"; K8SCP2_NAME="${K8SCP2_NAME:-k8s-cp2}"; K8SCP2_IP="${K8SCP2_IP:-10.100.10.118}"
K8SCP3_ID="${K8SCP3_ID:-1009}"; K8SCP3_NAME="${K8SCP3_NAME:-k8s-cp3}"; K8SCP3_IP="${K8SCP3_IP:-10.100.10.117}"
K8SW1_ID="${K8SW1_ID:-1010}"; K8SW1_NAME="${K8SW1_NAME:-k8s-w1}"; K8SW1_IP="${K8SW1_IP:-10.100.10.116}"
K8SW2_ID="${K8SW2_ID:-1011}"; K8SW2_NAME="${K8SW2_NAME:-k8s-w2}"; K8SW2_IP="${K8SW2_IP:-10.100.10.115}"
K8SW3_ID="${K8SW3_ID:-1012}"; K8SW3_NAME="${K8SW3_NAME:-k8s-w3}"; K8SW3_IP="${K8SW3_IP:-10.100.10.114}"

# ===== WireGuard planes (master) =====
WG1_IP="${WG1_IP:-10.78.0.1/16}"
WG1_PORT="${WG1_PORT:-51821}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.78.0.0/16}"

# ===== Per-minion WG IPs =====
PROM_WG1="${PROM_WG1:-10.78.0.2/32}"; GRAF_WG1="${GRAF_WG1:-10.78.0.3/32}"; K8S_WG1="${K8S_WG1:-10.78.0.4/32}"
STOR_WG1="${STOR_WG1:-10.78.0.5/32}"; K8SLB1_WG1="${K8SLB1_WG1:-10.78.0.101/32}"; K8SLB2_WG1="${K8SLB2_WG1:-10.78.0.102/32}"
K8SCP1_WG1="${K8SCP1_WG1:-10.78.0.110/32}"; K8SCP2_WG1="${K8SCP2_WG1:-10.78.0.111/32}"; K8SCP3_WG1="${K8SCP3_WG1:-10.78.0.112/32}"
K8SW1_WG1="${K8SW1_WG1:-10.78.0.120/32}"; K8SW2_WG1="${K8SW2_WG1:-10.78.0.121/32}"

# ===== VM sizing =====
MASTER_MEM="${MASTER_MEM:-4096}"; MASTER_CORES="${MASTER_CORES:-4}"; MASTER_DISK_GB="${MASTER_DISK_GB:-40}"
MINION_MEM="${MINION_MEM:-4096}"; MINION_CORES="${MINION_CORES:-4}"; MINION_DISK_GB="${MINION_DISK_GB:-32}"
K8S_MEM="${K8S_MEM:-8192}"
STOR_DISK_GB="${STOR_DISK_GB:-64}"

K8S_LB_MEM="${K8S_LB_MEM:-2048}"; K8S_LB_CORES="${K8S_LB_CORES:-2}"; K8S_LB_DISK_GB="${K8S_LB_DISK_GB:-16}"
K8S_CP_MEM="${K8S_CP_MEM:-8192}"; K8S_CP_CORES="${K8S_CP_CORES:-4}"; K8S_CP_DISK_GB="${K8S_CP_DISK_GB:-50}"
K8S_WK_MEM="${K8S_WK_MEM:-8192}"; K8S_WK_CORES="${K8S_WK_CORES:-4}"; K8S_WK_DISK_GB="${K8S_WK_DISK_GB:-60}"

# ===== Admin / auth =====
ADMIN_USER="${ADMIN_USER:-todd}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-}"
SSH_PUBKEY="${SSH_PUBKEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgqdaF+C41xwLS41+dOTnpsrDTPkAwo4Zejn4tb0lOt todd@onyx.unixbox.net}"               # direct key string
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-${ALLOW_TODD_PASSWORD:-no}}"
GUI_PROFILE="${GUI_PROFILE:-server}"

INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-no}"   # yes|try|no

BUILD_ROOT="${BUILD_ROOT:-/root/builds}"
mkdir -p "$BUILD_ROOT"

# Cluster enrollment SSH keypair (used by minions to reach master for wg-add-peer)
ENROLL_KEY_NAME="${ENROLL_KEY_NAME:-enroll_ed25519}"
ENROLL_KEY_DIR="$BUILD_ROOT/keys"
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

SSH_OPTS="-q -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o CheckHostIP=no -o ConnectTimeout=6 -o BatchMode=yes"
sssh(){ ssh $SSH_OPTS "$@"; }
sscp(){ scp -q $SSH_OPTS "$@"; }

log() { echo "[INFO]  $(date '+%F %T') - $*"; }
warn(){ echo "[WARN]  $(date '+%F %T') - $*" >&2; }
err() { echo "[ERROR] $(date '+%F %T') - $*"; }
die(){ err "$*"; exit 1; }

command -v xorriso >/dev/null || { err "xorriso not installed (needed for ISO build)"; }

# =============================================================================================
# PROXMOX HELPERS
# =============================================================================================

pmx() { sssh root@"$PROXMOX_HOST" "$@"; }

pmx_vm_state() { pmx "qm status $1 2>/dev/null | awk '{print tolower(\$2)}'" || echo "unknown"; }

# -----------------------------------------------------------------------------
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

# =============================================================================================
#
# =============================================================================================
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

# =============================================================================================
#
# =============================================================================================
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

# =============================================================================================
#
# =============================================================================================
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


# =============================================================================================
#
# =============================================================================================

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

# =============================================================================================
#
# =============================================================================================

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

# -----------------------------------------------------------------------------
wait_poweroff() { pmx_wait_for_state "$1" "stopped" "${2:-2400}"; }

# -----------------------------------------------------------------------------
boot_from_disk() {
  local vmid="$1"
  pmx "qm set $vmid --delete ide2; qm set $vmid --boot order=scsi0; qm start $vmid"
  pmx_wait_for_state "$vmid" "running" 600
}

# =========================
# ISO BUILDER (updated for UEFI-only fallback)
# =========================

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
    echo "WG1_PORT=${WG1_PORT}"
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
    cat >>"$cust/isolinux/txt.cfg" <<EOF
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

# =========================
# MASTER POSTINSTALL (simplified: WG backplane + SSH + Salt/Ansible on wg1)
# =========================

emit_postinstall_master() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/postinstall-master.log"
exec > >(tee -a "$LOG") 2>&1
exec 2>&1
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
WG1_IP="${WG1_IP:-10.78.0.1/16}"; WG1_PORT="${WG1_PORT:-51821}"
WG_ALLOWED_CIDR="${WG_ALLOWED_CIDR:-10.77.0.0/16,10.78.0.0/16,10.79.0.0/16,10.80.0.0/16}"
ADMIN_USER="${ADMIN_USER:-todd}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
INSTALL_ANSIBLE="${INSTALL_ANSIBLE:-yes}"
INSTALL_SEMAPHORE="${INSTALL_SEMAPHORE:-try}"   # yes|try|no
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
    iproute2 iputils-ping ethtool tcpdump net-tools \
    nftables wireguard-tools \
    chrony rsyslog qemu-guest-agent vim \
    python3-venv \
    libbpfcc llvm libclang-cpp* python3-bpfcc python3-psutil || true

  echo wireguard >/etc/modules-load.d/wireguard.conf || true
  modprobe wireguard 2>/dev/null || true

  systemctl enable --now qemu-guest-agent chrony rsyslog ssh || true

  cat >/etc/sysctl.d/99-master.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
  sysctl --system || true
}

# -----------------------------------------------------------------------------
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
  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
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

# -----------------------------------------------------------------------------
wg_setup_planes() {
  log "Configuring WireGuard control plane (wg1 only)"

  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077

  [ -f /etc/wireguard/wg1.key ] || wg genkey | tee /etc/wireguard/wg1.key | wg pubkey >/etc/wireguard/wg1.pub

  cat >/etc/wireguard/wg1.conf <<EOF
[Interface]
Address    = ${WG1_IP}
PrivateKey = $(cat /etc/wireguard/wg1.key)
ListenPort = ${WG1_PORT}
MTU        = 1420
EOF

  umask "${_old_umask}"

  # Bring wg1 up now that config exists
  systemctl enable wg-quick@wg1.service
  systemctl restart wg-quick@wg1.service
}

# -----------------------------------------------------------------------------
nft_firewall() {
  # Try to detect the primary LAN interface (fallback to ens18 if we can't)
  local lan_if
  lan_if="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')" || true
  : "${lan_if:=ens18}"

  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Basic sanity
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # SSH
    tcp dport 22 accept

    # Salt master
    tcp dport { 4505, 4506 } accept

    # WireGuard control plane
    udp dport ${WG1_PORT} accept
    iifname "wg1" accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept

    # Allow WG1 <-> LAN
    iifname "wg1" oifname "${lan_if}" accept
    iifname "${lan_if}" oifname "wg1" accept
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

# -----------------------------------------------------------------------------
helper_tools() {
  log "Installing cluster helper tools (wg-sync-from-salt, register-minion)"

  cat >/usr/local/sbin/wg-sync-from-salt <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

IFN="${1:-wg1}"
MASTER_CONF="/etc/wireguard/${IFN}.conf"

command -v salt >/dev/null 2>&1 || {
  echo "[X] salt command not found" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "[X] jq command not found" >&2
  exit 1
}
command -v wg >/dev/null 2>&1 || {
  echo "[X] wg command not found" >&2
  exit 1
}

# Pull role + WireGuard grains from all minions
DATA="$(salt --out=json '*' grains.item role wg1_ip wg1_pubkey 2>/dev/null || true)"

if [[ -z "${DATA}" || "${DATA}" = "{}" ]]; then
  echo "[WARN] No minion WireGuard grains found; nothing to sync"
  exit 0
fi

if [[ ! -s "${MASTER_CONF}" ]]; then
  echo "[X] ${MASTER_CONF} does not exist or is empty; configure master wg1 first" >&2
  exit 1
fi

tmp_conf="$(mktemp)"

# Keep only the [Interface] section from the existing config, drop all old [Peer] entries
awk 'BEGIN{in_peer=0}
     /^\[Peer\]/{in_peer=1}
     !in_peer{print}' "${MASTER_CONF}" > "${tmp_conf}"

echo "" >> "${tmp_conf}"

echo "${DATA}" \
 | jq -r 'to_entries[]
          | select(.value.wg1_pubkey != null and .value.wg1_ip != null and .value.wg1_pubkey != "" and .value.wg1_ip != "")
          | "\(.key) \(.value.role // \"unknown\") \(.value.wg1_ip) \(.value.wg1_pubkey)"' \
 | while read -r minion role ip pub; do
      ip_host="${ip%%/*}"
      [[ -n "${ip_host}" ]] || continue

      cat >> "${tmp_conf}" <<EOP
[Peer]
# ${minion} (${role})
PublicKey  = ${pub}
AllowedIPs = ${ip_host}/32
PersistentKeepalive = 25

EOP
   done

mv "${tmp_conf}" "${MASTER_CONF}"
chmod 600 "${MASTER_CONF}"

# Apply the new configuration to the running interface if it exists
if ip link show "${IFN}" >/dev/null 2>&1; then
  systemctl reload "wg-quick@${IFN}" 2>/dev/null \
    || wg syncconf "${IFN}" <(wg-quick strip "${MASTER_CONF}") \
    || true
fi

echo "[OK] Synced WireGuard peers for ${IFN} from Salt grains"
EOF
  chmod 0755 /usr/local/sbin/wg-sync-from-salt
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

  cat >/etc/salt/master.d/network.conf <<EOF
interface: ${MASTER_LAN}
ipv6: False
publish_port: 4505
ret_port: 4506
EOF

  # For now we keep salt-api without TLS to simplify; harden later.
  cat >/etc/salt/master.d/api.conf <<EOF
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

  install -d -m0755 /srv/pillar /srv/salt/common /srv/salt/roles

  # Minimal cluster pillar: for now just domain + master; can be extended
  cat >/srv/pillar/cluster.sls <<EOF
cluster:
  domain: ${DOMAIN}
  master:
    id: master
    lan_ip: ${MASTER_LAN}
    wg:
      wg1: ${WG1_IP}
EOF
  log "Seeding /srv/pillar and /srv/salt tree"

  install -d -m0755 /srv/pillar /srv/salt/common /srv/salt/roles

  # --------------------------------------
  # Pillar: top.sls
  # --------------------------------------
  cat >/srv/pillar/top.sls <<'EOF'
base:
  '*':
    - cluster
EOF

  # --------------------------------------
  # Pillar: cluster.sls
  # (uses ${DOMAIN} from deploy.sh)
  # --------------------------------------
  cat >/srv/pillar/cluster.sls <<EOF
cluster:
  domain: ${DOMAIN}

  grafana:
    host: grafana.${DOMAIN}

  prometheus:
    host: prometheus.${DOMAIN}

  k8s:
    api_vip: k8s-lb1.${DOMAIN}:6443
    pod_cidr: 10.244.0.0/16
EOF

  # --------------------------------------
  # Salt top.sls mapping grains:role -> states
  # --------------------------------------
  cat >/srv/salt/top.sls <<'EOF'
base:
  'role:graf':
    - match: grain
    - roles.grafana

  'role:prometheus':
    - match: grain
    - roles.prometheus

  'role:storage':
    - match: grain
    - roles.storage

  'role:k8s':
    - match: grain
    - roles.k8s_admin

  'role:k8s-lb':
    - match: grain
    - roles.k8s_lb

  'role:k8s-cp':
    - match: grain
    - roles.k8s_control_plane
    - roles.k8s_flannel

  'role:k8s-worker':
    - match: grain
    - roles.k8s_worker
EOF

  # --------------------------------------
  # common/baseline.sls (minimal baseline)
  # --------------------------------------
  cat >/srv/salt/common/baseline.sls <<'EOF'
common-baseline:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - vim-tiny
      - jq
EOF

  # --------------------------------------
  # roles/grafana.sls
  # --------------------------------------
  cat >/srv/salt/roles/grafana.sls <<'EOF'
# Grafana node for Debian 13

grafana-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg

grafana-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

grafana-apt-keyring:
  cmd.run:
    - name: |
        curl -fsSL https://packages.grafana.com/gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/grafana-archive-keyring.gpg
    - creates: /etc/apt/keyrings/grafana-archive-keyring.gpg
    - require:
      - file: grafana-keyrings-dir
      - pkg: grafana-prereqs

grafana-apt-repo:
  file.managed:
    - name: /etc/apt/sources.list.d/grafana.list
    - mode: '0644'
    - user: root
    - group: root
    - contents: |
        deb [signed-by=/etc/apt/keyrings/grafana-archive-keyring.gpg] https://packages.grafana.com/oss/deb stable main
    - require:
      - cmd: grafana-apt-keyring

grafana-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: grafana-apt-repo

grafana-package:
  pkg.installed:
    - name: grafana
    - require:
      - cmd: grafana-apt-update

grafana-service:
  service.running:
    - name: grafana-server
    - enable: True
    - require:
      - pkg: grafana-package
EOF

  # --------------------------------------
  # roles/k8s_admin.sls
  # --------------------------------------
  cat >/srv/salt/roles/k8s_admin.sls <<'EOF'
# Kubernetes admin / toolbox node for Debian 13
#
# Responsibilities:
# - Install kubectl and basic CLI tools
# - Install Helm from official Helm APT repo

{% set k8s_minor = "v1.34" %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

k8s-admin-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - gnupg
      - jq
      - git

# Kubernetes APT repo (same as other nodes)
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

# Helm APT repo
k8s-admin-helm-keyring:
  cmd.run:
    - name: >
        curl -fsSL https://baltocdn.com/helm/signing.asc
        | gpg --dearmor -o /etc/apt/keyrings/helm.gpg
    - creates: /etc/apt/keyrings/helm.gpg
    - require:
      - file: k8s-admin-keyrings-dir
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

# APT update when repos change
k8s-admin-apt-update:
  cmd.run:
    - name: apt-get update
    - onchanges:
      - file: k8s-admin-apt-repo
      - file: k8s-admin-helm-repo

# Admin tools: kubectl + helm
k8s-admin-tools:
  pkg.installed:
    - pkgs:
      - kubectl
      - helm
    - require:
      - cmd: k8s-admin-apt-update
EOF

  # --------------------------------------
  # roles/k8s_control_plane.sls
  # --------------------------------------
  cat >/srv/salt/roles/k8s_control_plane.sls <<'EOF'
# Kubernetes control-plane node role for Debian 13
#
# Responsibilities:
# - Disable swap (runtime + fstab)
# - Configure required kernel modules and sysctls
# - Install and configure containerd (SystemdCgroup = true)
# - Add Kubernetes APT repo (pkgs.k8s.io) and install kubeadm/kubelet/kubectl
# - Install some extra control-plane tools
# - Enable and start containerd + kubelet
#
# kubeadm init / join is still done manually (or via another state).

{% set k8s_minor = "v1.34" %}
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

# Swap must be disabled for Kubernetes (control-plane)
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

# Kernel modules for Kubernetes networking
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

# Sysctl settings required by Kubernetes
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

# Kubernetes APT repo (pkgs.k8s.io)
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

# Containerd installation & configuration
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
    - pattern: '^\s*SystemdCgroup\s*=\s*false'
    - repl: '            SystemdCgroup = true'
    - append_if_not_found: False
    - require:
      - cmd: k8s-cp-containerd-config-default

k8s-cp-containerd-service:
  service.running:
    - name: containerd
    - enable: True
    - require:
      - pkg: k8s-cp-containerd-pkg
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

# Extra control-plane tools
k8s-cp-extra-tools:
  pkg.installed:
    - pkgs:
      - jq
      - socat
      - conntrack
      - iproute2
      - net-tools
      - tcpdump
    - require:
      - cmd: k8s-cp-apt-update
EOF

  # --------------------------------------
  # roles/k8s_worker.sls
  # --------------------------------------
  cat >/srv/salt/roles/k8s_worker.sls <<'EOF'
# Kubernetes worker node role for Debian 13
#
# Responsibilities:
# - Disable swap (runtime + fstab)
# - Configure required kernel modules and sysctls
# - Install and configure containerd (SystemdCgroup = true)
# - Add Kubernetes APT repo (pkgs.k8s.io) and install kubeadm/kubelet/kubectl
# - Enable and start containerd + kubelet

{% set k8s_minor = "v1.34" %}
{% set k8s_repo_url = "https://pkgs.k8s.io/core:/stable:/" ~ k8s_minor ~ "/deb/" %}

# APT prerequisites
k8s-worker-prereqs:
  pkg.installed:
    - pkgs:
      - apt-transport-https
      - ca-certificates
      - curl
      - gpg
      - gnupg
      - lsb-release

# Swap must be disabled for Kubernetes (workers)
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

# Kernel modules for Kubernetes networking
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

# Sysctl settings required by Kubernetes
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

# Kubernetes APT repo (pkgs.k8s.io)
k8s-keyrings-dir:
  file.directory:
    - name: /etc/apt/keyrings
    - mode: '0755'
    - user: root
    - group: root

k8s-apt-keyring:
  cmd.run:
    - name: >
        curl -fsSL {{ k8s_repo_url }}Release.key
        | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    - require:
      - file: k8s-keyrings-dir
      - pkg: k8s-worker-prereqs

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

# Containerd installation & configuration
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
    - pattern: '^\s*SystemdCgroup\s*=\s*false'
    - repl: '            SystemdCgroup = true'
    - append_if_not_found: False
    - require:
      - cmd: k8s-containerd-config-default

k8s-containerd-service:
  service.running:
    - name: containerd
    - enable: True
    - require:
      - pkg: k8s-containerd-pkg
      - file: k8s-containerd-systemdcgroup

# Kubernetes packages
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

  # --------------------------------------
  # roles/k8s_lb.sls
  # --------------------------------------
  cat >/srv/salt/roles/k8s_lb.sls <<'EOF'
# Kubernetes API load balancer role (HAProxy) for Debian 13
#
# Responsibilities:
# - Install haproxy
# - Manage a simple /etc/haproxy/haproxy.cfg for Kubernetes API
# - Enable and start haproxy

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
          timeout connect 5s
          timeout client  50s
          timeout server  50s

        # Kubernetes API load balancer
        frontend k8s_api_frontend
          bind *:6443
          default_backend k8s_api_backend

        backend k8s_api_backend
          balance roundrobin
          option tcp-check
          default-server inter 10s fall 3 rise 2

          # Control plane nodes (Kubernetes API servers)
          server k8s-cp1 k8s-cp1.${DOMAIN}:6443 check
          server k8s-cp2 k8s-cp2.${DOMAIN}:6443 check
          server k8s-cp3 k8s-cp3.${DOMAIN}:6443 check

k8s-lb-haproxy-service:
  service.running:
    - name: haproxy
    - enable: True
    - require:
      - file: k8s-lb-haproxy-config
EOF

  # --------------------------------------
  # roles/prometheus.sls
  # --------------------------------------
  cat >/srv/salt/roles/prometheus.sls <<'EOF'
# Prometheus monitoring node for Debian 13

prometheus-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl

prometheus-packages:
  pkg.installed:
    - pkgs:
      - prometheus
      - prometheus-node-exporter
    - require:
      - pkg: prometheus-prereqs

prometheus-service:
  service.running:
    - name: prometheus
    - enable: True
    - require:
      - pkg: prometheus-packages

node-exporter-service:
  service.running:
    - name: prometheus-node-exporter
    - enable: True
    - require:
      - pkg: prometheus-packages
EOF

  # --------------------------------------
  # roles/storage.sls
  # --------------------------------------
  cat >/srv/salt/roles/storage.sls <<'EOF'
# Storage node role for Debian 13
#
# Responsibilities:
# - Install targetcli-fb for iSCSI/LIO target management
# - Ensure rtslib-fb-targetctl.service is enabled for persistent config
# - Install a few useful storage tools

storage-prereqs:
  pkg.installed:
    - pkgs:
      - ca-certificates
      - curl
      - lsscsi
      - sg3-utils
      - smartmontools

storage-iscsi-target-tools:
  pkg.installed:
    - pkgs:
      - targetcli-fb
    - require:
      - pkg: storage-prereqs

# Debian 13: persist LIO/targetcli config via rtslib-fb-targetctl.service
storage-rtslib-targetctl-service:
  service.running:
    - name: rtslib-fb-targetctl.service
    - enable: True
    - require:
      - pkg: storage-iscsi-target-tools

# Optional: make sure targetcli is present and usable
storage-verify-targetcli:
  cmd.run:
    - name: targetcli --version || targetcli -h || true
    - require:
      - pkg: storage-iscsi-target-tools
EOF

  # --------------------------------------
  # roles/k8s_flannel.sls
  # --------------------------------------
  cat >/srv/salt/roles/k8s_flannel.sls <<'EOF'
# Flannel CNI deployment for Kubernetes
#
# This state:
#   - waits for kubeadm init to be done (admin.conf exists)
#   - applies Flannel manifest if kube-flannel DS is not ready

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

  log "Pillar and state tree seeded under /srv"
}

# -----------------------------------------------------------------------------
ansible_stack() {
  if [ "${INSTALL_ANSIBLE}" != "yes" ]; then
    log "INSTALL_ANSIBLE != yes; skipping Ansible stack"
    return 0
  fi

  log "Installing Ansible and base config"
  apt-get install -y --no-install-recommends ansible || true

  install -d -m0755 /etc/ansible

  cat >/etc/ansible/ansible.cfg <<EOF
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

# -----------------------------------------------------------------------------
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

    cat >/etc/systemd/system/semaphore.service <<EOF
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

# -----------------------------------------------------------------------------
read_hub() {
  log "Searching for hub.env"
  local f loaded=0
  for f in "${HUB_ENV_CANDIDATES[@]}"; do
    if [ -r "$f" ]; then
      log "Loading hub env from $f"
      # shellcheck disable=SC1090
      . "$f"
      loaded=1
      break
    fi
  done

  if (( ! loaded )); then
    log "[WARN] hub.env not found; falling back to baked-in defaults"
  fi

  # Derive LAN_IP & WG1_ADDR if we didn’t get them from env
  local LAN_IP WG1_ADDR
  LAN_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  WG1_ADDR="$(ip -4 addr show wg1 2>/dev/null | awk '/inet /{print $2}' | head -n1 || true)"

  # Safe, best-effort defaults so we never explode under `set -u`
  : "${HUB_LAN:=${LAN_IP:-}}"
  : "${HUB_WG1_NET:=${WG1_ADDR:-10.78.0.1/16}}"
  : "${WG1_PORT:=${WG1_PORT:-51821}}"
  : "${WG_ALLOWED_CIDR:=${WG_ALLOWED_CIDR:-10.78.0.0/16}}"

  if [ -z "${WG1_PUB:-}" ] && [ -f /etc/wireguard/wg1.pub ]; then
    WG1_PUB="$(< /etc/wireguard/wg1.pub)"
  fi

  # Just warnings now, not hard failures
  for v in HUB_LAN WG1_PUB WG1_PORT HUB_WG1_NET; do
    if [ -z "${!v:-}" ]; then
      log "[WARN] $v is unset; some features (wg sync / ssh registration) may not work"
    fi
  done
}

# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
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

    # (Optional) Explicit mgmt LAN allow if you ever drop generic 22/4505/4506:
    # ip saddr 10.100.10.0/24 tcp dport { 22, 4505, 4506 } accept

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
# ~/.bashrc -- powerful defaults

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# Prompt
PS1='\[\e[0;32m\]\u@\h\[\e[m\]:\[\e[0;34m\]\w\[\e[m\]\$ '

# History with timestamps
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT='%F %T '
HISTCONTROL=ignoredups:erasedups
shopt -s histappend
shopt -s checkwinsize
shopt -s cdspell

# Color grep
alias grep='grep --color=auto'

# ls aliases
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Safe file ops
alias cp='cp -i'
alias mv='mv -i'
alias rm='rm -i'

# Net & disk helpers
alias ports='ss -tuln'
alias df='df -h'
alias du='du -h'

alias tk='tmux kill-server'

# Load bash completion if available
if [ -f /etc/bash_completion ]; then
  . /etc/bash_completion
fi

# Wide minion list:
alias slist='salt --static --no-color --out=json --out-indent=-1 "*" grains.item host os osrelease ipv4 num_cpus mem_total roles \
| jq -r '"'"'to_entries[]
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
| @tsv'"'"' \
| sort -k1,1'

alias ssall='salt "*" cmd.run "ss -tnlp || netstat -tnlp"'
alias sping='salt "*" test.ping'
alias skservices='salt "*" service.status kubelet containerd'
alias sdfall='salt "*" cmd.run "df -hT --exclude-type=tmpfs --exclude-type=devtmpfs"'
alias stop5='salt "*" cmd.run "ps aux --sort=-%cpu | head -n 5"'
alias smem5='salt "*" cmd.run "ps aux --sort=-%mem | head -n 5"'
alias skvers='echo "== kubelet versions =="; salt "*" cmd.run "kubelet --version 2>/dev/null || echo no-kubelet"; echo; echo "== kubectl client versions =="; salt "*" cmd.run "kubectl version --client --short 2>/dev/null || echo no-kubectl"'

alias shl='printf "%s\n" \
"Salt / cluster helper commands:" \
"  slist      - List all minions in a wide table" \
"  sping      - Ping all minions via Salt (test.ping)." \
"  ssall      - Show listening TCP sockets on all minions (ss/netstat)." \
"  skservices - Check kubelet and containerd service status on all minions." \
"  skvers     - Show kubelet and kubectl versions on all minions." \
"  sdfall     - Show disk usage (df -hT, no tmpfs/devtmpfs) on all minions." \
"  stop5      - Top 5 CPU-hungry processes on each minion." \
"  smem5      - Top 5 memory-hungry processes on each minion." \
"" \
"Other:" \
"  cp         - cp -i (prompt before overwrite)." \
"  ll/la/l    - ls variants." \
""' \

# Auto-activate BCC virtualenv if present
VENV_DIR="/root/bccenv"
if [ -d "$VENV_DIR" ]; then
  if [ -n "$PS1" ]; then
    source "$VENV_DIR/bin/activate"
  fi
fi

# Custom: Show welcome on login
echo "$USER! Connected to: $(hostname) on $(date)"
EOF

  log ".bashrc written to /etc/skel/.bashrc"

  for USERNAME in root ansible debian; do
    HOME_DIR=$(eval echo "~$USERNAME")
    if [ -d "$HOME_DIR" ]; then
      cp "$BASHRC" "$HOME_DIR/.bashrc"
      chown "$USERNAME:$USERNAME" "$HOME_DIR/.bashrc"
      log "Updated .bashrc for $USERNAME"
    else
      log "Skipped .bashrc update for $USERNAME (home not found)"
    fi
  done

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

# -----------------------------------------------------------------------------
setup_vim_config() {
  log "Writing standard Vim config..."
    apt-get install -y \
    vim \
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
  if ! grep -q "$VENV_DIR" "$ROOT_BASHRC"; then
    echo "" >> "$ROOT_BASHRC"
    echo "# Auto-activate BCC virtualenv" >> "$ROOT_BASHRC"
    echo "source \"$VENV_DIR/bin/activate\"" >> "$ROOT_BASHRC"
  fi

  # Auto-activate for future users
  local SKEL_BASHRC="/etc/skel/.bashrc"
  if ! grep -q "$VENV_DIR" "$SKEL_BASHRC"; then
    echo "" >> "$SKEL_BASHRC"
    echo "# Auto-activate BCC virtualenv if available" >> "$SKEL_BASHRC"
    echo "[ -d \"$VENV_DIR\" ] && source \"$VENV_DIR/bin/activate\"" >> "$SKEL_BASHRC"
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

write_hub_env() {
  log "Writing /srv/wg/hub.env for minions"

  local lan_ip wg1_net wg1_pub
  lan_ip="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  wg1_net="$(ip -4 addr show wg1 | awk '/inet /{print $2}' | head -n1)"
  wg1_pub="$(< /etc/wireguard/wg1.pub)"

  install -d -m0700 /srv/wg
  cat >/srv/wg/hub.env <<EOF
HUB_LAN=${lan_ip}
HUB_WG1_NET=${wg1_net}
WG1_PUB=${wg1_pub}
WG1_PORT=${WG1_PORT}
WG_ALLOWED_CIDR=${WG_ALLOWED_CIDR:-10.78.0.0/16}
EOF
}


main_master() {
  log "BEGIN postinstall (master control hub)"

  ensure_base
  ensure_users
  wg_setup_planes
  nft_firewall
  read_hub
  helper_tools
  salt_master_stack
  pillars_and_states_seed
  ansible_stack
  semaphore_stack
  configure_salt_master_network
  configure_nftables_master
  setup_python_env
  write_bashrc
  write_tmux_conf
  sync_skel_to_existing_users
  write_hub_env

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

# =========================
# MINION POSTINSTALL (with env sourcing + IPv6 hardening + WG auto-enroll)
# =========================

emit_postinstall_minion() {
  local out="$1"
  cat >"$out" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/minion-postinstall.log"
exec > >(tee -a "$LOG") 2>&1
exec 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }

# ---- Import environment from mk_iso wrapper ----
if [ -r /etc/environment.d/99-provision.conf ]; then
  # shellcheck disable=SC2046
  export $(grep -E '^[A-Z0-9_]+=' /etc/environment.d/99-provision.conf | xargs -d'\n' || true)
fi

ADMIN_USER="${ADMIN_USER:-todd}"
ALLOW_ADMIN_PASSWORD="${ALLOW_ADMIN_PASSWORD:-no}"
MY_GROUP="${MY_GROUP:-prom}"

# Per-minion WireGuard IPs (seeded by wrapper)
WG1_WANTED="${WG1_WANTED:-10.78.0.2/32}"  # Ansible / SSH plane

# Where hub.env may be
HUB_ENV_CANDIDATES=(
  "/root/darksite/cluster-seed/hub.env"
  "/root/cluster-seed/hub.env"
  "/srv/wg/hub.env"
)

# -----------------------------------------------------------------------------
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

# ---------- Admin user / SSH ----------
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

# -----------------------------------------------------------------------------
# Install the shared enrollment SSH key used to talk back to the hub
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

# =============================================================================================
# We'll wire SSH into LAN+wg1 after wg1 exists
# =============================================================================================

ssh_hardening_static() {
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
    cat >/etc/ssh/sshd_config.d/10-admin-lan-password.conf <<EOF
Match User ${ADMIN_USER} Address 10.100.10.0/24
    PasswordAuthentication yes
EOF
  fi

  install -d -m755 /etc/systemd/system/ssh.service.d
  cat >/etc/systemd/system/ssh.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
EOF

  if sshd -t; then
    systemctl daemon-reload
    systemctl restart ssh || true
  else
    log "WARNING: sshd config test failed (pre-WG); will retry after WG1 setup"
  fi
}

# =============================================================================================
# Later, after wg1 is up, bind ssh explicitly to LAN + wg1 IPs
# =============================================================================================

ssh_bind_lan_and_wg1() {
  log "Configuring SSH ListenAddress for LAN + wg1"

  local LAN_IP WG1_ADDR
  LAN_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  WG1_ADDR="$(echo "${WG1_WANTED}" | cut -d/ -f1)"

  if [ -z "$LAN_IP" ]; then
    log "WARNING: could not detect LAN IP; leaving ListenAddress unchanged"
    return 0
  fi

  cat >/etc/ssh/sshd_config.d/00-listen.conf <<EOF
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

# -----------------------------------------------------------------------------
# ---------- Read hub.env (from master) ----------
read_hub() {
  log "Searching for hub.env"
  local f loaded=0
  for f in "${HUB_ENV_CANDIDATES[@]}"; do
    if [ -r "$f" ]; then
      log "Loading hub env from $f"
      # shellcheck disable=SC1090
      . "$f"
      loaded=1
      break
    fi
  done

  if (( ! loaded )); then
    log "[WARN] hub.env not found; falling back to baked-in defaults"
  fi

  # Derive LAN_IP & WG1_ADDR if we didn’t get them from env
  local LAN_IP WG1_ADDR
  LAN_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  WG1_ADDR="$(ip -4 addr show wg1 2>/dev/null | awk '/inet /{print $2}' | head -n1 || true)"

  # Safe, best-effort defaults so we never explode under `set -u`
  : "${HUB_LAN:=${LAN_IP:-}}"
  : "${HUB_WG1_NET:=${WG1_ADDR:-10.78.0.1/16}}"
  : "${WG1_PORT:=${WG1_PORT:-51821}}"
  : "${WG_ALLOWED_CIDR:=${WG_ALLOWED_CIDR:-10.78.0.0/16}}"

  if [ -z "${WG1_PUB:-}" ] && [ -f /etc/wireguard/wg1.pub ]; then
    WG1_PUB="$(< /etc/wireguard/wg1.pub)"
  fi

  # Just warnings now, not hard failures
  for v in HUB_LAN WG1_PUB WG1_PORT HUB_WG1_NET; do
    if [ -z "${!v:-}" ]; then
      log "[WARN] $v is unset; some features (wg sync / ssh registration) may not work"
    fi
  done
}

# -----------------------------------------------------------------------------
# ---------- WireGuard planes ----------
wg_setup_planes() {
  log "Configuring WireGuard control plane (wg1 only)"

  install -d -m700 /etc/wireguard
  local _old_umask; _old_umask="$(umask)"
  umask 077

  [ -f /etc/wireguard/wg1.key ] || wg genkey | tee /etc/wireguard/wg1.key | wg pubkey >/etc/wireguard/wg1.pub

  cat >/etc/wireguard/wg1.conf <<EOF
[Interface]
Address    = ${WG1_WANTED}
PrivateKey = $(cat /etc/wireguard/wg1.key)
ListenPort = ${WG1_PORT}
MTU        = 1420
EOF

  umask "${_old_umask}"

  # Bring wg1 up now that config exists
  systemctl enable wg-quick@wg1.service
  systemctl restart wg-quick@wg1.service
}

# -----------------------------------------------------------------------------
# ---------- nftables ----------
nft_min() {
  log "Installing nftables rules on minion (wg1 only)"

  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    ct state { established, related } accept
    iif "lo" accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    tcp dport 22 accept
    udp dport ${WG1_PORT:-51821} accept
    iifname "wg1" accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state { established, related } accept
  }
}
EOF

  systemctl enable --now nftables || true
}

# -----------------------------------------------------------------------------
# ---------- Salt minion (LAN to master) ----------
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

  # Master is the hub LAN IP from hub.env
  mkdir -p /etc/salt/minion.d
  cat >/etc/salt/minion.d/master.conf <<EOF
master: ${HUB_LAN}
ipv6: False
EOF

  # Grains: role + LAN + WireGuard control-plane info
  local LAN_IP WG1_ADDR WG1_PUB
  LAN_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  WG1_ADDR="$(echo "${WG1_WANTED}" | cut -d/ -f1)"
  WG1_PUB="$(cat /etc/wireguard/wg1.pub 2>/dev/null || true)"

  cat >/etc/salt/minion.d/role.conf <<EOF
grains:
  role: ${MY_GROUP}
  lan_ip: ${LAN_IP}
  wg1_ip: ${WG1_ADDR}
  wg1_pubkey: ${WG1_PUB}
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

# -----------------------------------------------------------------------------
bind_node_exporter() {
  log "Binding node_exporter to wg1 IP"

  local WG1_ADDR
  WG1_ADDR="$(echo "${WG1_WANTED}" | cut -d/ -f1)"

  install -d -m755 /etc/systemd/system/prometheus-node-exporter.service.d
  cat >/etc/systemd/system/prometheus-node-exporter.service.d/override.conf <<EOF
[Service]
Environment=
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=${WG1_ADDR}:9100 --web.disable-exporter-metrics
EOF

  cat >/etc/systemd/system/prometheus-node-exporter.service.d/wg-order.conf <<'EOF'
[Unit]
After=wg-quick@wg1.service network-online.target
Wants=wg-quick@wg1.service network-online.target
EOF

  systemctl daemon-reload
  systemctl enable --now prometheus-node-exporter || true
}

# -----------------------------------------------------------------------------
# ---------- Register with master (Prom + Ansible) ----------
register_with_master() {
  log "Registering minion with master via register-minion"

  local ENROLL_KEY="/root/.ssh/enroll_ed25519"
  if [[ ! -r "$ENROLL_KEY" ]]; then
    log "Enrollment SSH key ${ENROLL_KEY} missing; skipping register-minion"
    return 0
  fi

  local WG1_ADDR
  WG1_ADDR="$(echo "${WG1_WANTED}" | cut -d/ -f1)"
  local HOST_SHORT
  HOST_SHORT="$(hostname -s)"

  local SSHOPTS="-i ${ENROLL_KEY} -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=6"

  if ssh $SSHOPTS "${ADMIN_USER}@${HUB_LAN}" \
       "sudo /usr/local/sbin/register-minion '${MY_GROUP}' '${HOST_SHORT}' '${WG1_ADDR}'" 2>/dev/null; then
    log "[OK] Registered ${HOST_SHORT} (${WG1_ADDR}) in group ${MY_GROUP}"
    return 0
  fi

  log "[WARN] Failed to register minion with master; Prom/Ansible inventories will miss this node until fixed"
}

# -----------------------------------------------------------------------------
# ---------- Optional role-specific bits ----------
maybe_role_specific() {
  case "${MY_GROUP}" in
    storage)
      log "Role=storage: installing minimal storage tooling (placeholder)"
      apt-get install -y --no-install-recommends zfsutils-linux || true
      modprobe zfs 2>/dev/null || true
      ;;
    # Other roles (k8s-cp, k8s-worker, k8s-lb, prom, graf) can be fleshed out
    # via Salt states and/or Ansible playbooks.
  esac
}

main() {
  log "BEGIN postinstall (minion)"
  ensure_base
  ensure_admin_user
  install_enroll_key
  ssh_hardening_static
  ssh_bind_lan_and_wg1
  wg_setup_planes
  nft_min
  install_salt_minion
  bind_node_exporter
  register_with_master
  maybe_role_specific

  systemctl disable --now openipmi.service 2>/dev/null || true
  systemctl mask openipmi.service 2>/dev/null || true

  log "Minion ready."
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
  echo "WG1_WANTED=${wg1}"
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

# =========================
# minion deploy helper
# =========================

deploy_minion_vm() {
  # deploy_minion_vm <vmid> <name> <lan_ip> <group> <wg1/32> <mem_mb> <cores> <disk_gb>
  local id="$1" name="$2" ip="$3" group="$4"
  local wg1="$5"
  local mem="$6" cores="$7" disk="$8"

  local payload iso
  payload="$(mktemp)"
  emit_minion_wrapper "$payload" "$group" "$wg1"

  iso="$BUILD_ROOT/${name}.iso"
  mk_iso "$name" "$payload" "$iso" "$ip"
  pmx_deploy "$id" "$name" "$iso" "$mem" "$cores" "$disk"

  wait_poweroff "$id" 2400
  boot_from_disk "$id"
  pmx_wait_for_state "$id" "running" 600
}

# =========================
# ORIGINAL: base proxmox_cluster
# =========================

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

    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment on || true' || \
    sssh root@"$MASTER_LAN" 'wg-enrollment on || true' || true

  deploy_minion_vm "$PROM_ID"  "$PROM_NAME"  "$PROM_IP"  "prom" \
    "$PROM_WG1" \
    "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$GRAF_ID"  "$GRAF_NAME"  "$GRAF_IP"  "graf" \
    "$GRAF_WG1" \
    "$MINION_MEM" "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$K8S_ID"   "$K8S_NAME"   "$K8S_IP"   "k8s"  \
    "$K8S_WG1" \
    "$K8S_MEM"  "$MINION_CORES" "$MINION_DISK_GB"

  deploy_minion_vm "$STOR_ID"  "$STOR_NAME"  "$STOR_IP"  "storage" \
    "$STOR_WG1" \
    "$MINION_MEM" "$MINION_CORES" "$STOR_DISK_GB"

  log "Closing WireGuard enrollment on master..."
    sssh "${ADMIN_USER}@${MASTER_LAN}" 'sudo wg-enrollment off || true' || \
    sssh root@"$MASTER_LAN" 'wg-enrollment off || true' || true

  log "Base cluster deployed and enrollment closed."
}

# =========================
# NEW: Proxmox K8s node VMs (no kubeadm yet, just clean VM creation)
# =========================

proxmox_k8s_ha() {
  log "=== Deploying K8s node VMs (LBs + CPs + workers) with unified pipeline ==="

  # Ensure master is up and hub.env present for wrappers
  pmx "qm start $MASTER_ID" >/dev/null 2>&1 || true
  pmx_wait_for_state "$MASTER_ID" "running" 600
  pmx_wait_qga "$MASTER_ID" 900

  mkdir -p "$BUILD_ROOT/hub"
  DEST="$BUILD_ROOT/hub/hub.env"
  if pmx_guest_cat "$MASTER_ID" "/srv/wg/hub.env" > "${DEST}.tmp" && [[ -s "${DEST}.tmp" ]]; then
    mv -f "${DEST}.tmp" "${DEST}"
    log "hub.env refreshed at ${DEST}"
  else
    [[ -s "$DEST" ]] || die "Could not get hub.env for K8s nodes."
  fi

  # LBs
  deploy_minion_vm "$K8SLB1_ID" "$K8SLB1_NAME" "$K8SLB1_IP" "k8s-lb" \
    "$K8SLB1_WG1" \
    "$K8S_LB_MEM" "$K8S_LB_CORES" "$K8S_LB_DISK_GB"

  deploy_minion_vm "$K8SLB2_ID" "$K8SLB2_NAME" "$K8SLB2_IP" "k8s-lb" \
    "$K8SLB2_WG1" \
    "$K8S_LB_MEM" "$K8S_LB_CORES" "$K8S_LB_DISK_GB"

  # Control planes
  deploy_minion_vm "$K8SCP1_ID" "$K8SCP1_NAME" "$K8SCP1_IP" "k8s-cp" \
    "$K8SCP1_WG1" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  deploy_minion_vm "$K8SCP2_ID" "$K8SCP2_NAME" "$K8SCP2_IP" "k8s-cp" \
    "$K8SCP2_WG1" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  deploy_minion_vm "$K8SCP3_ID" "$K8SCP3_NAME" "$K8SCP3_IP" "k8s-cp" \
    "$K8SCP3_WG1" \
    "$K8S_CP_MEM" "$K8S_CP_CORES" "$K8S_CP_DISK_GB"

  # Workers
  deploy_minion_vm "$K8SW1_ID" "$K8SW1_NAME" "$K8SW1_IP" "k8s-worker" \
    "$K8SW1_WG1" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  deploy_minion_vm "$K8SW2_ID" "$K8SW2_NAME" "$K8SW2_IP" "k8s-worker" \
    "$K8SW2_WG1" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  deploy_minion_vm "$K8SW3_ID" "$K8SW3_NAME" "$K8SW3_IP" "k8s-worker" \
    "$K8SW3_WG1" \
    "$K8S_WK_MEM" "$K8S_WK_CORES" "$K8S_WK_DISK_GB"

  log "K8s node VMs deployed (LBs/CPs/workers) via unified minion pipeline."
  log "⚠ Note: this script only provisions OS + WG + Salt/etc. K8s kubeadm bootstrap can be layered on in a follow-up step."
}

# -----------------------------------------------------------------------------
proxmox_all() {
  log "=== Running full Proxmox deployment: base cluster + K8s node VMs ==="
  proxmox_cluster
  proxmox_k8s_ha

  # New: after Salt minions are up and have published wg1_* grains, sync WG peers
  log "Running wg-sync-from-salt on master to sync WireGuard peers..."
  sssh root@"${MASTER_LAN}" 'wg-sync-from-salt wg1 || true' || \
    warn "wg-sync-from-salt failed; you can run it manually on the master"

  log "=== Proxmox ALL complete. ==="
}

# =========================
# MAIN
# =========================

case "$TARGET" in
  proxmox-all)     proxmox_all ;;
  proxmox-cluster) proxmox_cluster ;;
  proxmox-k8s-ha)  proxmox_k8s_ha ;;
  *)
    die "Unknown TARGET '$TARGET' (use proxmox-all | proxmox-cluster | proxmox-k8s-ha)"
    ;;
esac
