#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/root/install.txt"
exec &> >(tee -a "$LOG_FILE")

log()       { echo "[INFO] $(date '+%F %T') - $*"; }
error_log() { echo "[ERROR] $(date '+%F %T') - $*" >&2; }

# =============================================================================
# CONFIG
# =============================================================================

# ISO source
# ISO_ORIG="/root/debian-12.10.0-amd64-netinst.iso"
ISO_ORIG="/root/debian-13.2.0-amd64-DVD-1.iso"

# Build workspace
BUILD_DIR="/root/build"
CUSTOM_DIR="$BUILD_DIR/custom"
MOUNT_DIR="/mnt/build"
DARKSITE_DIR="$CUSTOM_DIR/darksite"
PRESEED_FILE="preseed.cfg"
OUTPUT_ISO="$BUILD_DIR/base.iso"
FINAL_ISO="/root/clone.iso"

# Cluster target
INPUT="${INPUT:-1}"           # 1|fiend, 2|dragon, 3|lion
VMID="${VMID:-4003}"
VMNAME="${VMNAME:-workstation}"      # short base name; domain added below

# Domain
DOMAIN="${DOMAIN:-unixbox.net}"

# Storage choices
# VM_STORAGE="local-zfs"
# VM_STORAGE="fireball"
VM_STORAGE="${VM_STORAGE:-local-zfs}"           # e.g., ceph RBD storage ID
ISO_STORAGE="${ISO_STORAGE:-local}"        # dir storage for ISO

# Disk / CPU / RAM
DISK_SIZE_GB="${DISK_SIZE_GB:-15}"
MEMORY_MB="${MEMORY_MB:-4096}"
CORES="${CORES:-4}"

# Installer networking
NETWORK_MODE="${NETWORK_MODE:-static}"     # static | dhcp
STATIC_IP="${STATIC_IP:-10.100.10.50}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

# Cloud-Init toggle for clones
USE_CLOUD_INIT="${USE_CLOUD_INIT:-true}"
CLONE_VLAN_ID="${CLONE_VLAN_ID:-}"

# Clone fanout
NUM_CLONES="${NUM_CLONES:-4}"
BASE_CLONE_VMID="${BASE_CLONE_VMID:-3000}"
BASE_CLONE_IP="${BASE_CLONE_IP:-$STATIC_IP}"
CLONE_MEMORY_MB="${CLONE_MEMORY_MB:-4096}"
CLONE_CORES="${CLONE_CORES:-4}"

# Extra disks for clones
EXTRA_DISK_COUNT="${EXTRA_DISK_COUNT:-0}"
EXTRA_DISK_SIZE_GB="${EXTRA_DISK_SIZE_GB:-10}"
EXTRA_DISK_TARGET="${EXTRA_DISK_TARGET:-}"

# Install Profile: server | gnome-min | gnome-full | xfce-min | kde-min
INSTALL_PROFILE="${INSTALL_PROFILE:-gnome-min}"

# Optional extra scripts into ISO
SCRIPTS_DIR="${SCRIPTS_DIR:-/root/custom-scripts}"

# =============================================================================
# Compute / Validate basics
# =============================================================================

VMNAME_CLEAN="${VMNAME//[_\.]/-}"
VMNAME_CLEAN="$(echo "$VMNAME_CLEAN" | sed 's/^-*//;s/-*$//;s/--*/-/g' | tr '[:upper:]' '[:lower:]')"
if [[ ! "$VMNAME_CLEAN" =~ ^[a-z0-9-]+$ ]]; then
  error_log "Invalid VM name after cleanup: '$VMNAME_CLEAN' (letters, digits, dashes only)."
  exit 1
fi
VMNAME="$VMNAME_CLEAN"

case "$INPUT" in
  1|fiend)  HOST_NAME="fiend.${DOMAIN}";  PROXMOX_HOST="10.100.10.225" ;;
  2|dragon) HOST_NAME="dragon.${DOMAIN}"; PROXMOX_HOST="10.100.10.226" ;;
  3|lion)   HOST_NAME="lion.${DOMAIN}";   PROXMOX_HOST="10.100.10.227" ;;
  *) error_log "Unknown host: $INPUT"; exit 1 ;;
esac

BASE_FQDN="${VMNAME}.${DOMAIN}"
BASE_VMNAME="${BASE_FQDN}-template"

log "Target: $HOST_NAME ($PROXMOX_HOST)  VMID=$VMID  VMNAME=$BASE_VMNAME"
log "Storages: VM_STORAGE=$VM_STORAGE  ISO_STORAGE=$ISO_STORAGE  Disk=${DISK_SIZE_GB}G"
log "Network: $NETWORK_MODE  DOMAIN=$DOMAIN  Cloud-Init: $USE_CLOUD_INIT  Profile: $INSTALL_PROFILE"

# =============================================================================
# Build ISO payload
# =============================================================================

log "Cleaning build dir..."
umount "$MOUNT_DIR" 2>/dev/null || true
rm -rf "$BUILD_DIR"
mkdir -p "$CUSTOM_DIR" "$MOUNT_DIR" "$DARKSITE_DIR"

log "Mount ISO..."
mount -o loop "$ISO_ORIG" "$MOUNT_DIR"

log "Copy ISO contents..."
cp -a "$MOUNT_DIR/"* "$CUSTOM_DIR/"
cp -a "$MOUNT_DIR/.disk" "$CUSTOM_DIR/"
umount "$MOUNT_DIR"

log "Stage custom scripts..."
mkdir -p "$DARKSITE_DIR/scripts"
if [[ -d "$SCRIPTS_DIR" ]] && compgen -G "$SCRIPTS_DIR/*" >/dev/null; then
  rsync -a "$SCRIPTS_DIR"/ "$DARKSITE_DIR/scripts"/
  log "Added scripts from $SCRIPTS_DIR"
else
  log "No scripts at $SCRIPTS_DIR; skipping."
fi

# -----------------------------------------------------------------------------
# postinstall.sh (runs inside the installed VM on first boot)
# -----------------------------------------------------------------------------
log "Writing postinstall.sh..."
cat > "$DARKSITE_DIR/postinstall.sh" <<'EOSCRIPT'
#!/bin/bash
set -euxo pipefail

LOGFILE="${LOGFILE:-/var/log/postinstall.log}"
exec > >(tee -a "$LOGFILE") 2>&1
trap 'echo "[✖] Postinstall failed on line $LINENO"; exit 1' ERR
log() { echo "[INFO] $(date '+%F %T') — $*"; }

log "Starting postinstall setup..."

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
USERS=(
  "todd:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgqdaF+C41xwLS41+dOTnpsrDTPkAwo4Zejn4tb0lOt todd@onyx.unixbox.net"
)

ALLOW_USERS=""
for entry in "${USERS[@]}"; do
  user="${entry%%:*}"
  ALLOW_USERS+="$user "
done
ALLOW_USERS="${ALLOW_USERS%% }"

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

update_and_upgrade() {
  log "Updating APT sources to trixie..."
  cat > /etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
EOF

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get -y upgrade
}

install_base_packages() {
  log "Installing base packages..."
  apt-get install -y --no-install-recommends \
    dbus polkitd pkexec \
    curl wget ca-certificates gnupg lsb-release unzip \
    net-tools traceroute tcpdump sysstat strace lsof ltrace \
    rsync rsyslog cron chrony sudo git ethtool jq \
    qemu-guest-agent openssh-server \
    ngrep nmap cloud-init \
    xwayland gdm3 gnome-session gnome-terminal gnome-settings-daemon \
    gnome-control-center firefox-esr nautilus gnome-tweaks \
    gtk2-engines-murrine gtk2-engines-pixbuf dbus-user-session \
    vim ufw tmux htop uuid-runtime \
    linux-image-amd64 linux-headers-amd64 \
    bpfcc-tools bpftrace libbpf-dev python3-bpfcc python3 python3-pip python3.13-venv \
    xrdp
}

create_user() {
  local user=$1
  local ssh_key=$2

  if ! id "$user" &>/dev/null; then
    log "Creating user: $user"
    adduser --disabled-password --gecos "" "$user"
    mkdir -p /home/"$user"/.ssh
    echo "$ssh_key" > /home/"$user"/.ssh/authorized_keys
    chmod 700 /home/"$user"/.ssh
    chmod 600 /home/"$user"/.ssh/authorized_keys
    chown -R "$user:$user" /home/"$user"/.ssh
    echo "$user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$user"
  fi
}

harden_ssh() {
  log "Hardening SSH config..."
  mkdir -p /etc/ssh/sshd_config.d/
  cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
PasswordAuthentication no
PermitRootLogin no
AllowUsers $ALLOW_USERS
EOF
}

setup_ufw() {
  log "Configuring UFW..."
  ufw allow 22/tcp
  ufw allow 3389/tcp
  ufw --force enable
}

configure_xrdp() {
  log "Configuring XRDP (using Xorg)..."
  echo "gnome-session" > /etc/skel/.xsession
  cp /etc/skel/.xsession /root/.xsession || true

  log "Disabling Wayland in GDM..."
  sed -i 's/^#WaylandEnable=.*/WaylandEnable=false/' /etc/gdm3/daemon.conf || \
    echo -e "[daemon]\nWaylandEnable=false" >> /etc/gdm3/daemon.conf
}

reset_cloud_init() {
  log "Resetting cloud-init state..."
  cloud-init clean --logs
  rm -rf /var/lib/cloud/
  rm -f /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit.conf
}

regenerate_identity() {
  log "Regenerating machine identity..."
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id || true
  ln -s /etc/machine-id /var/lib/dbus/machine-id
  hostnamectl set-hostname "node-$(uuidgen | cut -c1-8)"
  echo "$(hostname)" > /etc/hostname
  rm -f /etc/ssh/ssh_host_*
}

cleanup_logs() {
  log "Cleaning up logs and temp files..."
  find /var/log -type f -not -name 'postinstall.log' -delete
  rm -rf /tmp/* /var/tmp/*
}

enable_services() {
  log "Enabling services: gdm3, xrdp, qemu-guest-agent..."
  systemctl enable gdm3
  systemctl enable xrdp
  systemctl enable qemu-guest-agent
}

self_destruct() {
  log "Removing bootstrap.service..."
  systemctl disable bootstrap.service || true
  rm -f /etc/systemd/system/bootstrap.service
  systemctl daemon-reload
}

# ------------------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------------------

update_and_upgrade
install_base_packages

for entry in "${USERS[@]}"; do
  username="${entry%%:*}"
  sshkey="${entry#*:}"
  create_user "$username" "$sshkey"
done

harden_ssh
setup_ufw
configure_xrdp
reset_cloud_init
regenerate_identity
cleanup_logs
enable_services
self_destruct

log "[✔] Postinstall complete — powering off"
systemctl poweroff -i || shutdown -h now || halt
EOSCRIPT
chmod +x "$DARKSITE_DIR/postinstall.sh"

# -----------------------------------------------------------------------------
# bootstrap.service
# -----------------------------------------------------------------------------
log "Writing bootstrap.service..."
cat > "$DARKSITE_DIR/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (One-time)
After=network.target
Wants=network.target
ConditionPathExists=/root/darksite/postinstall.sh

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -lc '/root/darksite/postinstall.sh'
TimeoutStartSec=0
#StandardOutput=journal+console
#StandardError=journal+console
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

# -----------------------------------------------------------------------------
# Bake 99-provision.conf now (no heredoc in preseed)
# -----------------------------------------------------------------------------
cat > "$DARKSITE_DIR/99-provision.conf" <<EOF
DOMAIN=$DOMAIN
USE_CLOUD_INIT=$USE_CLOUD_INIT
INSTALL_PROFILE=$INSTALL_PROFILE
EOF

# -----------------------------------------------------------------------------
# finalize-template.sh (runs on the build host; controls Proxmox cloning)
# -----------------------------------------------------------------------------
log "Writing finalize-template.sh..."
cat > "$DARKSITE_DIR/finalize-template.sh" <<'EOSCRIPT'
#!/usr/bin/env bash
set -euo pipefail

: "${PROXMOX_HOST:?Missing PROXMOX_HOST}"
: "${TEMPLATE_VMID:?Missing TEMPLATE_VMID}"
: "${NUM_CLONES:?Missing NUM_CLONES}"
: "${BASE_CLONE_VMID:?Missing BASE_CLONE_VMID}"
: "${BASE_CLONE_IP:?Missing BASE_CLONE_IP}"
: "${CLONE_MEMORY_MB:=4096}"
: "${CLONE_CORES:=4}"
: "${CLONE_VLAN_ID:=}"
: "${CLONE_GATEWAY:=}"
: "${CLONE_NAMESERVER:=}"
: "${VMNAME_CLEAN:?Missing VMNAME_CLEAN}"
: "${VM_STORAGE:?Missing VM_STORAGE}"
: "${USE_CLOUD_INIT:=false}"
: "${DOMAIN:=localdomain}"
: "${EXTRA_DISK_COUNT:=0}"
: "${EXTRA_DISK_SIZE_GB:=100}"
: "${EXTRA_DISK_TARGET:=}"

echo "[*] Waiting for VM $TEMPLATE_VMID on $PROXMOX_HOST to shut down..."
SECONDS=0; TIMEOUT=900
while ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@"$PROXMOX_HOST" "qm status $TEMPLATE_VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { echo "[!] Timeout waiting for shutdown"; exit 1; }
  sleep 15
done

echo "[*] Converting $TEMPLATE_VMID to template..."
ssh root@"$PROXMOX_HOST" "qm template $TEMPLATE_VMID"

check_storage() {
  local stor="$1"
  ssh root@"$PROXMOX_HOST" "pvesm status --storage $stor 2>/dev/null | awk 'NR>1 {print \$6}'" | grep -qx active
}

IP_PREFIX=$(echo "$BASE_CLONE_IP" | cut -d. -f1-3)
IP_START=$(echo "$BASE_CLONE_IP" | cut -d. -f4)

if [[ "$EXTRA_DISK_COUNT" -gt 0 ]]; then
  if [[ -z "$EXTRA_DISK_TARGET" || ! $(check_storage "$EXTRA_DISK_TARGET" && echo ok) == ok ]]; then
    echo "[!] Extra disk target invalid or inactive; skipping extra disks."
    EXTRA_DISK_COUNT=0
  else
    echo "[*] Extra disks: ${EXTRA_DISK_COUNT} x ${EXTRA_DISK_SIZE_GB}G on $EXTRA_DISK_TARGET."
  fi
fi

for ((i=0; i<NUM_CLONES; i++)); do
  CLONE_VMID=$((BASE_CLONE_VMID + i))
  CLONE_IP="${IP_PREFIX}.$((IP_START + i))"

  INDEX=$((i+1))
  CLONE_NAME="${VMNAME_CLEAN}.${DOMAIN}-${INDEX}-${CLONE_IP}"
  FQDN="${VMNAME_CLEAN}.${DOMAIN}"
  DESC="${FQDN} - ${CLONE_IP}"

  echo "[*] Cloning $CLONE_NAME (VMID $CLONE_VMID, IP $CLONE_IP)..."

  ssh root@"$PROXMOX_HOST" "qm clone $TEMPLATE_VMID $CLONE_VMID --name '$CLONE_NAME' --full 1 --storage $VM_STORAGE"
  ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --delete ide3 || true"

  NET_OPTS="virtio,bridge=vmbr0"
  [[ -n "$CLONE_VLAN_ID" ]] && NET_OPTS="$NET_OPTS,tag=$CLONE_VLAN_ID"

  ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --memory $CLONE_MEMORY_MB --cores $CLONE_CORES --net0 $NET_OPTS --agent enabled=1 --boot order=scsi0"

  if [[ "$USE_CLOUD_INIT" == "true" ]]; then
    ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --ide3 ${VM_STORAGE}:cloudinit"
    ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --ipconfig0 ip=${CLONE_IP}/24${CLONE_GATEWAY:+,gw=${CLONE_GATEWAY}}"
    [[ -n "$CLONE_NAMESERVER" ]] && ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --nameserver '$CLONE_NAMESERVER'"
  fi

  if [[ "$EXTRA_DISK_COUNT" -gt 0 ]]; then
    echo "[*] Adding $EXTRA_DISK_COUNT extra disk(s) to VM $CLONE_VMID..."
    for ((d=1; d<=EXTRA_DISK_COUNT; d++)); do
      DISK_BUS="scsi$((d))"
      ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --${DISK_BUS} ${EXTRA_DISK_TARGET}:${EXTRA_DISK_SIZE_GB}"
    done
  fi

  ssh root@"$PROXMOX_HOST" "qm set $CLONE_VMID --description '$DESC'"
  ssh root@"$PROXMOX_HOST" "qm start $CLONE_VMID"
  echo "[+] Clone $CLONE_NAME started."
done

echo "[OK] All clones created."
EOSCRIPT
chmod +x "$DARKSITE_DIR/finalize-template.sh"

# =============================================================================
# Preseed (Network + Profile)
# =============================================================================
log "Creating preseed.cfg..."

if [[ "$NETWORK_MODE" == "dhcp" ]]; then
  NETBLOCK=$(cat <<EOF
# Networking (DHCP)
d-i netcfg/choose_interface select auto
d-i netcfg/disable_dhcp boolean false
d-i netcfg/get_hostname string $VMNAME
d-i netcfg/get_domain string $DOMAIN
EOF
)
else
  NETBLOCK=$(cat <<EOF
# Networking (Static)
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string $VMNAME
d-i netcfg/get_domain string $DOMAIN
d-i netcfg/disable_dhcp boolean true
d-i netcfg/get_ipaddress string $STATIC_IP
d-i netcfg/get_netmask string $NETMASK
d-i netcfg/get_gateway string $GATEWAY
d-i netcfg/get_nameservers string $NAMESERVER
EOF
)
fi

case "$INSTALL_PROFILE" in
  server)
    PROFILEBLOCK=$(cat <<'EOF'
# Server profile (no desktop)
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  gnome-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal GNOME (Wayland via gdm3)
tasksel tasksel/first multiselect standard
d-i pkgsel/include string gnome-core gdm3 gnome-terminal network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  gnome-full)
    PROFILEBLOCK=$(cat <<'EOF'
# Full GNOME
tasksel tasksel/first multiselect standard, desktop, gnome-desktop, ssh-server
d-i pkgsel/include string
d-i pkgsel/ignore-recommends boolean false
d-i pkgsel/upgrade select none
EOF
)
    ;;
  xfce-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal XFCE (X11)
tasksel tasksel/first multiselect standard
d-i pkgsel/include string xfce4 xfce4-terminal lightdm xorg network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  kde-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal KDE Plasma (Wayland)
tasksel tasksel/first multiselect standard
d-i pkgsel/include string plasma-desktop sddm plasma-workspace-wayland kwin-wayland konsole network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
)
    ;;
  *) error_log "Unknown INSTALL_PROFILE: $INSTALL_PROFILE"; exit 1 ;;
esac

cat > "$CUSTOM_DIR/$PRESEED_FILE" <<EOF
# Locale & keyboard
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us

$NETBLOCK

# Mirrors (we will re-point in postinstall)
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
d-i apt-setup/use_mirror boolean false
d-i apt-setup/non-free boolean true
d-i apt-setup/contrib boolean true

# Temporary user (postinstall creates real users)
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/username string debian
d-i passwd/user-fullname string Debian User
d-i passwd/user-password password debian
d-i passwd/user-password-again password debian

# Timezone
d-i time/zone string America/Toronto
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true

# Disk (guided LVM on whole disk)
d-i partman-auto/method string lvm
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-lvm/confirm_write_new_label boolean true
d-i partman-auto-lvm/guided_size string max

$PROFILEBLOCK

d-i grub-installer/bootdev string /dev/sda
d-i grub-installer/only_debian boolean true

d-i finish-install/keep-consoles boolean false
d-i finish-install/exit-installer boolean true
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true
d-i cdrom-detect/eject boolean true

tasksel tasksel/first multiselect standard, ssh-server
d-i finish-install/reboot_in_progress note
# Late command: copy darksite payload and enable bootstrap
d-i preseed/late_command string \
  mkdir -p /target/root/darksite ; \
  cp -a /cdrom/darksite/* /target/root/darksite/ ; \
  in-target chmod +x /root/darksite/postinstall.sh ; \
  in-target cp /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service ; \
  in-target mkdir -p /etc/environment.d ; \
  in-target cp /root/darksite/99-provision.conf /etc/environment.d/99-provision.conf ; \
  in-target chmod 0644 /etc/environment.d/99-provision.conf ; \
  in-target systemctl daemon-reload ; \
  in-target systemctl enable bootstrap.service ;

# Power off the installer VM (no reboot)
d-i debian-installer/exit/poweroff boolean true
EOF

# =============================================================================
# Boot menu & ISO rebuild
# =============================================================================
log "Updating isolinux/txt.cfg..."
TXT_CFG="$CUSTOM_DIR/isolinux/txt.cfg"
ISOLINUX_CFG="$CUSTOM_DIR/isolinux/isolinux.cfg"
cat >> "$TXT_CFG" <<EOF
label auto
  menu label ^base
  kernel /install.amd/vmlinuz
  append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz preseed/file=/cdrom/$PRESEED_FILE ---
EOF
sed -i 's/^default .*/default auto/' "$ISOLINUX_CFG"

log "Rebuilding ISO..."
xorriso -as mkisofs \
  -o "$OUTPUT_ISO" \
  -r -J -joliet-long -l \
  -b isolinux/isolinux.bin \
  -c isolinux/boot.cat \
  -no-emul-boot -boot-load-size 4 -boot-info-table \
  -isohybrid-mbr /usr/share/syslinux/isohdpfx.bin \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
  -no-emul-boot -isohybrid-gpt-basdat \
  "$CUSTOM_DIR"

mv "$OUTPUT_ISO" "$FINAL_ISO"
log "ISO ready: $FINAL_ISO"

# =============================================================================
# Upload ISO & create the base VM on Proxmox
# =============================================================================
log "Uploading ISO to $PROXMOX_HOST..."
scp -q "$FINAL_ISO" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/"
FINAL_ISO_BASENAME="$(basename "$FINAL_ISO")"

log "Creating VM $VMID on $PROXMOX_HOST..."
ssh root@"$PROXMOX_HOST" \
  VMID="$VMID" VMNAME="$BASE_VMNAME" FINAL_ISO="$FINAL_ISO_BASENAME" \
  VM_STORAGE="${VM_STORAGE:-void}" ISO_STORAGE="${ISO_STORAGE:-local}" \
  DISK_SIZE_GB="${DISK_SIZE_GB:-32}" MEMORY_MB="${MEMORY_MB:-4096}" \
  CORES="${CORES:-4}" USE_CLOUD_INIT="${USE_CLOUD_INIT:-false}" \
  'bash -s' <<'EOSSH'
set -euo pipefail
: "${VMID:?}"; : "${VMNAME:?}"; : "${FINAL_ISO:?}"
: "${VM_STORAGE:?}"; : "${ISO_STORAGE:?}"
: "${DISK_SIZE_GB:?}"; : "${MEMORY_MB:?}"; : "${CORES:?}"

qm destroy "$VMID" --purge || true

qm create "$VMID" \
  --name "$VMNAME" \
  --memory "$MEMORY_MB" \
  --cores "$CORES" \
  --net0 virtio,bridge=vmbr0,firewall=1 \
  --ide2 ${ISO_STORAGE}:iso/${FINAL_ISO},media=cdrom \
  --scsihw virtio-scsi-single \
  --scsi0 ${VM_STORAGE}:${DISK_SIZE_GB} \
  --serial0 socket \
  --ostype l26 \
  --agent enabled=1

qm set "$VMID" --efidisk0 ${VM_STORAGE}:0,efitype=4m,pre-enrolled-keys=0
qm set "$VMID" --boot order=ide2
qm start "$VMID"
EOSSH

# =============================================================================
# Wait for preseed shutdown, flip boot, set description
# =============================================================================
log "Waiting for VM $VMID to power off after installer..."
SECONDS=0; TIMEOUT=1800
while ssh root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { error_log "Timeout waiting for installer shutdown"; exit 1; }
  sleep 20
done

if [[ "$NETWORK_MODE" == "static" ]]; then
  BASE_DESC="${BASE_FQDN}-template - ${STATIC_IP}"
else
  BASE_DESC="${BASE_FQDN}-template - DHCP"
fi

log "Detach ISO, set boot=scsi0, optionally add cloudinit, set description..."
ssh root@"$PROXMOX_HOST" 'bash -s --' "$VMID" "$VM_STORAGE" "$USE_CLOUD_INIT" "$BASE_DESC" <<'EOSSH'
set -euo pipefail
VMID="$1"; VM_STORAGE="$2"; USE_CLOUD_INIT="$3"; VM_DESC="$4"

qm set "$VMID" --delete ide2
qm set "$VMID" --boot order=scsi0
if [ "$USE_CLOUD_INIT" = "true" ]; then
  qm set "$VMID" --ide3 ${VM_STORAGE}:cloudinit
fi
qm set "$VMID" --description "$VM_DESC"
qm start "$VMID"
EOSSH

# =============================================================================
# Wait for postinstall poweroff, then template + clone
# =============================================================================
log "Waiting for VM $VMID to power off after postinstall..."
SECONDS=0; TIMEOUT=1800
while ssh root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { error_log "Timeout waiting for postinstall shutdown"; exit 1; }
  sleep 20
done

log "Template + clone loop..."
IP_PREFIX="$(echo "$BASE_CLONE_IP" | cut -d. -f1-3)"
IP_START="$(echo "$BASE_CLONE_IP" | cut -d. -f4)"

export PROXMOX_HOST TEMPLATE_VMID="$VMID" VM_STORAGE USE_CLOUD_INIT DOMAIN
export NUM_CLONES BASE_CLONE_VMID BASE_CLONE_IP CLONE_MEMORY_MB CLONE_CORES
export CLONE_VLAN_ID CLONE_GATEWAY="$GATEWAY" CLONE_NAMESERVER="$NAMESERVER"
export VMNAME_CLEAN="$VMNAME" EXTRA_DISK_COUNT EXTRA_DISK_SIZE_GB EXTRA_DISK_TARGET

bash "$DARKSITE_DIR/finalize-template.sh"

log "All done."

