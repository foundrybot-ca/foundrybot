#!/usr/bin/env bash

: <<'COMMENT'
in-tune_nix.sh — Deployable linux desktops that "magically" join SCCM servers.

Overview
--------
This script is a WIP, but in short is motivated becasue none of the "big" guys
have "automated" this process and it sucks to manage.

Motivation
----------
There is no "good" fully automated deployment tool to ease enrollment and managment
problems with mixed windows/linux envrioments. 
COMMENT

set -euo pipefail

LOG_FILE="/root/install.txt"
exec &> >(tee -a "$LOG_FILE")

log()       { echo "[INFO]  $(date '+%F %T') - $*"; }
error_log() { echo "[ERROR] $(date '+%F %T') - $*" >&2; }

# =============================================================================
# CONFIG
# =============================================================================
ISO_ORIG="/root/debian-13.0.0-amd64-DVD-1.iso"

BUILD_DIR="/root/build"
CUSTOM_DIR="$BUILD_DIR/custom"
MOUNT_DIR="/mnt/build"
DARKSITE_DIR="$CUSTOM_DIR/darksite"
PRESEED_FILE="preseed.cfg"
OUTPUT_ISO="$BUILD_DIR/base.iso"
FINAL_ISO="/root/intunenix.iso"

# Proxmox target (single VM only)
INPUT="${INPUT:-1}"              # 1|fiend, 2|dragon, 3|lion
VMID="${VMID:-1002}"
VMNAME="${VMNAME:-intunenix}"
DOMAIN="${DOMAIN:-local}"

VM_STORAGE="${VM_STORAGE:-local-zfs}"
ISO_STORAGE="${ISO_STORAGE:-local}"

DISK_SIZE_GB="${DISK_SIZE_GB:-32}"
MEMORY_MB="${MEMORY_MB:-4096}"
CORES="${CORES:-4}"

NETWORK_MODE="${NETWORK_MODE:-dhcp}"   # dhcp | static
STATIC_IP="${STATIC_IP:-10.100.10.111}"
NETMASK="${NETMASK:-255.255.255.0}"
GATEWAY="${GATEWAY:-10.100.10.1}"
NAMESERVER="${NAMESERVER:-10.100.10.2 10.100.10.3 1.1.1.1}"

USE_CLOUD_INIT="${USE_CLOUD_INIT:-false}"

# server | gnome-min | gnome-full
INSTALL_PROFILE="${INSTALL_PROFILE:-gnome-min}"

SCRIPTS_DIR="${SCRIPTS_DIR:-/root/custom-scripts}"

# Optional extra OS behavior
APT_TRACK="${APT_TRACK:-trixie}"

# MasterControl defaults (can be overridden via env before running)
MC_DOMAIN="${MC_DOMAIN:-}"
MC_EMAIL="${MC_EMAIL:-admin@${DOMAIN}}"
MC_DB_NAME="${MC_DB_NAME:-mastercontrol}"
MC_DB_USER="${MC_DB_USER:-mcapi}"
MC_DB_PASS="${MC_DB_PASS:-}"
MC_API_BIND="${MC_API_BIND:-127.0.0.1:8000}"
MC_ORG="${MC_ORG:-MasterControl}"
MC_COUNTRY="${MC_COUNTRY:-US}"
MC_STATE="${MC_STATE:-State}"
MC_LOCALITY="${MC_LOCALITY:-City}"

# =============================================================================
# Compute basics
# =============================================================================
VMNAME_CLEAN="${VMNAME//[_\.]/-}"
VMNAME_CLEAN="$(echo "$VMNAME_CLEAN" | sed 's/^-*//;s/-*$//;s/--*/-/g' | tr '[:upper:]' '[:lower:]')"
[[ "$VMNAME_CLEAN" =~ ^[a-z0-9-]+$ ]] || { error_log "Invalid VM name: $VMNAME_CLEAN"; exit 1; }
VMNAME="$VMNAME_CLEAN"

case "$INPUT" in
  1|fiend)  HOST_NAME="fiend.${DOMAIN}";  PROXMOX_HOST="10.100.10.225" ;;
  2|dragon) HOST_NAME="dragon.${DOMAIN}"; PROXMOX_HOST="10.100.10.226" ;;
  3|lion)   HOST_NAME="lion.${DOMAIN}";   PROXMOX_HOST="10.100.10.227" ;;
  *) error_log "Unknown host: $INPUT"; exit 1 ;;
esac

BASE_FQDN="${VMNAME}.${DOMAIN}"
BASE_VMNAME="${BASE_FQDN}"    # no "-template"

log "Target: $HOST_NAME ($PROXMOX_HOST)  VMID=$VMID  VMNAME=$BASE_VMNAME"
log "Storages: VM_STORAGE=$VM_STORAGE  ISO_STORAGE=$ISO_STORAGE  Disk=${DISK_SIZE_GB}G"
log "Network: $NETWORK_MODE  Cloud-Init: $USE_CLOUD_INIT  Profile: $INSTALL_PROFILE"

# =============================================================================
# Build ISO payload
# =============================================================================
log "Cleaning build dir…"
umount "$MOUNT_DIR" 2>/dev/null || true
rm -rf "$BUILD_DIR"
mkdir -p "$CUSTOM_DIR" "$MOUNT_DIR" "$DARKSITE_DIR"

log "Mount ISO…"
mount -o loop "$ISO_ORIG" "$MOUNT_DIR"

log "Copy ISO contents…"
cp -a "$MOUNT_DIR/"* "$CUSTOM_DIR/"
cp -a "$MOUNT_DIR/.disk" "$CUSTOM_DIR/"
umount "$MOUNT_DIR"

log "Stage custom scripts…"
mkdir -p "$DARKSITE_DIR/scripts"
if [[ -d "$SCRIPTS_DIR" ]] && compgen -G "$SCRIPTS_DIR/*" >/dev/null; then
  rsync -a "$SCRIPTS_DIR"/ "$DARKSITE_DIR/scripts"/
  log "Added scripts from $SCRIPTS_DIR"
else
  log "No scripts at $SCRIPTS_DIR; skipping."
fi

# -----------------------------------------------------------------------------
# IntuneNix first-boot bits (BAKE THESE INTO THE ISO)
# -----------------------------------------------------------------------------
log "Writing IntuneNix first-boot bits…"
cat > "$DARKSITE_DIR/firstboot.sh" <<'EOF'
#!/usr/bin/env bash
# /opt/intunenix/firstboot.sh (copied from /root/darksite by postinstall)
set -Eeuo pipefail

LOG_DIR="/var/log/intunenix"
LOG="$LOG_DIR/firstboot.log"
STATE_DIR="/etc/intunenix"
STAMP="$STATE_DIR/.configured"
HOOKS_DIR="/opt/intunenix/firstboot.d"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$HOOKS_DIR"
exec > >(tee -a "$LOG") 2>&1

echo "[INFO] $(date '+%F %T') - firstboot start (pid $$)"

# Optional org-level secrets
if [[ -f /etc/mastercontrol/secrets.env ]]; then
  # shellcheck disable=SC1091
  . /etc/mastercontrol/secrets.env || true
fi

# Idempotent
if [[ -f "$STAMP" ]]; then
  echo "[INFO] already configured; exiting"
  exit 0
fi

# Best-effort wait for network
for _ in {1..60}; do
  ip route show default &>/dev/null && ping -c1 -W1 1.1.1.1 &>/dev/null && break
  sleep 2
done

# Run hook scripts if present
if compgen -G "$HOOKS_DIR/*.sh" >/dev/null; then
  for s in "$HOOKS_DIR"/*.sh; do
    [[ -x "$s" ]] || chmod +x "$s"
    echo "[INFO] -> running $s"
    "$s"
  done
fi

touch "$STAMP"
chmod 0644 "$STAMP"
systemctl disable intunenix-firstboot.service || true

echo "[INFO] $(date '+%F %T') - firstboot complete"
EOF
chmod +x "$DARKSITE_DIR/firstboot.sh"

cat > "$DARKSITE_DIR/intunenix-firstboot.service" <<'EOF'
[Unit]
Description=IntuneNix First Boot (one-time)
Wants=network-online.target
After=network.target network-online.target systemd-networkd-wait-online.service NetworkManager-wait-online.service cloud-init.service
ConditionPathIsExecutable=/opt/intunenix/firstboot.sh
ConditionPathExists=!/etc/intunenix/.configured

[Service]
Type=oneshot
# Safety: start even if network-online is flaky
ExecStartPre=/bin/bash -lc 'for i in {1..60}; do ip route show default &>/dev/null && ping -c1 -W1 1.1.1.1 &>/dev/null && exit 0; sleep 2; done; exit 0'
ExecStart=/opt/intunenix/firstboot.sh
User=root
Group=root
RemainAfterExit=yes
TimeoutStartSec=0
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

# -----------------------------------------------------------------------------
# postinstall.sh (runs inside the installed VM on first boot)
# -----------------------------------------------------------------------------
cat > "$DARKSITE_DIR/postinstall.sh" <<'EOSCRIPT'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/postinstall.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "[X] Failed at line $LINENO" >&2' ERR
log(){ echo "[INFO] $(date '+%F %T') - $*"; }
err(){ echo "[ERROR] $(date '+%F %T') - $*" >&2; }

# ------------------------------------------------------------------------------
# Load runtime vars (baked during ISO build)
# ------------------------------------------------------------------------------
if [ -f /etc/environment.d/99-provision.conf ]; then
  # shellcheck disable=SC1091
  . /etc/environment.d/99-provision.conf
else
  log "/etc/environment.d/99-provision.conf missing; continuing with fallbacks."
fi

# Sensible fallbacks
HOST_SHORT="$(hostname --short 2>/dev/null || echo intunenix)"
HOST_FQDN="$(hostname -f 2>/dev/null || echo "${HOST_SHORT}.localdomain")"

: "${DOMAIN:=${HOST_FQDN#${HOST_SHORT}.}}"
: "${USE_CLOUD_INIT:=false}"
: "${INSTALL_PROFILE:=server}"
: "${APT_TRACK:=trixie}"
: "${DISABLE_IPV6:=false}"

# ---- MasterControl (MC) defaults ----
: "${MC_DOMAIN:=${HOST_FQDN}}"
: "${MC_EMAIL:=admin@${DOMAIN}}"
: "${MC_DB_NAME:=mastercontrol}"
: "${MC_DB_USER:=mcapi}"
: "${MC_DB_PASS:=}"           # empty => autogenerate later
: "${MC_API_BIND:=127.0.0.1:8000}"
: "${MC_ORG:=MasterControl}"
: "${MC_COUNTRY:=US}"
: "${MC_STATE:=State}"
: "${MC_LOCALITY:=City}"

# ---- Kiosk defaults (ALWAYS ON) ----
KIOSK_URL="${KIOSK_URL:-https://${MC_DOMAIN}}"

# Persist kiosk URL into system environment for GUI sessions/autostart
install -d -m 0755 /etc/environment.d
cat >/etc/environment.d/20-kiosk.conf <<EOF
KIOSK_URL=${KIOSK_URL}
EOF

log "ENV SUMMARY  domain=${DOMAIN}  profile=${INSTALL_PROFILE}  cloud_init=${USE_CLOUD_INIT}  mc_domain=${MC_DOMAIN} kiosk_url=${KIOSK_URL}"

# Users & SSH keys
USERS=(
  "todd:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHV51Eelt8PwYreHhJJ4JJP3OMwrXswUShblYY10J+A/ todd@onyx"
)

ALLOW_USERS=""; for e in "${USERS[@]}"; do u="${e%%:*}"; ALLOW_USERS+="$u "; done; ALLOW_USERS="${ALLOW_USERS%% }"

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
apt_retry() {
  local tries=4
  until DEBIAN_FRONTEND=noninteractive "$@"; do
    ((tries--)) || return 1
    sleep 3
    apt-get update -y || true
  done
}

enable_if_exists() {
  for unit in "$@"; do
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "$unit"; then
      systemctl enable "$unit" || true
    else
      log "Unit not present, skipping enable: $unit"
    fi
  done
}

randstr(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"; }

wait_for_network() {
  log "Waiting for basic network..."
  for _ in {1..60}; do
    ip route show default &>/dev/null && ping -c1 -W1 1.1.1.1 &>/dev/null && return 0
    sleep 2
  done
  log "No network after wait; continuing."
}

# ------------------------------------------------------------------------------
# Base OS setup
# ------------------------------------------------------------------------------
update_and_upgrade() {
  log "APT sources -> ${APT_TRACK}"
  cat >/etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian ${APT_TRACK} main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${APT_TRACK}-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${APT_TRACK}-updates main contrib non-free non-free-firmware
EOF
  apt-get update -y
  log "Running apt dist-upgrade (unconditional)"
  apt_retry apt-get -y dist-upgrade
}

install_base_packages() {
  log "Installing base packages..."
  REALM="$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')"   # FIX: full domain, not just TLD
  echo "krb5-config krb5-config/default_realm string $REALM" | debconf-set-selections || true

  apt_retry apt-get install -y --no-install-recommends \
    dbus polkitd pkexec \
    curl wget ca-certificates gnupg lsb-release unzip jq uuid-runtime \
    net-tools traceroute tcpdump sysstat strace lsof ltrace ethtool \
    rsync rsyslog cron chrony sudo git \
    qemu-guest-agent openssh-server \
    ngrep nmap \
    bpfcc-tools bpftrace libbpf-dev python3-bpfcc python3 python3-pip python3-venv python3-dev build-essential \
    tmux htop \
    linux-image-amd64 linux-headers-amd64 \
    ufw nginx openssl \
    postgresql postgresql-contrib \
    realmd sssd sssd-tools adcli krb5-user packagekit samba-common-bin oddjob oddjob-mkhomedir \
    vim
}

maybe_install_desktop() {
  case "$INSTALL_PROFILE" in
    gnome-min)
      log "Installing minimal GNOME + NetworkManager..."
      apt_retry apt-get install -y --no-install-recommends gnome-core gdm3 gnome-terminal network-manager
      systemctl enable NetworkManager gdm3 || true ;;
    gnome-full) apt_retry apt-get install -y task-gnome-desktop ;;
    xfce-min)
      apt_retry apt-get install -y --no-install-recommends xfce4 xfce4-terminal lightdm xorg network-manager
      systemctl enable NetworkManager lightdm || true ;;
    server) log "Server profile selected. Skipping desktop." ;;
    *)      log "Unknown INSTALL_PROFILE='$INSTALL_PROFILE'. Skipping desktop." ;;
  esac
}

enforce_wayland_defaults() {
  if systemctl list-unit-files | grep -q '^gdm3\.service'; then
    mkdir -p /etc/gdm3
    if [ -f /etc/gdm3/daemon.conf ]; then
      if grep -q '^[# ]*WaylandEnable=' /etc/gdm3/daemon.conf; then
        sed -i 's/^[# ]*WaylandEnable=.*/WaylandEnable=true/' /etc/gdm3/daemon.conf
      else
        printf '\n[daemon]\nWaylandEnable=true\n' >> /etc/gdm3/daemon.conf
      fi
    else
      cat > /etc/gdm3/daemon.conf <<'EOF'
[daemon]
WaylandEnable=true
EOF
    fi
  fi
  if systemctl list-unit-files | grep -q '^sddm\.service'; then
    mkdir -p /etc/sddm.conf.d
    cat > /etc/sddm.conf.d/10-wayland.conf <<'EOF'
[General]
Session=plasmawayland.desktop
[Wayland]
EnableHiDPI=true
EOF
  fi
}

maybe_install_cloud_init() {
  if [[ "$USE_CLOUD_INIT" == "true" ]]; then
    log "Installing cloud-init..."
    apt_retry apt-get install -y cloud-init cloud-guest-utils
    enable_if_exists cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service
  else
    log "Cloud-Init disabled."
  fi
}

write_bashrc() {
  log "Writing /etc/skel/.bashrc"
  cat >/etc/skel/.bashrc <<'EOF'
# ~/.bashrc
[ -z "$PS1" ] && return
PS1='\[\e[0;32m\]\u@\h\[\e[m\]:\[\e[0;34m\]\w\[\e[m\]\$ '
HISTSIZE=10000; HISTFILESIZE=20000; HISTTIMEFORMAT='%F %T '; HISTCONTROL=ignoredups:erasedups
shopt -s histappend checkwinsize cdspell
alias grep='grep --color=auto'
alias ll='ls -alF'; alias la='ls -A'; alias l='ls -CF'
alias ports='ss -tuln'; alias df='df -h'; alias du='du -h'
[ -f /etc/bash_completion ] && . /etc/bash_completion
VENV_DIR="/root/bccenv"; [ -d "$VENV_DIR" ] && [ -n "$PS1" ] && . "$VENV_DIR/bin/activate"
echo "$USER connected to $(hostname) on $(date)"
EOF
  for u in root ansible debian; do
    h=$(eval echo "~$u") || true
    [ -d "$h" ] || continue
    cp /etc/skel/.bashrc "$h/.bashrc"; chown "$u:$u" "$h/.bashrc" || true
  done
}

configure_ufw_firewall() {
  log "Configuring UFW..."
  apt_retry apt-get install -y ufw
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 443/tcp
  ufw allow 80/tcp
  ufw --force enable
}

write_tmux_conf() {
  log "Writing tmux config..."
  cat >/etc/skel/.tmux.conf <<'EOF'
set -g mouse on
setw -g mode-keys vi
set -g history-limit 10000
set -g default-terminal "screen-256color"
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
bind r source-file ~/.tmux.conf \; display-message "Reloaded!"
EOF
  cp /etc/skel/.tmux.conf /root/.tmux.conf
}

install_custom_scripts() {
  log "Installing custom scripts (if any)..."
  if [[ -d /root/darksite/scripts ]] && compgen -G "/root/darksite/scripts/*" >/dev/null; then
    cp -a /root/darksite/scripts/* /usr/local/bin/
    chmod +x /usr/local/bin/* || true
  fi
}

setup_vim_config() {
  log "Setting up Vim..."
  apt_retry apt-get install -y vim vim-airline vim-airline-themes vim-ctrlp vim-fugitive vim-gitgutter vim-tabular
  mkdir -p /etc/skel/.vim/autoload/airline/themes
  cat >/etc/skel/.vimrc <<'EOF'
syntax on
filetype plugin indent on
set number
set relativenumber
set tabstop=2 shiftwidth=2 expandtab
EOF
}

setup_python_env() {
  log "Python env for BCC..."
  apt_retry apt-get install -y python3-psutil python3-bpfcc
  local VENV_DIR="/root/bccenv"
  python3 -m venv --system-site-packages "$VENV_DIR"
  . "$VENV_DIR/bin/activate"
  pip install --upgrade pip wheel setuptools
  pip install cryptography pyOpenSSL numba pytest
  deactivate
  for f in /root/.bashrc /etc/skel/.bashrc; do
    grep -q "$VENV_DIR" "$f" 2>/dev/null || echo -e "\n# Auto-activate BCC venv\n[ -d \"$VENV_DIR\" ] && . \"$VENV_DIR/bin/activate\"" >> "$f"
  done
}

setup_users_and_ssh() {
  log "Creating users and hardening sshd..."
  for entry in "${USERS[@]}"; do
    u="${entry%%:*}"; key="${entry#*:}"
    id -u "$u" &>/dev/null || useradd --create-home --shell /bin/bash "$u"
    h="/home/$u"; mkdir -p "$h/.ssh"; chmod 700 "$h/.ssh"
    echo "$key" >"$h/.ssh/authorized_keys"; chmod 600 "$h/.ssh/authorized_keys"
    chown -R "$u:$u" "$h"
    echo "$u ALL=(ALL) NOPASSWD:ALL" >"/etc/sudoers.d/90-$u"; chmod 440 "/etc/sudoers.d/90-$u"
  done
  mkdir -p /etc/ssh/sshd_config.d
  cat >/etc/ssh/sshd_config.d/99-custom.conf <<EOF
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers ${ALLOW_USERS}
EOF
  chmod 600 /etc/ssh/sshd_config.d/99-custom.conf
  systemctl restart ssh
}

configure_dns_hosts() {
  log "Hostname and /etc/hosts..."
  VMNAME="$(hostname --short)"
  FQDN="${VMNAME}.${DOMAIN}"
  hostnamectl set-hostname "$FQDN"
  echo "$VMNAME" >/etc/hostname
  cat >/etc/hosts <<EOF
127.0.0.1 localhost
127.0.1.1 ${FQDN} ${VMNAME}
EOF
}

# ------------------------------------------------------------------------------
# GNOME: operator user, autologin, plain desktop, icons + kiosk
# ------------------------------------------------------------------------------
ensure_operator_user() {
  id -u operator &>/dev/null || useradd --create-home --shell /bin/bash operator
  echo "operator ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-operator
  chmod 440 /etc/sudoers.d/90-operator
}

configure_gdm_autologin() {
  mkdir -p /etc/gdm3
  # Ensure [daemon] header exists
  grep -q '^\[daemon\]' /etc/gdm3/daemon.conf 2>/dev/null || printf '[daemon]\n' >>/etc/gdm3/daemon.conf
  # Wayland on (you already default it elsewhere, but keep it idempotent)
  if grep -q '^WaylandEnable' /etc/gdm3/daemon.conf 2>/dev/null; then
    sed -i 's/^WaylandEnable.*/WaylandEnable=true/' /etc/gdm3/daemon.conf
  else
    printf 'WaylandEnable=true\n' >>/etc/gdm3/daemon.conf
  fi
  # Autologin operator
  if grep -q '^AutomaticLoginEnable' /etc/gdm3/daemon.conf 2>/dev/null; then
    sed -i 's/^AutomaticLoginEnable.*/AutomaticLoginEnable=true/' /etc/gdm3/daemon.conf
  else
    printf 'AutomaticLoginEnable=true\n' >>/etc/gdm3/daemon.conf
  fi
  if grep -q '^AutomaticLogin' /etc/gdm3/daemon.conf 2>/dev/null; then
    sed -i 's/^AutomaticLogin.*/AutomaticLogin=operator/' /etc/gdm3/daemon.conf
  else
    printf 'AutomaticLogin=operator\n' >>/etc/gdm3/daemon.conf
  fi
}

ensure_packages_for_gnome_plain() {
  # Bits needed for desktop icons & config
  apt_retry apt-get install -y --no-install-recommends \
    gnome-shell-extensions nautilus xdg-user-dirs gsettings-desktop-schemas
}

write_system_dconf_defaults() {
  # System dconf profile
  install -d -m 0755 /etc/dconf/profile /etc/dconf/db/local.d /etc/dconf/db/local.d/locks

  cat >/etc/dconf/profile/user <<'EOF'
user-db:user
system-db:local
EOF

  # Retro-ish GNOME defaults + desktop icons
  cat >/etc/dconf/db/local.d/90-intunenix-gnome <<'EOF'
[org/gnome/desktop/background]
picture-uri=''
picture-uri-dark=''
primary-color='#008080'
secondary-color='#008080'
color-shading-type='solid'

[org/gnome/desktop/session]
idle-delay=uint32 0

[org/gnome/desktop/screensaver]
lock-enabled=false

[org/gnome/shell]
favorite-apps=[]   # <-- fixed syntax, no @as

[org/gnome/shell/extensions/ding]
show-home=true
show-trash=false
show-network-volumes=true
icon-size='standard'
EOF

  dconf update
}

enable_ding_extension_by_default() {
  local schema_dir="/usr/share/gnome-shell/extensions/ding@rastersoft.com"
  if [[ -d "$schema_dir" ]]; then
    cat >/etc/dconf/db/local.d/91-intunenix-extensions <<'EOF'
[org/gnome/shell]
disable-user-extensions=false
enabled-extensions=['ding@rastersoft.com']
EOF
    dconf update
  else
    log "DING extension not found; install gnome-shell-extensions first."
  fi
}

install_site_builder_placeholder() {
  # Simple placeholder app/script you can replace later with your UI starter
  cat >/usr/local/bin/site-builder.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
URL="${KIOSK_URL:-http://127.0.0.1:8080}"
if command -v xdg-open >/dev/null 2>&1; then
  exec xdg-open "$URL"
elif command -v firefox >/dev/null 2>&1; then
  exec firefox "$URL"
elif command -v chromium >/dev/null 2>&1; then
  exec chromium "$URL"
else
  echo "Open: $URL"
fi
EOF
  chmod +x /usr/local/bin/site-builder.sh
}

create_operator_desktop_items() {
  local user="operator" home="/home/${user}"
  ensure_operator_user
  su - "${user}" -c 'xdg-user-dirs-update || true'

  install -d -m 0700 "${home}/Desktop"
  chown -R "${user}:${user}" "${home}/Desktop"

  # Downloads
  cat >"${home}/Desktop/Downloads.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Downloads
Comment=Open Downloads folder
Exec=nautilus --new-window "$HOME/Downloads"
Terminal=false
Icon=folder-download
Categories=Utility;
EOF
  chmod +x "${home}/Desktop/Downloads.desktop"

  # Site Builder (script)
  cat >"${home}/Desktop/Site Builder.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Site Builder
Comment=Open the site repacker wizard
Exec=/usr/local/bin/site-builder.sh
Terminal=false
Icon=applications-system
Categories=Utility;
EOF
  chmod +x "${home}/Desktop/Site Builder.desktop"

  # Web link to the produced site
  cat >"${home}/Desktop/Site Console.desktop" <<EOF
[Desktop Entry]
Type=Link
Name=Site Console
URL=${KIOSK_URL}
Icon=web-browser
EOF
  chmod +x "${home}/Desktop/Site Console.desktop"

  # Mark trusted to avoid GNOME prompts
  su - "${user}" -c "gio set \"${home}/Desktop/Downloads.desktop\" metadata::trusted true || true"
  su - "${user}" -c "gio set \"${home}/Desktop/Site Builder.desktop\" metadata::trusted true || true"
  su - "${user}" -c "gio set \"${home}/Desktop/Site Console.desktop\"  metadata::trusted true || true"

  chown -R "${user}:${user}" "${home}/Desktop"
}

configure_kiosk() {
  # ALWAYS ON: Browser kiosk pointing to KIOSK_URL; autologin handled separately
  log "Configuring kiosk for URL: ${KIOSK_URL}"
  ensure_operator_user
  # Ensure a browser; prefer Firefox (present in repos), fallback to Chromium
  if ! command -v firefox &>/dev/null; then
    apt_retry apt-get install -y firefox-esr || apt_retry apt-get install -y firefox || true
  fi
  if ! command -v firefox &>/dev/null && ! command -v chromium &>/dev/null; then
    apt_retry apt-get install -y chromium || true
  fi

  su - operator -c 'mkdir -p ~/.config/autostart'
  cat >/home/operator/.config/autostart/kiosk.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Kiosk
X-GNOME-Autostart-enabled=true
Exec=/usr/local/bin/kiosk-launch.sh
EOF
  chown operator:operator /home/operator/.config/autostart/kiosk.desktop

  cat >/usr/local/bin/kiosk-launch.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Load system environment (so KIOSK_URL from /etc/environment.d is present)
if [ -r /etc/environment ]; then
  set -a; . /etc/environment; set +a
fi
if compgen -G "/etc/environment.d/*.conf" >/dev/null; then
  for f in /etc/environment.d/*.conf; do
    [ -r "$f" ] && { set -a; . "$f"; set +a; }
  done
fi

URL="${KIOSK_URL:-https://example.com}"

if command -v firefox &>/dev/null; then
  exec firefox --kiosk --private-window "$URL"
elif command -v chromium &>/dev/null; then
  exec chromium --kiosk --incognito "$URL"
else
  /usr/bin/xdg-open "$URL"
fi
EOF
  chmod +x /usr/local/bin/kiosk-launch.sh
}

configure_gnome_plain_desktop() {
  log "Configuring plain GNOME desktop layout…"
  ensure_packages_for_gnome_plain
  write_system_dconf_defaults
  enable_ding_extension_by_default
  install_site_builder_placeholder
  create_operator_desktop_items
  configure_gdm_autologin
  log "GNOME plain desktop ready."
}

# ------------------------------------------------------------------------------
# Install First Boot Script + Unit
# ------------------------------------------------------------------------------
install_intunenix_firstboot() {
  log "Installing & enabling IntuneNix first-boot service..."
  install -d -m 0755 /opt/intunenix /etc/intunenix
  install -m 0755 /root/darksite/firstboot.sh /opt/intunenix/firstboot.sh
  install -D -m 0644 /root/darksite/intunenix-firstboot.service \
    /etc/systemd/system/intunenix-firstboot.service
  systemctl daemon-reload
  systemctl enable intunenix-firstboot.service
}

# ------------------------------------------------------------------------------
# MasterControl: DB, API/Admin, NGINX reverse proxy (mTLS for /agent/*), AD helper
# ------------------------------------------------------------------------------
mc_setup() {
  log "Setting up MasterControl stack..."

  install -d -m 0755 /opt/mc/api
  install -d -m 0700 /opt/mc/ca
  install -d -m 0700 /etc/mastercontrol
  install -d -m 0755 /var/lib/mastercontrol
  install -d -m 0755 /var/log/mastercontrol
  install -d -m 0755 /opt/mc/api/templates
  install -d -m 0755 /opt/mc/api/static

  # PostgreSQL
  systemctl enable --now postgresql
  [[ -z "$MC_DB_PASS" ]] && MC_DB_PASS="$(randstr 48)" && log "Generated DB password for ${MC_DB_USER}"

  sudo -u postgres psql <<SQL >/dev/null 2>&1 || true
CREATE USER ${MC_DB_USER} WITH PASSWORD '${MC_DB_PASS}';
CREATE DATABASE ${MC_DB_NAME} OWNER ${MC_DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${MC_DB_NAME} TO ${MC_DB_USER};
SQL

  sudo -u postgres psql -d "${MC_DB_NAME}" -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' \
    || log "warning: could not create extension uuid-ossp"

  PGPASSWORD="$MC_DB_PASS" psql -h 127.0.0.1 -U "$MC_DB_USER" -d "$MC_DB_NAME" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE IF NOT EXISTS org_settings (
  id BOOLEAN PRIMARY KEY DEFAULT TRUE,
  initialized BOOLEAN NOT NULL DEFAULT FALSE,
  org_name TEXT,
  session_secret TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ad_domain TEXT,
  ad_admin TEXT,
  ad_ou TEXT
);
INSERT INTO org_settings (id, initialized, org_name, session_secret)
  VALUES (TRUE, FALSE, NULL, substr(md5(random()::text),1,32))
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_superadmin BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT UNIQUE NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  spec JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  cn TEXT UNIQUE NOT NULL,
  profile_id UUID REFERENCES profiles(id),
  enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
  token TEXT PRIMARY KEY,
  profile_id UUID REFERENCES profiles(id),
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE
);
SQL

  # Secrets (includes MC_API_BIND)
  cat >/etc/mastercontrol/secrets.env <<ENV
MC_DB_NAME=${MC_DB_NAME}
MC_DB_USER=${MC_DB_USER}
MC_DB_PASS=${MC_DB_PASS}
MC_ORG=${MC_ORG}
MC_DOMAIN=${MC_DOMAIN}
MC_API_BIND=${MC_API_BIND}
ENV
  chmod 600 /etc/mastercontrol/secrets.env

  # Root CA + server cert
  CA_DIR=/opt/mc/ca
  SERVER_DIR=/opt/mc/ca/server
  install -d -m 0700 "${SERVER_DIR}"

  if [[ ! -f "${CA_DIR}/root.key" ]]; then
    openssl genrsa -out "${CA_DIR}/root.key" 4096
    openssl req -x509 -new -nodes -key "${CA_DIR}/root.key" -sha256 -days 3650 \
      -subj "/C=${MC_COUNTRY}/ST=${MC_STATE}/L=${MC_LOCALITY}/O=${MC_ORG}/CN=${MC_ORG} Root CA" \
      -out "${CA_DIR}/root.crt"
  fi

  if [[ ! -f "${SERVER_DIR}/server.key" ]]; then
    openssl genrsa -out "${SERVER_DIR}/server.key" 4096
    cat >"${SERVER_DIR}/server.cnf" <<CONF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no
[ req_distinguished_name ]
C  = ${MC_COUNTRY}
ST = ${MC_STATE}
L  = ${MC_LOCALITY}
O  = ${MC_ORG}
CN = ${MC_DOMAIN}
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = ${MC_DOMAIN}
CONF
    openssl req -new -key "${SERVER_DIR}/server.key" -out "${SERVER_DIR}/server.csr" -config "${SERVER_DIR}/server.cnf"
    openssl x509 -req -in "${SERVER_DIR}/server.csr" -CA "${CA_DIR}/root.crt" -CAkey "${CA_DIR}/root.key" -CAcreateserial \
      -out "${SERVER_DIR}/server.crt" -days 825 -sha256 -extfile "${SERVER_DIR}/server.cnf" -extensions req_ext
  fi

  # Python venv + API (adds itsdangerous + python-multipart)
  python3 -m venv /opt/mc/api/venv
  /opt/mc/api/venv/bin/pip install --upgrade pip >/dev/null
  /opt/mc/api/venv/bin/pip install fastapi "uvicorn[standard]" jinja2 psycopg2-binary \
    pydantic cryptography python-dateutil passlib[bcrypt] starlette itsdangerous python-multipart >/dev/null

  cat >/opt/mc/api/app.py <<'PY'
import os
import uuid
import json
import datetime as dt
from typing import List, Optional

from fastapi import FastAPI, Request, Form, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

import psycopg2
import psycopg2.extras

# ---------------------- App & Templating ----------------------
app = FastAPI()
BASE_DIR = "/opt/mc/api"
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# ---------------------- DB Helpers ----------------------------
DB_NAME = os.getenv("MC_DB_NAME", "mastercontrol")
DB_USER = os.getenv("MC_DB_USER", "mcapi")
DB_PASS = os.getenv("MC_DB_PASS", "")
DB_HOST = os.getenv("MC_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("MC_DB_PORT", "5432"))

def db_conn():
    return psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )

def db_safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default

# ---------------------- Simple Pages --------------------------
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/healthz")
def healthz():
    # Soft DB check: OK even if DB is still starting.
    ok = db_safe(lambda: bool(db_conn().close() or True), default=False)
    return PlainTextResponse("ok" if ok else "degraded", status_code=200)

# ---------------------- Dashboard -----------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    def counts():
        with db_conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT COALESCE((SELECT COUNT(*) FROM devices),0) AS devices")
            devices = cur.fetchone()["devices"]
            cur.execute("SELECT COALESCE((SELECT COUNT(*) FROM profiles),0) AS profiles")
            profiles = cur.fetchone()["profiles"]
            cur.execute("SELECT * FROM org_settings WHERE id=TRUE LIMIT 1")
            org = cur.fetchone() or {"org_name": "MasterControl", "ad_domain": None}
            return devices, profiles, org
    devices, profiles, org = db_safe(counts, default=(0, 0, {"org_name":"MasterControl","ad_domain":None}))
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "devices": devices, "profiles": profiles, "org": org},
    )

# ---------------------- Profiles ------------------------------
@app.get("/profiles", response_class=HTMLResponse)
def profiles_page(request: Request):
    def _load():
        with db_conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT name, version, created_at FROM profiles ORDER BY created_at DESC")
            return cur.fetchall()
    profiles = db_safe(_load, default=[])
    return templates.TemplateResponse("profiles.html", {"request": request, "profiles": profiles})

@app.post("/profiles/new")
def profiles_new(name: str = Form(...), spec: str = Form(...)):
    try:
        json.loads(spec)  # validate
    except Exception:
        return PlainTextResponse("Spec must be valid JSON", status_code=400)
    def _upsert():
        with db_conn() as c, c.cursor() as cur:
            cur.execute(
                """
                INSERT INTO profiles(name, spec)
                VALUES (%s, %s::jsonb)
                ON CONFLICT (name) DO UPDATE
                SET version = profiles.version + 1, spec = EXCLUDED.spec
                """,
                (name, spec),
            )
    db_safe(_upsert)
    return RedirectResponse(url="/profiles", status_code=303)

# ---------------------- Devices -------------------------------
@app.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    def _load():
        with db_conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT d.cn, p.name AS profile, d.enrolled_at, d.last_seen
                FROM devices d
                LEFT JOIN profiles p ON p.id = d.profile_id
                ORDER BY d.enrolled_at DESC
            """)
            devs = cur.fetchall()
            cur.execute("SELECT name FROM profiles ORDER BY name")
            profs = [r["name"] for r in cur.fetchall()]
            return devs, profs
    devices, profiles = db_safe(_load, default=([], []))
    return templates.TemplateResponse(
        "devices.html", {"request": request, "devices": devices, "profiles": profiles}
    )

@app.post("/devices/assign")
def devices_assign(cn: str = Form(...), profile: str = Form(...)):
    def _assign():
        with db_conn() as c, c.cursor() as cur:
            cur.execute("SELECT id FROM profiles WHERE name=%s LIMIT 1", (profile,))
            row = cur.fetchone()
            if not row:
                return False
            pid = row[0]
            cur.execute(
                "UPDATE devices SET profile_id=%s WHERE cn=%s",
                (pid, cn),
            )
            return True
    ok = db_safe(_assign, default=False)
    return RedirectResponse(url="/devices", status_code=303 if ok else 302)

# ---------------------- Tokens (Enroll) -----------------------
@app.post("/tokens/new")
def tokens_new(profile: str = Form(...), ttl: str = Form("24h")):
    # Accept "24h", "7d" etc.
    hours = 24
    if ttl.endswith("h"):
        hours = int(ttl[:-1] or 24)
    elif ttl.endswith("d"):
        hours = int(ttl[:-1] or 1) * 24
    token = str(uuid.uuid4())
    def _insert():
        with db_conn() as c, c.cursor() as cur:
            cur.execute("SELECT id FROM profiles WHERE name=%s LIMIT 1", (profile,))
            row = cur.fetchone()
            if not row:
                return False
            pid = row[0]
            cur.execute(
                "INSERT INTO enroll_tokens(token, profile_id, expires_at) VALUES (%s, %s, now() + interval '%s hour')",
                (token, pid, hours),
            )
            return True
    ok = db_safe(_insert, default=False)
    if not ok:
        return JSONResponse({"error": "profile not found"}, status_code=404)
    return JSONResponse({"token": token, "expires_in_hours": hours})

# Agent enrollment (no client cert path)
@app.post("/enroll")
async def enroll(request: Request):
    data = await request.json()
    cn = data.get("cn")
    token = data.get("token")
    if not cn or not token:
        return JSONResponse({"error": "cn and token required"}, status_code=400)

    def _enroll():
        with db_conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT profile_id FROM enroll_tokens WHERE token=%s AND used=false AND expires_at>now()",
                (token,),
            )
            row = cur.fetchone()
            if not row:
                return False
            pid = row["profile_id"]
            cur.execute(
                """
                INSERT INTO devices(cn, profile_id)
                VALUES (%s, %s)
                ON CONFLICT (cn) DO UPDATE SET profile_id=EXCLUDED.profile_id, last_seen=now()
                """,
                (cn, pid),
            )
            cur.execute("UPDATE enroll_tokens SET used=true WHERE token=%s", (token,))
            return True

    ok = db_safe(_enroll, default=False)
    return JSONResponse({"status": "ok" if ok else "invalid_token"}, status_code=200 if ok else 400)

# ---------------------- AD Settings ---------------------------
@app.get("/settings/ad", response_class=HTMLResponse)
def settings_ad_get(request: Request):
    def _load():
        with db_conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM org_settings WHERE id=TRUE LIMIT 1")
            row = cur.fetchone() or {}
            return row
    s = db_safe(_load, default={})
    return templates.TemplateResponse(
        "settings_ad.html", {"request": request, "s": s, "last_log": "—"}
    )

@app.post("/settings/ad", response_class=HTMLResponse)
def settings_ad_post(
    request: Request,
    ad_domain: str = Form(...),
    ad_admin: str = Form(...),
    ad_password: str = Form(...),
    ad_ou: Optional[str] = Form(None),
    join_now: Optional[str] = Form(None),
):
    def _save():
        with db_conn() as c, c.cursor() as cur:
            cur.execute(
                """
                INSERT INTO org_settings(id, initialized, org_name, session_secret, ad_domain, ad_admin, ad_ou)
                VALUES (TRUE, TRUE, COALESCE((SELECT org_name FROM org_settings WHERE id=TRUE),'MasterControl'),
                        COALESCE((SELECT session_secret FROM org_settings WHERE id=TRUE), substr(md5(random()::text),1,32)),
                        %s, %s, %s)
                ON CONFLICT (id) DO UPDATE
                SET ad_domain=EXCLUDED.ad_domain, ad_admin=EXCLUDED.ad_admin, ad_ou=EXCLUDED.ad_ou
                """,
                (ad_domain, ad_admin, ad_ou),
            )
    db_safe(_save)

    # (optional) Domain join would be invoked here; we only persist for now.
    return RedirectResponse(url="/settings/ad", status_code=303)

# ---------------------- Auth stubs ----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "msg": None})

@app.post("/login")
def login_post(username: str = Form(...), password: str = Form(...)):
    # Stub: Accept anything (replace with real auth later)
    return RedirectResponse(url="/dashboard", status_code=303)

@app.get("/logout")
def logout():
    return RedirectResponse(url="/login", status_code=303)
PY

  cat >/opt/mc/api/run.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source /etc/mastercontrol/secrets.env || true
MC_API_BIND="${MC_API_BIND:-127.0.0.1:8000}"
export MC_DB_NAME MC_DB_USER MC_DB_PASS
exec /opt/mc/api/venv/bin/uvicorn app:app --host "${MC_API_BIND%%:*}" --port "${MC_API_BIND##*:}" --workers 2
SH
  chmod +x /opt/mc/api/run.sh

  cat >/etc/systemd/system/mastercontrol-api.service <<'UNIT'
[Unit]
Description=MasterControl API + Admin UI
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/mastercontrol/secrets.env
WorkingDirectory=/opt/mc/api
ExecStart=/opt/mc/api/run.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now mastercontrol-api.service

  # Minimal templates & CSS
  cat >/opt/mc/api/templates/base.html <<'HTML'
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MasterControl</title>
<link rel="stylesheet" href="/static/style.css">
</head><body>
<nav>
  <a href="/dashboard">Dashboard</a>
  <a href="/profiles">Profiles</a>
  <a href="/devices">Devices</a>
  <a href="/settings/ad">AD Settings</a>
  <span style="flex:1"></span>
  <a href="/logout">Logout</a>
</nav>
<main>
  {% block content %}{% endblock %}
</main>
</body></html>
HTML

  cat >/opt/mc/api/templates/setup.html <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Setup - MasterControl</title>
<link rel="stylesheet" href="/static/style.css"></head><body class="center">
<h1>MasterControl · Initial Setup</h1>
<form method="post" class="card">
  <h2>Organization</h2>
  <label>Organization Name <input name="org_name" required></label>
  <h2>Admin User</h2>
  <label>Email <input type="email" name="admin_email" required></label>
  <label>Username <input name="admin_user" required></label>
  <label>Password <input type="password" name="admin_pass" required></label>
  <h2>Active Directory (optional)</h2>
  <label>AD Domain <input name="ad_domain"></label>
  <label>AD Admin User <input name="ad_admin"></label>
  <label>AD Admin Password <input type="password" name="ad_password"></label>
  <label>Computer OU (optional) <input name="ad_ou" placeholder="OU=Computers,DC=corp,DC=example,DC=com"></label>
  <label class="chk"><input type="checkbox" name="join_now" value="1"> Join domain now</label>
  <button type="submit">Finish Setup</button>
</form>
</body></html>
HTML

  cat >/opt/mc/api/templates/login.html <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Login - MasterControl</title>
<link rel="stylesheet" href="/static/style.css"></head><body class="center">
<h1>MasterControl · Login</h1>
<form method="post" class="card">
  {% if msg %}<div class="msg">{{ msg }}</div>{% endif %}
  <label>Username <input name="username" required></label>
  <label>Password <input type="password" name="password" required></label>
  <button type="submit">Login</button>
</form>
</body></html>
HTML

  cat >/opt/mc/api/templates/dashboard.html <<'HTML'
{% extends "base.html" %}{% block content %}
<h1>{{ org.org_name or "MasterControl" }}</h1>
<div class="grid">
  <div class="tile"><h2>Devices</h2><div class="big">{{ devices }}</div></div>
  <div class="tile"><h2>Profiles</h2><div class="big">{{ profiles }}</div></div>
  <div class="tile"><h2>AD Domain</h2><div>{{ org.ad_domain or "Not configured" }}</div></div>
</div>
<section>
  <h2>Quick Issue Enrollment Token</h2>
  <form action="/tokens/new" method="post" class="row">
    <label>Profile <input name="profile" placeholder="e.g. default" required></label>
    <label>TTL <input name="ttl" value="24h"></label>
    <button type="submit">Issue</button>
  </form>
  <p>Returns JSON with a token you can pass to the agent enroll call.</p>
</section>
{% endblock %}
HTML

  cat >/opt/mc/api/templates/profiles.html <<'HTML'
{% extends "base.html" %}{% block content %}
<h1>Profiles</h1>
<form method="post" action="/profiles/new" class="card">
  <label>Name <input name="name" required></label>
  <label>Spec (JSON) <textarea name="spec" rows="10" placeholder='{"packages":{"apt_install":["vim","curl"]},"security":{"auto_updates":true}}'></textarea></label>
  <button type="submit">Create/Update</button>
</form>
<table class="list"><tr><th>Name</th><th>Version</th><th>Created</th></tr>
{% for p in profiles %}
<tr><td>{{p.name}}</td><td>{{p.version}}</td><td>{{p.created_at}}</td></tr>
{% endfor %}
</table>
{% endblock %}
HTML

  cat >/opt/mc/api/templates/devices.html <<'HTML'
{% extends "base.html" %}{% block content %}
<h1>Devices</h1>
<table class="list"><tr><th>CN</th><th>Profile</th><th>Enrolled</th><th>Last Seen</th></tr>
{% for d in devices %}
<tr><td>{{d.cn}}</td><td>{{d.profile or "-"}}</td><td>{{d.enrolled_at}}</td><td>{{d.last_seen or "-"}}</td></tr>
{% endfor %}
</table>
<h2>Assign Profile</h2>
<form method="post" action="/devices/assign" class="row">
  <label>Device CN <input name="cn" required></label>
  <label>Profile
    <select name="profile">
      {% for p in profiles %}<option>{{p}}</option>{% endfor %}
    </select>
  </label>
  <button type="submit">Assign</button>
</form>
{% endblock %}
HTML

  cat >/opt/mc/api/templates/settings_ad.html <<'HTML'
{% extends "base.html" %}{% block content %}
<h1>Active Directory</h1>
<form method="post" class="card">
  <label>AD Domain <input name="ad_domain" value="{{ (s.ad_domain or '')|e }}" required></label>
  <label>AD Admin User <input name="ad_admin" value="{{ (s.ad_admin or '')|e }}" required></label>
  <label>AD Admin Password <input type="password" name="ad_password" required></label>
  <label>Computer OU (optional) <input name="ad_ou" value="{{ (s.ad_ou or '')|e }}"></label>
  <label class="chk"><input type="checkbox" name="join_now" value="1"> Join/Retry join now</label>
  <button type="submit">Save</button>
</form>
<h2>Last Join Output</h2>
<pre class="log">{{ last_log }}</pre>
{% endblock %}
HTML

  cat >/opt/mc/api/static/style.css <<'CSS'
:root { --bg:#0b0f14; --fg:#e8eef2; --mut:#9fb3c8; --acc:#6aa0ff; --card:#111722; --line:#1c2432;}
*{box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Inter,Arial;}
body{margin:0;background:var(--bg);color:var(--fg);}
nav{display:flex;gap:1rem;align-items:center;padding:12px 18px;border-bottom:1px solid var(--line);}
nav a{color:var(--mut);text-decoration:none} nav a:hover{color:var(--fg)}
main{padding:24px;max-width:980px;margin:0 auto;}
.center{display:grid;place-items:center;height:100vh;background:var(--bg);color:var(--fg)}
.card{display:grid;gap:.6rem;background:var(--card);padding:20px;border:1px solid var(--line);border-radius:10px;min-width:360px}
label{display:grid;gap:.3rem;color:var(--mut)}
input,textarea,select{padding:10px;border-radius:8px;border:1px solid var(--line);background:#0e1520;color:var(--fg)}
button{padding:10px 14px;border-radius:8px;border:1px solid var(--acc);background:transparent;color:var(--fg);cursor:pointer}
button:hover{background:#0e1a2b}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
.tile{background:var(--card);padding:16px;border:1px solid var(--line);border-radius:10px}
.big{font-size:30px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:end}
.list{width:100%;border-collapse:collapse;margin-top:14px}
.list th,.list td{border-bottom:1px solid var(--line);padding:8px 6px;text-align:left}
.chk{display:flex;align-items:center;gap:10px}
.log{background:#0e1520;border:1px solid var(--line);padding:12px;border-radius:8px;white-space:pre-wrap;max-height:320px;overflow:auto}
CSS

  # ----------------------------------------------------------------------------
  # NGINX reverse proxy (client cert required for /agent/*)
  # ----------------------------------------------------------------------------
  CA_DIR=/opt/mc/ca
  SERVER_DIR=/opt/mc/ca/server

  cat >/etc/nginx/sites-available/mastercontrol.conf <<NGX
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }

server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name ${MC_DOMAIN};

  ssl_certificate     ${SERVER_DIR}/server.crt;
  ssl_certificate_key ${SERVER_DIR}/server.key;
  ssl_protocols       TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_session_cache   shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_session_tickets off;

  ssl_client_certificate ${CA_DIR}/root.crt;
  ssl_verify_client optional;

  proxy_http_version 1.1;
  proxy_set_header Host              \$host;
  proxy_set_header X-Real-IP         \$remote_addr;
  proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Host  \$host;
  proxy_set_header Upgrade           \$http_upgrade;
  proxy_set_header Connection        \$connection_upgrade;
  proxy_read_timeout   60s;
  proxy_connect_timeout 60s;
  proxy_send_timeout   60s;

  location /enroll { proxy_pass http://${MC_API_BIND}; }
  location /agent/ {
    if (\$ssl_client_verify != SUCCESS) { return 401; }
    proxy_set_header X-Client-Verified \$ssl_client_verify;
    proxy_set_header X-Client-DN       \$ssl_client_s_dn;
    proxy_pass http://${MC_API_BIND};
  }
  location / { proxy_pass http://${MC_API_BIND}; }
  location = /healthz { proxy_pass http://${MC_API_BIND}/healthz; }
}

server {
  listen 80;
  listen [::]:80;
  server_name ${MC_DOMAIN};
  return 301 https://\$host\$request_uri;
}
NGX

  rm -f /etc/nginx/sites-enabled/default || true
  ln -sf /etc/nginx/sites-available/mastercontrol.conf /etc/nginx/sites-enabled/mastercontrol.conf
  nginx -t
  systemctl enable --now nginx

  # Optional CLI
  cat >/usr/local/bin/mcctl <<'MC'
#!/usr/bin/env bash
set -euo pipefail
CMD="${1:-}"; shift || true
source /etc/mastercontrol/secrets.env
psql_cmd(){ sudo -u postgres psql -tA -d "${MC_DB_NAME}" -c "$1"; }
case "$CMD" in
  new-profile) name="${1:-}"; file="${2:-}"; [[ -z "$name"||-z "$file" ]] && { echo "usage: mcctl new-profile NAME FILE.json"; exit 1; }
    spec="$(tr -d '\n' <"$file")"
    psql_cmd "INSERT INTO profiles(name,spec) VALUES('$name','${spec}'::jsonb) ON CONFLICT (name) DO UPDATE SET version=profiles.version+1,spec='${spec}'::jsonb;"
    echo "OK";;
  issue-token) prof="${1:-}"; ttl="${2:-24h}"; [[ -z "$prof" ]] && { echo "usage: mcctl issue-token PROFILE [TTL]"; exit 1; }
    pid="$(psql_cmd "SELECT id FROM profiles WHERE name='${prof}' LIMIT 1;")"
    [[ -z "$pid" ]] && { echo "Profile not found"; exit 1; }
    tok="$(uuidgen | tr 'A-Z' 'a-z')"
    case "$ttl" in *h) int="${ttl%h} hour";; *d) int="${ttl%d} day";; *) int="24 hour";; esac
    sudo -u postgres psql -d "${MC_DB_NAME}" -c "INSERT INTO enroll_tokens(token,profile_id,expires_at) VALUES ('${tok}','${pid}', now()+ interval '${int}');"
    echo "TOKEN: ${tok}";;
  ls-devices) sudo -u postgres psql -d "${MC_DB_NAME}" -c "SELECT cn,profile_id,enrolled_at,last_seen FROM devices ORDER BY enrolled_at DESC;";;
  *) echo "mcctl new-profile|issue-token|ls-devices";;
esac
MC
  chmod +x /usr/local/bin/mcctl

  log "MasterControl ready at https://${MC_DOMAIN}"
}

# --------------------------- Enable Services ---------------------------
enable_services() {
  systemctl enable qemu-guest-agent ssh rsyslog chrony || true
  if [[ "$USE_CLOUD_INIT" == "true" ]]; then
    enable_if_exists cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service
  fi
}

# --------------------------- template hygiene ---------------------------
cleanup_identity() {
  log "Cleaning identity for template safety..."
  truncate -s 0 /etc/machine-id || true
  rm -f /var/lib/dbus/machine-id || true
  ln -sf /etc/machine-id /var/lib/dbus/machine-id || true

  # re-generate host keys noninteractively
  rm -f /etc/ssh/ssh_host_* || true
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure openssh-server || true
}

final_cleanup() {
  log "Final cleanup..."
  apt-get -y autoremove || true
  apt-get -y clean || true
  rm -rf /tmp/* /var/tmp/* || true
  find /var/log -type f -exec truncate -s 0 {} \; || true
}

# ------------------------------ RUNLIST --------------------------------
log "BEGIN postinstall"
wait_for_network
update_and_upgrade
install_base_packages
maybe_install_desktop
enforce_wayland_defaults
maybe_install_cloud_init
setup_vim_config
write_bashrc
configure_ufw_firewall
write_tmux_conf
setup_users_and_ssh
setup_python_env
configure_dns_hosts
install_custom_scripts
enable_services

# GNOME desktop & kiosk (always)
configure_gnome_plain_desktop
configure_kiosk

# App stack
mc_setup

# First-boot driver (runs next boot)
install_intunenix_firstboot

# Template hygiene + cleanup
cleanup_identity
final_cleanup

systemctl set-default graphical.target || true
systemctl unmask gdm3.service gdm.service sddm.service lightdm.service display-manager.service || true

# Disable bootstrap and power off cleanly
log "Disabling bootstrap service..."
systemctl disable bootstrap.service || true
rm -f /etc/systemd/system/bootstrap.service
rm -f /etc/systemd/system/multi-user.target.wants/bootstrap.service

log "Postinstall complete. Powering off cleanly..."
sync
systemctl poweroff --no-wall
EOSCRIPT
chmod +x "$DARKSITE_DIR/postinstall.sh"

# -----------------------------------------------------------------------------
# bootstrap.service  (runs postinstall once on first boot)
# -----------------------------------------------------------------------------
log "Writing bootstrap.service..."
cat > "$DARKSITE_DIR/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script (One-time)
After=network-online.target cloud-init.target
Wants=network-online.target
ConditionPathExists=/root/darksite/postinstall.sh

[Service]
Type=oneshot
Environment=DEBIAN_FRONTEND=noninteractive
# non-fatal wait for default route + ping
ExecStartPre=/bin/bash -lc 'for i in {1..60}; do ip route show default &>/dev/null && ping -c1 -W1 1.1.1.1 &>/dev/null && exit 0; sleep 2; done; exit 0'
# trace to live log
ExecStart=/bin/bash -lc '\
  export PS4="+ [$(date +%F\ %T)] [\${BASH_SOURCE##*/}:\${LINENO}] "; \
  exec > >(tee -a /var/log/bootstrap-live.log) 2>&1; \
  set -Eeuo pipefail; \
  bash -x /root/darksite/postinstall.sh \
'
TimeoutStartSec=3600
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

# =============================================================================
# Preseed (disk autodetect + networking + profile + copy darksite + enable bootstrap)
# =============================================================================
log "Creating preseed.cfg…"

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
) ;;
  gnome-min)
    PROFILEBLOCK=$(cat <<'EOF'
# Minimal GNOME
tasksel tasksel/first multiselect standard
d-i pkgsel/include string gnome-core gdm3 gnome-terminal network-manager
d-i pkgsel/ignore-recommends boolean true
d-i pkgsel/upgrade select none
EOF
) ;;
  gnome-full)
    PROFILEBLOCK=$(cat <<'EOF'
# Full GNOME
tasksel tasksel/first multiselect standard, desktop, gnome-desktop, ssh-server
d-i pkgsel/ignore-recommends boolean false
d-i pkgsel/upgrade select none
EOF
) ;;
  *) error_log "Unknown INSTALL_PROFILE: $INSTALL_PROFILE"; exit 1 ;;
esac

cat > "$CUSTOM_DIR/$PRESEED_FILE" <<EOF
# Locale, keyboard, time
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us
d-i time/zone string America/Toronto
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true

# Early command: auto-select first non-removable disk and point partman+grub at it
d-i preseed/early_command string \
  DISK="\$(list-devices disk | while read d; do b=\$(basename "\$d"); \
    if [ -r "/sys/class/block/\$b/removable" ] && [ "\$(cat /sys/class/block/\$b/removable)" = "1" ]; then continue; fi; \
    echo "\$d"; break; done)"; \
  [ -n "\$DISK" ] || DISK="\$(list-devices disk | head -n1)"; \
  logger -t preseed "Autoselected install disk: \$DISK"; \
  echo "partman-auto/disk string \$DISK" | debconf-set-selections; \
  echo "grub-installer/bootdev string \$DISK" | debconf-set-selections; \
  echo "grub-installer/choose_bootdev select \$DISK" | debconf-set-selections

# Networking
$NETBLOCK

# Mirrors
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string
d-i apt-setup/use_mirror boolean false
d-i apt-setup/non-free boolean true
d-i apt-setup/contrib boolean true
d-i hw-detect/load_firmware boolean true

# Throwaway user (postinstall makes real users)
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/username string debian
d-i passwd/user-fullname string Debian User
d-i passwd/user-password password debian
d-i passwd/user-password-again password debian

# Disk (guided LVM, full disk)
d-i partman-auto/method string lvm
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-lvm/confirm_write_new_label boolean true
d-i partman-auto-lvm/guided_size string max
d-i partman/default_filesystem string ext4

# Tasks / packages
$PROFILEBLOCK

# Strongly prevent installer from auto-pulling a desktop
d-i pkgsel/run_tasksel boolean false

d-i grub-installer/bootdev string /dev/sda
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/force-efi-extra-removable boolean true
d-i finish-install/keep-consoles boolean false
d-i finish-install/exit-installer boolean true

d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true
d-i cdrom-detect/eject boolean true

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

d-i debian-installer/exit/poweroff boolean true
EOF

# Normalize preseed endings
sed -i 's/\r$//' "$CUSTOM_DIR/$PRESEED_FILE"

# =============================================================================
# Boot menus (BIOS + UEFI) & ISO rebuild
# =============================================================================
log "Patching isolinux (BIOS)…"
TXT_CFG="$CUSTOM_DIR/isolinux/txt.cfg"
ISOLINUX_CFG="$CUSTOM_DIR/isolinux/isolinux.cfg"
cat >> "$TXT_CFG" <<EOF
label auto
  menu label ^Install (Unattended)
  kernel /install.amd/vmlinuz
  append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz preseed/file=/cdrom/$PRESEED_FILE ---
EOF
sed -i 's/^default .*/default auto/' "$ISOLINUX_CFG" || true

log "Patching GRUB (UEFI)…"
GRUB_CFG="$CUSTOM_DIR/boot/grub/grub.cfg"
if [[ -f "$GRUB_CFG" ]]; then
  awk -v preseed="$PRESEED_FILE" '
    BEGIN{
      print "set default=0"
      print "set timeout=3"
      print ""
      print "menuentry '\''Install (Unattended)'\'' {"
      print "    linux   /install.amd/vmlinuz auto=true priority=critical preseed/file=/cdrom/" preseed " ---"
      print "    initrd  /install.amd/initrd.gz"
      print "}"
      printed=1
    }
    { print }' "$GRUB_CFG" > "${GRUB_CFG}.new" && mv "${GRUB_CFG}.new" "$GRUB_CFG"
else
  error_log "Missing $GRUB_CFG (unexpected ISO layout)."
fi

log "Regenerating md5sum.txt…"
(
  cd "$CUSTOM_DIR"
  rm -f md5sum.txt
  find . -type f ! -name md5sum.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 md5sum > md5sum.txt
)

log "Rebuilding ISO…"
xorriso -as mkisofs \
  -o "$OUTPUT_ISO" \
  -r -J -joliet-long -l \
  -b isolinux/isolinux.bin \
  -c isolinux/boot.cat \
  -no-emul-boot -boot-load-size 4 -boot-info-table \
  -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
  -eltorito-alt-boot \
  -e boot/grub/efi.img \
  -no-emul-boot -isohybrid-gpt-basdat \
  "$CUSTOM_DIR"

mv "$OUTPUT_ISO" "$FINAL_ISO"
log "ISO ready: $FINAL_ISO"

# =============================================================================
# Upload ISO, create VM, run installer
# =============================================================================
log "Uploading ISO to $PROXMOX_HOST…"
scp -q "$FINAL_ISO" "root@${PROXMOX_HOST}:/var/lib/vz/template/iso/"
FINAL_ISO_BASENAME="$(basename "$FINAL_ISO")"

log "Creating VM $VMID on $PROXMOX_HOST…"
ssh root@"$PROXMOX_HOST" \
  VMID="$VMID" VMNAME="$BASE_VMNAME" FINAL_ISO="$FINAL_ISO_BASENAME" \
  VM_STORAGE="$VM_STORAGE" ISO_STORAGE="$ISO_STORAGE" \
  DISK_SIZE_GB="$DISK_SIZE_GB" MEMORY_MB="$MEMORY_MB" CORES="$CORES" \
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
# Pivot boot after installer powers off, start OS to run postinstall
# =============================================================================
log "Waiting for VM $VMID to power off after installer…"
SECONDS=0; TIMEOUT=3600
while ssh root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { error_log "Timeout waiting for installer shutdown"; exit 1; }
  sleep 15
done

DESC="${BASE_FQDN}-${NETWORK_MODE}"
log "Detach ISO, set boot=scsi0, set description, start VM for postinstall…"
ssh root@"$PROXMOX_HOST" 'bash -s --' "$VMID" "$VM_STORAGE" "$DESC" <<'EOSSH'
set -euo pipefail
VMID="$1"; VM_STORAGE="$2"; VM_DESC="$3"
qm set "$VMID" --delete ide2 || true
qm set "$VMID" --boot order=scsi0
qm set "$VMID" --description "$VM_DESC"
qm start "$VMID"
EOSSH

# =============================================================================
# Wait for postinstall poweroff, then start VM so it's up and ready
# =============================================================================
log "Waiting for VM $VMID to power off after postinstall…"
SECONDS=0; TIMEOUT=5400
while ssh root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  (( SECONDS > TIMEOUT )) && { error_log "Timeout waiting for postinstall shutdown"; exit 1; }
  sleep 20
done

log "Starting VM $VMID (final)…"
ssh root@"$PROXMOX_HOST" "qm start $VMID"

log "Done. The VM has installed, ran postinstall, and is now running."
