#!/bin/bash
set -euxo pipefail

# === Logging Setup ===
LOGFILE="${LOGFILE:-/var/log/postinstall.log}"  # Ensure LOGFILE is set
exec > >(tee -a "$LOGFILE") 2>&1
trap 'echo "[✖] Postinstall failed on line $LINENO"; exit 1' ERR
log() { echo "[INFO] $(date '+%F %T') — $*"; }

log "Starting postinstall setup..."
# === Function Definitions ===

remove_cd_sources() {
  sed -i '/cdrom:/d' /etc/apt/sources.list
}

install_packages() {
  # Update apt repository and install essential packages
  apt update
  apt install -y --no-install-recommends cloud-init openssh-server sudo \
    gnome-session gnome-terminal gdm3 gnome-settings-daemon gnome-control-center firefox-esr nautilus \
    xwayland ufw vim dbus-user-session \
    gtk2-engines-murrine gtk2-engines-pixbuf gnome-tweaks

  # Enable GDM (GNOME Display Manager) but don't start it yet
  systemctl enable gdm3

  log "[✔] GNOME Desktop environment installed and GDM enabled."
}

harden_ssh() {
  mkdir -p /etc/ssh/sshd_config.d/
  cat > /etc/ssh/sshd_config.d/hardening.conf <<EOF
PasswordAuthentication no
PermitRootLogin no
EOF
  systemctl restart ssh
}

create_user() {
  local user=$1
  local ssh_key=$2

  if ! id "$user" &>/dev/null; then
    adduser --disabled-password --gecos "" "$user"
    mkdir -p /home/"$user"/.ssh
    echo "$ssh_key" > /home/"$user"/.ssh/authorized_keys
    chmod 700 /home/"$user"/.ssh
    chmod 600 /home/"$user"/.ssh/authorized_keys
    chown -R "$user:$user" /home/"$user"/.ssh
    echo "$user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$user"
  fi
}

# === Create Users (SSH and sudo access) ===
create_user "todd" "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDS35Kk/U8c0iff0Z70gAfd2wzmb5F6X6V2QT85FIua+CQzIV5qbjA+SodaZU0w30JdcK+aBwLoHcPQF0BZrZesOt727cdY1SoFzeeOZAl3DSGsAxk2HDveHfFbaiaB+Y67bvQhX4Ao7bR98wA9EDmJKLrFUodLU5x8MSnw0ahg4F4PBeDIRlmNk45PV42yBF5UXtuohlMytFeRIc4wLTyCek2knV3hst5NUMZ0w+I9s/kUyMGVI9IlGxeZcrv96z0i5bu1SAbgUvY3Mr8tYeMhW4h/c1Y/luPKx97U/OwfAm+OvKCMnAVYMmFO7dOmi+U/pCRkmU7E4Z3BuACkhJQCRWS2M3kDBoRgpWOMhENgnmkQyVxTmvazFn6Fg9Jw2Mhz1EqZd8hAeL7+oQf5W9P/H06yiziai2m7ZpRCDuZ57SMugDx7ZFQtAZQOPpz2NFgtvo0JPoJSHl908wzLsjLTXXIcOMbdhyhKxOU6oOTnWrxKfPrZNexNSreOT5XrJlwum7vApVabk2p9okWWRY63yE3oKHCgb7tlcaBA9EDsleVNtG9otMAjVAPazRyUkMHaf7am+2A4xyjXM/1JHzUeIABNQClAAsWmbgoRavU8s0/Gu22m28/qW9xP8Lp7MoGIOl/mbXb73PhxTZXx7MZs8csjW7ZlNB3zCpwzMk3okQ== todd@onyx todd@host"

setup_ufw() {
  ufw allow 22/tcp
  ufw --force enable
}

reset_cloud_init() {
  cloud-init clean --logs
  rm -rf /var/lib/cloud/
  rm -f /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit.conf
}

regenerate_identity() {
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id || true
  ln -s /etc/machine-id /var/lib/dbus/machine-id
  hostnamectl set-hostname "node-$(uuidgen | cut -c1-8)"
  echo "$(hostname)" > /etc/hostname
  rm -f /etc/ssh/ssh_host_*
}

cleanup_logs() {
  find /var/log -type f -not -name 'postinstall.log' -delete
  rm -rf /tmp/* /var/tmp/*
}

self_destruct() {
  log "Disabling and removing bootstrap.service..."
  systemctl disable bootstrap.service || true
  rm -f /etc/systemd/system/bootstrap.service
  systemctl daemon-reload
}

# === Execution Flow ===

remove_cd_sources
install_packages
harden_ssh
setup_ufw
reset_cloud_init
regenerate_identity
cleanup_logs
self_destruct

log "[✔] Postinstall complete — rebooting..."
#reboot
poweroff
