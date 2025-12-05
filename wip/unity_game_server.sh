
#!/bin/bash
set -euo pipefail

LOG_FILE="/root/install.txt"
exec &> >(tee -a "$LOG_FILE")

log() { echo "[INFO] $(date): $1"; }
error_log() { echo "[ERROR] $(date): $1" >&2; }

# === CONFIGURATION ===
#ISO_ORIG="/root/debian-12.10.0-amd64-DVD-1.iso"
#ISO_ORIG="/root/debian-12.10.0-amd64-DVD-1.iso"
ISO_ORIG="/root/debian-12.10.0-amd64-netinst.iso"
BUILD_DIR="/root/debian-iso"
CUSTOM_DIR="$BUILD_DIR/custom"
MOUNT_DIR="/mnt/iso"
DARKSITE_DIR="$CUSTOM_DIR/darksite"
PRESEED_FILE="preseed.cfg"
OUTPUT_ISO="$BUILD_DIR/debian-12-unity.iso"
FINAL_ISO="/root/debian-12-unity.iso"
PROXMOX_HOST="10.200.0.100"
VMID="${1:-}"

if [ -z "$VMID" ]; then
  error_log "Usage: $0 <VMID>"
  exit 1
fi

log "[*] Using VMID $VMID"

log "[*] Cleaning up..."
umount "$MOUNT_DIR" 2>/dev/null || true
rm -rf "$BUILD_DIR"
mkdir -p "$CUSTOM_DIR" "$MOUNT_DIR" "$DARKSITE_DIR"

log "[*] Mounting ISO..."
mount -o loop "$ISO_ORIG" "$MOUNT_DIR"

log "[*] Copying ISO contents..."
cp -a "$MOUNT_DIR/"* "$CUSTOM_DIR/"
cp -a "$MOUNT_DIR/.disk" "$CUSTOM_DIR/"
umount "$MOUNT_DIR"

mkdir -p "$DARKSITE_DIR/opt/unityserver"
UNITY_DIR="$DARKSITE_DIR/opt/unityserver"
rm -rf "$UNITY_DIR"
mkdir -p "$UNITY_DIR/Data" "$UNITY_DIR/Scenes" "$UNITY_DIR/Scripts"
echo "Dummy Asset Data" > "$UNITY_DIR/Data/readme.txt"
echo "Dummy Scene Data" > "$UNITY_DIR/Scenes/sample_scene.unity"
echo "Dummy Script Content" > "$UNITY_DIR/Scripts/sample_script.cs"

cat > "$UNITY_DIR/server.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 7777

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    printf("[INFO] Starting Unity Dummy Server on port %d...\n", PORT);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) { perror("[ERROR] Socket failed"); exit(EXIT_FAILURE); }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[ERROR] Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) {
        perror("[ERROR] Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Unity Dummy Server ready. Waiting for players...\n");
    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket >= 0) {
            printf("[INFO] Player connected: %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            send(new_socket, "Welcome to Dummy Unity Server!\n", 30, 0);
            close(new_socket);
        }
    }
}
EOF

gcc "$UNITY_DIR/server.c" -o "$UNITY_DIR/server.x86_64" -static
rm "$UNITY_DIR/server.c"
chmod +x "$UNITY_DIR/server.x86_64"

log "[*] Creating Unity systemd unit..."
mkdir -p "$DARKSITE_DIR/etc/systemd/system"
cat > "$DARKSITE_DIR/etc/systemd/system/unityserver.service" <<'EOF'
[Unit]
Description=Unity Headless MMO Server
After=network.target

[Service]
WorkingDirectory=/opt/unityserver
ExecStart=/opt/unityserver/server.x86_64
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

log "[*] Writing postinstall.sh..."
cat > "$DARKSITE_DIR/postinstall.sh" <<'EOSCRIPT'
#!/bin/bash
set -euxo pipefail

# === Config ===
LOGFILE="/var/log/postinstall.log"
UNITY_DB="unityworld"
UNITY_USER="unity"
UNITY_PASS="unitypass"
REDIS_PASS="redispass"
UNITY_DEST="/opt/unityserver"
UNITY_SRC="/root/darksite/opt/unityserver"

# === Logging Setup ===
exec > >(tee -a "$LOGFILE") 2>&1
trap 'echo "[✖] Postinstall failed on line $LINENO"; exit 1' ERR
log() { echo "[INFO] $(date '+%F %T') — $*"; }

log "Starting postinstall setup..."

# === Function Definitions ===

remove_cd_sources() {
  sed -i '/cdrom:/d' /etc/apt/sources.list
}

install_packages() {
  apt update
  apt install -y cloud-init redis-server postgresql nginx varnish ufw tmux openssh-server sudo
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
create_user "ansible" "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDF4fqB9C+AKYc0uE2olUP+kOalJpANzGmSxZMxvLb8eD4KNs0yXhdFoGNvHSADV6f7rkquFetAkHJUI0b6jKbK8qj0r9q3D2TpB60fgGNmxdhFXIT8WfWAbiiYMWmvvUPpuOx4WYC31vtd/VsV/8ZYMkul4ysUKXZTXVEVvHthAjN2CtqKmVVXTIV2oml4qcRDmn9CepG+jAXAR9/fjZnPgxFP/q+yZk8vjPgVSV74e7oCNjKK1txlSnzS3esV67kdsJqmMBAx+R/Y74Ru4QpVOwn/C5OUy0rFeNvCXWHqbjhfCF8+4vMhxYlNWqTbVHKX7N/z3un4NDqssfozE/ozQnVrGMupIqwg+ys0qntGSVCcb6uOHmVD6dBpaKE8hBQdFHLiQ+n8N72Bd5SG7dqjDUV86DNWv2RaMtMzRGzQSeibBiU7o7r6//RKZH3G5dhbDu4y+ai5sHLgdRC4cxt55o5oGuGATwdv3JXAbkgRJA6MpKWes/8MhrWrnYXrhuiGXsiGLLL3pkd0vIwydGehy4R2QWhixHGv7IUgGRFkcVAl9+SLHxvx3mSlN4KW8Ds/lJ9fAoqsZoGVJ7gSuDzy7rN5QH4icVhhxwPxJg8uPta8lhM1ZI2WoObOWCd5POWPpooiXMerQmDTx27uSiebZhn0nNp3mbWGCySICN34aw== ansible@fiend ansible@host"
create_user "todd"    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDS35Kk/U8c0iff0Z70gAfd2wzmb5F6X6V2QT85FIua+CQzIV5qbjA+SodaZU0w30JdcK+aBwLoHcPQF0BZrZesOt727cdY1SoFzeeOZAl3DSGsAxk2HDveHfFbaiaB+Y67bvQhX4Ao7bR98wA9EDmJKLrFUodLU5x8MSnw0ahg4F4PBeDIRlmNk45PV42yBF5UXtuohlMytFeRIc4wLTyCek2knV3hst5NUMZ0w+I9s/kUyMGVI9IlGxeZcrv96z0i5bu1SAbgUvY3Mr8tYeMhW4h/c1Y/luPKx97U/OwfAm+OvKCMnAVYMmFO7dOmi+U/pCRkmU7E4Z3BuACkhJQCRWS2M3kDBoRgpWOMhENgnmkQyVxTmvazFn6Fg9Jw2Mhz1EqZd8hAeL7+oQf5W9P/H06yiziai2m7ZpRCDuZ57SMugDx7ZFQtAZQOPpz2NFgtvo0JPoJSHl908wzLsjLTXXIcOMbdhyhKxOU6oOTnWrxKfPrZNexNSreOT5XrJlwum7vApVabk2p9okWWRY63yE3oKHCgb7tlcaBA9EDsleVNtG9otMAjVAPazRyUkMHaf7am+2A4xyjXM/1JHzUeIABNQClAAsWmbgoRavU8s0/Gu22m28/qW9xP8Lp7MoGIOl/mbXb73PhxTZXx7MZs8csjW7ZlNB3zCpwzMk3okQ== todd@onyx todd@host"

deploy_unity_server() {
  mkdir -p "$UNITY_DEST"
  cp -a "$UNITY_SRC"/* "$UNITY_DEST"/ || log "Unity server files already copied"
  chmod +x "$UNITY_DEST"/server.x86_64
  cp /root/darksite/etc/systemd/system/unityserver.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable unityserver.service
  systemctl start unityserver.service
}

setup_postgres() {
  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$UNITY_DB'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $UNITY_DB"

  if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$UNITY_USER'" | grep -q 1; then
    sudo -u postgres psql -c "CREATE USER $UNITY_USER WITH ENCRYPTED PASSWORD '$UNITY_PASS';"
  fi

  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $UNITY_DB TO $UNITY_USER;"
}

configure_redis() {
  sed -i "s/^# requirepass .*/requirepass $REDIS_PASS/" /etc/redis/redis.conf
  systemctl restart redis
}

tune_varnish() {
  sed -i 's/.port = "6081";/.port = "80";/' /etc/varnish/default.vcl
  sed -i 's|^ExecStart=.*|ExecStart=/usr/sbin/varnishd -a :80 -b localhost:8080|' /lib/systemd/system/varnish.service
  systemctl daemon-reexec
  systemctl restart varnish
}

setup_ufw() {
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 6081/tcp
  ufw allow 7777/tcp
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

prepare_logs() {
  log "Creating tmpfiles.d entries for default logs..."
  cat > /etc/tmpfiles.d/services.conf <<EOF
d /var/log/nginx 0755 www-data www-data -
f /var/log/nginx/access.log 0640 www-data www-data -
f /var/log/nginx/error.log 0640 www-data www-data -
d /var/log/redis 0755 redis redis -
f /var/log/redis/redis-server.log 0640 redis redis -
d /var/log/postgresql 0755 postgres postgres -
f /var/log/postgresql/postgresql.log 0640 postgres postgres -
d /var/log/varnish 0755 varnishlog adm -
f /var/log/varnish/varnishncsa.log 0640 varnishlog adm -
EOF

  systemd-tmpfiles --create
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
deploy_unity_server
setup_postgres
configure_redis
tune_varnish
setup_ufw
reset_cloud_init
regenerate_identity
prepare_logs
cleanup_logs
self_destruct

log "[✔] Postinstall complete — rebooting..."
#reboot
poweroff
EOSCRIPT

chmod +x "$DARKSITE_DIR/postinstall.sh"

log "[*] Writing bootstrap.service..."
cat > "$DARKSITE_DIR/bootstrap.service" <<'EOF'
[Unit]
Description=Initial Bootstrap Script
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/darksite/postinstall.sh
RemainAfterExit=false
TimeoutStartSec=900
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

log "[*] Writing finalize-template.sh..."
cat > "$DARKSITE_DIR/finalize-template.sh" <<'EOSCRIPT'
#!/bin/bash
set -euxo pipefail

VMID="${1:-}"
PROXMOX_HOST="10.200.0.100"

if [ -z "$VMID" ]; then
  echo "Usage: $0 <VMID>"
  exit 1
fi

echo "[*] Waiting for VM $VMID to shut down after cloud-init..."

SECONDS=0
TIMEOUT=900  # 15 minutes

while ssh root@"$PROXMOX_HOST" "qm status $VMID" | grep -q running; do
  if (( SECONDS > TIMEOUT )); then
    echo "[!] ERROR: Timeout waiting for VM $VMID to shut down."
    exit 1
  fi
  sleep 30
done

echo "[*] VM $VMID has shut down after cloud-init. Marking as template..."
ssh root@"$PROXMOX_HOST" "qm template $VMID"
echo "[✓] Template finalized."
EOSCRIPT

chmod +x "$DARKSITE_DIR/finalize-template.sh"

# --- Preseed file ---
log "[*] Creating preseed.cfg..."
cat > "$CUSTOM_DIR/$PRESEED_FILE" <<EOF
# Localization
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us

# Networking
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string debian
d-i netcfg/get_domain string lan.xaeon.io

# Mirrors
d-i mirror/country string manual
d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

# Comment this out to enable mirrors on NetInst
#d-i mirror/no_mirror boolean true

# APT sections
d-i apt-setup/use_mirror boolean true
d-i apt-setup/non-free boolean true
d-i apt-setup/contrib boolean true

# User setup
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

# Partitioning (automated with LVM)
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

# Task selection
tasksel tasksel/first multiselect

# Popularity
popularity-contest popularity-contest/participate boolean false

# GRUB
d-i grub-installer/bootdev string /dev/sda
d-i grub-installer/only_debian boolean true

d-i finish-install/keep-consoles boolean false
d-i finish-install/exit-installer boolean true
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true
d-i cdrom-detect/eject boolean true

tasksel tasksel/first multiselect standard, ssh-server
d-i finish-install/reboot_in_progress note

d-i preseed/late_command string \
  cp -a /cdrom/darksite /target/root/ ; \
  in-target chmod +x /root/darksite/postinstall.sh ; \
  in-target cp /root/darksite/bootstrap.service /etc/systemd/system/bootstrap.service ; \
  in-target systemctl daemon-reexec ; \
  in-target systemctl enable bootstrap.service ;

# Make installer shut down after install
d-i debian-installer/exit/poweroff boolean true

EOF
# --- Update isolinux ---
log "[*] Updating isolinux config..."
TXT_CFG="$CUSTOM_DIR/isolinux/txt.cfg"
ISOLINUX_CFG="$CUSTOM_DIR/isolinux/isolinux.cfg"

cat >> "$TXT_CFG" <<EOF
label auto
  menu label ^Automated Unity MMO Server Install
  kernel /install.amd/vmlinuz
  append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz preseed/file=/cdrom/$PRESEED_FILE ---
EOF

sed -i 's/^default .*/default auto/' "$ISOLINUX_CFG"

# --- Rebuild ISO ---
log "[*] Rebuilding ISO..."
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

  log "[*] ISO ready at $FINAL_ISO — done!"
  # === UPLOAD TO PROXMOX ===
  log "[*] Uploading ISO to Proxmox host $PROXMOX_HOST..."
  scp "$FINAL_ISO" root@"$PROXMOX_HOST":/var/lib/vz/template/iso/

  log "[*] Creating and running VM $VMID on Proxmox host $PROXMOX_HOST..."

  FINAL_ISO_BASENAME=$(basename "$FINAL_ISO")

  log "[*] Creating and running VM $VMID on Proxmox host $PROXMOX_HOST..."
  ssh root@"$PROXMOX_HOST" bash <<EOSSH
  set -euxo pipefail

  VMID=$VMID
  FINAL_ISO="$FINAL_ISO_BASENAME"

  # Clean previous VM if exists
  qm destroy \$VMID --purge || true

  # Create base VM with ISO boot
  qm create \$VMID \\
    --name debian-unity-template \\
    --memory 4096 \\
    --cores 6 \\
    --net0 virtio,bridge=vmbr0,firewall=1 \\
    --ide2 local:iso/\$FINAL_ISO,media=cdrom \\
    --efidisk0 local-zfs:0,efitype=4m,pre-enrolled-keys=0 \\
    --scsihw virtio-scsi-single \\
    --scsi0 local-zfs:32 \\
    --boot order=ide2 \\
    --serial0 socket \\
    --ostype l26 \\
    --agent enabled=1

  # Start VM to run the ISO installer
  qm start \$VMID

  SECONDS=0
  TIMEOUT=900  # 15 minutes

  # Wait for the installer to finish and poweroff
  while qm status \$VMID | grep -q running; do
    if (( SECONDS > TIMEOUT )); then
      echo "[!] ERROR: Timeout waiting for VM \$VMID shutdown after \$TIMEOUT seconds."
      exit 1
    fi
    sleep 30
  done

  echo "[*] VM \$VMID has powered off after \${SECONDS}s."
  echo "[*] Detaching ISO and preparing for cloud-init..."

  # Remove CD-ROM
  qm set \$VMID --delete ide2

  # Set boot order to disk
  qm set \$VMID --boot order=scsi0

  # Attach Cloud-Init drive
  qm set \$VMID --ide3 local-zfs:cloudinit

  # Set description
  qm set \$VMID --description 'Unity Server - Cloud-init Phase'

  # Start again to trigger postinstall script
  qm start \$VMID
EOSSH

# === Finalize Template After Postinstall (and second shutdown)
  log "[*] Running finalize-template.sh after second VM shutdown..."
  bash "$DARKSITE_DIR/finalize-template.sh" "$VMID"

  log "[✓] VM $VMID fully built, configured, and saved as a template."
