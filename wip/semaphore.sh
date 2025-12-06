#!/bin/bash
set -euo pipefail

LOGFILE="/var/log/postinstall.log"
SEMAPHORE_VERSION="latest"
HOSTNAME_OVERRIDE="semaphore"
SEMAPHORE_BIND_IP="10.0.10.40"
SEMAPHORE_PORT="3000"

exec > >(tee -a "$LOGFILE") 2>&1
trap 'echo "[✖] Postinstall failed on line $LINENO" | tee -a "$LOGFILE"; exit 1' ERR
log() { echo "[INFO] $(date '+%F %T') — $*" | tee -a "$LOGFILE"; }

install_packages() {
  log "Installing required system packages..."

  apt update

  echo "lightdm shared/default-x-display-manager select lightdm" | debconf-set-selections

  DEBIAN_FRONTEND=noninteractive   apt install -y --no-install-recommends     sudo curl gnupg ca-certificates net-tools gnupg2     software-properties-common openssh-server ufw wget rsyslog     xrdp xorgxrdp gnome-session gnome-terminal task-gnome-desktop     lightdm firefox-esr wireplumber x11-xserver-utils dbus-x11     ansible docker.io docker-compose git make htop tmux     traceroute ngrep nmap tcpdump sysstat vim jq

  systemctl enable ssh
  systemctl restart ssh

  systemctl disable gdm3 || true
  systemctl mask gdm3 || true
  systemctl enable lightdm

  hostnamectl set-hostname "$HOSTNAME_OVERRIDE"
  echo "$HOSTNAME_OVERRIDE" > /etc/hostname
}

configure_network() {
  log "Configuring static IP (10.0.10.40) and disabling IPv6..."

  systemctl enable systemd-networkd
  systemctl stop NetworkManager || true
  systemctl disable NetworkManager || true

  cat > /etc/systemd/network/10-ens18.network <<EOF
[Match]
Name=ens18

[Network]
Address=10.0.10.40/24
Gateway=10.0.10.1
DNS=10.0.10.1
IPv6AcceptRA=no

[Link]
MTUBytes=9000
EOF

  echo "nameserver 10.0.10.1" > /etc/resolv.conf

  cat > /etc/sysctl.d/99-disable-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sysctl --system

  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<EOF
{
  "ipv6": false
}
EOF

  systemctl restart systemd-networkd
  systemctl restart docker || true
}

configure_users() {
  log "Creating users: ansible, semaphore, todd..."

  for user in ansible semaphore; do
    id "$user" &>/dev/null || adduser --disabled-password --gecos "" "$user"

    ssh_dir="/home/${user}/.ssh"
    mkdir -p "$ssh_dir"
    chown "$user:$user" "$ssh_dir"
    chmod 700 "$ssh_dir"

    if [[ ! -f "$ssh_dir/id_ed25519" ]]; then
      sudo -u "$user" ssh-keygen -t ed25519 -a 100 -f "$ssh_dir/id_ed25519" -N "" -C "$user@$HOSTNAME_OVERRIDE"
    fi

    cp "$ssh_dir/id_ed25519.pub" "$ssh_dir/authorized_keys"
    chmod 600 "$ssh_dir/"*
    chown -R "$user:$user" "$ssh_dir"

    echo "$user ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$user"
    usermod -aG docker "$user"
  done

  id todd &>/dev/null || adduser --disabled-password --gecos "" todd
  todd_ssh="/home/todd/.ssh"
  mkdir -p "$todd_ssh"
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBAqna/F+DbSFjh2++slefqPwefb15Twix1We1olD7Bw todd@onyx" > "$todd_ssh/authorized_keys"
  chmod 700 "$todd_ssh"
  chmod 600 "$todd_ssh/authorized_keys"
  chown -R todd:todd "$todd_ssh"
  echo "todd ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/todd
  usermod -aG docker todd
}

configure_rdp_desktop() {
  log "Configuring XRDP with GNOME (Xorg)..."
  sed -i 's/#WaylandEnable=false/WaylandEnable=false/' /etc/gdm3/custom.conf || echo "WaylandEnable=false" >> /etc/gdm3/custom.conf
  systemctl enable xrdp
  systemctl restart xrdp
  for user in todd semaphore ansible; do
    echo "gnome-session" > /home/$user/.xsession
    chmod +x /home/$user/.xsession
    chown $user:$user /home/$user/.xsession
  done
}

install_docker_compose_plugin() {
  log "Installing Docker Compose plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -sSL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64     -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
}

install_semaphore_stack() {
  log "Setting up Semaphore with Docker Compose and HTTPS proxy..."

  mkdir -p /opt/semaphore
  cd /opt/semaphore

  ENCRYPTION_KEY=$(head -c32 /dev/urandom | base64)
  DB_PASSWORD="QyNTUxOQAAACA0MQqjqpTT47"
  ADMIN_PASSWORD="QyNTUxOQAAACA0MQqjqpTT47"

  cat > docker-compose.yml <<EOF
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    restart: unless-stopped
    hostname: mysql
    volumes:
      - semaphore-mysql:/var/lib/mysql
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: 'yes'
      MYSQL_DATABASE: semaphore
      MYSQL_USER: semaphore
      MYSQL_PASSWORD: ${DB_PASSWORD}

  semaphore:
    image: semaphoreui/semaphore:${SEMAPHORE_VERSION}
    restart: unless-stopped
    expose:
      - "3000"
    environment:
      SEMAPHORE_DB_USER: semaphore
      SEMAPHORE_DB_PASS: ${DB_PASSWORD}
      SEMAPHORE_DB_HOST: mysql
      SEMAPHORE_DB_PORT: 3306
      SEMAPHORE_DB_DIALECT: mysql
      SEMAPHORE_DB: semaphore
      SEMAPHORE_PLAYBOOK_PATH: /tmp/semaphore/
      SEMAPHORE_ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      SEMAPHORE_ADMIN_NAME: admin
      SEMAPHORE_ADMIN_EMAIL: admin@localhost
      SEMAPHORE_ADMIN: admin
      SEMAPHORE_ACCESS_KEY_ENCRYPTION: ${ENCRYPTION_KEY}
      SEMAPHORE_LDAP_ACTIVATED: 'no'
      TZ: UTC
    depends_on:
      - mysql
    entrypoint: ["/bin/sh", "-c", "sleep 5; echo 'INSERT INTO migration_log (id, created_at) VALUES (\'v2.12.5\', NOW());' | mysql -h mysql -usemaphore -p${DB_PASSWORD} semaphore || true; /bin/semaphore"]

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - semaphore
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config

volumes:
  semaphore-mysql:
  caddy_data:
  caddy_config:
EOF

  # Write Caddyfile
  cat > Caddyfile <<EOF
http://10.0.10.40 {
  redir https://10.0.10.40{uri}
}

https://10.0.10.40 {
  reverse_proxy semaphore:3000
  tls internal
}
EOF

  docker compose up -d

  cat > /etc/systemd/system/semaphore-compose.service <<EOF
[Unit]
Description=Semaphore + Caddy via Docker Compose
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=exec
WorkingDirectory=/opt/semaphore
ExecStartPre=/usr/bin/docker compose pull
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
Restart=always
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable semaphore-compose.service
  systemctl start semaphore-compose.service

  log "Access Semaphore securely at: https://10.0.10.40"
}

configure_firewall() {
  log "Configuring firewall rules..."
  ufw allow 22/tcp
  ufw allow 3389/tcp
  ufw allow 443/tcp
  ufw allow 80/tcp
  ufw --force enable
}

main() {
  log "Starting full Semaphore GUI + HTTPS install"
  install_packages
  configure_network
  configure_users
  configure_rdp_desktop
  install_docker_compose_plugin
  install_semaphore_stack
  configure_firewall
  log "Installation complete. Reboot recommended."
  sync
}

main
