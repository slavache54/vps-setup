#!/bin/bash

set -e

export GIT_BRANCH="main"
export GIT_REPO="igroza/xray-vps-setup"

# Check if script started as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Install idn and jq
apt-get update
apt-get install idn jq -y

# Read domain input
read -ep "Enter your domain:"$'\n' input_domain

export VLESS_DOMAIN=$(echo "$input_domain" | idn)
export TEST_DOMAIN=$(nslookup "$VLESS_DOMAIN" | awk -F': ' 'NR==6 { print $2 } ')
if [ -z "$TEST_DOMAIN" ]; then
  read -ep "Are you sure? That domain has no DNS record. If you didn't add that you will have to restart xray and caddy by yourself [y/N]"$'\n' prompt_response
  if [[ "$prompt_response" =~ ^([yY]) ]]; then
    echo "Ok"
  else
    echo "Come back later"
    exit 1
  fi
fi

read -ep "Do you want to install marzban? [y/N] "$'\n' marzban_input

if [[ "${marzban_input,,}" == "y" ]]; then
  read -ep "Do you want setup telegram bot for Marzban? [y/N] "$'\n' configure_tg_bot
  if [[ "${configure_tg_bot,,}" == "y" ]]; then
    read -ep "Enter your telegram bot token:"$'\n' input_telegram_api_token
    export TELEGRAM_API_TOKEN=$(echo "$input_telegram_api_token" | idn)

    read -ep "Enter your telegram user id, use @userinfobot:"$'\n' input_telegram_admin_id
    export TELEGRAM_ADMIN_ID=$(echo "$input_telegram_admin_id" | idn)
  fi
fi

export PORT_VLESS_XHTTP_REALITY=20001
export PORT_VLESS_H2_REALITY=20002
export PORT_VLESS_TCP_REALITY_EXTRA=20003
export PORT_VLESS_GRPC_REALITY=20004
export PORT_VLESS_WS_TLS=443
export PORT_VLESS_KCP_NOTLS=8080
export PORT_VLESS_WS_NOTLS=8081
export PORT_TROJAN_WS_NOTLS=8082
export PORT_VLESS_TCP_HEADER_NOTLS=20005

read -ep "Enter your custom xray port for main VLESS REALITY. Default 433, can't use ports: 80, $PORT_VLESS_WS_TLS, $PORT_VLESS_XHTTP_REALITY, $PORT_VLESS_H2_REALITY, $PORT_VLESS_TCP_REALITY_EXTRA, $PORT_VLESS_GRPC_REALITY, $PORT_VLESS_KCP_NOTLS, $PORT_VLESS_WS_NOTLS, $PORT_TROJAN_WS_NOTLS, $PORT_VLESS_TCP_HEADER_NOTLS, 4123:"$'\n' input_xray_port

while [[ "$input_xray_port" == "80" || \
         "$input_xray_port" == "$PORT_VLESS_WS_TLS" || \
         "$input_xray_port" == "$PORT_VLESS_XHTTP_REALITY" || \
         "$input_xray_port" == "$PORT_VLESS_H2_REALITY" || \
         "$input_xray_port" == "$PORT_VLESS_TCP_REALITY_EXTRA" || \
         "$input_xray_port" == "$PORT_VLESS_GRPC_REALITY" || \
         "$input_xray_port" == "$PORT_VLESS_KCP_NOTLS" || \
         "$input_xray_port" == "$PORT_VLESS_WS_NOTLS" || \
         "$input_xray_port" == "$PORT_TROJAN_WS_NOTLS" || \
         "$input_xray_port" == "$PORT_VLESS_TCP_HEADER_NOTLS" || \
         "$input_xray_port" == "4123" ]]; do
  read -ep "Error: Port $input_xray_port is reserved or conflicts with other services. Please choose a different port for main VLESS REALITY:"$'\n' input_xray_port
done

if [[ -n "$input_xray_port" ]]; then
  export XRAY_PORT=$input_xray_port
else
  export XRAY_PORT=433
fi

read -ep "Do you want to configure server security? Do this on first run only. [y/N] "$'\n' configure_ssh_input
if [[ "${configure_ssh_input,,}" == "y" ]]; then
  read -ep "Enter SSH port. Default 22, can't use ports: 80, $XRAY_PORT, $PORT_VLESS_WS_TLS, $PORT_VLESS_XHTTP_REALITY, $PORT_VLESS_H2_REALITY, $PORT_VLESS_TCP_REALITY_EXTRA, $PORT_VLESS_GRPC_REALITY, $PORT_VLESS_KCP_NOTLS, $PORT_VLESS_WS_NOTLS, $PORT_TROJAN_WS_NOTLS, $PORT_VLESS_TCP_HEADER_NOTLS, 4123:"$'\n' input_ssh_port

  while [[ "$input_ssh_port" == "80" || \
           "$input_ssh_port" == "$XRAY_PORT" || \
           "$input_ssh_port" == "$PORT_VLESS_WS_TLS" || \
           "$input_ssh_port" == "$PORT_VLESS_XHTTP_REALITY" || \
           "$input_ssh_port" == "$PORT_VLESS_H2_REALITY" || \
           "$input_ssh_port" == "$PORT_VLESS_TCP_REALITY_EXTRA" || \
           "$input_ssh_port" == "$PORT_VLESS_GRPC_REALITY" || \
           "$input_ssh_port" == "$PORT_VLESS_KCP_NOTLS" || \
           "$input_ssh_port" == "$PORT_VLESS_WS_NOTLS" || \
           "$input_ssh_port" == "$PORT_TROJAN_WS_NOTLS" || \
           "$input_ssh_port" == "$PORT_VLESS_TCP_HEADER_NOTLS" || \
           "$input_ssh_port" == "4123" ]]; do
    read -ep "Error: Port $input_ssh_port is reserved or conflicts with other services. Please choose a different SSH port:"$'\n' input_ssh_port
  done
  read -ep "Enter SSH public key:"$'\n' input_ssh_pbk
  echo "$input_ssh_pbk" > ./test_pbk
  if ! ssh-keygen -l -f ./test_pbk > /dev/null 2>&1; then
    echo "Can't verify the public key. Try again and make sure to include 'ssh-rsa' or 'ssh-ed25519' followed by 'user@pcname' at the end of the file."
    rm ./test_pbk
    exit 1
  fi
  rm ./test_pbk
fi

read -ep "Do you want to install WARP and use it on russian websites? [y/N] "$'\n' configure_warp_input

if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
    echo "BBR is already used"
else
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    echo "Enabled BBR"
fi

yq_install() {
  wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq
}

if ! command -v yq &> /dev/null; then
    yq_install
fi

docker_install() {
  curl -fsSL https://get.docker.com -o get-docker.sh
  sh get-docker.sh
  rm get-docker.sh
}

if ! command -v docker &> /dev/null; then
    docker_install
fi

export SSH_USER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo)
export SSH_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export SSH_PORT=${input_ssh_port:-22}
export ROOT_LOGIN="yes"
export IP_CADDY=$(hostname -I | cut -d' ' -f1)
export CADDY_BASIC_AUTH=$(docker run --rm caddy caddy hash-password --plaintext "$SSH_USER_PASS")
export XRAY_PIK=$(docker run --rm ghcr.io/xtls/xray-core x25519 | head -n1 | cut -d' ' -f 3)
export XRAY_PBK=$(docker run --rm ghcr.io/xtls/xray-core x25519 -i "$XRAY_PIK" | tail -1 | cut -d' ' -f 3)
export XRAY_SID=$(openssl rand -hex 8)
export XRAY_UUID=$(docker run --rm ghcr.io/xtls/xray-core uuid)
export TROJAN_FALLBACK_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16; echo)

export CURRENT_XRAY_CONFIG_PATH=""

xray_setup() {
  mkdir -p /opt/xray-vps-setup
  cd /opt/xray-vps-setup

  if [[ "${marzban_input,,}" == "y" ]]; then
    export MARZBAN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 42; echo)
    export MARZBAN_PATH=$(openssl rand -hex 21)
    export MARZBAN_SUB_PATH=$(openssl rand -hex 21)
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose" | envsubst > ./docker-compose.yml
    yq eval \
    '.services.marzban.image = "gozargah/marzban:v0.8.4" |
     .services.marzban.restart = "always" |
     .services.marzban.env_file = "./marzban/.env" |
     .services.marzban.network_mode = "host" |
     .services.marzban.volumes[0] = "./marzban_lib:/var/lib/marzban" |
     .services.marzban.volumes[1] = "./marzban/xray_config.json:/code/xray_config.json" |
     .services.marzban.volumes[2] = "./marzban/templates:/var/lib/marzban/templates" |
     .services.caddy.volumes[2] = "./marzban_lib:/run/marzban"' -i /opt/xray-vps-setup/docker-compose.yml
    mkdir -p marzban caddy
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/marzban" | envsubst > ./marzban/.env
    mkdir -p /opt/xray-vps-setup/marzban/templates/home
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page" | envsubst > ./marzban/templates/home/index.html
    export CADDY_REVERSE="reverse_proxy * unix//run/marzban/marzban.socket"
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst > ./caddy/Caddyfile
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst > ./marzban/xray_config.json
    CURRENT_XRAY_CONFIG_PATH="/opt/xray-vps-setup/marzban/xray_config.json"
  else
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose" | envsubst > ./docker-compose.yml
    mkdir -p /opt/xray-vps-setup/caddy/templates
    yq eval \
    '.services.xray.image = "ghcr.io/xtls/xray-core:25.1.1" |
    .services.xray.restart = "always" |
    .services.xray.network_mode = "host" |
    .services.caddy.volumes[2] = "./caddy/templates:/srv" |
    .services.xray.volumes[0] = "./xray:/etc/xray"' -i /opt/xray-vps-setup/docker-compose.yml
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page" | envsubst > ./caddy/templates/index.html
    export CADDY_REVERSE="root * /srv
    file_server"
    mkdir -p xray caddy
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst > ./xray/config.json
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst > ./caddy/Caddyfile
    CURRENT_XRAY_CONFIG_PATH="/opt/xray-vps-setup/xray/config.json"
  fi

  echo "Adding additional Xray inbounds..."

  local vless_client_settings_json='[]'
  local trojan_client_settings_json='[]'

  if [[ "${marzban_input,,}" != "y" ]]; then
    vless_client_settings_json='[{"id": "'"$XRAY_UUID"'"}]'
    trojan_client_settings_json='[{"password": "'"$TROJAN_FALLBACK_PASS"'"}]'
  fi

  yq eval -i '.inbounds += [{
    "tag": "VLESS XHTTP REALITY", "listen": "0.0.0.0", "port": env(PORT_VLESS_XHTTP_REALITY), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "xhttp", "xhttpSettings": { "mode": "auto" }, "security": "reality",
      "realitySettings": { "show": false, "dest": strenv(VLESS_DOMAIN) + ":443", "xver": 0, "serverNames": [strenv(VLESS_DOMAIN), ""], "privateKey": strenv(XRAY_PIK), "SpiderX": "/", "shortIds": [strenv(XRAY_SID)] }
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "VLESS H2 REALITY", "listen": "0.0.0.0", "port": env(PORT_VLESS_H2_REALITY), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "h2", "security": "reality",
      "realitySettings": { "show": false, "dest": strenv(VLESS_DOMAIN) + ":443", "xver": 0, "serverNames": [strenv(VLESS_DOMAIN), ""], "privateKey": strenv(XRAY_PIK), "SpiderX": "/h2-reality", "shortIds": [strenv(XRAY_SID)] }
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "VLESS TCP REALITY Extra", "listen": "0.0.0.0", "port": env(PORT_VLESS_TCP_REALITY_EXTRA), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": { "show": false, "dest": strenv(VLESS_DOMAIN) + ":443", "xver": 0, "serverNames": [strenv(VLESS_DOMAIN), ""], "privateKey": strenv(XRAY_PIK), "SpiderX": "/tcp-reality", "shortIds": [strenv(XRAY_SID)] }
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "VLESS GRPC REALITY", "listen": "0.0.0.0", "port": env(PORT_VLESS_GRPC_REALITY), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "grpc", "grpcSettings": { "serviceName": "grpc-reality" }, "security": "reality",
      "realitySettings": { "show": false, "dest": strenv(VLESS_DOMAIN) + ":443", "xver": 0, "serverNames": [strenv(VLESS_DOMAIN), ""], "privateKey": strenv(XRAY_PIK), "SpiderX": "/grpc-reality", "shortIds": [strenv(XRAY_SID)] }
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  local cert_path="/var/lib/marzban/certs/fullchain.pem"
  local key_path="/var/lib/marzban/certs/key.pem"
  if [[ "${marzban_input,,}" != "y" ]]; then
      echo "Warning: VLESS WS TLS (port $PORT_VLESS_WS_TLS) for non-Marzban setup relies on certificates at '$cert_path' and '$key_path'."
      echo "These paths are standard for Marzban. If not using Marzban, ensure Xray can access certificates there, or this profile may fail."
  fi
  yq eval -i '.inbounds += [{
    "tag": "VLESS WS TLS", "listen": "0.0.0.0", "port": env(PORT_VLESS_WS_TLS), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "ws", "wsSettings": { "path": "/vless-ws-tls" }, "security": "tls",
      "tlsSettings": { "serverName": strenv(VLESS_DOMAIN), "certificates": [{ "certificateFile": "'"$cert_path"'", "keyFile": "'"$key_path"'" }], "minVersion": "1.2", "cipherSuites": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "VLESS KCP NoTLS", "listen": "0.0.0.0", "port": env(PORT_VLESS_KCP_NOTLS), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "kcp", "kcpSettings": { "mtu": 1350, "tti": 20, "uplinkCapacity": 5, "downlinkCapacity": 20, "congestion": false, "readBufferSize": 2, "writeBufferSize": 2, "header": { "type": "wechat-video" }, "seed": "ЭтоМойСекретныйСидДляKCP" }, "security": "none"
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "VLESS WS NoTLS", "listen": "0.0.0.0", "port": env(PORT_VLESS_WS_NOTLS), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless-ws-notls" }, "security": "none" },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "TROJAN WS NOTLS", "listen": "0.0.0.0", "port": env(PORT_TROJAN_WS_NOTLS), "protocol": "trojan",
    "settings": { "clients": '$trojan_client_settings_json' },
    "streamSettings": { "network": "ws", "wsSettings": { "path": "/trojan-ws-notls" }, "security": "none" },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  yq eval -i '.inbounds += [{
    "tag": "VLESS TCP Header NoTLS", "listen": "0.0.0.0", "port": env(PORT_VLESS_TCP_HEADER_NOTLS), "protocol": "vless",
    "settings": { "clients": '$vless_client_settings_json', "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "tcpSettings": { "header": { "type": "http", "request": { "method": "GET", "path": ["/"], "headers": { "Host": [strenv(VLESS_DOMAIN)] } } } }, "security": "none"
    }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }]' "$CURRENT_XRAY_CONFIG_PATH"

  echo "Finished adding additional Xray inbounds."
}

sshd_edit() {
  grep -rl "Port " /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ | xargs -r --no-run-if-empty sed -i -e "/^Port /c\Port $SSH_PORT"
  grep -rl "PasswordAuthentication " /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ | xargs -r --no-run-if-empty sed -i -e "/^PasswordAuthentication /c\PasswordAuthentication no"
  grep -rl "PermitRootLogin " /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ | xargs -r --no-run-if-empty sed -i -e "/^PermitRootLogin /c\PermitRootLogin no"
  systemctl restart ssh
}

add_user() {
  useradd -m -s /bin/bash "$SSH_USER"
  usermod -aG sudo "$SSH_USER"
  echo "$SSH_USER:$SSH_USER_PASS" | chpasswd
  mkdir -p "/home/$SSH_USER/.ssh"
  touch "/home/$SSH_USER/.ssh/authorized_keys"
  echo "$input_ssh_pbk" >> "/home/$SSH_USER/.ssh/authorized_keys"
  chmod 700 "/home/$SSH_USER/.ssh/"
  chmod 600 "/home/$SSH_USER/.ssh/authorized_keys"
  chown "$SSH_USER:$SSH_USER" -R "/home/$SSH_USER/.ssh"
  chown "$SSH_USER:$SSH_USER" "/home/$SSH_USER"
  usermod -aG docker "$SSH_USER"
}

debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

edit_iptables() {
  apt-get install iptables-persistent netfilter-persistent -y
  iptables -F INPUT
  iptables -P INPUT DROP
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -p icmp -j ACCEPT
  iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport "$SSH_PORT" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$XRAY_PORT" -j ACCEPT

  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_XHTTP_REALITY" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_H2_REALITY" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_TCP_REALITY_EXTRA" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_GRPC_REALITY" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_WS_TLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_KCP_NOTLS" -j ACCEPT
  iptables -A INPUT -p udp -m udp --dport "$PORT_VLESS_KCP_NOTLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_WS_NOTLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_TROJAN_WS_NOTLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_TCP_HEADER_NOTLS" -j ACCEPT

  netfilter-persistent save
}

xray_setup

if [[ "${configure_ssh_input,,}" == "y" ]]; then
  sshd_edit
  add_user
  edit_iptables
  echo "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT."
elif [[ "${configure_ssh_input,,}" != "y" ]]; then
  echo "SSH security not configured. Ensuring Xray ports are open if iptables is active..."
  if ! dpkg -s iptables-persistent &> /dev/null; then
    apt-get install iptables-persistent netfilter-persistent -y
  fi
  iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$XRAY_PORT" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_XHTTP_REALITY" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_H2_REALITY" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_TCP_REALITY_EXTRA" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_GRPC_REALITY" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_WS_TLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_KCP_NOTLS" -j ACCEPT
  iptables -A INPUT -p udp -m udp --dport "$PORT_VLESS_KCP_NOTLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_WS_NOTLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_TROJAN_WS_NOTLS" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$PORT_VLESS_TCP_HEADER_NOTLS" -j ACCEPT
  netfilter-persistent save
fi

warp_install() {
  apt install gpg -y
  echo "If this fails then warp won't be added to routing and everything will work without it"
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
  apt update
  apt install cloudflare-warp -y

  if ! warp-cli --accept-tos registration new; then
    echo "Couldn't register with WARP. WARP will not be configured."
    return 1
  fi

  warp-cli mode proxy
  warp-cli proxy port 40000
  if ! warp-cli connect; then
    echo "Couldn't connect to WARP. WARP will not be configured."
    return 1
  fi

  if [ -z "$CURRENT_XRAY_CONFIG_PATH" ]; then
      echo "Error: Xray config path not set. Cannot configure WARP."
      return 1
  fi

  yq eval -i \
  '.outbounds += {"tag": "warp","protocol": "socks","settings": {"servers": [{"address": "127.0.0.1","port": 40000}]}}' \
  "$CURRENT_XRAY_CONFIG_PATH"
  yq eval -i \
  '.routing.rules += {"type": "field", "outboundTag": "warp", "domain": ["geosite:category-ru", "regexp:.*\\.xn--$", "regexp:.*\\.ru$", "regexp:.*\\.su$"]}' \
  "$CURRENT_XRAY_CONFIG_PATH"

  echo "Restarting Xray services to apply WARP configuration..."
  cd /opt/xray-vps-setup
  docker compose down && docker compose up -d
  echo "WARP configured and Xray restarted."
}

end_script() {
  cd /opt/xray-vps-setup
  docker run -v "$(pwd)/caddy/Caddyfile:/Caddyfile" --rm caddy caddy fmt --overwrite /Caddyfile
  docker compose up -d

  echo ""
  echo "===================================================================="
  echo " SERVER CONFIGURATION COMPLETE"
  echo "===================================================================="

  if [[ "${marzban_input,,}" == "y" ]]; then
    echo "Marzban Admin Panel: https://$VLESS_DOMAIN:$XRAY_PORT/$MARZBAN_PATH"
    echo "Marzban User: xray_admin, Password: $MARZBAN_PASS"
    echo "---"
    echo "For Marzban, add users and get connection details via the admin panel."
    echo "The following are a reminder of the ports and types configured:"
    echo "  - Main VLESS REALITY: Port $XRAY_PORT (TCP)"
    echo "  - VLESS XHTTP REALITY: Port $PORT_VLESS_XHTTP_REALITY"
    echo "  - VLESS H2 REALITY: Port $PORT_VLESS_H2_REALITY (Path /h2-reality)"
    echo "  - VLESS TCP REALITY Extra: Port $PORT_VLESS_TCP_REALITY_EXTRA"
    echo "  - VLESS GRPC REALITY: Port $PORT_VLESS_GRPC_REALITY (Service Name: grpc-reality)"
    echo "  - VLESS WS TLS: Port $PORT_VLESS_WS_TLS (Path /vless-ws-tls)"
    echo "  - VLESS KCP NoTLS: Port $PORT_VLESS_KCP_NOTLS (Seed: ЭтоМойСекретныйСидДляKCP, Header: wechat-video)"
    echo "  - VLESS WS NoTLS: Port $PORT_VLESS_WS_NOTLS (Path /vless-ws-notls)"
    echo "  - TROJAN WS NoTLS: Port $PORT_TROJAN_WS_NOTLS (Path /trojan-ws-notls)"
    echo "  - VLESS TCP Header NoTLS: Port $PORT_VLESS_TCP_HEADER_NOTLS (Host: $VLESS_DOMAIN)"
  else
    echo "--- Main VLESS REALITY (Original Script Profile) ---"
    echo "  Protocol: VLESS, Network: TCP, Security: REALITY (Vision)"
    echo "  Address: $VLESS_DOMAIN"
    echo "  Port: $XRAY_PORT"
    echo "  UUID: $XRAY_UUID"
    echo "  Public Key (pbk): $XRAY_PBK"
    echo "  Short ID (sid): $XRAY_SID"
    echo "  SNI: $VLESS_DOMAIN"
    echo "  Fingerprint (fp): chrome"
    echo "  Flow: xtls-rprx-vision"
    echo "  SpiderX (spx): /"
    echo "  Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$XRAY_PORT?type=tcp&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&spx=%2F&flow=xtls-rprx-vision"
    echo ""
    echo "--- Additional Standalone Xray Profiles (UUID: $XRAY_UUID, Trojan Pass: $TROJAN_FALLBACK_PASS) ---"
    echo "1. VLESS XHTTP REALITY:"
    echo "   Port: $PORT_VLESS_XHTTP_REALITY, Path: /, SNI: $VLESS_DOMAIN, SpiderX: /"
    echo "   Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$PORT_VLESS_XHTTP_REALITY?type=http&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&path=%2F&host=$VLESS_DOMAIN&headerType=http"
    echo "2. VLESS H2 REALITY:"
    echo "   Port: $PORT_VLESS_H2_REALITY, Path: /h2-reality, SNI: $VLESS_DOMAIN, SpiderX: /h2-reality"
    echo "   Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$PORT_VLESS_H2_REALITY?type=h2&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&path=%2Fh2-reality&host=$VLESS_DOMAIN"
    echo "3. VLESS TCP REALITY Extra:"
    echo "   Port: $PORT_VLESS_TCP_REALITY_EXTRA, SNI: $VLESS_DOMAIN, SpiderX: /tcp-reality"
    echo "   Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$PORT_VLESS_TCP_REALITY_EXTRA?type=tcp&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&spx=%2Ftcp-reality"
    echo "4. VLESS GRPC REALITY:"
    echo "   Port: $PORT_VLESS_GRPC_REALITY, ServiceName: grpc-reality, SNI: $VLESS_DOMAIN, SpiderX: /grpc-reality"
    echo "   Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$PORT_VLESS_GRPC_REALITY?type=grpc&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&serviceName=grpc-reality&path=%2Fgrpc-reality" # path был указан как spiderx, для grpc обычно serviceName
    echo "5. VLESS WS TLS:"
    echo "   Port: $PORT_VLESS_WS_TLS, Path: /vless-ws-tls, SNI: $VLESS_DOMAIN, Security: tls"
    echo "   Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$PORT_VLESS_WS_TLS?type=ws&security=tls&sni=$VLESS_DOMAIN&fp=chrome&path=%2Fvless-ws-tls&host=$VLESS_DOMAIN"
    echo "6. VLESS KCP NoTLS:"
    echo "   Port: $PORT_VLESS_KCP_NOTLS, Seed: ЭтоМойСекретныйСидДляKCP, HeaderType: wechat-video"
    echo "   (KCP requires client-side configuration for seed and header)"
    echo "7. VLESS WS NoTLS:"
    echo "   Port: $PORT_VLESS_WS_NOTLS, Path: /vless-ws-notls, Security: none"
    echo "   Clipboard: vless://$XRAY_UUID@$VLESS_DOMAIN:$PORT_VLESS_WS_NOTLS?type=ws&security=none&path=%2Fvless-ws-notls&host=$VLESS_DOMAIN"
    echo "8. TROJAN WS NoTLS:"
    echo "   Port: $PORT_TROJAN_WS_NOTLS, Path: /trojan-ws-notls, Password: $TROJAN_FALLBACK_PASS, Security: none"
    echo "   Clipboard: trojan://$TROJAN_FALLBACK_PASS@$VLESS_DOMAIN:$PORT_TROJAN_WS_NOTLS?type=ws&security=none&path=%2Ftrojan-ws-notls&host=$VLESS_DOMAIN"
    echo "9. VLESS TCP Header NoTLS:"
    echo "   Port: $PORT_VLESS_TCP_HEADER_NOTLS, Header: HTTP (Host: $VLESS_DOMAIN), Security: none"
    echo "   (Requires client-side configuration for HTTP header)"
  fi
  echo "===================================================================="
}

end_script
set +e

if [[ "${configure_warp_input,,}" == "y" ]]; then
  echo "Attempting to install and configure WARP..."
  if warp_install; then
    echo "WARP installation and configuration successful."
  else
    echo "WARP installation or configuration failed. Continuing without WARP."
    echo "Ensuring Xray services are up with latest configuration..."
    cd /opt/xray-vps-setup
    docker compose up -d --force-recreate
  fi
fi

echo "Script finished."
