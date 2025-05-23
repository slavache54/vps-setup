#!/bin/bash

# Проверка, что скрипт запущен от root
if [ "$(id -u)" != "0" ]; then
   echo "Этот скрипт должен быть запущен от имени root" 1>&2
   exit 1
fi

# Функция для проверки статуса команды
check_status() {
    if [ $? -eq 0 ]; then
        echo "[OK] $1"
    else
        echo "[Ошибка] $1"
        exit 1
    fi
}

# Установка UFW, если не установлен
echo "Проверка наличия UFW..."
if ! command -v ufw &> /dev/null; then
    echo "UFW не установлен. Устанавливаем..."
    apt-get update
    apt-get install -y ufw
    check_status "Установка UFW"
else
    echo "UFW уже установлен"
fi

# Запрос имени нового пользователя
read -p "Введите имя нового пользователя: " NEW_USER
if [ -z "$NEW_USER" ]; then
    echo "Имя пользователя не может быть пустым"
    exit 1
fi

# Создание пользователя и добавление в группу sudo
useradd -m -s /bin/bash "$NEW_USER"
check_status "Создание пользователя $NEW_USER"
usermod -aG sudo "$NEW_USER"
check_status "Добавление $NEW_USER в группу sudo"

# Запрос публичного SSH-ключа
echo "Введите публичный SSH-ключ для пользователя $NEW_USER (или оставьте пустым, чтобы сгенерировать новый):"
read -r SSH_KEY
if [ -z "$SSH_KEY" ]; then
    echo "Генерация новой пары ключей для $NEW_USER..."
    su - "$NEW_USER" -c "ssh-keygen -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa"
    check_status "Генерация SSH-ключа"
    SSH_KEY=$(cat /home/"$NEW_USER"/.ssh/id_rsa.pub)
    echo "Публичный ключ: $SSH_KEY"
else
    mkdir -p /home/"$NEW_USER"/.ssh
    echo "$SSH_KEY" > /home/"$NEW_USER"/.ssh/authorized_keys
    chown -R "$NEW_USER":"$NEW_USER" /home/"$NEW_USER"/.ssh
    chmod 700 /home/"$NEW_USER"/.ssh
    chmod 600 /home/"$NEW_USER"/.ssh/authorized_keys
    check_status "Настройка SSH-ключа"
fi

# Запрос портов Xray (если используются)
read -p "Введите дополнительные порты Xray для Remnawave (через запятую, например, 10000,10001) или оставьте пустым: " XRAY_PORTS

# Настройка SSH-порта
echo "Изменение порта SSH на 5555..."
sed -i 's/#Port 22/Port 5555/' /etc/ssh/sshd_config
check_status "Изменение порта SSH"

# Запрет входа root по SSH
echo "Запрет входа root по SSH..."
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
check_status "Запрет входа root"

# Включение аутентификации по ключу
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
check_status "Включение аутентификации по ключу"

# Перезапуск SSH
systemctl restart sshd
check_status "Перезапуск службы SSH"

# Настройка UFW
echo "Настройка UFW..."
ufw default deny incoming
ufw default allow outgoing
check_status "Установка политик UFW по умолчанию"

# Разрешение необходимых портов
ufw allow 5555/tcp comment 'SSH port'
ufw allow 80/tcp comment 'HTTP for NGINX'
ufw allow 443/tcp comment 'HTTPS for NGINX'
check_status "Разрешение портов 5555, 80, 443"

# Разрешение портов Xray, если указаны
if [ ! -z "$XRAY_PORTS" ]; then
    IFS=',' read -ra PORT_ARRAY <<< "$XRAY_PORTS"
    for port in "${PORT_ARRAY[@]}"; do
        ufw allow "$port"/tcp comment 'Xray port'
        check_status "Разрешение порта $port"
    done
fi

# Ограничение попыток подключения к SSH
ufw limit 5555/tcp comment 'Limit SSH connections'
check_status "Ограничение попыток SSH"

# Включение UFW
ufw enable
check_status "Включение UFW"

# Проверка статуса UFW
ufw status verbose

echo "Настройка завершена!"
echo "Теперь вы можете подключиться по SSH с новым пользователем $NEW_USER на порт 5555."
if [ -z "$SSH_KEY" ]; then
    echo "Сохраните приватный ключ из /home/$NEW_USER/.ssh/id_rsa для доступа."
fi
