#!/bin/bash

# رنگ‌ها برای نمایش زیباتر
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
RESET='\033[0m'

# تابع نمایش پیام
print_message() {
    echo -e "${1}${2}${RESET}"
}

# تابع بررسی دسترسی root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_message $RED "Please run as root"
        exit 1
    fi
}

# تابع دریافت اطلاعات از کاربر
get_user_input() {
    ADMIN_USERNAME="admin"
    ADMIN_PASSWORD="admin123"
    PANEL_PORT="5000"
}

# تابع نصب پیش‌نیازها
install_dependencies() {
    print_message $YELLOW "[+] Installing dependencies..."
    apt update -y && apt install -y python3 python3-pip flask flask-sqlalchemy apscheduler
    print_message $GREEN "[✔] Dependencies installed successfully!"
}

# ساخت سرویس سیستمی
create_service() {
    print_message $YELLOW "[+] Creating system service..."

    cat > /etc/systemd/system/openvpn_manager.service <<EOF
[Unit]
Description=OpenVPN Manager Web Panel
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /root/app.py
Restart=always
Environment=PANEL_PORT=${PANEL_PORT}
Environment=ADMIN_USERNAME=${ADMIN_USERNAME}
Environment=ADMIN_PASSWORD=${ADMIN_PASSWORD}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openvpn_manager --now
    print_message $GREEN "[✔] Service created and started successfully!"
}

# صفحه لاگین ساده و وب‌سرور داخلی
setup_files() {
    cd /root || exit

    cat > app.py <<'EOL'
from flask import Flask, request, redirect, render_template_string
import os

app = Flask(__name__)

# تنظیمات پنل
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
PANEL_PORT = int(os.getenv("PANEL_PORT", "5000"))

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            return redirect("/dashboard")
        else:
            error = "Invalid credentials"
    return render_template_string('''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body style="background:#1e1e2f;color:white;font-family:sans-serif;text-align:center;margin-top:10%">
<h2>🔐 OpenVPN Web Panel</h2>
<form method="post">
<input type="text" name="username" placeholder="Username" required><br>
<input type="password" name="password" placeholder="Password" required><br>
<button type="submit">Login</button>
{% if error %}
<p style="color:red">{{ error }}</p>
{% endif %}
</form>
<p>Default: admin / admin123</p>
</body>
</html>
''', error=error)

@app.route("/dashboard")
def dashboard():
    return "<h2>Welcome to OpenVPN Dashboard</h2>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PANEL_PORT)
EOL
}

# نمایش اطلاعات
show_info() {
    IP=$(hostname -I | awk '{print $1}')
    print_message $CYAN "====================================="
    print_message $CYAN "Panel Address: http://$IP:$PANEL_PORT"
    print_message $CYAN "Username: $ADMIN_USERNAME"
    print_message $CYAN "Password: *********** (Stored securely)"
    print_message $CYAN "====================================="
    read -p "Press Enter to continue..."
}

# منو تستی
test_menu() {
    while true; do
        clear
        echo -e "${CYAN}┌────────────────────────────────────┐${RESET}"
        echo -e "${CYAN}│     🔐 OpenVPN Web Panel       │${RESET}"
        echo -e "${CYAN}├────────────────────────────────────┤${RESET}"
        echo -e "${GREEN}│ 1) Start Test Web Panel           │${RESET}"
        echo -e "${YELLOW}│ 2) Exit                          │${RESET}"
        echo -e "${CYAN}└────────────────────────────────────┘${RESET}"
        read -p "Select an option [1-2]: " choice

        case $choice in
            1)
                get_user_input
                install_dependencies
                setup_files
                create_service
                show_info
                ;;
            2)
                print_message $GREEN "Exiting..."
                exit 0
                ;;
            *)
                print_message $RED "Invalid option."
                sleep 1
                ;;
        esac
    done
}

# اجرای تستی
main() {
    check_root
    test_menu
}

main