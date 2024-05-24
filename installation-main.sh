#!/bin/bash
source ssh-config.sh


mkdir -p results
cp ssh-config.sh results
sudo apt install expect
sudo apt install timeshift
sudo apt install sshpass
chmod +x rollbackinstallation.sh
chmod +x log-main-audit.sh
chmod +x log-main-config.sh
chmod +x initial-setup-main-audit.sh
chmod +x initial-setup-main-config.sh
chmod +x services-main-audit.sh
chmod +x services-main-config.sh
chmod +x network-audit.sh
chmod +x network-config.sh
chmod +x rollback-main.sh
chmod +x installation-main.sh