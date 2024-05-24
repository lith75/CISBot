#!/bin/bash

#set network adpator option to "bridge bla bla bla"
## clents script


sudo apt update  
sudo apt install openssh-server -y
sudo echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config 
sudo echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
sudo echo "root:password123"|chpasswd
sudo systemctl restart ssh