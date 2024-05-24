#!/bin/bash



# Install Ansible and dependencies
echo "Installing Ansible and dependencies..."
sudo apt-add-repository ppa:ansible/ansible
sudo apt update && sudo apt install openssh-server ansible -y

# Initialize Ansible configuration
echo "Initializing Ansible configuration..."
sudo ansible-config init --disabled >> /etc/ansible/ansible.cfg

# Disable host key checking in Ansible configuration
echo "Disabling host key checking..."
sudo sed -i 's/;host_key_checking=True/host_key_checking=False/g' /etc/ansible/ansible.cfg

# Create Ansible hosts file
echo "Creating Ansible hosts file..."

# Add clients to Ansible hosts file
echo "Adding clients to Ansible hosts file..."
sudo tee -a /etc/ansible/hosts <<EOF
[my_clients]
192.168.1.107
192.168.1.108

[my_clients:vars]
ansible_user=root
ansible_password=password123
EOF

# Create Ansible playbook
echo "Creating Ansible playbook..."


# Create playbook content
echo "Creating playbook content..."
sudo tee /root/cis_playbook.yml <<EOF
---
- hosts: my_clients
  become: true

  tasks:
  - name: Transfer the script
    copy:
      src: /home/sehara/Downloads/CISAutomation/
      dest: /root/
      mode: 0777

  - name: Run service audit script
    command: bash /root/main.sh -s
    register: service_output
  - debug: var=service_output.stdout_lines
  #########################################
  - name: Retrive results file
    fetch:
      src: /root/results/network-audit-results.txt
      dest: /home/sehara/Downloads/
      flat: yes
EOF
sudo apt install git -y
cd /home/sehara/Downloads/ 
git clone https://github.com/Dinithoshan/CISAutomation.git

echo "##############################################################"
echo ""
echo "change ip adresses in /etc/ansible/hosts"
echo ""
echo ""
echo "ansible-playbook /root/cis_playbook.yml"
echo "run above command to run the playbook"
echo ""
echo "##############################################################"
