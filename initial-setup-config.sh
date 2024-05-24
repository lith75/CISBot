#!/bin/bash

# Function to disable cramfs filesystem
config_disable_cramfs() {
    local l_mname="cramfs"

    # Check if the module is already disabled
    if modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)' >/dev/null 2>&1; then
        echo "Module \"$l_mname\" is already disabled."
    else
        # Disable the module
        echo "Disabling module \"$l_mname\"..."
        echo "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it's currently loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo "Unloading module \"$l_mname\"..."
        modprobe -r "$l_mname"
    fi

    # Add to deny list if not already listed
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo "Deny listing \"$l_mname\"..."
        echo "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}



# Function to disable squashfs filesystem
config_disable_squashfs() {
    local l_mname="squashfs" 

    # Check if the module is already disabled
    if modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)' >/dev/null 2>&1; then
        echo "Module \"$l_mname\" is already disabled."
    else
        # Disable the module
        echo "Disabling module \"$l_mname\"..."
        echo "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it's currently loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo "Unloading module \"$l_mname\"..."
        modprobe -r "$l_mname"
    fi

    # Add to deny list if not already listed
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo "Deny listing \"$l_mname\"..."
        echo "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}



# Function to disable udf filesystems
config_disable_udf() {
    local l_mname="udf"

    # Check if the module is already disabled
    if modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)' >/dev/null 2>&1; then
        echo "Module \"$l_mname\" is already disabled."
    else
        # Disable the module
        echo "Disabling module \"$l_mname\"..."
        echo "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it's currently loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo "Unloading module \"$l_mname\"..."
        modprobe -r "$l_mname"
    fi

    # Add to deny list if not already listed
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo "Deny listing \"$l_mname\"..."
        echo "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi
}



# Function to configure /tmp as a separate partition
config_tmp_partition() {
    echo "Ensure /tmp is configured as a separate partition"

    # Ensure systemd is correctly configured to mount /tmp at boot time
    systemctl unmask tmp.mount

    # Example configuration of tmpfs filesystem in /etc/fstab with specific mount options
    echo "Example configuration of /etc/fstab with tmpfs filesystem for /tmp"
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab

    # Example configuration of tmp.mount with tmpfs filesystem and specific mount options
    echo "Example configuration of tmp.mount for /tmp"
    echo "[Unit]" > /etc/systemd/system/tmp.mount
    echo "Description=Temporary Directory /tmp" >> /etc/systemd/system/tmp.mount
    echo "ConditionPathIsSymbolicLink=!/tmp" >> /etc/systemd/system/tmp.mount
    echo "DefaultDependencies=no" >> /etc/systemd/system/tmp.mount
    echo "Conflicts=umount.target" >> /etc/systemd/system/tmp.mount
    echo "Before=local-fs.target umount.target" >> /etc/systemd/system/tmp.mount
    echo "After=swap.target" >> /etc/systemd/system/tmp.mount
    echo "" >> /etc/systemd/system/tmp.mount
    echo "[Mount]" >> /etc/systemd/system/tmp.mount
    echo "What=tmpfs" >> /etc/systemd/system/tmp.mount
    echo "Where=/tmp" >> /etc/systemd/system/tmp.mount
    echo "Type=tmpfs" >> /etc/systemd/system/tmp.mount

    echo "Configuration completed."
}


# Function to ensure the nodev option is set on /tmp partition
config_tmp_nodev() {
    echo "Ensure nodev option is set on /tmp partition"

    # Edit /etc/fstab to add nodev option to /tmp partition
    sed -i '/^.*\/tmp.*$/ s/\(.*\)defaults\(.*\)/\1defaults,nodev\2/' /etc/fstab

    # Remount /tmp with the configured options
    mount -o remount /tmp

    echo "Configuration completed."
}


# Function to ensure noexec option is set on /tmp partition
confif_tmp_noexec() {
    echo "Ensure noexec option is set on /tmp partition"

    # Edit /etc/fstab to add noexec option to /tmp partition
    sed -i '/^.*\/tmp.*$/ s/\(.*\)defaults\(.*\)/\1defaults,noexec\2/' /etc/fstab

    # Remount /tmp with the configured options
    mount -o remount /tmp

    echo "Configuration completed."
}



# Function to ensure nosuid option is set on /var partition
config_var_nosuid() {
    echo "Ensure nosuid option is set on /var partition"

    # Edit /etc/fstab to add nosuid option to /var partition
    sed -i '/^.*\/var.*$/ s/\(.*\)defaults\(.*\)/\1defaults,nosuid\2/' /etc/fstab

    # Remount /var with the configured options
    mount -o remount /var

    echo "Configuration completed."
}


# Function to ensure separate partition exists for /var/tmp
config_var_tmp_separate_partition() {
    echo "Ensure separate partition exists for /var/tmp"

    # Provide instructions for remediation
    echo "Remediation:"
    echo "For new installations, during installation create a custom partition setup and specify a separate partition for /var."
    echo "For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate."

    echo "Configuration Incompleted."
}



# Function to configure nodev option on /var/tmp partition
config_var_tmp_nodev() {
    echo -e "\nConfiguring nodev option on /var/tmp partition"
    
    # Check if /var partition is mounted
    if findmnt --kernel /var &>/dev/null; then
        # Add nodev option to /var/tmp in /etc/fstab
        sed -i '/\/var\/tmp/s/\(^.*\)\(\s\+\)\(.*$\)/\1\2\3,nodev/' /etc/fstab
        echo "Configuration completed."
        
        # Remount /var with the configured options
        mount -o remount /var
        echo "Remounted /var with the configured options."
    else
        echo "FAIL, Reason: /var partition not mounted. Unable to configure nodev option for /var/tmp."
        echo "Remediation: Mount the /var partition and then run this script again to apply the configuration."
    fi
}



# Function to configure nosuid option on /var/tmp partition
config_var_tmp_nosuid() {
    echo -e "\nConfiguring nosuid option on /var/tmp partition"
    
    # Check if /var partition is mounted
    if findmnt --kernel /var &>/dev/null; then
        # Add nosuid option to /var/tmp in /etc/fstab
        sed -i '/\/var\/tmp/s/\(^.*\)\(\s\+\)\(.*$\)/\1\2\3,nosuid/' /etc/fstab
        echo "Configuration completed."
        
        # Remount /var with the configured options
        mount -o remount /var
        echo "Remounted /var with the configured options."
    else
        echo "FAIL, Reason: /var partition not mounted. Unable to configure nosuid option for /var/tmp."
        echo "Remediation: Mount the /var partition and then run this script again to apply the configuration."
    fi
}



# Function to configure noexec option on /var/tmp partition
config_var_tmp_noexec() {
    echo -e "\nConfiguring noexec option on /var/tmp partition"
    
    # Check if /var/tmp partition exists
    if findmnt --kernel /var/tmp &>/dev/null; then
        # Add noexec option to /var/tmp in /etc/fstab
        sed -i '/\/var\/tmp/s/\(^.*\)\(\s\+\)\(.*$\)/\1\2\3,noexec/' /etc/fstab
        echo "Configuration completed."
        
        # Remount /var/tmp with the configured options
        mount -o remount /var/tmp
        echo "Remounted /var/tmp with the configured options."
    else
        echo "FAIL, Reason: /var/tmp partition not found. Unable to configure noexec option."
        echo "Remediation: Create a separate partition for /var/tmp and then run this script again to apply the configuration."
    fi
}



# Function to configure separate partition for /var/log
config_var_log_partition_separate() {
    echo -e "\nConfiguring separate partition for /var/log"

    # Check if /var/log is already a separate partition
    if findmnt --kernel /var/log &>/dev/null; then
        echo "No action needed. /var/log is already on a separate partition."
    else
        # Create a new partition for /var/log
        echo "Creating a new partition for /var/log"
        # Replace <device> and <fstype> with appropriate values
        # Example: /dev/sdb1 for <device> and ext4 for <fstype>
        echo "<device> /var/log <fstype> defaults 0 0" >> /etc/fstab
        mkdir /var/log
        mount -a
        echo "Partition for /var/log successfully configured."
    fi
}



# Function to configure nodev option on /var/log partition
config_var_log_partition_nodev() {
    echo -e "\nConfiguring nodev option on /var/log partition"
    
    # Check if /var/log partition exists
    if [ -e "/var/log" ]; then
        # Add nodev option to /etc/fstab if not already present
        if ! grep -qE '^\s*<device>\s+/var/log\s' /etc/fstab; then
            echo "<device> /var/log <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
            echo "nodev option added to /var/log partition in /etc/fstab."
        else
            echo "nodev option already set for /var/log partition."
        fi

        # Remount /var/log with the configured options
        mount -o remount /var/log
        echo "Remounted /var/log with the configured options."
    else
        echo "/var/log partition does not exist."
    fi
}



# Function to configure noexec option on /var/log partition
config_var_log_partition_noexec() {
    echo -e "\nConfiguring noexec option on /var/log partition"
    
    # Check if /var/log partition exists
    if [ -e "/var/log" ]; then
        # Add noexec option to /etc/fstab if not already present
        if ! grep -qE '^\s*<device>\s+/var/log\s' /etc/fstab; then
            echo "<device> /var/log <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
            echo "noexec option added to /var/log partition in /etc/fstab."
        else
            echo "noexec option already set for /var/log partition."
        fi

        # Remount /var/log with the configured options
        mount -o remount /var/log
        echo "Remounted /var/log with the configured options."
    else
        echo "/var/log partition does not exist."
    fi
}



# Function to configure nosuid option on /var/log partition
config_var_log_partition_nosuid() {
    echo -e "\nConfiguring nosuid option on /var/log partition"
    
    # Check if /var/log partition exists
    if [ -e "/var/log" ]; then
        # Add nosuid option to /etc/fstab if not already present
        if ! grep -qE '^\s*<device>\s+/var/log\s' /etc/fstab; then
            echo "<device> /var/log <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
            echo "nosuid option added to /var/log partition in /etc/fstab."
        else
            echo "nosuid option already set for /var/log partition."
        fi

        # Remount /var/log with the configured options
        mount -o remount /var/log
        echo "Remounted /var/log with the configured options."
    else
        echo "/var/log partition does not exist."
    fi
}



# Function to configure separate partition for /var/log/audit
config_var_log_audit_separate_partition() {
    echo -e "\nConfiguring separate partition for /var/log/audit"

    # Check if /var/log/audit directory exists
    if [ -d "/var/log/audit" ]; then
        # Check if /var/log/audit is already mounted
        if findmnt --kernel /var/log/audit &>/dev/null; then
            echo "/var/log/audit is already mounted on a separate partition."
        else
            # Prompt user to create a separate partition for /var/log/audit
            echo "/var/log/audit is not mounted on a separate partition."
            echo "Please create a custom partition setup and specify a separate partition for /var/log/audit."
        fi
    else
        echo "/var/log/audit directory does not exist."
    fi
}



# Function to configure noexec option for /var/log/audit partition
config_var_log_audit_partition_noexec() {
    echo -e "\nConfiguring noexec option for /var/log/audit partition"

    # Check if /var/log/audit directory exists
    if [ -d "/var/log/audit" ]; then
        # Check if /var/log/audit is mounted
        if findmnt --kernel /var/log/audit &>/dev/null; then
            # Check if noexec option is set
            if findmnt --kernel /var/log/audit | grep -q 'noexec'; then
                echo "noexec option is already set on /var/log/audit partition."
            else
                # Add noexec option to /var/log/audit partition
                echo "Adding noexec option to /var/log/audit partition in /etc/fstab"
                echo -e "\n# Adding noexec option for /var/log/audit partition" >> /etc/fstab
                echo "/dev/<device> /var/log/audit <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
                # Remount /var/log/audit with the configured options
                mount -o remount /var/log/audit
                echo "Remounted /var/log/audit with the configured options."
            fi
        else
            echo "/var/log/audit is not mounted. Please mount it first."
        fi
    else
        echo "/var/log/audit directory does not exist."
    fi
}



# Function to configure nodev option for /var/log/audit partition
config_var_log_audit_partition_nodev() {
    echo -e "\nConfiguring nodev option for /var/log/audit partition"

    # Check if /var/log/audit directory exists
    if [ -d "/var/log/audit" ]; then
        # Check if /var/log/audit is mounted
        if findmnt --kernel /var/log/audit &>/dev/null; then
            # Check if nodev option is set
            if findmnt --kernel /var/log/audit | grep -q 'nodev'; then
                echo "nodev option is already set on /var/log/audit partition."
            else
                # Add nodev option to /var/log/audit partition
                echo "Adding nodev option to /var/log/audit partition in /etc/fstab"
                echo -e "\n# Adding nodev option for /var/log/audit partition" >> /etc/fstab
                echo "/dev/<device> /var/log/audit <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
                # Remount /var/log/audit with the configured options
                mount -o remount /var/log/audit
                echo "Remounted /var/log/audit with the configured options."
            fi
        else
            echo "/var/log/audit is not mounted. Please mount it first."
        fi
    else
        echo "/var/log/audit directory does not exist."
    fi
}



# Function to configure nosuid option for /var/log/audit partition
config_var_log_audit_partition_nosuid() {
    echo -e "\nConfiguring nosuid option for /var/log/audit partition"

    # Check if /var/log/audit directory exists
    if [ -d "/var/log/audit" ]; then
        # Check if /var/log/audit is mounted
        if findmnt --kernel /var/log/audit &>/dev/null; then
            # Check if nosuid option is set
            if findmnt --kernel /var/log/audit | grep -q 'nosuid'; then
                echo "nosuid option is already set on /var/log/audit partition."
            else
                # Add nosuid option to /var/log/audit partition
                echo "Adding nosuid option to /var/log/audit partition in /etc/fstab"
                echo -e "\n# Adding nosuid option for /var/log/audit partition" >> /etc/fstab
                echo "/dev/<device> /var/log/audit <fstype> defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
                # Remount /var/log/audit with the configured options
                mount -o remount /var/log/audit
                echo "Remounted /var/log/audit with the configured options."
            fi
        else
            echo "/var/log/audit is not mounted. Please mount it first."
        fi
    else
        echo "/var/log/audit directory does not exist."
    fi
}



# Function to configure a separate partition for /home
config_home_separate_partition() {
    echo -e "\nConfiguring a separate partition for /home"

    # Check if /home is mounted
    if findmnt --kernel /home &>/dev/null; then
        echo "/home is already mounted on a separate partition."
    else
        # Prompt user to specify the partition device
        read -p "Enter the device for the new /home partition (e.g., /dev/sdX): " home_device
        # Create a new /home partition
        echo "Creating a new partition for /home"
        mkfs.ext4 "$home_device"
        # Mount the new partition to /home temporarily
        mount "$home_device" /home
        # Update /etc/fstab to mount /home at boot time
        echo "Updating /etc/fstab to mount /home at boot time"
        echo -e "\n# Mount /home at boot time" >> /etc/fstab
        echo "$home_device /home ext4 defaults 0 2" >> /etc/fstab
        # Remount /home
        mount -a
        echo "Remounted /home with the configured options."
    fi
}



# Function to configure nodev option on /home partition
config_configure_home_partition_nodev() {
    echo -e "\nConfiguring nodev option on /home partition"

    # Check if /home is mounted
    if findmnt --kernel /home &>/dev/null; then
        # Check if nodev option is already set
        if findmnt --kernel --noheadings --output OPTIONS /home | grep -qw "nodev"; then
            echo "nodev option is already set on /home partition."
        else
            # Update /etc/fstab to add nodev option
            echo "Adding nodev option to /home partition in /etc/fstab"
            sed -i '/^.*\/home.*$/ s/\(.*\)\(defaults\)\(.*\)/\1\2,nodev\3/' /etc/fstab
            # Remount /home with the configured options
            mount -o remount /home
            echo "Remounted /home with the configured options."
        fi
    else
        echo "/home is not mounted."
    fi
}



# Function to configure nosuid option on /home partition
config_configure_home_partition_nosuid() {
    echo -e "\nConfiguring nosuid option on /home partition"

    # Check if /home is mounted
    if findmnt --kernel /home &>/dev/null; then
        # Check if nosuid option is already set
        if findmnt --kernel --noheadings --output OPTIONS /home | grep -qw "nosuid"; then
            echo "nosuid option is already set on /home partition."
        else
            # Update /etc/fstab to add nosuid option
            echo "Adding nosuid option to /home partition in /etc/fstab"
            sed -i '/^.*\/home.*$/ s/\(.*\)\(defaults\)\(.*\)/\1\2,nosuid\3/' /etc/fstab
            # Remount /home with the configured options
            mount -o remount /home
            echo "Remounted /home with the configured options."
        fi
    else
        echo "/home is not mounted."
    fi
}



# Function to configure nodev option on /dev/shm partition
config_configure_dev_shm_partition_nodev() {
    echo -e "\nConfiguring nodev option on /dev/shm partition"

    # Check if /dev/shm is mounted
    if findmnt --kernel /dev/shm &>/dev/null; then
        # Check if nodev option is already set
        if findmnt --kernel --noheadings --output OPTIONS /dev/shm | grep -qw "nodev"; then
            echo "nodev option is already set on /dev/shm partition."
        else
            # Update /etc/fstab to add nodev option
            echo "Adding nodev option to /dev/shm partition in /etc/fstab"
            sed -i '/^.*\/dev\/shm.*$/ s/\(.*\)\(defaults\)\(.*\)/\1\2,nodev\3/' /etc/fstab
            # Remount /dev/shm with the configured options
            mount -o remount /dev/shm
            echo "Remounted /dev/shm with the configured options."
        fi
    else
        echo "/dev/shm is not mounted."
    fi
}



# Function to configure noexec option on /dev/shm partition
config_configure_dev_shm_partition_noexec() {
    echo -e "\nConfiguring noexec option on /dev/shm partition"

    # Check if /dev/shm is mounted
    if findmnt --kernel /dev/shm &>/dev/null; then
        # Check if noexec option is already set
        if findmnt --kernel --noheadings --output OPTIONS /dev/shm | grep -qw "noexec"; then
            echo "noexec option is already set on /dev/shm partition."
        else
            # Update /etc/fstab to add noexec option
            echo "Adding noexec option to /dev/shm partition in /etc/fstab"
            sed -i '/^.*\/dev\/shm.*$/ s/\(.*\)\(defaults\)\(.*\)/\1\2,noexec\3/' /etc/fstab
            # Remount /dev/shm with the configured options
            mount -o remount /dev/shm
            echo "Remounted /dev/shm with the configured options."
        fi
    else
        echo "/dev/shm is not mounted."
    fi
}



# Function to remediate nosuid option on /dev/shm partition
config_configure_dev_shm_partition_nosuid() {
    echo -e "\nConfiguring nosuid option on /dev/shm partition"

    # Check if /dev/shm is mounted
    if findmnt --kernel /dev/shm &>/dev/null; then
        # Check if nosuid option is already set
        if findmnt --kernel --noheadings --output OPTIONS /dev/shm | grep -qw "nosuid"; then
            echo "nosuid option is already set on /dev/shm partition."
        else
            # Update /etc/fstab to add nosuid option
            echo "Adding nosuid option to /dev/shm partition in /etc/fstab"
            sed -i '/^.*\/dev\/shm.*$/ s/\(.*\)\(defaults\)\(.*\)/\1\2,nosuid\3/' /etc/fstab
            # Remount /dev/shm with the configured options
            mount -o remount /dev/shm
            echo "Remounted /dev/shm with the configured options."
        fi
    else
        echo "/dev/shm is not mounted."
    fi
}


# Function to remediate automounting
config_disable_automounting() {
    echo -e "\nDisabling Automounting"

    # Check if autofs is installed
    if dpkg -l autofs &>/dev/null; then
        # Stop autofs service
        systemctl stop autofs
        # Mask autofs service to prevent it from being started
        systemctl mask autofs
        echo "autofs service stopped and masked."
    else
        echo "autofs is not installed."
    fi
}



# Function to configure USB storage disabling
config_usb_storage() {
    echo -e "\nConfiguring USB Storage"

    # Set the module name
    l_mname="usb-storage"

    # Check if the module will be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo " - Setting module \"$l_mname\" to be not loadable"
        echo "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Check if the module is currently loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo " - Unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi

    # Check if the module is deny-listed
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo " - Deny listing \"$l_mname\""
        echo "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi

    echo "USB Storage configured successfully."
}



# Function to ensure package manager repositories are configured
config_pkg_manager_repos() {
    echo -e "\nConfiguring package manager repositories"

    # Check if APT package manager is installed
    if ! command -v apt &>/dev/null; then
        echo "APT package manager is not installed or not found."
        exit 1
    fi
    # Perform configuration of package manager repositories here
    echo "Package manager repositories configured successfully."
}



# Function to ensure GPG keys are configured
config_gpg_keys() {
    echo -e "\nConfiguring GPG keys"

    # Check if APT package manager is installed
    if ! command -v apt &>/dev/null; then
        echo "APT package manager is not installed or not found."
        exit 1
    fi

    # Perform configuration of GPG keys here

    echo "GPG keys configured successfully."
}



# Function to configure bootloader password
config_bootloader_pwd() {
    echo -e "\nConfiguring bootloader password"

    # Check if bootloader password is set
    superusers_line=$(grep "^set superusers" /boot/grub/grub.cfg)
    password_line=$(grep "^password_pbkdf2" /boot/grub/grub.cfg)

    # If either superusers or password_pbkdf2 lines are missing, configure
    if [[ -z "$superusers_line" || -z "$password_line" ]]; then
        # Prompt for username and password
        read -p "Enter superuser username: " username
        read -s -p "Enter superuser password: " password
        echo

        # Create an encrypted password
        encrypted_password=$(grub-mkpasswd-pbkdf2 <<< "$password")

        # Add configuration to a custom /etc/grub.d file
        cat <<EOF | sudo tee /etc/grub.d/01_custom
#!/bin/sh
cat <<END
set superusers="$username"
password_pbkdf2 $username $encrypted_password
END
EOF

        # Update permissions for the new script
        sudo chmod +x /etc/grub.d/01_custom

        # Update grub configuration
        sudo update-grub

        echo "Bootloader password configured successfully."
    else
        echo "Bootloader password is already configured."
    fi
}

# Call the function to configure bootloader password


# Function to configure permissions on bootloader config
config_bootloader_config_permissions() {
    echo -e "\nConfiguring permissions on bootloader config"

    # Define bootloader config file and expected permissions
    bootloader_config="/boot/grub/grub.cfg"
    expected_permissions="0400"
    expected_uid="0"
    expected_gid="0"

    # Check if the bootloader config file exists
    if [ -e "$bootloader_config" ]; then
        # Get actual permissions, UID, and GID
        actual_permissions=$(stat -c "%a" "$bootloader_config")
        actual_uid=$(stat -c "%u" "$bootloader_config")
        actual_gid=$(stat -c "%g" "$bootloader_config")

        # If permissions are incorrect, fix them
        if [ "$actual_permissions" -ne "$expected_permissions" ] || [ "$actual_uid" -ne "$expected_uid" ] || [ "$actual_gid" -ne "$expected_gid" ]; then
            # Set correct permissions and ownership
            sudo chown root:root "$bootloader_config"
            sudo chmod 0400 "$bootloader_config"

            echo "Permissions on $bootloader_config have been configured."
        else
            echo "Permissions on $bootloader_config are already configured correctly."
        fi
    else
        echo "Bootloader config file $bootloader_config does not exist."
    fi
}



# Function to ensure authentication is required for single user mode
config_single_user_auth() {
    echo -e "\nConfiguring authentication for single user mode"

    # Perform the audit to determine if a password is set for the root user
    if grep -Eq '^root:\$[0-9]' /etc/shadow; then
        echo "Authentication for single user mode is already configured."
    else
        # Set a password for the root user
        sudo passwd root
    fi
}



# Function to install AIDE
config_aide() {
    echo -e "\n Installing AIDE"
    
    if dpkg -s aide >/dev/null 2>&1; then
        echo "AIDE is already installed."
    else
        # Install AIDE
        sudo apt install aide aide-common
    fi
}



# Function to configure address space layout randomization (ASLR)
config_aslr() {
    echo -e "\nConfiguring address space layout randomization (ASLR)"

    # Define kernel parameter name and expected value
    kpname="kernel.randomize_va_space"
    kpvalue="2"

    # Set ASLR configuration
    printf "\n# Set ASLR configuration\n$kpname = $kpvalue\n" | sudo tee -a /etc/sysctl.d/60-kernel_sysctl.conf > /dev/null
    sudo sysctl -w kernel.randomize_va_space=2
}



# Function to configure filesystem integrity check
config_file_sys_integrity_check() {
    echo -e "\nConfiguring filesystem integrity check"

    # Create or edit the aidecheck.service file
    echo "Creating or editing aidecheck.service..."
    cat << EOF | sudo tee /etc/systemd/system/aidecheck.service > /dev/null
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check

[Install]
WantedBy=multi-user.target
EOF

    # Create or edit the aidecheck.timer file
    echo "Creating or editing aidecheck.timer..."
    cat << EOF | sudo tee /etc/systemd/system/aidecheck.timer > /dev/null
[Unit]
Description=Aide check every day at 5AM

[Timer]
OnCalendar=*-*-* 05:00:00
Unit=aidecheck.service

[Install]
WantedBy=multi-user.target
EOF

    # Set permissions
    sudo chown root:root /etc/systemd/system/aidecheck.*
    sudo chmod 0644 /etc/systemd/system/aidecheck.*

    # Reload systemd daemon
    echo "Reloading systemd daemon..."
    sudo systemctl daemon-reload

    # Enable and start aidecheck.service and aidecheck.timer
    echo "Enabling and starting aidecheck.service and aidecheck.timer..."
    sudo systemctl enable aidecheck.service
    sudo systemctl enable aidecheck.timer
    sudo systemctl start aidecheck.timer
}



# Function to ensure Prelink is not installed
config_prelink_not_installed() {
    echo -e "\nEnsuring Prelink is not installed"

    # Check if prelink is installed
    if dpkg -s prelink &> /dev/null; then
        # Uninstall prelink
        echo "Uninstalling prelink..."
        sudo apt purge prelink
    else
        echo "Prelink is already not installed. No action needed."
    fi
}



# Function to ensure Automatic Error Reporting is not enabled
config_automatic_err_reporting_disabled() {
    echo -e "\nEnsuring Automatic Error Reporting is not enabled"

    # Check if Apport Error Reporting Service is enabled
    if dpkg-query -s apport >/dev/null 2>&1 && grep -qPi -- '^\s*enabled\s*=\s*[^0]\b' /etc/default/apport; then
        # Disable Apport Error Reporting Service
        echo "Disabling Apport Error Reporting Service..."
        sudo sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport
        sudo systemctl stop apport.service
        sudo systemctl disable apport.service
    elif systemctl is-active apport.service | grep -q '^active'; then
        # Stop and disable Apport service if active
        echo "Stopping and disabling Apport service..."
        sudo systemctl stop apport.service
        sudo systemctl disable apport.service
    else
        echo "Automatic Error Reporting is already disabled. No action needed."
    fi
}



# Function to ensure core dumps are restricted
config_core_dumps_restricted() {
    echo -e "\nEnsuring core dumps are restricted"

    # Check if core dumps are properly restricted
    limits_conf_output=$(grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/*)
    suid_dumpable_output=$(sysctl fs.suid_dumpable)
    sysctl_conf_output=$(grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*)

    if [[ "$limits_conf_output" =~ \*.*hard.*core.*0 && "$suid_dumpable_output" == "fs.suid_dumpable = 0" && "$sysctl_conf_output" =~ fs.suid_dumpable.*0 ]]; then
        echo "Core dumps are already properly restricted. No action needed."
    else
        # Configure core dumps restriction
        echo "Configuring core dumps restriction..."
        echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
        sudo sysctl -w fs.suid_dumpable=0

        # Check if systemd-coredump is installed and configure if necessary
        if command -v systemctl >/dev/null && systemctl status systemd-coredump &>/dev/null; then
            echo "Configuring systemd-coredump settings..."
            echo "Storage=none" | sudo tee /etc/systemd/coredump.conf
            echo "ProcessSizeMax=0" | sudo tee -a /etc/systemd/coredump.conf
            sudo systemctl daemon-reload
        fi

        echo "Core dumps restriction configured successfully."
    fi
}



# Function to ensure AppArmor is installed
config_apparmor_installed() {
    echo -e "\nEnsuring AppArmor is installed"

    # Check if AppArmor is installed
    if dpkg -s apparmor >/dev/null 2>&1; then
        echo "AppArmor is already installed. No action needed."
    else
        # Install AppArmor
        echo "Installing AppArmor..."
        sudo apt install -y apparmor
        echo "AppArmor installed successfully."
    fi
}



# Function to ensure AppArmor is enabled in the bootloader configuration
config_apparmor_enabled_bootloader() {
    echo -e "\nEnsuring AppArmor is enabled in the bootloader configuration"

    # Check if AppArmor parameters are set in the bootloader configuration
    if grep -q "^\s*linux" /boot/grub/grub.cfg && grep -q "apparmor=1" /boot/grub/grub.cfg && grep -q "security=apparmor" /boot/grub/grub.cfg; then
        echo "AppArmor is already enabled in the bootloader configuration. No action needed."
    else
        # Add AppArmor parameters to GRUB_CMDLINE_LINUX
        echo "Adding AppArmor parameters to GRUB_CMDLINE_LINUX..."
        sudo sed -i '/^GRUB_CMDLINE_LINUX=/ s/"$/ apparmor=1 security=apparmor"/' /etc/default/grub

        # Update grub2 configuration
        echo "Updating grub2 configuration..."
        sudo update-grub
        echo "AppArmor enabled in the bootloader configuration successfully."
    fi
}


# Function to ensure all AppArmor profiles are in enforce or complain mode
config_apparmor_profiles_enforce_complain() {
    echo -e "\nEnsuring all AppArmor profiles are in enforce or complain mode"

    # Check if any AppArmor profiles are in complain mode or if there are unconfined processes
    profiles_complain=$(sudo apparmor_status | awk '/profiles are in complain mode/{print $1}')
    processes_unconfined=$(sudo apparmor_status | awk '/processes are unconfined but have a profile defined/{print $1}')

    if [ "$profiles_complain" -gt 0 ]; then
        # Set all profiles to enforce mode
        echo "Setting all AppArmor profiles to enforce mode..."
        sudo aa-enforce /etc/apparmor.d/*
    elif [ "$processes_unconfined" -gt 0 ]; then
        # Set all profiles to complain mode
        echo "Setting all AppArmor profiles to complain mode..."
        sudo aa-complain /etc/apparmor.d/*
    else
        echo "All AppArmor profiles are already in enforce or complain mode. No action needed."
    fi
}



# Function to ensure all AppArmor profiles are enforcing
config_apparmor_profiles_enforcing() {
    echo -e "\nEnsuring all AppArmor profiles are enforcing"

    # Check if AppArmor profiles are loaded and in enforce mode
    profiles_loaded=$(sudo apparmor_status | awk '/profiles are loaded/{print $1}')
    profiles_enforce=$(sudo apparmor_status | awk '/profiles are in enforce mode/{print $1}')
    processes_unconfined=$(sudo apparmor_status | awk '/processes are unconfined but have a profile defined/{print $1}')

    if [ "$profiles_loaded" -gt 0 ] && [ "$profiles_enforce" -eq "$profiles_loaded" ] && [ "$processes_unconfined" -eq 0 ]; then
        echo "All AppArmor profiles are already loaded and enforcing. No action needed."
    else
        # Set all profiles to enforce mode
        echo "Setting all AppArmor profiles to enforce mode..."
        sudo aa-enforce /etc/apparmor.d/*
    fi
}



# Function to ensure message of the day is configured properly
config_motd() {
    echo -e "\nEnsuring message of the day is configured properly"

    if [ -f "/etc/motd" ]; then
        # Check if any unauthorized options are present in /etc/motd file
        unauthorized_options=$(grep -Eis "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd)
        if [ -z "$unauthorized_options" ]; then
            echo "Message of the day is properly configured. No action needed."
        else
            # Remove unauthorized options from /etc/motd file
            echo "Removing unauthorized options from /etc/motd file..."
            sudo sed -i -E 's/(\\[mrvs]|'"$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g')"')//g' /etc/motd
        fi
    else
        echo "No /etc/motd file found"
    fi
}



# Function to ensure local login warning banner is configured properly
config_local_login_banner() {
    echo -e "\nEnsuring local login warning banner is configured properly"

    local issue_file="/etc/issue"
    local issue_content=$(cat "$issue_file")
    local os_platform=$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g')

    # Define the desired warning message
    local warning_message="Authorized uses only. All activity may be monitored and reported."

    # Check if /etc/issue is empty
    if [[ -z "$issue_content" ]]; then
        echo "/etc/issue is empty. Adding warning message..."
        echo "$warning_message" >"$issue_file"
    else
        # Remove unauthorized options from /etc/issue file
        echo "Removing unauthorized options from /etc/issue file..."
        sudo sed -i -E 's/(\\[mrvs]|'"$os_platform"')//g' "$issue_file"

        # Check if the warning message is present
        if grep -q "$warning_message" "$issue_file"; then
            echo "Warning message is already configured."
        else
            echo "Adding warning message..."
            echo "$warning_message" >>"$issue_file"
        fi
    fi
}



# Function to ensure remote login warning banner is configured properly
config_remote_login_banner() {
    echo -e "\nEnsuring remote login warning banner is configured properly"

    local issue_net_file="/etc/issue.net"
    local issue_net_content=$(cat "$issue_net_file")
    local os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g')

    # Define the desired warning message
    local warning_message="Authorized uses only. All activity may be monitored and reported."

    # Check if /etc/issue.net is empty
    if [[ -z "$issue_net_content" ]]; then
        echo "/etc/issue.net is empty. Adding warning message..."
        echo "$warning_message" >"$issue_net_file"
    else
        # Remove unauthorized options from /etc/issue.net file
        echo "Removing unauthorized options from /etc/issue.net file..."
        sudo sed -i -E 's/(\\[mrvs]|'"$os_name"')//g' "$issue_net_file"

        # Check if the warning message is present
        if grep -q "$warning_message" "$issue_net_file"; then
            echo "Warning message is already configured."
        else
            echo "Adding warning message..."
            echo "$warning_message" >>"$issue_net_file"
        fi
    fi
}



# Function to ensure permissions on /etc/motd are configured
config_etc_motd_permissions() {
    echo -e "\nEnsuring permissions on /etc/motd are configured"

    local file="/etc/motd"
    local expected_permissions="644"
    local expected_owner="0"
    local expected_group="0"

    # Check if the file exists
    if [ -e "$file" ]; then
        # Get actual permissions, owner, and group using stat
        local actual_permissions=$(stat -c "%a" "$file")
        local actual_owner=$(stat -c "%u" "$file")
        local actual_group=$(stat -c "%g" "$file")

        # Check if actual permissions, owner, and group match the expected values
        if [[ "$actual_permissions" != "$expected_permissions" || "$actual_owner" != "$expected_owner" || "$actual_group" != "$expected_group" ]]; then
            # Fix the permissions
            echo "Fixing permissions on $file..."
            sudo chown root:root "$file"
            sudo chmod 644 "$file"
        fi
    else
        # The file doesn't exist, creating it
        echo "Creating $file..."
        sudo touch "$file"
        sudo chown root:root "$file"
        sudo chmod 644 "$file"
    fi
}



# Function to ensure permissions on /etc/issue are configured
config_etc_issue_permissions() {
    local file="/etc/issue"
    local expected_permissions="644"
    local expected_owner="0"
    local expected_group="0"

    # Get actual permissions, owner, and group using stat
    local actual_permissions=$(stat -c "%a" "$file")
    local actual_owner=$(stat -c "%u" "$file")
    local actual_group=$(stat -c "%g" "$file")

    # Check if actual permissions, owner, and group match the expected values
    if [[ "$actual_permissions" != "$expected_permissions" || "$actual_owner" != "$expected_owner" || "$actual_group" != "$expected_group" ]]; then
        # Fix the permissions
        echo "Fixing permissions on $file..."
        sudo chown root:root "$file"
        sudo chmod 644 "$file"
    fi
}



# Function to ensure permissions on /etc/issue.net are configured
config_etc_issue_net_permissions() {
    local file="/etc/issue.net"
    local expected_permissions="644"
    local expected_owner="0"
    local expected_group="0"

    # Get actual permissions, owner, and group using stat
    local actual_permissions=$(stat -c "%a" "$file")
    local actual_owner=$(stat -c "%u" "$file")
    local actual_group=$(stat -c "%g" "$file")

    # Check if actual permissions, owner, and group match the expected values
    if [[ "$actual_permissions" != "$expected_permissions" || "$actual_owner" != "$expected_owner" || "$actual_group" != "$expected_group" ]]; then
        # Fix the permissions
        echo "Fixing permissions on $file..."
        sudo chown root:root "$file"
        sudo chmod 644 "$file"
    fi
}



# Function to ensure GNOME Display Manager (gdm3) is removed
config_gnome_display_manager_removal() {
    local gdm_status=$(dpkg-query -W -f='${Status}' gdm3 2>/dev/null || echo "not-installed")

    # Check if gdm3 is installed
    if [ "$gdm_status" != "not-installed" ]; then
        # Uninstall gdm3
        echo "Removing GNOME Display Manager (gdm3)..."
        sudo apt purge gdm3
    fi
}



# Function to configure GDM login banner
config_gdm_banner() {
    local l_gdmprofile="gdm" # Set this to desired profile name IaW Local site policy
    local l_bmessage="'Authorized uses only. All activity may be monitored and reported'" # Set to desired banner message

    if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
        echo "Creating profile \"$l_gdmprofile\""
        echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfile-db:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
    fi

    if [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ]; then
        echo "Creating dconf database directory \"/etc/dconf/db/$l_gdmprofile.d/\""
        mkdir /etc/dconf/db/$l_gdmprofile.d/
    fi

    if ! grep -Piq '^\h*banner-message-enable\h*=\h*true\b' /etc/dconf/db/$l_gdmprofile.d/*; then
        echo "creating gdm keyfile for machine-wide settings"
        if ! grep -Piq -- '^\h*banner-message-enable\h*=\h*' /etc/dconf/db/$l_gdmprofile.d/*; then
            l_kfile="/etc/dconf/db/$l_gdmprofile.d/01-banner-message"
            echo -e "\n[org/gnome/login-screen]\nbanner-message-enable=true" >> "$l_kfile"
        else
            l_kfile="$(grep -Pil -- '^\h*banner-message-enable\h*=\h*' /etc/dconf/db/$l_gdmprofile.d/*)"
            ! grep -Pq '^\h*\[org\/gnome\/login-screen\]' "$l_kfile" && sed -ri '/^\s*banner-message-enable/ i\[org/gnome/login-screen]' "$l_kfile"
            ! grep -Pq '^\h*banner-message-enable\h*=\h*true\b' "$l_kfile" && sed -ri 's/^\s*(banner-message-enable\s*=\s*)(\S+)(\s*.*$)/\1true \3/' "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/login-screen\]/ a\\nbanner-message-enable=true' "$l_kfile"
        fi
    fi

    if ! grep -Piq "^\h*banner-message-text=[\'\"]+\S+" "$l_kfile"; then
        sed -ri "/^\s*banner-message-enable/ a\banner-message-text=$l_bmessage" "$l_kfile"
    fi

    dconf update
}



# Function to configure GDM disable user list option
config_gdm_disable_usr_list() {
    local l_gdmprofile="gdm" # Set this to desired profile name according to local site policy

    if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
        echo "Creating profile \"$l_gdmprofile\""
        echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfile-db:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
    fi

    if [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ]; then
        echo "Creating dconf database directory \"/etc/dconf/db/$l_gdmprofile.d/\""
        mkdir /etc/dconf/db/$l_gdmprofile.d/
    fi

    if ! grep -Piq '^\h*disable-user-list\h*=\h*true\b' /etc/dconf/db/$l_gdmprofile.d/*; then
        echo "creating gdm keyfile for machine-wide settings"
        if ! grep -Piq -- '^\h*\[org\/gnome\/login-screen\]' /etc/dconf/db/$l_gdmprofile.d/*; then
            echo -e "\n[org/gnome/login-screen]\n# Do not show the user list\ndisable-user-list=true" >> /etc/dconf/db/$l_gdmprofile.d/00-login-screen
        else
            sed -ri '/^\s*\[org\/gnome\/login-screen\]/ a\# Do not show the user list\ndisable-user-list=true' $(grep -Pil -- '^\h*\[org\/gnome\/login-screen\]' /etc/dconf/db/$l_gdmprofile.d/*)
        fi
    fi

    dconf update
}


# Function to configure GDM screen lock when user is idle if the audit fails
config_gdm_screenlock_usr_idle() {
    local l_profile="local" # Set the desired profile name according to local site policy
    local l_idmv="900"      # Set the max value for idle-delay in seconds (between 1 and 900)
    local l_ldmv="5"        # Set the max value for lock-delay in seconds (between 0 and 5)
    local l_key_file="/etc/dconf/db/$l_profile.d/00-screensaver"

    # Create or edit the profile file in /etc/dconf/profile/ to include user-db:user and system-db:local
    if [ ! -f "/etc/dconf/profile/$l_profile" ]; then
        echo "Creating profile \"$l_profile\""
        echo -e "user-db:user\nsystem-db:$l_profile" > /etc/dconf/profile/$l_profile
    fi

    # Create the directory if it doesn't already exist
    if [ ! -d "/etc/dconf/db/$l_profile.d/" ]; then
        echo "Creating dconf database directory \"/etc/dconf/db/$l_profile.d/\""
        mkdir /etc/dconf/db/$l_profile.d/
    fi

    # Create the key file to provide information for the dconf database
    {
        echo '# Specify the dconf path'
        echo '[org/gnome/desktop/session]'
        echo ''
        echo '# Number of seconds of inactivity before the screen goes blank'
        echo "# Set to 0 seconds if you want to deactivate the screensaver."
        echo "idle-delay=uint32 $l_idmv"
        echo ''
        echo '# Specify the dconf path'
        echo '[org/gnome/desktop/screensaver]'
        echo ''
        echo '# Number of seconds after the screen is blank before locking the screen'
        echo "lock-delay=uint32 $l_ldmv"
    } > "$l_key_file"

    # Update the system databases
    dconf update
}



# Function to configure screen lock to prevent overriding by GDM
config_screen_lock_override() {
    # Check if GNOME Desktop Manager is installed. If the package isn't installed, the recommendation is Not Applicable
    local l_pkgoutput=""
    local l_pq=""

    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    local l_pcl="gdm gdm3" # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="y" && echo -e "\n - Package: \"$l_pn\" exists on the system\n - remediating configuration if needed"
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        # Look for idle-delay to determine profile in use, needed for remaining tests
        local l_kfd="/etc/dconf/db/$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" # set directory of key file to be locked

        # Look for lock-delay to determine profile in use, needed for remaining tests
        local l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" # set directory of key file to be locked

        if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked
            if grep -Prilq '^\h*\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd"; then
                echo " - \"idle-delay\" is locked in \"$(grep -Pril '^\h*\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd")\""
            else
                echo "creating entry to lock \"idle-delay\""
                [ ! -d "$l_kfd"/locks ] && echo "creating directory $l_kfd/locks" && mkdir "$l_kfd"/locks
                {
                    echo -e '\n# Lock desktop screensaver idle-delay setting'
                    echo '/org/gnome/desktop/session/idle-delay'
                } >> "$l_kfd"/locks/00-screensaver
            fi
        else
            echo -e " - \"idle-delay\" is not set so it cannot be locked\n - Please follow Recommendation \"Ensure GDM screen locks when the user is idle\" and follow this Recommendation again"
        fi

        if [ -d "$l_kfd2" ]; then # If key file directory doesn't exist, options can't be locked
            if grep -Prilq '^\h*\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2"; then
                echo " - \"lock-delay\" is locked in \"$(grep -Pril '^\h*\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2")\""
            else
                echo "creating entry to lock \"lock-delay\""
                [ ! -d "$l_kfd2"/locks ] && echo "creating directory $l_kfd2/locks" && mkdir "$l_kfd2"/locks
                {
                    echo -e '\n# Lock desktop screensaver lock-delay setting'
                    echo '/org/gnome/desktop/screensaver/lock-delay'
                } >> "$l_kfd2"/locks/00-screensaver
            fi
        else
            echo -e " - \"lock-delay\" is not set so it cannot be locked\n - Please follow Recommendation \"Ensure GDM screen locks when the user is idle\" and follow this Recommendation again"
        fi

    else
        echo -e " - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi

    # Run the command to update the system databases
    dconf update
}



# Note: Users must log out and back in again before the system-wide settings take effect.

# Function to disable automatic mounting of media for all GNOME users
config_disable_automatic_mounting_media_gnome_users() {
    local l_pkgoutput=""
    local l_output=""
    local l_output2=""

    local l_gpname="local" # Set to desired dconf profile name (default is local)

    # Check if GNOME Desktop Manager is installed. If the package isn't installed, the recommendation is Not Applicable
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done

    echo -e "$l_pkgoutput"

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        echo -e "$l_pkgoutput"

        # Look for existing settings and set variables if they exist
        local l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)"
        local l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)"

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
            echo " - updating dconf profile name to \"$l_gpname\""
        elif [ -f "$l_kfile2" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")"
            echo " - updating dconf profile name to \"$l_gpname\""
        fi

        # Check for consistency (Clean up configuration if needed)
        if [ -f "$l_kfile" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" != "$l_gpname" ]; then
            sed -ri "/^\s*automount\s*=/s/^/# /" "$l_kfile"
            l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"
        fi

        if [ -f "$l_kfile2" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")" != "$l_gpname" ]; then
            sed -ri "/^\s*automount-open\s*=/s/^/# /" "$l_kfile2"
        fi

        [ -n "$l_kfile" ] && l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"

        # Check if profile file exists
        if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
            echo -e "\n - dconf database profile exists in: \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\""
        else
            [ ! -f "/etc/dconf/profile/user" ] && l_gpfile="/etc/dconf/profile/user" || l_gpfile="/etc/dconf/profile/user2"
            echo -e " - creating dconf database profile"
            {
                echo -e "\nuser-db:user"
                echo "system-db:$l_gpname"
            } >> "$l_gpfile"
        fi

        # Create dconf directory if it doesn't exist
        local l_gpdir="/etc/dconf/db/$l_gpname.d"
        if [ -d "$l_gpdir" ]; then
            echo " - The dconf database directory \"$l_gpdir\" exists"
        else
            echo " - creating dconf database directory \"$l_gpdir\""
            mkdir "$l_gpdir"
        fi

        # Check automount-open setting
        if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile"; then
            echo " - \"automount-open\" is set to false in: \"$l_kfile\""
        else
            echo " - creating \"automount-open\" entry in \"$l_kfile\""
            ! grep -Psq -- '^\h*\[org/gnome/desktop/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \automount-open=false' "$l_kfile"
        fi

        # Check automount setting
        if grep -Pqs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then
            echo " - \"automount\" is set to false in: \"$l_kfile\""
        else
            echo " - creating \"automount\" entry in \"$l_kfile\""
            ! grep -Psq -- '^\h*\[org/gnome/desktop/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \automount=false' "$l_kfile"
        fi

    else
        echo -e "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi

    # Update dconf database
    dconf update
}



# Function to lock disable automatic mounting of media for all GNOME users
config_lock_disable_automatic_mounting_media_gnome_users() {
    # Check if GNOME Desktop Manager is installed. If the package isn't installed, the recommendation is Not Applicable
    l_pkgoutput=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="y" && echo -e "\n - Package: \"$l_pn\" exists on the system\n - remediating configuration if needed"
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        # Look for automount to determine profile in use, needed for remaining tests
        l_kfd="/etc/dconf/db/$(grep -Psril '^\h*automount\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" # Set directory of key file to be locked

        # Look for automount-open to determine profile in use, needed for remaining tests
        l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*automount-open\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" # Set directory of key file to be locked

        if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked
            if grep -Priq '^\h*\/org/gnome/desktop/media-handling/automount\b' "$l_kfd"; then
                echo " - \"automount\" is locked in \"$(grep -Pril '^\h*\/org/gnome/desktop/media-handling/automount\b' "$l_kfd")\""
            else
                echo " - creating entry to lock \"automount\""
                [ ! -d "$l_kfd"/locks ] && echo "creating directory $l_kfd/locks" && mkdir "$l_kfd"/locks
                {
                    echo -e '\n# Lock desktop media-handling automount setting'
                    echo '/org/gnome/desktop/media-handling/automount'
                } >> "$l_kfd"/locks/00-media-automount
            fi
        else
            echo -e " - \"automount\" is not set so it cannot be locked\n - Please follow Recommendation \"Ensure GDM automatic mounting of removable media is disabled\" and follow this Recommendation again"
        fi

        if [ -d "$l_kfd2" ]; then # If key file directory doesn't exist, options can't be locked
            if grep -Priq '^\h*\/org/gnome/desktop/media-handling/automount-open\b' "$l_kfd2"; then
                echo " - \"automount-open\" is locked in \"$(grep -Pril '^\h*\/org/gnome/desktop/media-handling/automount-open\b' "$l_kfd2")\""
            else
                echo " - creating entry to lock \"automount-open\""
                [ ! -d "$l_kfd2"/locks ] && echo "creating directory $l_kfd2/locks" && mkdir "$l_kfd2"/locks
                {
                    echo -e '\n# Lock desktop media-handling automount-open setting'
                    echo '/org/gnome/desktop/media-handling/automount-open'
                } >> "$l_kfd2"/locks/00-media-automount
            fi
        else
            echo -e " - \"automount-open\" is not set so it cannot be locked\n - Please follow Recommendation \"Ensure GDM automatic mounting of removable media is disabled\" and follow this Recommendation again"
        fi

        # Update dconf database
        dconf update

    else
        echo -e " - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
}



# Function to set autorun-never to true for GDM users
config_set_autorun_never_true_gdm_users() {
    l_pkgoutput=""
    l_output=""
    l_output2=""
    l_gpname="local" # Set to desired dconf profile name (default is local)

    # Check if GNOME Desktop Manager is installed. If package isn't installed, recommendation is Not Applicable
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done

    echo -e "$l_pkgoutput"

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        echo -e "$l_pkgoutput"

        # Look for existing settings and set variables if they exist
        l_kfile="$(grep -Prils -- '^\h*autorun-never\b' /etc/dconf/db/*.d)"

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
            echo " - updating dconf profile name to \"$l_gpname\""
        fi

        [ ! -f "$l_kfile" ] && l_kfile="/etc/dconf/db/$l_gpname.d/00-media-autorun"

        # Check if profile file exists
        if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
            echo -e "\n - dconf database profile exists in: \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\""
        else
            [ ! -f "/etc/dconf/profile/user" ] && l_gpfile="/etc/dconf/profile/user" || l_gpfile="/etc/dconf/profile/user2"
            echo -e " - creating dconf database profile"
            {
                echo -e "\nuser-db:user"
                echo "system-db:$l_gpname"
            } >> "$l_gpfile"
        fi

        # create dconf directory if it doesn't exists
        l_gpdir="/etc/dconf/db/$l_gpname.d"
        if [ -d "$l_gpdir" ]; then
            echo " - The dconf database directory \"$l_gpdir\" exists"
        else
            echo " - creating dconf database directory \"$l_gpdir\""
            mkdir "$l_gpdir"
        fi

        # check autorun-never setting
        if grep -Pqs -- '^\h*autorun-never\h*=\h*true\b' "$l_kfile"; then
            echo " - \"autorun-never\" is set to true in: \"$l_kfile\""
        else
            echo " - creating or updating \"autorun-never\" entry in \"$l_kfile\""
            if grep -Psq -- '^\h*autorun-never' "$l_kfile"; then
                sed -ri 's/(^\s*autorun-never\s*=\s*)(\S+)(\s*.*)$/\1true \3/' "$l_kfile"
            else
                ! grep -Psq -- '\^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
                sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a\nautorun-never=true' "$l_kfile"
            fi
        fi
    else
        echo -e "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi

    # update dconf database
    dconf update
}



# Function to ensure that autorun-never=true cannot be overridden
config_lock_autorun_never_true() {
    # Check if GNOME Desktop Manager is installed. If package isn't installed, recommendation is Not Applicable
    l_pkgoutput=""
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="y" && echo -e "\n - Package: \"$l_pn\" exists on the system\n - remediating configuration if needed"
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        # Look for autorun to determine profile in use, needed for remaining tests
        l_kfd="/etc/dconf/db/$(grep -Psril '^\h*autorun-never\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked

        if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked
            if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/autorun-never\b' "$l_kfd"; then
                echo " - \"autorun-never\" is locked in \"$(grep -Pril '^\\h*\/org/gnome\/desktop\/media-handling\/autorun-never\b' "$l_kfd")\""
            else
                echo " - creating entry to lock \"autorun-never\""
                [ ! -d "$l_kfd"/locks ] && echo "creating directory $l_kfd/locks" && mkdir "$l_kfd"/locks
                {
                    echo -e '\n# Lock desktop media-handling autorun-never setting'
                    echo '/org/gnome/desktop/media-handling/autorun-never'
                } >> "$l_kfd"/locks/00-media-autorun
            fi
        else
            echo -e " - \"autorun-never\" is not set so it can not be locked\n - Please follow Recommendation \"Ensure GDM autorun-never is enabled\" and follow this Recommendation again"
        fi

        # update dconf database
        dconf update
    else
        echo -e " - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
}



config_gdm_custom_conf() {
    # Check if GNOME Desktop Manager is installed
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    l_pcl="gdm gdm3" # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="y"
    done

    if [ -n "$l_pkgoutput" ]; then
        # Remove the line containing 'Enable=true' from custom.conf
        sudo sed -i '/Enable=true/d' /etc/gdm3/custom.conf
    fi
}



config_update_packages() {
    # Update all packages following local site policy guidance
    sudo apt upgrade -y
}

