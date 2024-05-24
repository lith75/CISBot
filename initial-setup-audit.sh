#!/bin/bash

##Return Values

#Ensuring mounting of cramfs filesystem is disabled
audit_cramfs_disabled() {
    echo -e "\n Ensuring mounting of cramfs filesystem is disabled"
    local l_output=""
    local l_output2=""
    local l_mname="cramfs" # set module name

    # Check how module will be loaded
    local l_loadable="$(modprobe -n -v "$l_mname")"
    if grep -Pq -- '^\h*install \/bin\/(true|false)' <<<"$l_loadable"; then
        l_output="Module \"$l_mname\" is not loadable: \"$l_loadable\""
    else
        l_output2="Module \"$l_mname\" is loadable: \"$l_loadable\""
    fi

    # Check if the module is currently loaded
    if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
        l_output="Module \"$l_mname\" is not loaded"
    else
        l_output2="Module \"$l_mname\" is loaded"
    fi

    # Check if the module is deny listed
    if grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        l_output="Module \"$l_mname\" is deny listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
    else
        l_output2="Module \"$l_mname\" is not deny listed"
    fi

    # Report results. If no failures output in l_output2, pass
    if [ -z "$l_output2" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason: $l_output"
    fi
}



audit_squashfs_disabled() { # Ensuring mounting of squashfs filesystem is disabled
    echo -e "\n Ensuring mounting of squashfs filesystem is disabled"
    local l_output=""
    local l_mname="squashfs" # set module name

    # Check how module will be loaded
    local l_loadable="$(modprobe -n -v "$l_mname")"
    if grep -Pq -- '^\h*install \/bin\/(true|false)' <<<"$l_loadable"; then
        l_output="Module \"$l_mname\" is not loadable: \"$l_loadable\""
    fi

    # Check if the module is currently loaded
    if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
        l_output="Module \"$l_mname\" is not loaded"
    fi

    # Check if the module is deny-listed
    if grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        l_output="Module \"$l_mname\" is deny-listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
    fi

    # Report results. If no failures output in l_output, we pass
    if [ -z "$l_output" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason: $l_output"
    fi
}



#Ensuring mounting of udf filesystems is disabled
audit_udf_disabled() {
    echo -e "\n Ensuring mounting of udf filesystems is disabled"
    local l_output=""
    local l_output2=""
    local l_mname="udf" # set module name

    # Check how module will be loaded
    local l_loadable="$(modprobe -n -v "$l_mname")"
    if grep -Pq -- '^\h*install \/bin\/(true|false)' <<<"$l_loadable"; then
        l_output="Module \"$l_mname\" is not loadable: \"$l_loadable\""
    else
        l_output2="Module \"$l_mname\" is loadable: \"$l_loadable\""
    fi

    # Check if the module is currently loaded
    if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
        l_output="Module \"$l_mname\" is not loaded"
    else
        l_output2="Module \"$l_mname\" is loaded"
    fi

    # Check if the module is deny-listed
    if grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        l_output="Module \"$l_mname\" is deny-listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
    else
        l_output2="Module \"$l_mname\" is not deny-listed"
    fi

    # Report results. If no failures output in l_output2, we pass
    if [ -z "$l_output2" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason: $l_output2"
        [ -n "$l_output" ] && echo -e "Correctly set: $l_output"
    fi
}


##Configure /tmp

audit_tmp_partition_separate() {
    echo -e "\n Ensure /tmp is a separate partition"

    # Check if /tmp is mounted
    tmp_mount=$(findmnt --kernel /tmp)
    if [ -n "$tmp_mount" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: /tmp is not mounted."
        return
    fi

    # Check if systemd will mount the /tmp partition at boot time
    systemctl_is_enabled=$(systemctl is-enabled tmp.mount)
    if [ "$systemctl_is_enabled" == "enabled" ]; then
        echo "Audit: FAIL, Reason: Systemd mount for /tmp is enabled."
    else
        echo "Audit: PASS"
    fi
}



#Ensure nodev option set on /tmp partition
audit_tmp_partition_nodev() {
    echo -e "\n Ensure nodev option set on /tmp partition"
    nodev_option=$(findmnt --kernel /tmp | grep -q nodev && echo "yes" || echo "no")

    # Check if the nodev option is set
    if [ "$nodev_option" == "yes" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: The nodev option is not set on /tmp partition."
    fi
}



#Ensure noexec option set on /tmp partition
audit_tmp_partition_noexec() {
    echo -e "\n Ensure noexec option set on /tmp partition"
    noexec_option=$(findmnt --kernel /tmp | grep -q noexec && echo "yes" || echo "no")

    # Check if the noexec option is set
    if [ "$noexec_option" == "yes" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: The noexec option is not set on /tmp partition."
    fi
}



#Ensure nosuid option set on /tmp partition
audit_tmp_partition_nosuid() {
    echo -e "\n Ensure nosuid option set on /tmp partition"
    nosuid_option=$(findmnt --kernel /tmp | grep -q nosuid && echo "yes" || echo "no")

    # Check if the nosuid option is set
    if [ "$nosuid_option" == "yes" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: The nosuid option is not set on /tmp partition."
    fi
}



##Configure /var

#Ensure seperate partition exist for /var
audit_var_partition_seperate() {
    echo -e "\n Ensure seperate partition exist for /var"
    # Perform the audit to verify if /var is mounted on a separate partition
    if findmnt --kernel /var >/dev/null; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL ,Reason: /var is not mounted on a separate partition"
    fi
}



##Protection from exploitation /var

#Ensure nodev option is set on /var partition
audit_var_partition_nodev() {
    echo -e "\n Ensure nodev option is set on /var partition"
    # Perform the audit to verify if the nodev option is set for the /var mount
    if findmnt --kernel /var | grep -q 'nodev'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nodev option is not set for the /var mount"
    fi
}



# Function to ensure noexec option is set on /tmp partition
audit_tmp_partition_noexec() {
    echo -e "\nEnsure noexec option is set on /tmp partition"
    # Perform the audit to verify if the noexec option is set for the /tmp mount
    if findmnt --kernel /tmp | grep -q 'noexec'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: noexec option is not set for the /tmp mount"
    fi
}



#Ensure nosuid option is set on /var partition
audit_var_partition_nosuid() {
    echo -e "\n Ensure nosuid option is set on /var partition"
    # Perform the audit to verify if the nosuid option is set for the /var mount
    if findmnt --kernel /var | grep -q 'nosuid'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nosuid option is not set for the /var mount"
    fi
}



##Configure /var/tmp

#Ensure seperate partition exist for /var/tmp
audit_var_tmp_seperate_partition() {
    echo -e "\n Ensure seperate partition exist for /var/tmp"
    # Perform the audit to verify if /var/tmp is mounted
    if findmnt --kernel /var/tmp &>/dev/null; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: /var/tmp is not mounted on a separate partition"
    fi
}


##Protection from exploitation - /var/tmp

#Ensure noexec option set on /var/tmp partition
audit_var_tmp_partition_noexec() {
    echo -e "\n Ensure noexec option set on /var/tmp partition"
    # Perform the audit to verify if the nosuid option is set for /var/tmp mount
    if findmnt --kernel /var/tmp | grep -q nosuid; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: The nosuid option is not set for /var/tmp mount"
    fi
}


#Ensure nosuid option set on /var/tmp partition
audit_var_tmp_partition_nosuid() {
    echo -e "\n Ensure nosuid option set on /var/tmp partition"
    # Perform the audit to verify if the nosuid option is set for /var/tmp mount
    if findmnt --kernel /var/tmp | grep -q nosuid; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: The nosuid option is not set for /var/tmp mount"
    fi
}



#Ensure nodev option set on /var/tmp partition
audit_var_tmp_partition_nodev() {
    echo -e "\n Ensure nodev option set on /var/tmp partition"
    # Perform the audit to verify if the nodev option is set for /var/tmp mount
    if findmnt --kernel /var/tmp | grep -q nodev; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: The nodev option is not set for /var/tmp mount"
    fi
}



##Configure /var/log

#Ensure seperate partition exist for /var/log partition
audit_var_log_partition_seperate() {
    echo -e "\n Ensure seperate partition exist for /var/log partition"
    # Perform the audit to verify if a separate partition exists for /var/log
    if findmnt --kernel /var/log >/dev/null 2>&1; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: Separate partition for /var/log does not exist"
    fi
}



##Protection of Log data

#Ensure nodev option set on /var/log partition
audit_var_log_partition_nodev() {
    echo -e "\n Ensure nodev option set on /var/log partition"
    # Perform the audit to verify nodev option is set on /var/log partition
    audit_result=$({
        # Check if the nodev option is set for the /var/log mount
        findmnt --kernel /var/log | grep -q nodev
        if [ $? -eq 0 ]; then
            echo " PASS"
        else
            echo " FAIL, Reason: The nodev option is not set for the /var/log mount"
        fi
    })

    # Output the audit result
    echo -e "Audit:$audit_result"
}



#Ensure noexec option set on /var/log partition
audit_var_log_partition_noexec() {
    echo -e "\n Ensure noexec option set on /var/log partition"
    # Perform the audit to verify noexec option is set on /var/log partition
    audit_result=$({
        # Check if the noexec option is set for the /var/log mount
        findmnt --kernel /var/log | grep -q noexec
        if [ $? -eq 0 ]; then
            echo " PASS"
        else
            echo " FAIL, Reason: The noexec option is not set for the /var/log mount"
        fi
    })

    # Output the audit result
    echo -e "Audit:$audit_result"
}



#Ensure nosuid option set on /var/log partition
audit_var_log_partition_nosuid() {
    echo -e "\n Ensure nosuid option set on /var/log partition"
    # Perform the audit to verify nosuid option is set on /var/log partition
    audit_result=$({
        # Check if the nosuid option is set for the /var/log mount
        findmnt --kernel /var/log | grep -q nosuid
        if [ $? -eq 0 ]; then
            echo " PASS"
        else
            echo " FAIL, Reason: The nosuid option is not set for the /var/log mount"
        fi
    })

    # Output the audit result
    echo -e "Audit:$audit_result"
}



##Configure /var/log/audit

#Ensure seperate partition exist for /var/log/audit
audit_var_log_audit_seperate_partition() {
    echo -e "\n Ensure seperate partition exist for /var/log/audit"
    # Perform the audit to verify if /var/log/audit is mounted on a separate partition
    if findmnt --kernel /var/log/audit | grep -q '/var/log/audit'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: /var/log/audit is not mounted on a separate partition"
    fi

}



##Protection of Audit data

#Ensure noexec option set on /var/log/audit partition
audit_var_log_audit_partition_noexec() {
    echo -e "\n Ensure noexec option set on /var/log/audit partition"
    # Perform the audit to verify if the noexec option is set on /var/log/audit partition
    if findmnt --kernel /var/log/audit | grep -q 'noexec'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: noexec option is not set on /var/log/audit partition"
    fi
}



#Ensure nodev option set on /var/log/audit partition
audit_var_log_audit_partition_nodev() {
    echo -e "\n Ensure nodev option set on /var/log/audit partition"
    # Perform the audit to verify if the nodev option is set on /var/log/audit partition
    if findmnt --kernel /var/log/audit | grep -q 'nodev'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nodev option is not set on /var/log/audit partition"
    fi
}



#Ensure nosuid option set on /var/log/audit partition
audit_var_log_audit_partition_nosuid() {
    echo -e "\n Ensure nosuid option set on /var/log/audit partition"
    # Perform the audit to verify if the nosuid option is set on /var/log/audit partition
    if findmnt --kernel /var/log/audit | grep -q 'nosuid'; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nosuid option is not set on /var/log/audit partition"
    fi
}



##Configure /home

#Ensure seperate partition exists for /home
audit_home_sperate_partition() {
    echo -e "\n Ensure seperate partition exists for /home"
    home_mount=$(findmnt --kernel /home)

    # Check if /home is mounted
    if [ -n "$home_mount" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: /home is not mounted."
    fi
}



##Protection of User Data

#Ensure nodev option set on /home partition
audit_home_partition_nodev() {
    echo -e "\n Ensure nodev option set on /home partition"
    nodev_option=$(findmnt --kernel --noheadings --output OPTIONS /home | grep -w "nodev")

    # Check if nodev option is set
    if [ -n "$nodev_option" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nodev option is not set on /home partition."
    fi
}



#Ensure nosuid option set on /home partition
audit_home_partition_nosuid() {
    echo -e "\n Ensure nosuid option set on /home partition"
    nosuid_option=$(findmnt --kernel --noheadings --output OPTIONS /home | grep -w "nosuid")
    # Check if nosuid option is set
    if [ -n "$nosuid_option" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nosuid option is not set on /home partition."
    fi
}



##Configure /dev/shm

#Ennsure nodev option set on /dev/shm partition
audit_dev_shm_partition_nodev() {
    echo -e "\n Ennsure nodev option set on /dev/shm partition"
    # Verify that the nodev option is set for the /dev/shm mount
    if findmnt --kernel /dev/shm | grep -q nodev; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nodev option is not set for /dev/shm partition"
    fi
}



#Ensure noexec option set on /dev/shm partition
audit_dev_shm_partition_noexec() {
    echo -e "\n Ensure noexec option set on /dev/shm partition"
    # Verify that the noexec option is set for the /dev/shm mount
    if findmnt --kernel /dev/shm | grep -q noexec; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: noexec option is not set for /dev/shm partition"
    fi
}



#Ensure nosuid option set on /dev/shm partition
audit_dev_shm_partition_nosui() {
    echo -e "\n Ensure nosuid option set on /dev/shm partition"
    # Verify that the nosuid option is set for the /dev/shm mount
    if findmnt --kernel /dev/shm | grep -q nosuid; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: nosuid option is not set for /dev/shm partition"
    fi
}



#Disable Automounting
audit_disable_automounting() {
    echo -e "\n Disable Automounting"
    local result=""
    # Check if autofs is installed
    if ! dpkg -l autofs &>/dev/null; then
        result="autofs is not installed"
    else
        # Check if autofs is enabled
        if systemctl is-enabled autofs.service 2>/dev/null | grep -q 'enabled'; then
            result="autofs is enabled"
        else
            result="autofs is installed but not enabled"
        fi
    fi
    # Report audit result
    if [[ "$result" == "autofs is not installed" ]]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: $result"
    fi
}



#Disable USB Storage
audit_disable_usb_storage() {
    echo -e "\n Disable USB Storage"
    # Perform the audit to verify usb-storage is disabled
    audit_result=$({
        l_output=""
        l_output2=""
        l_mname="usb-storage" # set module name
        # Check how module will be loaded
        l_loadable="$(modprobe -n -v "$l_mname")"
        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<<"$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable: \"$l_loadable\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable: \"$l_loadable\""
        fi
        # Check if the module is currently loaded
        if ! lsmod | grep "$l_mname" >/dev/null 2>&1; then
            l_output="$l_output\n - module: \"$l_mname\" is not loaded"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loaded"
        fi
        # Check if the module is deny listed
        if grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
            l_output="$l_output\n - module: \"$l_mname\" is deny listed in: \"$(grep -Pl -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*)\""
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is not deny listed"
        fi
        # Report results. If no failures output in l_output2, we pass
        if [ -z "$l_output2" ]; then
            echo -e "PASS"
        else
            echo -e "FAIL, Reason:$l_output2"
        fi
    })

    # Output the audit result
    echo -e "Audit: $audit_result"

}



##Configure software packages

# #Ensure package manager repositories are configured
# audit_pkg_manager_repo_config_manual() {
#     echo -e "\n Ensure package manager repositories are configured \n**A Manual Process**\n"
#     #!/bin/bash

#     # Check if APT package manager is installed
#     if ! command -v apt &>/dev/null; then
#         echo "APT package manager is not installed or not found."
#         exit 1
#     fi

#     # Display packages in the repositories
#     echo -e "Below are the package manager repositories \n"
#     apt-cache policy
# }

# audit_pkg_manager_repo_config_manual

# #Ensure GPG keys are configured
# audit_gpg_keys_config() {
#     echo -e "\n Ensure GPG keys are configured \n **A Manual Process**"
#     # Check if APT package manager is installed
#     if ! command -v apt &>/dev/null; then
#         echo "APT package manager is not installed or not found."
#         exit 1
#     fi

#     # Display GPG keys configuration for APT package manager
#     echo "\nBelow are the existing GPG keys /n"
#     apt-key list
# }

# audit_gpg_keys_config

# Check if AIDE is installed
audit_aide_installed() {
    echo -e "\n Check if AIDE is installed"
    if dpkg -s aide >/dev/null 2>&1; then
        echo "Audit: PASS"
    else
        echo "Audit: Failed, Reason: AIDE is not installed"
    fi
}



#Ensure filesystem integrity is regularly checked
audit_file_sys_integrity_checked() {
    # Check if a cron job is configured for filesystem integrity checks
    echo -e "\n Ensure filesystem integrity is regularly checked"
    # if crontab -l | grep -q '/usr/bin/aide --check'; then
    #     echo "Audit: PASS (Cron job for filesystem integrity check is configured)"
    # else
    #     echo "Audit: Failed, Reason: Cron job for filesystem integrity check is not configured"
    # fi

    # Check if aidecheck.service and aidecheck.timer are enabled and running
    if systemctl is-enabled aidecheck.service &>/dev/null && systemctl is-enabled aidecheck.timer &>/dev/null; then
        if systemctl is-active aidecheck.timer &>/dev/null; then
            echo "Audit: PASS"
        else
            echo "Audit: Failed, Reason: aidecheck.timer is not running"
        fi
    else
        echo "Audit: Failed, Reason: aidecheck.service and aidecheck.timer are not both enabled"
    fi
}



##Filesystem Integrity Checking

#Ensuring bootloader password is set
audit_bootloader_pwd() {
    echo -e "\n Ensure bootloader password is set"
    # Check if bootloader password is set
    superusers_line=$(grep "^set superusers" /boot/grub/grub.cfg)
    password_line=$(grep "^password_pbkdf2" /boot/grub/grub.cfg)

    if [[ -n "$superusers_line" && -n "$password_line" ]]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: Bootloader password is not set"
    fi
}



#Ensuring permissions on bootloader config are configured
audit_bootloader_config_permissions() {
    echo -e "\n Ensure permissions on bootloader config are configured"
    # Check permissions on the bootloader config file
    bootloader_config="/boot/grub/grub.cfg"
    expected_permissions="0400"
    expected_uid="0"
    expected_gid="0"

    if [ -e "$bootloader_config" ]; then
        actual_permissions=$(stat -c "%a" "$bootloader_config")
        actual_uid=$(stat -c "%u" "$bootloader_config")
        actual_gid=$(stat -c "%g" "$bootloader_config")

        if [ "$actual_permissions" -ge "$expected_permissions" ] && [ "$actual_uid" -eq "$expected_uid" ] && [ "$actual_gid" -eq "$expected_gid" ]; then
            echo "Audit: PASS"
        else
            echo "Audit: FAIL, Reason: Incorrect permissions or ownership on $bootloader_config"
        fi
    else
        echo "Audit: FAIL, Reason: $bootloader_config does not exist"
    fi
}



#Ensurig authentication is required for single user mode
audit_single_usr_auth() {
    echo -e "\n Ensure authentication is required for single user mode"
    # Perform the audit to determine if a password is set for the root user
    if grep -Eq '^root:\$[0-9]' /etc/shadow; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL"
    fi
}



## Additional Process Hardening

#Ensure address space layout randomization (ASLR) is enabled
audit_aslr_enabled() {
    echo -e "\n Ensure address space layout randomization (ASLR) is enabled"
    krp="" pafile="" fafile=""
    kpname="kernel.randomize_va_space"
    kpvalue="2"
    searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"
    krp="$(sysctl "$kpname" | awk -F= '{print $2}' | xargs)"
    pafile="$(grep -Psl -- "^\h*$kpname\h*=\h*$kpvalue\b\h*(#.*)?$" $searchloc)"
    fafile="$(grep -s -- "^\s*$kpname" $searchloc | grep -Pv -- "\h*=\h*$kpvalue\b\h*" | awk -F: '{print $1}')"
    if [ "$krp" = "$kpvalue" ] && [ -n "$pafile" ] && [ -z "$fafile" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason: "
        [ "$krp" != "$kpvalue" ] && echo -e "\"$kpname\" is set to \"$krp\" in the running configuration"
        [ -n "$fafile" ] && echo -e "\"$kpname\" is set incorrectly in \"$fafile\""
        [ -z "$pafile" ] && echo -e "\"$kpname = $kpvalue\" is not set in a kernel parameter configuration file"
    fi
}



#Ensure Prelink is not installed
audit_prelink_not_insalled() {
    echo -e "\n Ensure Prelink is not installed"
    prelink_status=$(dpkg-query -W -f='${Status}' prelink 2>/dev/null || echo "not-installed")
    # Check if prelink is not installed
    if [ "$prelink_status" == "not-installed" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: prelink is installed."
    fi
}



#Ensure Automatic Error Reporting is not enabled
audit_automatic_err_reporting_disabled() {
    echo -e "\n Ensure Automatic Error Reporting is not enabled"
    # Check if Apport Error Reporting Service is enabled
    if dpkg-query -s apport >/dev/null 2>&1 && grep -qPi -- '^\s*enabled\s*=\s*[^0]\b' /etc/default/apport; then
        echo "Audit: FAIL, Reason: Apport Error Reporting Service is enabled"
    elif systemctl is-active apport.service | grep -q '^active'; then
        echo "Audit: FAIL, Reason: Apport service is active"
    else
        echo "Audit: PASS"
    fi
}



#Ensure core dumps are restricted
audit_core_dumps_restricted() {
    echo -e "\n Ensure core dumps are restricted"
    limits_conf_output=$(grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/*)
    suid_dumpable_output=$(sysctl fs.suid_dumpable)
    sysctl_conf_output=$(grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*)

    # Skip coredump service check
    if [[ "$limits_conf_output" =~ \*.*hard.*core.*0 && "$suid_dumpable_output" == "fs.suid_dumpable = 0" && "$sysctl_conf_output" =~ fs.suid_dumpable.*0 ]]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: Core dumps are not properly restricted."
    fi
}


##Configure AppArmor

#Ensure Apparmor is installed
audit_apparmor_installed() {
    echo -e "\n Ensure AppArmor is installed"
    if dpkg -s apparmor >/dev/null 2>&1; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: AppArmor is not installed"
    fi
}



#Ensure Apparmor is enabled in the bootloader Configuration
audit_apparmor_enabled_bootloader() {
    echo -e "\n Ensure AppArmor is enabled in the bootloader configuration"
    if grep -q "^\s*linux" /boot/grub/grub.cfg && ! grep -q "^\s*linux" /boot/grub/grub.cfg | grep -q "apparmor=1"; then
        echo "Audit: Failed, Reason: AppArmor is not enabled in the bootloader configuration"
    elif grep -q "^\s*linux" /boot/grub/grub.cfg && ! grep -q "^\s*linux" /boot/grub/grub.cfg | grep -q "security=apparmor"; then
        echo "Audit: FAIL, Reason: 'security=apparmor' parameter is not set in the bootloader configuration"
    else
        echo "Audit: PASS"
    fi
}



#Ensure all Apparmor profiles are in enforce or complain mode
audit_apparmor_all_profiles_enforce_complian() {
    echo -e "\n Ensure all AppArmor profiles are in enforce or complain mode"
    profiles_loaded=$(apparmor_status | awk '/profiles are loaded/{print $1}')
    profiles_enforce=$(apparmor_status | awk '/profiles are in enforce mode/{print $1}')
    profiles_complain=$(apparmor_status | awk '/profiles are in complain mode/{print $1}')
    processes_unconfined=$(apparmor_status | awk '/processes are unconfined but have a profile defined/{print $1}')

    if [ "$profiles_loaded" -eq 0 ]; then
        echo "Audit: FAIL, Reason: No AppArmor profiles are loaded"
    elif [ "$profiles_complain" -gt 0 ]; then
        echo "Audit: FAIL, Reason: Some AppArmor profiles are in complain mode"
    elif [ "$processes_unconfined" -gt 0 ]; then
        echo "Audit: FAIL, Reason: Some processes are unconfined but have a profile defined"
    else
        echo "Audit: PASS"
    fi
}



#Ensure all Apparmor profiles are enforcing
audit_apparmor_all_profiles_enforcing() {
    echo -e "\n Check if AppArmor profiles are loaded and in enforce mode"
    profiles_loaded=$(apparmor_status | grep "profiles are loaded" | awk '{print $1}')
    profiles_enforce=$(apparmor_status | grep "profiles are in enforce mode" | awk '{print $1}')
    processes_unconfined=$(apparmor_status | grep "processes are unconfined but have a profile defined" | awk '{print $1}')
    if [ "$profiles_loaded" -gt 0 ] && [ "$profiles_enforce" -gt 0 ] && [ "$processes_unconfined" -eq 0 ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: AppArmor profiles are not properly loaded, or some processes are unconfined"
    fi
}



##Command Line Warning Banners

#Ensure message of the day is configured properly
audit_message_ofthe_day_config() {
    echo -e "\n Ensure message of the day is configured properly"
    if [ -f "/etc/motd" ]; then
        # Check if any unauthorized options are present in /etc/motd file
        unauthorized_options=$(grep -Eis "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd)
        if [ -z "$unauthorized_options" ]; then
            echo "Audit: PASS"
        else
            echo "Audit: FAIL, Reason: Unauthorized options found in /etc/motd file."
        fi
    else
        echo "Audit: PASS"
    fi
}



audit_banner_local_login_warning() {
    echo -e "\nEnsure local login warning banner is configured properly"
    local issue_content=$(cat /etc/issue)

    # Check if /etc/issue is empty
    if [[ -z "$issue_content" ]]; then
        echo "Audit: FAIL, Reason: /etc/issue is empty"
        return
    fi

    # Check if the contents of /etc/issue match the site policy
    grep_result=$(grep -E -i "(\\v|\\r|\\m|\\s|$issue_content)" /etc/issue 2>/dev/null)
    if [[ $? -eq 2 ]]; then
        echo "Audit: FAIL, Reason: Unable to process /etc/issue due to invalid characters"
        return
    fi

    if [[ "$grep_result" ]]; then
        echo "Audit: FAIL, Reason: /etc/issue contains unauthorized information"
    else
        echo "Audit: PASS"
    fi
}




#Ensure remote login warning banner is configured properly
audit_banner_remote_login_warning() {
    echo -e "\nEnsure remote login warning banner is configured properly"
    local issue_net_content=$(cat /etc/issue.net)
    local os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g')
    local grep_result=$(grep -E -i "(\\v|\\r|\\m|\\s|$os_name|$issue_net_content)" /etc/issue.net 2>/dev/null)

    # Check if /etc/issue.net is empty
    if [[ -z "$issue_net_content" ]]; then
        echo "Audit: FAIL, Reason: /etc/issue.net is empty"
        return
    fi

    # Check if the contents of /etc/issue.net match the site policy
    if [[ "$grep_result" ]]; then
        echo "Audit: FAIL, Reason: /etc/issue.net contains unauthorized information"
    else
        echo "Audit: PASS"
    fi
}



#Ensure permissions on /etc/motd are configured
audit_etc_motd_permissions_config() {
    echo -e "\n Ensure permissions on /etc/motd are configured"
    file="/etc/motd"
    # Check if the file exists
    if [ -e "$file" ]; then
        # Expected permissions
        expected_permissions="644"
        expected_owner="0"
        expected_group="0"

        # Get actual permissions, owner, and group using stat
        actual_permissions=$(stat -c "%a" "$file")
        actual_owner=$(stat -c "%u" "$file")
        actual_group=$(stat -c "%g" "$file")

        # Check if actual permissions, owner, and group match the expected values
        if [[ "$actual_permissions" == "$expected_permissions" && "$actual_owner" == "$expected_owner" && "$actual_group" == "$expected_group" ]]; then
            echo "Audit: PASS"
        else
            echo "Audit: FAIL, Reason: Permissions on $file are not properly configured."
        fi
    else
        echo "Audit: PASS, Reason: The file $file does not exist."
    fi
}



#Ensure permissions on /etc/issue are configured
audit_etc_issue_permisions_config() {
    echo -e "\n Ensure permissions on /etc/issue are configured"
    file="/etc/issue"

    # Expected permissions
    expected_permissions="644"
    expected_owner="0"
    expected_group="0"

    # Get actual permissions, owner, and group using stat
    actual_permissions=$(stat -c "%a" "$file")
    actual_owner=$(stat -c "%u" "$file")
    actual_group=$(stat -c "%g" "$file")

    # Check if actual permissions, owner, and group match the expected values
    if [[ "$actual_permissions" == "$expected_permissions" && "$actual_owner" == "$expected_owner" && "$actual_group" == "$expected_group" ]]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: Permissions on $file are not properly configured."
    fi
}



#Ensure permissions on /etc/issue.net are configured
audit_etc_issuenet_permisions_config() {
    echo -e "\n Ensure permissions on /etc/issue.net are configured"
    file="/etc/issue.net"

    # Expected permissions
    expected_permissions="644"
    expected_owner="0"
    expected_group="0"

    # Get actual permissions, owner, and group using stat
    actual_permissions=$(stat -c "%a" "$file")
    actual_owner=$(stat -c "%u" "$file")
    actual_group=$(stat -c "%g" "$file")

    # Check if actual permissions, owner, and group match the expected values
    if [[ "$actual_permissions" == "$expected_permissions" && "$actual_owner" == "$expected_owner" && "$actual_group" == "$expected_group" ]]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: Permissions on $file are not properly configured."
    fi
}



#GNOME Disaplay Manager

#Ensure gnome display manager is removed
audit_gnome_display_mnger_rm() {
    echo -e "\n Ensure gnome display manager is removed"
    #check if gdm3 is installed
    gdm_status=$(dpkg-query -W -f='${Status}' gdm3 2>/dev/null || echo "not-installed")

    # Check if gdm3 is not installed
    if [ "$gdm_status" == "not-installed" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: GNOME Display Manager (gdm3) is installed."
    fi
}


audit_gdm_login_banner_config() {
    echo -e "\nEnsure GDM Login banner is configured"
    local l_pkgoutput=""
    local l_output=""
    local l_output2=""

    # Check if dpkg-query or rpm command is available
    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # List of packages to check
    local l_pcl="gdm gdm3"

    # Check if packages exist
    for l_pn in $l_pcl; do
        if $l_pq "$l_pn" >/dev/null 2>&1; then
            l_pkgoutput="$l_pkgoutput - Package: \"$l_pn\" exists on the system - Checking configuration"
        fi
    done

    # If packages are installed, check their configuration
    if [ -n "$l_pkgoutput" ]; then
        # Look for existing settings and set variables if they exist
        l_gdmfile="$(grep -Prils '^\s*banner-message-enable\b' /etc/dconf/db/*.d)"
        if [ -n "$l_gdmfile" ]; then
            # Check if banner message is enabled
            if grep -Pisq '^\s*banner-message-enable=true\b' "$l_gdmfile"; then
                l_output="$l_output - The \"banner-message-enable\" option is enabled in \"$l_gdmfile\""
            else
                l_output2="$l_output2 - The \"banner-message-enable\" option is not enabled"
            fi

            # Check banner-message-text option
            l_lsbt="$(grep -Pios '^\s*banner-message-text=.*$' "$l_gdmfile")"
            if [ -n "$l_lsbt" ]; then
                l_output="$l_output - The \"banner-message-text\" option is set in \"$l_gdmfile\"\nbanner-message-text is set to:\n\"$l_lsbt\""
            else
                l_output2="$l_output2 - The \"banner-message-text\" option is not set"
            fi
        else
            l_output2="$l_output2 - The \"banner-message-enable\" option isn't configured"
        fi
    else
        # If packages are not installed, return recommendation as "Not Applicable"
        echo "Audit: PASS, Reason: GNOME Desktop Manager isn't installed - Recommendation is Not Applicable"
        return
    fi

    # Report results. If no failures, output PASS, otherwise output FAIL and reasons
    if [ -z "$l_output2" ]; then
        echo "Audit: PASS"
    else
        echo "Audit: FAIL, Reason: $l_output2"
    fi
}



#Ensure GDM disable user list option is enabled
audit_gdm_disable_usr_list_enable() {
    echo -e "\n Ensure GDM disable user list option is enabled"
    l_pkgoutput=""

    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    l_pcl="gdm gdm3" # Space-separated list of packages to check

    for l_pn in $l_pcl; do
        $l_pq "$l_pn" >/dev/null 2>&1 && l_pkgoutput="$l_pkgoutput - Package: \"$l_pn\" exists on the system - checking configuration"
    done

    if [ -n "$l_pkgoutput" ]; then
        output=""
        output2=""
        l_gdmfile="$(grep -Pril '^\s*disable-user-list\s*=\s*true\b' /etc/dconf/db)"

        if [ -n "$l_gdmfile" ]; then
            output="$output\n - The \"disable-user-list\" option is enabled in \"$l_gdmfile\""
            l_gdmprofile="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<<"$l_gdmfile")"

            if grep -Pq "^\s*system-db:$l_gdmprofile" /etc/dconf/profile/"$l_gdmprofile"; then
                output="$output\ The \"$l_gdmprofile\" exists"
            else
                output2="$output2\ The \"$l_gdmprofile\" doesn't exist"
            fi

            if [ -f "/etc/dconf/db/$l_gdmprofile" ]; then
                output="$output The \"$l_gdmprofile\" profile exists in the dconf database"
            else
                output2="$output2 The \"$l_gdmprofile\" profile doesn't exist in the dconf database"
            fi
        else
            output2="$output2 The \"disable-user-list\" option is not enabled"
        fi

        if [ -z "$output2" ]; then
            echo -e "Audit: PASS"
        else
            echo -e "Audit: FAIL, Reason: $output2"
            [ -n "$output" ] && echo -e "$output\n"
        fi
    else
        echo -e "\n Audit: PASS"
    fi
}



audit_gdm_screenlock_usr_idle() {
    echo -e "\nEnsure GDM screen locks when the user is idle"
    local l_pkgoutput=""

    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    local l_pcl="gdm gdm3"

    for l_pn in $l_pcl; do
        $l_pq "$l_pn" >/dev/null 2>&1 && l_pkgoutput="Package: \"$l_pn\" exists on the system - Checking configuration"
    done

    if [ -n "$l_pkgoutput" ]; then
        local l_output=""
        local l_output2=""
        local l_idmv="900" # Set for max value for idle-delay in seconds
        local l_ldmv="5"   # Set for max value for lock-delay in seconds

        local l_kfile="$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/)" 

        if [ -n "$l_kfile" ]; then
            local l_profile="$(awk -F'/' '{split($(NF-1),a,".");print a[1]}' <<<"$l_kfile")"
            local l_pdbdir="/etc/dconf/db/$l_profile.d"                                      

            local l_idv="$(awk -F 'uint32' '/idle-delay/{print $2}' "$l_kfile" | xargs)"

            if [ -n "$l_idv" ]; then
                [ "$l_idv" -gt "0" -a "$l_idv" -le "$l_idmv" ] && l_output="$l_output The \"idle-delay\" option is set to \"$l_idv\" seconds in \"$l_kfile\""
                [ "$l_idv" = "0" ] && l_output2="$l_output2 The \"idle-delay\" option is set to \"$l_idv\" (disabled) in \"$l_kfile\""
                [ "$l_idv" -gt "$l_idmv" ] && l_output2="$l_output2 The \"idle-delay\" option is set to \"$l_idv\" seconds (greater than $l_idmv) in \"$l_kfile\""
            else
                l_output2="$l_output2 The \"idle-delay\" option is not set in \"$l_kfile\""
            fi

            local l_ldv="$(awk -F 'uint32' '/lock-delay/{print $2}' "$l_kfile" | xargs)"

            if [ -n "$l_ldv" ]; then
                [ "$l_ldv" -ge "0" -a "$l_ldv" -le "$l_ldmv" ] && l_output="$l_output The \"lock-delay\" option is set to \"$l_ldv\" seconds in \"$l_kfile\""
                [ "$l_ldv" -gt "$l_ldmv" ] && l_output2="$l_output2 The \"lock-delay\" option is set to \"$l_ldv\" seconds (greater than $l_ldmv) in \"$l_kfile\""
            else
                l_output2="$l_output2 The \"lock-delay\" option is not set in \"$l_kfile\""
            fi

            if grep -Psq "^\h*system-db:$l_profile" /etc/dconf/profile/*; then
                l_output="$l_output The \"$l_profile\" profile exists"
            else
                l_output2="$l_output2 The \"$l_profile\" profile doesn't exist"
            fi

            if [ -f "/etc/dconf/db/$l_profile" ]; then
                l_output="$l_output The \"$l_profile\" profile exists in the dconf database"
            else
                l_output2="$l_output2 The \"$l_profile\" profile doesn't exist in the dconf database"
            fi
        else
            l_output2="$l_output2 The \"idle-delay\" option doesn't exist"
        fi
    else
        l_output="$l_output GNOME Desktop Manager package is not installed on the system"
    fi

    [ -n "$l_pkgoutput" ] && 
        if [ -z "$l_output2" ]; then
            echo "Audit: PASS $l_output"
        else
            echo "Audit: FAIL, Reason:$l_output2"
            [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output"
        fi
}



audit_gdm_screenlock_override() {
    echo -e "\nEnsure GDM screen locks cannot be overridden"
    local l_pkgoutput=""

    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    local l_pcl="gdm gdm3"

    for l_pn in $l_pcl; do
        $l_pq "$l_pn" >/dev/null 2>&1 && l_pkgoutput="Package: \"$l_pn\" exists on the system - Checking configuration"
    done

    if [ -n "$l_pkgoutput" ]; then
        local l_output=""
        local l_output2=""

        local l_kfd=$(grep -l -r -P '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d
        local l_kfd2=$(grep -l -r -P '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d 

        if [ -d "$l_kfd" ]; then
            if grep -q '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd"; then
                l_output="$l_output \"idle-delay\" is locked in \"$(grep -l '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd")\""
            else
                l_output2="$l_output2 \"idle-delay\" is not locked"
            fi
        else
            l_output2="$l_output2 \"idle-delay\" is not set so it cannot be locked"
        fi

        if [ -d "$l_kfd2" ]; then
            if grep -q '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2"; then
                l_output="$l_output \"lock-delay\" is locked in \"$(grep -l '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2")\""
            else
                l_output2="$l_output2 \"lock-delay\" is not locked"
            fi
        else
            l_output2="$l_output2 \"lock-delay\" is not set so it cannot be locked"
        fi
    else
        l_output="$l_output GNOME Desktop Manager package is not installed on the system - Recommendation is not applicable"
    fi

    [ -n "$l_pkgoutput" ] && 
        if [ -z "$l_output2" ]; then
            echo "Audit: PASS"
        else
            echo "Audit: FAIL, Reason:$l_output2"
        fi
}



audit_gdm_auto_mounting_removable_disable() {
    echo -e "\nEnsure GDM automatic mounting of removable media is disabled"
    local l_pkgoutput=""
    local l_output=""
    local l_output2=""

    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    else
        echo "Package manager not found, exiting."
        exit 1
    fi

    local l_pcl="gdm gdm3"

    for l_pn in $l_pcl; do
        if $l_pq "$l_pn" >/dev/null 2>&1; then
            l_pkgoutput="$l_pkgoutput Package: \"$l_pn\" exists on the system - Checking configuration"
        fi
    done

    if [ -n "$l_pkgoutput" ]; then
        local l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)"
        local l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)"

        local l_gpname=""
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F'/' '{split($(NF-1),a,".");print a[1]}' <<<"$l_kfile")"
        elif [ -f "$l_kfile2" ]; then
            l_gpname="$(awk -F'/' '{split($(NF-1),a,".");print a[1]}' <<<"$l_kfile2")"
        fi

        if [ -n "$l_gpname" ]; then
            local l_gpdir="/etc/dconf/db/$l_gpname.d"

            if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
                l_output="dconf database profile file \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists"
            else
                l_output2="dconf database profile isn't set"
            fi

            if [ -f "/etc/dconf/db/$l_gpname" ]; then
                l_output="The dconf database \"$l_gpname\" exists"
            else
                l_output2="The dconf database \"$l_gpname\" doesn't exist"
            fi

            if [ -d "$l_gpdir" ]; then
                l_output="The dconf directory \"$l_gpdir\" exists"
            else
                l_output2="The dconf directory \"$l_gpdir\" doesn't exist"
            fi

            if grep -Pqrs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then
                l_output="\"automount\" is set to false in \"$l_kfile\""
            else
                l_output2="\"automount\" is not set correctly"
            fi

            if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile2"; then
                l_output="\"automount-open\" is set to false in \"$l_kfile2\""
            else
                l_output2="\"automount-open\" is not set correctly"
            fi
        else
            l_output2="Neither \"automount\" nor \"automount-open\" is set"
        fi
    else
        l_output="GNOME Desktop Manager package is not installed on the system - Recommendation is not applicable"
    fi

    if [ -z "$l_output2" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason: $l_output2"

    fi
}



# Ensuring GDM disabling automatic mounting of removable media is disabled
audit_gdm_auto_mounting_removable_disable_pr() {
    echo -e "\n Ensuring GDM disabling automatic mounting of removable media is disabled"
    local l_pkgoutput=""
    local l_output=""
    local l_output2=""

    # Determine system's package manager
    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    local l_pcl="gdm gdm3" # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" >/dev/null 2>&1 && l_pkgoutput="$l_pkgoutput Package: \"$l_pn\" exists on the system checking configuration"
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        local l_kfd="/etc/dconf/db/$(grep -Psril '^\h*automount\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"       # Set directory of key file to be locked
        local l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*automount-open\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" # Set directory of key file to be locked

        if [ -d "$l_kfd" ]; then # If key file directory exists, options can be locked
            if grep -Piq '^\h*\/org/gnome/desktop/media-handling/automount\b' "$l_kfd"; then
                l_output="$l_output \"automount\" is locked in \"$(grep -Pil '^\h*\/org/gnome/desktop/media-handling/automount\b' "$l_kfd")\""
            else
                l_output2="$l_output2 \"automount\" is not locked"
            fi
        else
            l_output2="$l_output2 \"automount\" is not set so it cannot be locked"
        fi

        if [ -d "$l_kfd2" ]; then # If key file directory exists, options can be locked
            if grep -Piq '^\h*\/org/gnome/desktop/media-handling/automount-open\b' "$l_kfd2"; then
                l_output="$l_output \"automount-open\" is locked in \"$(grep -Pril '^\h*\/org/gnome/desktop/media-handling/automount-open\b' "$l_kfd2")\""
            else
                l_output2="$l_output2 \"automount-open\" is not locked"
            fi
        else
            l_output2="$l_output2 \"automount-open\" is not set so it cannot be locked"
        fi
    else
        l_pkgoutput="$l_pkgoutput GNOME Desktop Manager package is not installed on the system - Recommendation is not applicable"
    fi

    # Report results. If no failures output in l_output2, we pass
    if [ -z "$l_output2" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason:$l_output2"
    fi
}




#Ensuring GDM autorun-never is enabled
audit_gdm_autorun_never_enable() {
    echo -e "\n Ensuring GDM autorun-never is enabled"
    l_pkgoutput=""
    l_output=""
    l_output2=""
    # Determine system's package manager
    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space separated list of packages to check
    for l_pn in $l_pcl; do
        if $l_pq "$l_pn" >/dev/null 2>&1; then
            l_pkgoutput="$l_pkgoutput Package: \"$l_pn\" exists on the system checking configuration"
            #echo -e "$l_pkgoutput"
        fi
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        #echo -e "$l_pkgoutput"

        # Look for existing settings and set variables if they exist
        l_kfile="$(grep -Prils -- '^\h*autorun-never\b' /etc/dconf/db/*.d)"

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<<"$l_kfile")"
        fi

        # If the profile name exists, continue checks
        if [ -n "$l_gpname" ]; then
            l_gpdir="/etc/dconf/db/$l_gpname.d"

            # Check if profile file exists
            if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
                l_output="$l_output dconf database profile file \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists"
            else
                l_output2="$l_output2 dconf database profile isn't set"
            fi

            # Check if the dconf database file exists
            if [ -f "/etc/dconf/db/$l_gpname" ]; then
                l_output="$l_output The dconf database \"$l_gpname\" exists"
            else
                l_output2="$l_output2 The dconf database \"$l_gpname\" doesn't exist"
            fi

            # Check if the dconf database directory exists
            if [ -d "$l_gpdir" ]; then
                l_output="$l_output The dconf directory \"$l_gpdir\" exists"
            else
                l_output2="$l_output2 The dconf directory \"$l_gpdir\" doesn't exist"
            fi

            # Check autorun-never setting
            if grep -Pqrs -- '^\h*autorun-never\h*=\h*true\b' "$l_kfile"; then
                l_output="$l_output \"autorun-never\" is set to true in: $l_kfile"
            else
                l_output2="$l_output2 \"autorun-never\" is not set correctly"
            fi
        else
            # Settings don't exist. Nothing further to check
            l_output2="$l_output2 \"autorun-never\" is not set"
        fi
    else
        l_output="$l_output GNOME Desktop Manager package is not installed on the system - Recommendation is not applicable"
    fi

    # Report results. If no failures output in l_output2, we pass
    if [ -z "$l_output2" ]; then
        echo -e " Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason:$l_output2"
    fi
}



#Ensuring GDM aurorun never is not overriden
audit_gmd_autorun_never_override() {
    echo -e "\n Ensuring GDM aurorun never is not overriden"
    # determine system's package manager
    l_pkgoutput=""
    if command -v dpkg-query >/dev/null 2>&1; then
        l_pq="dpkg-query -W"
    elif command -v rpm >/dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space separated list of packages to check
    for l_pn in $l_pcl; do
        if $l_pq "$l_pn" >/dev/null 2>&1; then
            l_pkgoutput="$l_pkgoutput Package: \"$l_pn\" exists on the system checking configuration"
        fi
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        l_output=""
        l_output2=""

        # Look for idle-delay to determine profile in use, needed for remaining tests
        l_kfd=$(grep -Psril '^\h*autorun-never\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}')
        l_kfd="/etc/dconf/db/$l_kfd.d" # set directory of key file to be locked

        if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked
            if grep -Piq '^\h*\/org/gnome/desktop/media-handling/autorun-never\b' "$l_kfd"; then
                l_output="$l_output \"autorun-never\" is locked in \"$(grep -Pil '^\h*\/org/gnome/desktop/media-handling/autorun-never\b' "$l_kfd")\""
            else
                l_output2="$l_output2 \"autorun-never\" is not locked"
            fi
        else
            l_output2="$l_output2 \"autorun-never\" is not set so it can not be locked"
        fi
    else
        l_output="$l_output GNOME Desktop Manager package is not installed on the system - Recommendation is not applicable"
    fi

    # Report results. If no failures output in l_output2, we pass
    [ -n "$l_pkgoutput" ] # && echo -e "$l_pkgoutput"

    if [ -z "$l_output2" ]; then
        echo -e "Audit: PASS"
    else
        echo -e "Audit: FAIL, Reason: $l_output2"
    fi
}



#Ensuring XDCMP is not enabled
audit_xdcmp_notenabled() {
    echo -e "\n Ensuring XDCMP is not enabled"
    # Check if XDMCP is enabled in the GDM3 custom configuration file
    if grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf &>/dev/null; then
        echo "Audit: FAIL, Reason: XDMCP is enabled"
    else
        echo "Audit: PASS"
    fi

}



audit_updates_installed() {
    echo -e "\nEnsuring updates, patches, and additional security software are installed"

    # Update the package lists, ignoring errors
    apt-get update >/dev/null 2>&1 || true

    # Perform a simulation of the upgrade process
    upgradeable_packages=$(apt-get --just-print upgrade 2>/dev/null | grep -c "^Inst")

    # Check if there are any updates available
    if [ "$upgradeable_packages" -gt 0 ]; then
        echo "Audit: FAIL, Reason: Updates, patches, or additional security software are available."
    else
        echo "Audit: PASS"
    fi
}