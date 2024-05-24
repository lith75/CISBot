#!/bin/bash
#Author: Dinith Oshan
#Date: 18/03/2024

NO_COLOR='\033[0m'        # No Color
RED='\033[0;31m'          # Red
GREEN='\033[0;32m'        # Green


#Install, enable and start auditd
function configure-auditd {
    echo 'Installing and configuring auditd'
    apt install auditd audispd-plugins
#     systemctl --now enable auditd
}

# Add options to GRUB_CMDLINE_LINUX
function add_grub_options() {
    echo 'Adding Grub Options'
    options="audit=1 audit_backlog_limit=8192"

    # Check if GRUB_CMDLINE_LINUX is already defined in /etc/default/grub
    if grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub; then
        # If defined, add options to existing line
        sudo sed -i "s/\(^GRUB_CMDLINE_LINUX=\"[^\"]*\)\"/\1 $options\"/" /etc/default/grub
    else
        # If not defined, create a new line with options
        sudo bash -c "echo 'GRUB_CMDLINE_LINUX=\"$options\"' >> /etc/default/grub"
    fi

    update-grub

}

#Ensure audit log storage size is configured
#max_log_file should be set as site policy (Default value is 8) This value is sufficient for an endpoint workstation

function set_audit_parameters() {
    # Set max_log_file_action parameter
    sudo sed -i "s/^max_log_file_action =.*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf
    echo "max_log_file_action set to 'keep_logs' in /etc/audit/auditd.conf"

    # Set max_log_file parameter
    sudo sed -i "s/^max_log_file =.*/max_log_file = 8/" /etc/audit/auditd.conf
    echo "max_log_file set to '8' in /etc/audit/auditd.conf"

    #set space_left_action parameter
    sudo sed -i "s/^space_left_action =.*/space_left_action = email/" /etc/audit/auditd.conf
    echo "space_left_action set to 'email' in /etc/audit/auditd.conf"

    #set action_mail_acct parameter
    sudo sed -i "s/^action_mail_acct =.*/action_mail_acct = root/" /etc/audit/auditd.conf
    echo "action_mail_acct set to 'root' in /etc/audit/auditd.conf"

    #set action_space_left_action parameter
    sudo sed -i "s/^admin_space_left_action =.*/admin_space_left_action = halt/" /etc/audit/auditd.conf
    echo "admin_space_left_action to 'halt' in /etc/audit/auditd.conf"

}


#NEED TO ADD VALIDATION TO HANDLE IF RULES FILE NAME EXISTS.
#Ensure changes to the system administration scope is collected. - 4.1.3.1
function configure-audit-rules {
    rules="# This script creates audit rules for monitoring changes to scope of admins
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
  "
  sudo mkdir -p /etc/audit/rules.d/
  sudo echo "$rules" >> /etc/audit/rules.d/50-scope.rules
  echo "Audit rules for monitoring changes to scope of admins created successfully!"
}

#creating audit rules to configure actions as other user is logged - 4.1.3.2
function configure-other-user-actions-logged() {
  rules="# This script creates audit rules for monitoring elevated privileges
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
  "
  sudo mkdir -p /etc/audit/rules.d/
  sudo echo "$rules" >> /etc/audit/rules.d/50-user_emulation.rules
  echo "Audit rules for monitoring elevated privileges created successfully!"
}


#creating audit rules to configure actions as other user is logged - 4.1.3.3
# function configure-changes-sudo-log-file{
#   SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' -e 's/"//g')
# [ -n "${SUDO_LOG_FILE}" ] && printf "
# -w ${SUDO_LOG_FILE} -p wa -k sudo_log_file
# " >> /etc/audit/rules.d/50-sudo.rules || printf "ERROR: Variable
# 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
# }

function configure-changes-sudo-log-file {
    local SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' -e 's/"//g')
    
    if [ -n "${SUDO_LOG_FILE}" ]; then
        printf "
-w ${SUDO_LOG_FILE} -p wa -k sudo_log_file
" >> /etc/audit/rules.d/50-sudo.rules
    else
        printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n"
    fi
}


#creating audit rules to trigegr when events that modify date/time information are collected. 4.1.3.4
function configure-modify-datetime-logged() {
  rules="# This script creates audit rules for events that modify date and time.
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
"
  sudo mkdir -p /etc/audit/rules.d/
  sudo echo "$rules" >> /etc/audit/rules.d/50-time-change.rules
  echo "Audit rules for for events that modify date and time created successfully!"
}


#Creating audit rules to ensure events that modify they system's network environment are collected 4.1.3.5
function configure-system-network-env {
    rules="# This script creates audit rules for events that systems network environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
"
  sudo mkdir -p /etc/audit/rules.d/
  sudo echo "$rules" >> /etc/audit/rules.d/50-system_local.rules
  echo "Audit rules for for events that modify system's network environment created successfully!"
}

#Creating audit rule that monitor the use of privileged commands 4.1.3.6
function configure-privileged-command-logs {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-privileged.rules"
  NEW_DATA=()
  for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
    readarray -t DATA < <(find "${PARTITION}" -xdev -perm /6000 -type f | awk -v UID_MIN=${UID_MIN} '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>="UID_MIN" -F auid!=unset -k privileged" }')
    for ENTRY in "${DATA[@]}"; do
      NEW_DATA+=("${ENTRY}")
    done
  done
  readarray &> /dev/null -t OLD_DATA < "${AUDIT_RULE_FILE}"
  COMBINED_DATA=( "${OLD_DATA[@]}" "${NEW_DATA[@]}" )
  printf '%s\n' "${COMBINED_DATA[@]}" | sort -u > "${AUDIT_RULE_FILE}"
}

#Configure audit rule that logs file access attempts are collected 4.1.3.7
function configure-audit-file-access-attempts {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access \n" >> /etc/audit/rules.d/50-access.rules || printf "ERROR: Variable 'UID_MIN'is unset. \n"
  echo "Audit rules for file access logging created succeffully!"
}


#Configure log that modify user/group information 4.1.3.8
function configure-audit-modify-user-group-information {
  rules="# This script creates audit rules for events that modify user/group information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
"
  sudo mkdir -p /etc/audit/rules.d/
  sudo echo "$rules" >> /etc/audit/rules.d/50-identity.rules
  echo "Audit rules for for events that modify user/group information created successfully!"
}


#Configure Discretionary access control permission modification events are collected 4.1.3.9
function  configure-audit-dac-permission-modification {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
" >> /etc/audit/rules.d/50-perm_mod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}



#Configure Successful fille system mountes are collected 4.1.3.10
function configure-audit-file-system-mounts {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
" >> /etc/audit/rules.d/50-mounts.rules || printf "ERROR: Variable 'UID_MIN'
is unset.\n"
echo -e "${GREEN} Added audit rule to collect"
}

#Configure Session initiation information is collected 4.1.3.11
function configure-audit-session-initiation {
  printf "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
" >> /etc/audit/rules.d/50-session.rules
echo -e "${GREEN} Added audit rule to collect session initiation information ${NO_COLOR}"
}

#Configure Login and logout events are collected 4.1.3.12
function configure-audit-login-logout {
  printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" >> /etc/audit/rules.d/50-login.rules
echo -e "${GREEN} Added audit rule to collect login logout information ${NO_COLOR}"
}

#Configure file deletion events by users are collected 4.1.3.13
function configure-audit-file-deletion {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
  " >> /etc/audit/rules.d/50-delete.rules || printf "ERROR: Variable 'UID_MIN'
  is unset.\n"

echo -e "${GREEN} Added audit rule to collect information about file deletion."
}

#Configure audit modify systems MAC 4.1.3.14
function config-audit-modify-mac {
  printf "
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
" >> /etc/audit/rules.d/50-MAC-policy.rules
echo -e "${GREEN} Added audit rule to collect information about Mandatory Access Control modifications"
}

#Configure audit attempts to use the chcon command 4.1.3.15
function config-audit-chcon-usage-attempts {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable
  'UID_MIN' is unset.\n"
  echo -e "${GREEN} Added audit rule to collect information about chcon usage attempts."
}

#Configure audit attempts to use setfacl command  4.1.3.16
function config-audit-setfacl-usage-attempts {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-priv_cmd.rules || printf "ERROR: Variable
'UID_MIN' is unset.\n"

echo -e "${GREEN} Added audit rule to collect information about setfacl usage attempts."
}


#Configure audit attempts to use the chacl command are recorded 4.1.3.17
function config-audit-chacl-usage-attempts {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable
  'UID_MIN' is unset.\n"
  
  echo -e "${GREEN} Added audit rule to collect information about chacl usage attempts."
}

#Configure audit attempts to use the usermod command are recorded 4.1.3.18
function config-audit-usermod-usage-attempts {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod
" >> /etc/audit/rules.d/50-usermod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
echo -e "${GREEN} Added audit rule to collect information about usermod usage attempts."
}

#Configure audit kernal module loading unloading and modification 4.1.3.19
function config-audit-kernel-module-changes {
  UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
  [ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
" >> /etc/audit/rules.d/50-kernel_modules.rules || printf "ERROR: Variable
'UID_MIN' is unset.\n"
echo -e "${GREEN} Added audit rule to collect information about kernal module changes."
}

#Configure audit rules are immutable 4.1.3.20
function config-audit-immutable {
  printf -- "-e 2
" >> /etc/audit/rules.d/99-finalize.rules
echo -e "${GREEN} Added audit rule to finalize auditd setup."
}

#Configure audit rules both running and onn disk rules are the same 4.1.3.21
function config-audit-running-ondisk {
  augenrules --load
}


#Configure audit log files permission mode 4.1.4.1
function config-permission-log-files {
    log_file_path=$(grep -E "^log_file\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')

    if [ -n "$log_file_path" ]; then
        log_file_dir=$(dirname "$log_file_path")
        while IFS= read -r line; do
            file=$(echo "$line" | awk '{print $1}')
            permissions=$(echo "$line" | awk '{print $2}')
            if [ "$permissions" -gt 640 ]; then
                echo "Adjusting permissions of $file to 640"
                chmod 640 "$file"
            fi
        done < <(stat -Lc "%n %a" "$log_file_dir"/*)
    else
        echo "Log file path not found in auditd.conf"
    fi

}


#configure audit log files owner as root 4.1.4.2
function config-audit-log-file-owner {
    log_file_path=$(grep -E "^log_file\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')

    if [ -n "$log_file_path" ]; then
        log_file_dir=$(dirname "$log_file_path")
        while IFS= read -r line; do
            file=$(echo "$line" | awk '{print $1}')
            owner=$(echo "$line" | awk '{print $2}')
            if [ "$owner" != "root" ]; then
                echo "Adjusting owner of $file to root"
                chown root "$file"
            fi
        done < <(stat -Lc "%n %U" "$log_file_dir"/*)
    else
        echo "Log file path not found in auditd.conf"
    fi
}

#configure audit to check audit group ownership 4.1.4.3
function config-audit-group-ownership {

    log_file_path=$(grep -E "^log_file\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')
    sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf
    if [ -n "$log_file_path" ]; then
        log_file_dir=$(dirname "$log_file_path")
        find "$log_file_dir" -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} +
    else
        echo "Log file path not found in auditd.conf"
    fi
    chgrp adm /var/log/audit
    systemctl restart auditd
}


#configure audit to check permissions of the log directory 4.1.4.4
function config-audit-log-directory-restriction {
  log_file_path=$(grep -E "^\s*log_file\s*=" /etc/audit/auditd.conf | cut -d "=" -f 2 | tr -d ' ')
  if [ -n "$log_file_path" ]; then
        # Extract the directory containing the log file
        log_file_dir=$(dirname "$log_file_path")

        # Get permissions of the directory
        chmod g-w,o-rwx "$log_file_dir"
    else
        echo "Log file path not found in auditd.conf"
    fi
}

#Configure audit to check permissions of the configuration files 4.1.4.5
function config-audit-config-file {
  find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +
}


#configure audit to check configuration files are owned by root 4.1.4.6
function config-audit-config-files-owned-by-root {
  find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +
}

#configure audit to check coinfiguration files are owned by group root 4.1.4.7
function config-audit-config-files-owned-group-root {
  find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +
}

#Configure audit tools are 755 or more restrictive 4.1.4.8
function  config-restriction-audit-tools {
  chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
}

#configure audit tools owned by root 4.1.4.9
function configure-audit-tools-owned-root {
  chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
}

#Configure audit tools are owned by group root 4.1.4.10 
function configure-audit-tools-group-root {
  chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
  chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
}

#Configure Crptographic mechanisms used to protect Integrit of audit tools 4.1.4.11
function configure-cryptographic-mechanisms-audit-tools {
  rules="/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512"
  sudo echo "$rules" >> /etc/aide/aide.conf
  echo "Cryptographic mechanisms used to protect integrity created successfully!"
} 


#configure systemd-journal-remote instal{lation 4.2.1.1.1
function install-systemd-journal-remote {
  sudo apt install systemd-journal-remote
}

#configure journald to reject receiving logs from remote clients 4.2.1.1.4
function config-reject-remote-logs-journald {
  systemctl --now disable systemd-journal-remote.socket
}

#Configure journald to compress large log files 4.2.1.3
function config-compress-large-log-files {
  rules="Compress=yes"
  sudo echo "$rules" >> /etc/systemd/journald.conf
  echo "Journald Log file compress enabled successfully!"
}
  
#configure journald  writes to persistant disk 4.2.1.4
function config-journald-write-persistant-disk {
  rules="Storage=persistent"
  sudo echo "$rules" >> /etc/systemd/journald.conf
  echo "Journald Log file writes to persistent disk enabled successfully!"
}

#Config restrict sending logs to rsyslog from journald 4.2.1.5
function config-journald-restrict-sending-to-rsyslog {
  JOURNALD_CONF="/etc/systemd/journald.conf"
  if grep -q "ForwardToSyslog=yes" "$JOURNALD_CONF"; then
    # Remove the line from the file
    sed -i '/ForwardToSyslog=yes/d' "$JOURNALD_CONF"
    echo "ForwardToSyslog=yes removed from $JOURNALD_CONF"
  else
      echo "ForwardToSyslog=yes not found in $JOURNALD_CONF"
  fi
  systemctl restart systemd-journald
}

#!/usr/bin/env bash

remediate_logfiles_permissions_ownership() {
    echo -e "\n- Start remediation - logfiles have appropriate permissions and ownership"
    find /var/log -type f | while read -r fname; do
        bname="$(basename "$fname")"
        case "$bname" in
            lastlog | lastlog.* | wtmp | wtmp.* | btmp | btmp.*)
                ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6][0,4]\h*$' && echo -e "- changing mode on \"$fname\"" && chmod ug-x,o-wx "$fname"
                ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*root\h*$' && echo -e "- changing owner on \"$fname\"" && chown root "$fname"
                ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(utmp|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
                ;;
            secure | auth.log)
                ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$' && echo -e "- changing mode on \"$fname\"" && chmod u-x,g-wx,o-rwx "$fname"
                ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*(syslog|root)\h*$' && echo -e "- changing owner on \"$fname\"" && chown root "$fname"
                ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(adm|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
                ;;
            SSSD | sssd)
                ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6]0\h*$' && echo -e "- changing mode on \"$fname\"" && chmod ug-x,o-rwx "$fname"
                ! stat -Lc "%U" "$fname" | grep -Piq -- '^\h*(SSSD|root)\h*$' && echo -e "- changing owner on \"$fname\"" && chown root "$fname"
                ! stat -Lc "%G" "$fname" | grep -Piq -- '^\h*(SSSD|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
                ;;
            gdm | gdm3)
                ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6]0\h*$' && echo -e "- changing mode on \"$fname\"" && chmod ug-x,o-rwx "$fname"
                ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*root\h*$' && echo -e "- changing owner on \"$fname\"" && chown root "$fname"
                ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(gdm3?|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
                ;;
            *.journal)
                ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$' && echo -e "- changing mode on \"$fname\"" && chmod u-x,g-wx,o-rwx "$fname"
                ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*root\h*$' && echo -e "- changing owner on \"$fname\"" && chown root "$fname"
                ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(systemd-journal|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
                ;;
            *)
                ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$' && echo -e "- changing mode on \"$fname\"" && chmod u-x,g-wx,o-rwx "$fname"
                ! stat -Lc "%U" "$fname" | grep -Pq -- '^\h*(syslog|root)\h*$' && echo -e "- changing owner on \"$fname\"" && chown root "$fname"
                ! stat -Lc "%G" "$fname" | grep -Pq -- '^\h*(adm|root)\h*$' && echo -e "- changing group on \"$fname\"" && chgrp root "$fname"
                ;;
        esac
    done
    echo -e "- End remediation - logfiles have appropriate permissions and ownership\n"
}
