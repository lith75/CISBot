#!/bin/bash
#There isn't one size fits all to loggiing solutions and enterprises should use what is feasible for them.
#4.2.1.6 is skipped due to manually having to check the parameters as per your site policy.
#4.2.2 is skipped as  journald chosen as logging mechanism. 




## Ensure Auditing is enabled.
#Ensure auditd is installed (Automated) 4.1.1.1
function verify-auditd-installed {
    dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' auditd audispd-plugins >> temp.txt
    search_string="auditd	install ok installed	installed"
    file="temp.txt"
    file_content=$(<"$file")
    if [[ "$file_content" == *"$search_string"* ]];then
        echo "Audit Passed: Auditd is installed"
    else
        echo "Audit Failed: Auditd is not installed"
    fi
    rm temp.txt
}


#Ensure auditd service is enabled(Automated) 4.1.1.2
function verify-auditd-enabled {
    systemctl is-enabled auditd >> temp.txt
    output=$(grep -e "enabled" temp.txt)
    if [ -n "$output" ]; then
        echo "Audit Passed: Auditd enabled"
    else
        echo "Audit failed: Auditd is not enabled"
    fi
    rm temp.txt
}

#Ensure auditd service is active (Autmated) 4.1.1.2
function verify-auditd-active {
    systemctl is-active auditd >> temp.txt
    output=$(grep -e "active" temp.txt)
    if [ -n "$output" ]; then
        echo "Audit Passed: Auditd active"
    else
        echo "Audit failed: Auditd is not active"
    fi    
    rm temp.txt
}



#NOT WORKING - ISSUE WITH BOOTLOADER
#Ensure auditing for processes that start prior to auditd is enabled [grub2] (Automated)4.1.1.3
function find-grub2 {
    find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -v 'audit=1'
}

#Ensure audit_backlog _limit is sufficient 4.1.1.4
function check-backlog-limit {
    find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -Pv 'audit_backlog_limit=\d+\b'
}





#Ensure Data Retention is configured 4.1.2
function check-data-retention {
    grep -Po -- '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf >> temp.txt #4.1.2.1
    grep max_log_file_action /etc/audit/auditd.conf >> temp.txt #4.1.2.2
    grep ^space_left_action /etc/audit/auditd.conf >> temp.txt  #4.1.2.3
    grep -E 'admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf >> temp.txt #4.1.2.3

    if [[ $(grep -E '^max_log_file\s*=\s*8' temp.txt) && \
      $(grep -E '^max_log_file_action\s*=\s*keep_logs' temp.txt) && \
      $(grep -E '^space_left_action\s*=\s*email' temp.txt) && \
      $(grep -E '^admin_space_left_action\s*=\s*halt' temp.txt) ]]; then
        echo "Audit passed: Auditd Data retention configured"
    else
        echo "Audit Failed: Auditd Data retention not configured"
    fi

}

#Ensure Changes to the system administration scope (sudoers) is collected (Automated) - 4.1.3.1
function check-changes-admin-scope {

    # Iterate over files in /etc/audit/rules.d/
    for file in /etc/audit/rules.d/*.rules; do
        # Check for relevant rules using awk
        awk '/^ *-w/ && /\/etc\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' "$file" >> temp.txt
    done

    auditctl -l | awk '/^ *-w/ && /\/etc\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' >> temp.txt
    
    if [[ $(grep -E '^-w /etc/sudoers -p wa -k scope' temp.txt) && \
        $(grep -E '^-w /etc/sudoers.d -p wa -k scope' temp.txt) ]]; then
        echo "Audit Passed: Changes to admin scope is logged"
    else
        echo "Audit Failed: Changes to admin scope is not logged"
    fi

    rm temp.txt
}



#Ensure actions as another users are always logged - 4.1.3.2
function check-other-user-actions-logged {
    output= grep -r -l -E '^ *-a *always,exit| -F *arch=b[2346]{2}|(-F *auid!=(unset|-1|4294967295))|(-C *euid!=uid|-C *uid!=euid)| -S *execve|( key= *[!-~]* *$|-k *[!-~]* *$)' /etc/audit/rules.d/*.rules

    output2= auditctl -l | awk '/^ *-a *always,exit/ &&/ -F *arch=b[2346]{2}/ &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) &&(/ -C *euid!=uid/||/ -C *uid!=euid/) &&/ -S *execve/ &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

    if [ -z "$output" ]
    then
        echo "Audit Passed: On disk configuration configured to log actions as another user"
    else
        echo "Audit Failed: On disk configuration not configured to log actions as another user"
    fi

    if [ -z "$output2" ]
    then
        echo "Audit Passed: Running configuration confifgured to log actions as another user"
    else
        echo "Audit Failed: Running configuration not configured to log actions as another user"
    fi

}


#Ensure events that modify the sudo log file are collected (Automated)
function check-changes-to-sudo-log-file {
    
    # SUDO_LOG_FILE_ESCAPED=$(  | sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')
    # [ -n "${SUDO_LOG_FILE_ESCAPED}" ] && awk "/^ *-w/ \
    # &&/"${SUDO_LOG_FILE_ESCAPED}"/ \
    # &&/ +-p *wa/ \
    # &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
    # || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
    local SUDO_LOG_FILE_ESCAPED=$(grep -oP 'logfile=\K[^,]*' /etc/sudoers | sed -e 's/"//g' -e 's|/|\\/|g')
    if [ -n "${SUDO_LOG_FILE_ESCAPED}" ]; then
        awk '/^ *-w/ && /'"${SUDO_LOG_FILE_ESCAPED}"'/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt
    else
        printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"
    fi

    if [ -s "temp.txt" ]; then
        echo "Audit Passed: Changes to sudo log file is logged"
    else
        echo "Audit Failed: Changes to sudo log file are not logged"
    fi

    rm temp.txt

}



#Ensure events that modify date and time are collected 4.1.3.4
function check-events-modify-date-time-info {
    awk '/^ *-a *always,exit/ \
    &&/ -F *arch=b[2346]{2}/ \
    &&/ -S/ \
    &&(/adjtimex/ \
        ||/settimeofday/ \
        ||/clock_settime/ ) \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt
    awk '/^ *-w/ \
    &&/\/etc\/localtime/ \
    &&/ +-p *wa/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt


    if [ -s "temp.txt" ]; then
        echo "Audit Passed: Events that modify date/time are logged"
    else
        echo "Audit Failed: Events that modify Date/time are not logged"
    fi
}

#Ensure use of privileged commands are collected 4.1.3.6
function check-privileged-commands-logged {
    for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
        for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
            grep -qr "${PRIVILEGED}" /etc/audit/rules.d && printf "OK:
    '${PRIVILEGED}' found in auditing rules.\n" || printf "Warning:
    '${PRIVILEGED}' not found in on disk configuration.\n"
        done
    done
}

#Ensure unsuccessful file access attempts are collected 4.1.3.7
function check-unsuccessful-access-attempt-logged-disk {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
&&/ -F *arch=b[2346]{2}/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&/ -F *auid>=${UID_MIN}/ \
&&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \
&&/ -S/ \
&&/creat/ \
&&/open/ \
&&/truncate/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
    || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}

function check-unsuccessful-access-attempt-logged-running {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && auditctl -l | awk "/^ *-a *always,exit/ \
    &&/ -F *arch=b[2346]{2}/ \
    &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
    &&/ -F *auid>=${UID_MIN}/ \
    &&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \
    &&/ -S/ \
    &&/creat/ \
    &&/open/ \
    &&/truncate/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" \
    || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}




#Ensure events that modify user/group information are collected (Automated) 4.1.3.8
function check-changes-user-group-information {
    awk '/^ *-w/ \
    &&(/\/etc\/group/ \
        ||/\/etc\/passwd/ \
        ||/\/etc\/gshadow/ \
        ||/\/etc\/shadow/ \
        ||/\/etc\/security\/opasswd/) \
    &&/ +-p *wa/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit Passed: Events that modify user/group information are logged"
    else
        echo "Audit Failed: Events that modify user/group information are not logged"
    fi

    rm temp.txt
}

function check-changes-user-group-information-running {
    auditctl -l | awk '/^ *-w/ \
    &&(/\/etc\/group/ \
        ||/\/etc\/passwd/ \
        ||/\/etc\/gshadow/ \
        ||/\/etc\/shadow/ \
        ||/\/etc\/security\/opasswd/) \
    &&/ +-p *wa/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit Passed: Events that modify user/group information are logged (Disk)"
    else
        echo "Audit Failed: Events that modify user/group information are not logged (Running)"
    fi

    rm temp.txt
}

#Check DAC permission modification events are collected 4.1.3.9 - Not COnfiguration Working Audit not working.
function check-changes-dac-permission-modification {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
    &&/ -F *arch=b[2346]{2}/ \
    &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
    &&/ -S/ \
    &&/ -F *auid>=${UID_MIN}/ \
    &&(/chmod/||/fchmod/||/fchmodat/ \
        ||/chown/||/fchown/||/fchownat/||/lchown/ \
        ||/setxattr/||/lsetxattr/||/fsetxattr/ \
        ||/removexattr/||/lremovexattr/||/fremovexattr/) \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
    || printf "ERROR: Variable 'UID_MIN' is unset.\n"
}


#Ensure successful file system mounts are collected 4.1.3.10
function check-file-system-mounts() {

    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    if [ -n "${UID_MIN}" ]; then
        awk '/-a always,exit/ && /-F arch=b[32|64]/ && (/ -F auid!=unset/ || / -F auid!=-1/ || / -F auid!=4294967295/) && / -F auid>='"${UID_MIN}"'/ && / -S/ && /mount/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/50-mounts.rules >> temp.txt
    else
        echo "ERROR: Variable 'UID_MIN' is unset."
    fi


    if [ -s temp.txt ]; then
        echo "Audit passed: File system mounts are logged"
    else
        echo "Audit Failede: File system mounts are not logged"
    fi

    rm temp.txt

}


#Ensure session initiation information is collected
function check-audit-session-initiation-information {
    awk '/^ *-w/ \
    &&(/\/var\/run\/utmp/ \
        ||/\/var\/log\/wtmp/ \
        ||/\/var\/log\/btmp/) \
    &&/ +-p *wa/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit passed: Session initiation information are logged"
    else
        echo "Audit Failed: Session initiation information are not logged"
    fi 

    rm temp.txt
}

#Ensure login and logout events are collected 4.1.3.12
function check-audit-login-logout {
    awk '/^ *-w/ \
    &&(/\/var\/log\/lastlog/ \
        ||/\/var\/run\/faillock/) \
    &&/ +-p *wa/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit passed: Login logout are logged"
    else
        echo "Audit Failed: login logout are not logged"
    fi

    rm temp.txt
}


#Ensure file deletion events by users aere collected 4.1.3.13
function check-audit-file-deletion() {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    if [ -n "${UID_MIN}" ]; then
        awk '/-a always,exit/ && /-F arch=b[32|64]/ && (/ -F auid!=unset/ || / -F auid!=-1/ || / -F auid!=4294967295/) && / -F auid>='"${UID_MIN}"'/ && / -S/ && (/unlink/ ||    /rename/ || /unlinkat/ || /renameat/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt
    else
        echo "ERROR: Variable 'UID_MIN' is unset."
    fi

    if [ -s temp.txt ]; then
        echo "Audit Passed: File deletion is logged"
    else
        echo "Audit Failed: File deletion is not logged"
    fi
    
    rm temp.txt
}


#Ensure events that modify the system's mandatory access controls are collected 4.1.3.14
function check-audit-modify-mac {
    awk '/^ *-w/ \
    &&(/\/etc\/apparmor/ \
        ||/\/etc\/apparmor.d/) \
    &&/ +-p *wa/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit passed: Changes to mandatory Access controls are logged"
    else 
        echo "Audit Failed: Changes to mandatory access controls are not logged"
    fi 

    rm temp.txt

}

#Ensure successful and unsuccessful attempts to use the chcon command are recorded 4.1.3.15
function check-audit-attempts-chcon-use {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    if [ -n "${UID_MIN}" ]; then
        awk '/-a always,exit/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && / -F *auid>='"${UID_MIN}"'/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/chcon/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt
    else
        echo "ERROR: Variable 'UID_MIN' is unset."
    fi

    if [ -s temp.txt ]; then
        echo "Audit Passed: chcon usage attempts are logged"
    else
        echo "Audit Failed: chcon usage attempts are not logged"
    fi

    rm temp.txt

}
#Ensure Successful and unsuccessful attempts to use the setfacl command are recorded 4.1.3.16
function check-audit-attempts-setfacl-usage() {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    if [ -n "${UID_MIN}" ]; then
        awk '/-a always,exit/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && / -F *auid>='"${UID_MIN}"'/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/setfacl/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt
    else
        echo "ERROR: Variable 'UID_MIN' is unset."
    fi

    if [ -s temp.txt ]; then
        echo "Audit Passed: setfacl usage is logged"
    else
        echo "Audit Failed: setfacl usage is not logged"
    fi

    rm temp.txt
}


#Ensure successful and unsuccessful attempts to use chacl command are recorded 4.1.3.17
function check-audit-attempts-chacl-usage() {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    if [ -n "${UID_MIN}" ]; then
        awk '/-a always,exit/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && / -F *auid>='"${UID_MIN}"'/ && / -F *perm=x/ && / -F *path=\/usr\/bin\/chacl/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt
    else
        echo "ERROR: Variable 'UID_MIN' is unset."
    fi

    if [ -s temp.txt ]; then
        echo "Audit passed: chacl usage is logged"
    else
        echo "Audit failed: chacl usage is not logged"
    fi

    rm temp.txt
}


#Ensure successful and unsuccesful attempts to use the usermod command are recorded 4.1.3.18
function check-audit-attempts-usermod-usage {
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    if [ -n "${UID_MIN}" ]; then
        awk '/-a always,exit/ && (/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && / -F *auid>='"${UID_MIN}"'/ && / -F *perm=x/ && / -F *path=\/usr\/sbin\/usermod/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules > temp.txt
    else
        echo "ERROR: Variable 'UID_MIN' is unset."
    fi

    if [ -s temp.txt ]; then
        echo "Audit passed: usermod usage are being recorded"
    else
        echo "Audit failed: usermod command is not being recorded"
    fi

    rm temp.txt
}


#Ensure kernal module loading unloading and modification is collected 4.1.3.19
function check-audit-kernel-changes-1 {
    
    awk '/^ *-a *always,exit/ \
    &&/ -F *arch=b(32|64)/ \
    &&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) \
    &&/ -S/ \
    &&(/init_module/ \
    ||/finit_module/ \
    ||/delete_module/) \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit Passed: system calls related to kernel modules are logged"
    else
        echo "Audit Failed: system calls related to kernel modules are not logged"
    fi

    rm temp.txt
}

#Ensure kernal module loading unloading and modification is collected 4.1.3.19
function check-audit-kernel-changes-2 {

    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
    &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
    &&/ -F *auid>=${UID_MIN}/ \
    &&/ -F *perm=x/ \
    &&/ -F *path=\/usr\/bin\/kmod/ \
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
    >> temp.txt || printf "ERROR: Variable 'UID_MIN' is unset.\n"

    if [ -s temp.txt ]; then
        echo "Audit Passed: kmod command usage is logged"
    else
        echo "Audit Failed: kmod command usage is not logged"
    fi

    rm temp.txt
}


#Ensure the audit configurationis immutable 4.1.3.20
function check-audit-immutable {
    grep -Ph -- '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules | tail -1 >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit Passed: Auditd immutable"
    else
        echo "Audit Failed: Auditd not immutable"
    fi

    rm temp.txt

}

#Ensure the running and on disk configuiration is the same 4.1.3.21
function check-audit-running-ondisk {
    augenrules --check
}


#Ensure audit log files are mode 0640 or less permissive (Automated) 4.1.4.1 (EXTERNAL)
function check-audit-log-file-permission {
    log_file_path=$(grep -E "^log_file\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')

    if [ -n "$log_file_path" ]; then
        log_file_dir=$(dirname "$log_file_path")
        stat -Lc "%n %a" "$log_file_dir"/* >> temp.txt
    else
        echo "Log file path not found in auditd.conf"
    fi

    local audit_fail=false
    while IFS= read -r line; do
        last_three_digits=$(echo "$line" | grep -oE '[0-9]{3}$')
        if [ "$last_three_digits" -gt 640 ]; then
            audit_fail=true
            break
        fi
    done < "temp.txt"

    if [ "$audit_fail" = true ]; then
        echo "Audit fail: Some files have permissions greater than 640"
    else
        echo "Audit passed: All files have permissions 640 or less permissive"
    fi

    rm temp.txt
}


#Ensure only authorized users own audit log files 4.1.4.2 (EXTERNAL)
function check-audit-log-file-ownership {
    log_file_path=$(grep -E "^log_file\s*=" /etc/audit/auditd.conf | awk -F "=" '{print $2}' | tr -d ' ')

    if [ -n "$log_file_path" ]; then
        log_file_dir=$(dirname "$log_file_path")
        stat -Lc "%n %U" "$log_file_dir"/* >> temp.txt
    else
        echo "Log file path not found in auditd.conf"
    fi

    local audit_fail=false
    while IFS= read -r line; do
        owner=$(echo "$line" | awk '{print $2}')
        if [ "$owner" != "root" ]; then
            audit_fail=true
            break
        fi
    done < "temp.txt"

    if [ "$audit_fail" = true ]; then
        echo "Audit fail: Some files are not owned by root user"
    else
        echo "Audit passed: All files are owned by root user"
    fi

    rm temp.txt

}


#Ensure only authorized groups are assigned ownership of audit log files 4.1.4.3
function check-audit-group-ownership {
    grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf >> temp.txt

    local audit_fail=false
    while IFS= read -r line; do
        if [[ "$line" == *adm ]]; then
            audit_fail=true
            break
        fi
    done < "temp.txt"

    if [ "$audit_fail" = true ]; then
        echo "Audit passed: Log group owned by admin"
    else
        echo "Audit Failed: Log group not owned by admin"
    fi

    rm temp.txt
}



#Ensure the audit log directory is 0750 or more restrictive 4.1.4.4
function check-audit-log-directory-restricted {
    log_file_path=$(grep -E "^\s*log_file\s*=" /etc/audit/auditd.conf | cut -d "=" -f 2 | tr -d ' ')

    if [ -n "$log_file_path" ]; then
        log_file_dir=$(dirname "$log_file_path")

        permissions=$(stat -Lc "%a" "$log_file_dir")
        
        if [ "$permissions" -ge 750 ]; then
            echo "Audit passed: Log directory permissions are 750 or more restrictive"
        else
            echo "Audit fail: Log directory permissions are less than 750"
        fi
    else
        echo "Log file path not found in auditd.conf"
    fi
}



#Ensure audit configuration filesa re 640 or more restrictive 4.1.4.5
function check-audit-config-file-restrictions {
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$' >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Failed: log configuration files are not restrictive"
    else
        echo "Audit Passed: log configuration files are restrictive"
    fi
    rm temp.txt
}



#Ensure audit configuration files are owned by root 4.1.4.6
function check-audit-config-owned-by-root {
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root >> temp.txt

    if [ -s temp.txt ]; then
        echo "Audit Failed: log configuration files are not owned by root"
    else
        echo "Audit Passed: log configuration files are owned by root"
    fi

    rm temp.txt
}

#Ensure audit configuration files belong to greoup root 4.1.4.7
function check-audit-config-file-group-root {
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Failed: audit configuration files are not owned by root"
    else
        echo "Audit Passed: audit configuration files are owned by root"
    fi

    rm temp.txt
}

#Ensure audit tools are 577 or more restrictive 4.1.4.8
function check-audit-audit-tools-restrictive {
    stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$' >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Failed: audit tools are not restrictive"
    else
        echo "Audit Passed: audit tools are restrictive"
    fi
    rm temp.txt
}

#Ensure audit tools are owned by root 4.1.4.9
function check-audit-tools-owned-root {
    stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+root\h*$' >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Failed: audit tools are not owned by root"
    else
        echo "Audit Passed: audit tools are owned by root"
    fi
    rm temp.txt
}

#Ensure audit tools belong to group root 4.1.4.10
function check-audit-tools-group-root {
    stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$' >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Failed: audit tools does not belong to group root"
    else
        echo "Audit Passed: audit tools are owned by group root"
    fi
    rm temp.txt
}

#Ensure cryptographicmechanisms are used to protect the integrity of audit tools 4.1.4.11
function check-cryptographicmechanisms-audit-tools {
    grep -P -- '(\/sbin\/(audit|au)\H*\b)' /etc/aide/aide.conf >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Passed: cryptography used to protect integrity of logs"
    else
        echo "Audit Failed: cryptography not used to protect integrity of logs"
    fi
    rm temp.txt
}

#Ensure systemd-journal-remote is installed 4.2.1.1.1
function check-systemd-journal-remote-installed {
    sudo dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' systemd-journal-remote >> temp.txt
    search_string="systemd-journal-remote	install ok installed	installed"
    file="temp.txt"
    file_content=$(<"$file")
    if [[ "$file_content" == *"$search_string"* ]]; then
        echo "Audit Passed: Systemd-journal remote is installed."
    else
        echo "Audit Failed: Systemd-journal remote is not installed."
    fi
    rm temp.txt
}

#Ensure journald is not configured to recieve logs from a remote client 4.2.1.1.4
function journald-restrict-remote-logs {
    systemctl is-enabled systemd-journal-remote.socket >> temp.txt
    search_string="disabled"
    file="temp.txt"
    file_content=$(<"$file")
    if [[ "$file_content" == *"$search_string"* ]];then
        echo "Audit Passed: Systemd Journal restricted remote logs"
    else
        echo "Audit Failed: Systemd journal not restricted remote logs"
    fi
    rm temp.txt
}

#Ensure journald service is enabled 4.2.1.2
function check-audit-enable-journald-service {
    systemctl is-enabled systemd-journald.service >> temp.txt
    search_string="static"
    file="temp.txt"
    file_content=$(<"$file")
    if [[ "$file_content" == *"$search_string"* ]];then
        echo "Audit Passed: Systemd Journal enabled"
    else
        echo "Audit Failed: Systemd journal disabled"
    fi
    rm temp.txt
}

#Ensure journald is configured to compress large log files 4.2.1.3
function check-audit-journald-compress-check {
    grep ^\s*Compress /etc/systemd/journald.conf >> temp.txt
    search_string="Compress=yes"
    file="temp.txt"
    file_content=$(<"$file")
    if [[ "$file_content" == *"$search_string"* ]];then
        echo "Audit Passed: Systemd Journal compress enabled"
    else
        echo "Audit Failed: Systemd journal compress enabled"
    fi
    rm temp.txt

}

#Ensure journald is configured to write logfiles to persistent disk 4.2.1.4
function check-audit-journal-persistent-disk {
    grep ^\s*Storage /etc/systemd/journald.conf >> temp.txt
    search_string="Storage=persistent"
    file="temp.txt"
    file_content=$(<"$file")
    if [[ "$file_content" == *"$search_string"* ]];then
        echo "Audit Passed: Systemd Journal compress enabled"
    else
        echo "Audit Failed: Systemd journal compress enabled"
    fi
    rm temp.txt
}

#Ensure journald is not configured to send logs to rsyslog 4.2.1.5
function check-audit-journald-not-rsyslog {
    grep ^\s*ForwardToSyslog /etc/systemd/journald.conf >> temp.txt
    if [ -s temp.txt ]; then
        echo "Audit Failed: configuired to send logs to rsyslog"
    else
        echo "Audit Passed: not configured to send logs to other logging services"
    fi
    rm temp.txt
}

#Ensure all logfiles have appropriate  permissions and ownership 4.2.3
#!/usr/bin/env bash

function check_logfiles_permissions_ownership {
    echo -e "\n- Start check - logfiles have appropriate permissions and ownership"
    output=""
    find /var/log -type f | (
        while read -r fname; do
            bname="$(basename "$fname")"
            case "$bname" in
                lastlog | lastlog.* | wtmp | wtmp.* | btmp | btmp.*)
                    if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6][0,4]\h*$'; then
                        output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                    fi
                    if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*root\h+(utmp|root)\h*$'; then
                        output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                    fi
                    ;;
                secure | auth.log)
                    if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$'; then
                        output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                    fi
                    if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(syslog|root)\h+(adm|root)\h*$'; then
                        output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                    fi
                    ;;
                SSSD | sssd)
                    if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6]0\h*$'; then
                        output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                    fi
                    if ! stat -Lc "%U %G" "$fname" | grep -Piq -- '^\h*(SSSD|root)\h+(SSSD|root)\h*$'; then
                        output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                    fi
                    ;;
                gdm | gdm3)
                    if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,2,4,6]0\h*$'; then
                        output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                    fi
                    if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(root)\h+(gdm3?|root)\h*$'; then
                        output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                    fi
                    ;;
                *.journal)
                    if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$'; then
                        output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                    fi
                    if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(root)\h+(systemd-journal|root)\h*$'; then
                        output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                    fi
                    ;;
                *)
                    if ! stat -Lc "%a" "$fname" | grep -Pq -- '^\h*[0,2,4,6][0,4]0\h*$'; then
                        output="$output\n- File: \"$fname\" mode: \"$(stat -Lc "%a" "$fname")\"\n"
                    fi
                    if ! stat -Lc "%U %G" "$fname" | grep -Pq -- '^\h*(syslog|root)\h+(adm|root)\h*$'; then
                        output="$output\n- File: \"$fname\" ownership: \"$(stat -Lc "%U:%G" "$fname")\"\n"
                    fi
                    ;;
            esac
        done
        # If all files passed, then we pass
        if [ -z "$output" ]; then
            echo -e "\n- PASS\n- All files in \"/var/log/\" have appropriate permissions and ownership\n"
        else
            # print the reason why we are failing
            echo -e "\n- FAIL:\n$output"
        fi
        echo -e "- End check - logfiles have appropriate permissions and ownership\n"
    )
}

