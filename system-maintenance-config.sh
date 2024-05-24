#!/bin/bash

################### 7.1.1 Ensure permissions on /etc/passwd are configured
function checkPasswdPerms1reme {
    chmod u-x,go-wx /etc/passwd
    chown root:root /etc/passwd
}
################### 7.1.2 Ensure permissions on /etc/passwd- are configured
function checkPasswdPerms2reme {
    chmod u-x,go-wx /etc/passwd-
    chown root:root /etc/passwd-
}
################### 7.1.3 Ensure permissions on /etc/group are configured
function checkgrpPerms1reme {
    chmod u-x,go-wx /etc/group
    chown root:root /etc/group
}
################### 7.1.4 Ensure permissions on /etc/group- are configured
function checkgrpPerms2reme {
    chmod u-x,go-wx /etc/group-
    chown root:root /etc/group-
}
################### 7.1.5 Ensure permissions on /etc/shadow are configured
function checkshdwPerms1reme {
    chown root:root /etc/shadow
    chmod u-x,g-wx,o-rwx /etc/shadow-
}
################### 7.1.6 Ensure permissions on /etc/shadow- are configured
function checkshdwPerms2reme {
    chown root:root /etc/shadow-
    chmod u-x,g-wx,o-rwx /etc/shadow-
}
################### 7.1.7 Ensure permissions on /etc/gshadow are configured
function checkgshdwPerms1reme {
    chown root:root /etc/gshadow
    chmod u-x,g-wx,o-rwx /etc/gshadow
}
################### 7.1.8 Ensure permissions on /etc/gshadow- are configured
function checkgshdwPerms2reme {
    chown root:root /etc/gshadow-
    chmod u-x,g-wx,o-rwx /etc/gshadow-
}

################### 7.1.9 Ensure permissions on /etc/shells are configured
function checkshllsPermsreme {
    chmod u-x,go-wx /etc/shells
    chown root:root /etc/shells
}

################### 7.1.10 Ensure permissions on /etc/security/opasswd are configured 
function checkOpasswdPermsreme {
    [ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd
    [ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd
    [ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
    [ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old
}
###################7.1.11 Ensure world writable files and directories are secured
function secureWorldAccessreme {
    
    l_smask='01000'
    a_file=(); a_dir=() # Initialize arrays
    a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")

    while IFS= read -r l_mount; do
        while IFS= read -r -d $'\0' l_file; do
            if [ -e "$l_file" ]; then
                l_mode="$(stat -Lc '%#a' "$l_file")"
                if [ -f "$l_file" ]; then # Remove excess permissions from WW files
                    echo -e " - File: \"$l_file\" is mode: \"$l_mode\"\n - removing write permission on \"$l_file\" from \"other\""
                    chmod o-w "$l_file"
                fi
                if [ -d "$l_file" ]; then # Add sticky bit
                    if [ ! $(( $l_mode & $l_smask )) -gt 0 ]; then
                        echo -e " - Directory: \"$l_file\" is mode: \"$l_mode\" and doesn't have the sticky bit set\n - Adding the sticky bit"
                        chmod a+t "$l_file"
                    fi
                fi
            fi
        done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2> /dev/null)
    done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}')


}









checkPasswdPerms1reme
checkPasswdPerms2reme 
checkgrpPerms1reme
checkgrpPerms2reme
checkshdwPerms1reme 
checkshdwPerms2reme 
checkgshdwPerms1reme 
checkgshdwPerms2reme
checkshllsPermsreme
checkOpasswdPermsreme 
secureWorldAccessreme 









