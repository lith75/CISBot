#!/bin/bash

################### 7.1.1 Ensure permissions on /etc/passwd are configured
function check_PasswdPerms1 {
    audit_name="Ensure permissions on /etc/passwd are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0644"
    # Get the current permissions of /etc/passwd
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/passwd)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/passwd)
    GROUP=$(stat -c "%g:%G" /etc/passwd)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}



################### 7.1.2 Ensure permissions on /etc/passwd- are configured
function check_PasswdPerms2 {
    audit_name=" Ensure permissions on /etc/passwd- are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0644"
    # Get the current permissions of /etc/passwd-
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/passwd-)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/passwd-)
    GROUP=$(stat -c "%g:%G" /etc/passwd-)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}



################### 7.1.3 Ensure permissions on /etc/group are configured
function check_grpPerms1 {
    audit_name="Ensure permissions on /etc/group are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0644"
    # Get the current permissions of /etc/group
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/group)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/group)
    GROUP=$(stat -c "%g:%G" /etc/group)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.4 Ensure permissions on /etc/group- are configured
function check_grpdPerms2 {
    audit_name="Ensure permissions on /etc/group- are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0644"
    # Get the current permissions of /etc/group-
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/group-)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/group-)
    GROUP=$(stat -c "%g:%G" /etc/group-)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.5 Ensure permissions on /etc/shadow are configured
function check_shdwdPerms1 {
    audit_name="Ensure permissions on /etc/shadow are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0640"
    # Get the current permissions of /etc/shadow
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/shadow)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/shadow)
    GROUP=$(stat -c "%g:%G" /etc/shadow)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.6 Ensure permissions on /etc/shadow- are configured
function check_shdwdPerms2 {
    audit_name="Ensure permissions on /etc/shadow- are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0640"
    # Get the current permissions of /etc/shadow-
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/shadow-)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/shadow-)
    GROUP=$(stat -c "%g:%G" /etc/shadow-)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.7 Ensure permissions on /etc/gshadow are configured
function check_gshdwdPerms1 {
    audit_name="Ensure permissions on /etc/gshadow are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0640"
    # Get the current permissions of /etc/gshadow
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/gshadow)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/gshadow)
    GROUP=$(stat -c "%g:%G" /etc/gshadow)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.7 Ensure permissions on /etc/gshadow- are configured
function check_gshdwdPerms2 {
    audit_name="Ensure permissions on /etc/gshadow- are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0640"
    # Get the current permissions of /etc/gshadow-
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/gshadow-)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/gshadow-)
    GROUP=$(stat -c "%g:%G" /etc/gshadow-)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.9 Ensure permissions on /etc/shells are configured
function check_shllsPerms {
    audit_name="Ensure permissions on /etc/shells are configured"
    # Define the expected permissions (octal format)
    EXPECTED_PERMISSIONS="0644"
    # Get the current permissions of /etc/shells
    CURRENT_PERMISSIONS=$(stat -c "%#a" /etc/shells)
    # Expected owner and group (both UID/name)
    EXPECTED_OWNER="0:root"
    EXPECTED_GROUP="0:root"

    # Get current owner and group information
    OWNER=$(stat -c "%u:%U" /etc/shells)
    GROUP=$(stat -c "%g:%G" /etc/shells)

    # Check if owner and group match expectations
    if [[ "$OWNER" == "$EXPECTED_OWNER" && "$GROUP" == "$EXPECTED_GROUP" &&  $CURRENT_PERMISSIONS == $EXPECTED_PERMISSIONS ]]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n"

    
    printf "Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$CURRENT_PERMISSIONS"
    printf "Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$OWNER"
    printf "Group: Expected: %s, Current: %s\n" "$EXPECTED_GROUP" "$GROUP"

    fi
}




################### 7.1.10 Ensure permissions on /etc/security/opasswd are configured 
function check_OpasswdPerms {
  audit_name="Ensure permissions on /etc/security/opasswd and /etc/security/opasswd.old"

  # Check for existence of both files
  if [[ ! -e "/etc/security/opasswd" && ! -e "/etc/security/opasswd.old" ]]; then
    echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n  - Both files are absent.\n"
    return 0  # Exit function with success code
  fi

  # Define expected permissions (octal format)
  EXPECTED_PERMISSIONS="0600"
  EXPECTED_OWNER="0:root"
  EXPECTED_GROUP="0:root"

  # Function to check and report on a single file
  check_opasswd_file() {
    local file_path="$1"
    if [[ -e "$file_path" ]]; then
      # Get current permissions and ownership information
      local current_perms=$(stat -c "%#a" "$file_path")
      local owner=$(stat -c "%u:%U" "$file_path")
      local group=$(stat -c "%g:%G" "$file_path")

      # Check permissions, owner, and group
      if [[ $current_perms -ge $EXPECTED_PERMISSIONS && "$owner" == "$EXPECTED_OWNER" && "$group" == "$EXPECTED_GROUP" ]]; then
        echo "  - $file_path: PASS (Permissions: $current_perms, Owner: $owner, Group: $group)"
      else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n   - $file_path: FAIL\n     Reason(s) for audit failure:\n"
        printf "      Permissions: Expected: %s, Current: %s\n" "$EXPECTED_PERMISSIONS" "$current_perms"
        printf "      Owner: Expected: %s, Current: %s\n" "$EXPECTED_OWNER" "$owner"
        printf "      Group: Expected: %s, Current: %s\n\n" "$EXPECTED_GROUP" "$group"
      fi
    fi
  }

  # Check both files using the helper function
  check_opasswd_file "/etc/security/opasswd"
  check_opasswd_file "/etc/security/opasswd.old"
}




################### 7.1.11 Ensure world writable files and directories are secured
function secure_WorldAccess {
    audit_name="Ensure world writable files and directories are secured"
    l_output=""
    l_output2=""
    l_smask='01000'
    a_file=(); a_dir=() # Initialize arrays
    a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")

    while IFS= read -r l_mount; do
        while IFS= read -r -d $'\0' l_file; do
            if [ -e "$l_file" ]; then
                [ -f "$l_file" ] && a_file+=("$l_file") # Add WR files
                if [ -d "$l_file" ]; then # Add directories w/o sticky bit
                    l_mode="$(stat -Lc '%#a' "$l_file")"
                    [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=("$l_file")
                fi
            fi
        done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2> /dev/null)
    done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}')

    if ! (( ${#a_file[@]} > 0 )); then
        l_output="$l_output\n - No world writable files exist on the local filesystem."
    else
        l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_file[@]}")\" World writable files on the system.\n" # - The following is a list of World writable files:\n$(printf '%s\n' "${a_file[@]}")\n - end of list\n"
    fi

    if ! (( ${#a_dir[@]} > 0 )); then
        l_output="$l_output\n - Sticky bit is set on world writable directories on the local filesystem."
    else
        l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_dir[@]}")\" World writable directories without the sticky bit on the system.\n" # - The following is a list of World writable directories without the sticky bit:\n$(printf '%s\n' "${a_dir[@]}")\n - end of list\n"
    fi

    unset a_path; unset a_arr; unset a_file; unset a_dir # Remove arrays

    # If l_output2 is empty, we pass
    # if [ -z "$l_output2" ]; then
    #     echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured * :\n$l_output\n"
    # else
    #     echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
    #     [ -n "$l_output" ] && echo -e "- * Correctly configured * :\n$l_output\n"
    # fi
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi
}




################### 7.1.12 Ensure no files or directories without an owner and a group exist
function findUnowned {
    audit_name="Ensure no files or directories without an owner and a group exist"
    l_output="" l_output2=""
    a_nouser=(); a_nogroup=() # Initialize arrays
    a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")
    
    while IFS= read -r l_mount; do
        while IFS= read -r -d $'\0' l_file; do
            if [ -e "$l_file" ]; then
                while IFS=: read -r l_user l_group; do
                    [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_file")
                    [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_file")
                done < <(stat -Lc '%U:%G' "$l_file")
            fi
        done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2> /dev/null)
    done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')
    
    if ! (( ${#a_nouser[@]} > 0 )); then
        l_output="$l_output\n - No files or directories without an owner exist on the local filesystem."
    else
        l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_nouser[@]}")\" unowned files or directories on the system.\n" # - The following is a list of unowned files and/or directories:\n$(printf '%s\n' "${a_nouser[@]}")\n - end of list"
    fi
    
    if ! (( ${#a_nogroup[@]} > 0 )); then
        l_output="$l_output\n - No files or directories without a group exist on the local filesystem."
    else
        l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_nogroup[@]}")\" ungrouped files or directories on the system.\n" # - The following is a list of ungrouped files and/or directories:\n$(printf '%s\n' "${a_nogroup[@]}")\n - end of list"
    fi
    
    unset a_path; unset a_arr ; unset a_nouser; unset a_nogroup # Remove arrays
    
    # if [ -z "$l_output2" ]; then # If l_output2 is empty, we pass
    #     echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured * :\n$l_output\n"
    # else
    #     echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2"
    #     [ -n "$l_output" ] && echo -e "\n- * Correctly configured * :\n$l_output\n"
    # fi
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi
}




################### 7.1.13 Ensure SUID and SGID files are reviewed (Manual)
function check_suid_sgid_perms {
    l_output="" l_output2=""
    a_suid=(); a_sgid=() # initialize arrays
    
    while IFS= read -r l_mount_point; do
        if ! grep -Pqs '^\h*\/run\/usr\b' <<< "$l_mount_point" && ! grep -Pqs -- '\bnoexec\b' <<< "$(findmnt -krn "$l_mount_point")"; then
            while IFS= read -r -d $'\0' l_file; do
                if [ -e "$l_file" ]; then
                    l_mode="$(stat -Lc '%#a' "$l_file")"
                    [ $(( $l_mode & 04000 )) -gt 0 ] && a_suid+=("$l_file")
                    [ $(( $l_mode & 02000 )) -gt 0 ] && a_sgid+=("$l_file")
                fi
            done < <(find "$l_mount_point" -xdev -type f \( -perm -2000 -o -perm -4000 \) -print0 2>/dev/null)
        fi
    done <<< "$(findmnt -Derno target)"
    
    if ! (( ${#a_suid[@]} > 0 )); then
        l_output="$l_output\n - No executable SUID files exist on the system"
    else
        l_output2="$l_output2\n - \"$(printf '%s' "${#a_suid[@]}")\" SUID executable files:\n$(printf '%s\n' "${a_suid[@]}")\n - end of list -\n"
    fi
    
    if ! (( ${#a_sgid[@]} > 0 )); then
        l_output="$l_output\n - There are no SGID files exist on the system"
    else
        l_output2="$l_output2\n - \"$(printf '%s' "${#a_sgid[@]}")\" SGID executable files:\n$(printf '%s\n' "${a_sgid[@]}")\n - end of list -\n"
    fi
    
    [ -n "$l_output2" ] && l_output2="$l_output2\n- Review the preceding list(s) of SUID and/or SGID files to\n- ensure that no rogue programs have been introduced onto the system.\n"
    
    unset a_arr; unset a_suid; unset a_sgid # Remove arrays
    
    # If l_output2 is empty, Nothing to report
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT RESULT:\n\e[0m$l_output\n"
    else
        echo -e "\n\e[32mAUDIT RESULT:\n\e[0m$l_output2\n"
        [ -n "$l_output" ] && echo -e "$l_output\n"
    fi
}




################### 7.2.1 Ensure accounts in /etc/passwd use shadowed passwords
function check_shadowed_passwords {
    # Run the command and store the output
    output=$(awk -F: '($2 != "x" ) { print "User: \"" $1 "\" is not set to shadowed passwords "}' /etc/passwd)
    
    # Check if the output is empty
    if [ -z "$output" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - Ensure accounts in /etc/passwd use shadowed passwords]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - Ensure accounts in /etc/passwd use shadowed passwords]\N"
    fi
}




################### 7.2.2 Ensure /etc/shadow password fields are not empty 
# Define the function
function check_passwordless_accounts {
    # Run the command and store the output
    output=$(awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow)
    
    # Check if the output is empty
    if [ -z "$output" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - Ensure /etc/shadow password fields are not empty]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - Ensure /etc/shadow password fields are not empty]\N"
    fi
}







check_PasswdPerms1
check_PasswdPerms2
check_grpPerms1 
check_grpdPerms2 
check_shdwdPerms1 
check_shdwdPerms2 
check_gshdwdPerms1
check_gshdwdPerms2
check_shllsPerms
check_OpasswdPerms #######
secure_WorldAccess
findUnowned 
check_suid_sgid_perms 
check_shadowed_passwords

