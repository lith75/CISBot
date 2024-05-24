#!/bin/bash




############################################## 3.1.1 Ensure system is checked to determine if IPv6 is enabled ##################################################################




function IPv6_status {
    output=""  # Initialize variable 'output' to an empty string

    # Find GRUB configuration files that contain kernel-related options
    grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)

    # Define locations to search for sysctl configuration files
    searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf"

    # Check if IPv6 is not disabled in the GRUB configuration file
    if [ -s "$grubfile" ]; then
        ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && output="\e[32m[IPv6 Disabled in \"$grubfile\"]\e[0m]"
    fi

    # Check if IPv6 is disabled in sysctl configuration files
    if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $searchloc && grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $searchloc && sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" >/dev/null && sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" >/dev/null; then
        [ -n "$output" ] && output="$output, and in sysctl config" || output="\e[32m[ipv6 disabled in sysctl config]\e[0m]"
    fi

    # Print the result
    [ -n "$output" ] && echo -e "\n$output\n" || echo -e "\n\e[32m[IPv6 is enabled on the system]\e[0m\n"
}




########################################### 3.1.2 Ensure wireless interfaces are disabled ###################################################################




function wireless_int_check {
    # Check if the 'nmcli' command is available
    if command -v nmcli >/dev/null 2>&1; then
        # If 'nmcli' is available, check the status of wireless radios
        if nmcli radio all | grep -Eq '\s*\S+\s+disabled\s+\S+\s+disabled\b'; then
            # If any wireless radio is disabled, print a message indicating that wireless is not enabled
            echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure wireless interfaces are disabled]\n"
        else
            # If all wireless radios are enabled, print a message indicating that wireless is enabled
            echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure wireless interfaces are disabled]\n"
            #exit 1
        fi
    # If 'nmcli' command is not available
    elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then # checks if there are directories named "wireless" in '/sys/class/net'
        #initiate counter
        t=0
        # Get the names of wireless modules
        mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do
                    basename "$(readlink -f "$driverdir"/device/driver/module)";
                done | sort -u)
        # Iterate over each wireless module
        for dm in $mname; do
            # Check if the module doneis disabled in modprobe configuration
            if grep -Eq "^\s*install\s+$dm\s+/bin/(true|false)" /etc/modprobe.d/*.conf; then
                # If module is disabled, set a flag and continue
                :
            else
                # increment counetr
                t=1
            fi
        done
        # If no wireless module is found to be enabled
        if [ "$t" -eq 0 ]; then 
            echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure wireless interfaces are disabled]\n"
        else
            echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure wireless interfaces are disabled]\n"
            #exit 1
        fi        #initiate c
    else
        # If neither 'nmcli' nor wireless directories are found, print a message indicating wireless is not enabled
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure wireless interfaces are disabled]\n"
    fi
}




################################################### 3.2.1 Ensure packet redirect sending is disabled  ##########################################################################





function packet_re_send {

    # Initialize variables
    audit_name="Ensure packet redirect sending is disabled"
    l_output=""  # For storing output messages for parameters correctly set
    l_output2=""  # For storing output messages for parameters incorrectly set

    l_parlist="net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0"  # List of kernel parameters to audit
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $(if [ -f /etc/default/ufw ]; then awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw; fi)"  # Locations to search for kernel parameter configuration files

    KPC() {
        # Get the current value of the kernel parameter
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" 

        # Find the file where the parameter is correctly configured
        l_pafile="$(grep -Psl -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc)"

        # Find files where the parameter is incorrectly configured
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"

        # Check if the current value matches the desired value
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is set to \"$l_krp\" in the running configuration"
        fi

        # Check if the parameter is correctly configured in a file
        if [ -n "$l_pafile" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in \"$l_pafile\""
        else
            l_output2="$l_output2\n - \"$l_kpname = $l_kpvalue\" is not set in a kernel parameter configuration file"
        fi

        # Check if the parameter is incorrectly configured in files
        [ -n "$l_fafile" ] && l_output2="$l_output2\n - \"$l_kpname\" is set incorrectly in \"$l_fafile\""
    }

    # Loop through each kernel parameter in the list
    for l_kpe in $l_parlist; do
        # Extract the parameter name and value
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        # Call the KPC function to audit the parameter
        KPC
    done

    #print the results
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"

    fi

}




########################################################################### 3.2.2 Ensure IP forwarding is disabled ############################################################################################################





function ip_forwrd_dis {
    # Initialize variables
    audit_name="Ensure IP forwarding is disabled"
    l_output=""
    l_output2=""
    l_parlist="net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    
    KPC() {
        # Get the current value of the kernel parameter
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" 

        # Find the file where the parameter is correctly configured
        l_pafile="$(grep -Psl -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc)"

        # Find files where the parameter is incorrectly configured
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"

        # Check if the current value matches the desired value
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is set to \"$l_krp\" in the running configuration"
        fi

        # Check if the parameter is correctly configured in a file
        if [ -n "$l_pafile" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in \"$l_pafile\""
        #else
            #l_output2="$l_output2\n - \"$l_kpname = $l_kpvalue\" is not set in a kernel parameter configuration file"
        fi

        # Check if the parameter is incorrectly configured in files
        [ -n "$l_fafile" ] && l_output2="$l_output2\n - \"$l_kpname\" is set incorrectly in \"$l_fafile\""
    }

    # Function to check IPv6 configuration
    ipv6_chk() {
        # Initialize variable to store IPv6 status
        l_ipv6s=""

        # Find GRUB configuration file
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        
        # Check if GRUB file exists and if IPv6 is disabled in kernel options
        if [ -s "$grubfile" ]; then
            # Check if IPv6.disable is not set in kernel options
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi
        
        # Check if IPv6 is disabled in sysctl configuration files and active in the kernel
        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi
        
        # Check if IPv6 is disabled and set appropriate message
        if [ -n "$l_ipv6s" ]; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            # If IPv6 is not disabled, continue auditing other parameters
            KPC
        fi
    }

    # Loop through each kernel parameter in l_parlist
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            ipv6_chk
        else
            KPC
        fi
    done
    
    # Print audit result
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi
}






###################################################### 3.3.1 Ensure source routed packets are not accepted ########################################################



function source_rt_pac {
    
    audit_name="Ensure source routed packets are not accepted"
    l_output=""
    l_output2=""
    a_parlist=(
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.accept_source_route=0"
        "net.ipv6.conf.default.accept_source_route=0"
    )

    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() { 
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration

        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi

        unset A_out
        declare -A A_out # Check durable setting (files)

        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')

        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi

        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"
                l_fkpvalue="${l_fkpvalue// /}"

                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"
        l_kpvalue="${l_kpvalue// /}"

        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then # Provide output from checks
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n - Reason(s) for audit failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}






################################################################### 3.3.2 Ensure ICMP redirects are not accepted ###################################################





function icmp_redirect {
    # Initialize variables
    audit_name="Ensure ICMP redirects are not accepted"
    l_output=""
    l_output2=""
    l_parlist="net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    KPC() {
        # Get the current value of the kernel parameter
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" 

        # Find the file where the parameter is correctly configured
        l_pafile="$(grep -Psl -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc)"

        # Find files where the parameter is incorrectly configured
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"

        # Check if the current value matches the desired value
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is set to \"$l_krp\" in the running configuration"
        fi

        # Check if the parameter is correctly configured in a file
        if [ -n "$l_pafile" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in \"$l_pafile\""
        #else
            #l_output2="$l_output2\n - \"$l_kpname = $l_kpvalue\" is not set in a kernel parameter configuration file"
        fi

        # Check if the parameter is incorrectly configured in files
        [ -n "$l_fafile" ] && l_output2="$l_output2\n - \"$l_kpname\" is set incorrectly in \"$l_fafile\""
    }

    # Function to check IPv6 configuration
    ipv6_chk() {
        # Initialize variable to store IPv6 status
        l_ipv6s=""

        # Find GRUB configuration file
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        
        # Check if GRUB file exists and if IPv6 is disabled in kernel options
        if [ -s "$grubfile" ]; then
            # Check if IPv6.disable is not set in kernel options
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi
        
        # Check if IPv6 is disabled in sysctl configuration files and active in the kernel
        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi
        
        # Check if IPv6 is disabled and set appropriate message
        if [ -n "$l_ipv6s" ]; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            # If IPv6 is not disabled, continue auditing other parameters
            KPC
        fi
    }

    # Iterate over each kernel parameter and perform the audit
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        # Check if the parameter is related to IPv6 and call the appropriate function
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            ipv6_chk
        else
            KPC
        fi
    done

    # print the results of the audit
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi

}





############################################################## 3.3.3 Ensure secure ICMP redirects are not accepted ########################################################################





function sec_icmp_redirect 

{
    l_output=""
    l_output2=""
    a_parlist=("net.ipv4.conf.all.secure_redirects=0" "net.ipv4.conf.default.secure_redirects=0")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() { 
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration

        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi

        unset A_out
        declare -A A_out # Check durable setting (files)

        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')

        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi

        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"

                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"

        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then # Provide output from checks
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]"
    else
        echo -e "\n- Audit Result:\n\e[91m AUDIT FAIL\e[0m\n - Reason(s) for audit failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}






################################################################## 3.3.4 Ensure suspicious packets are logged ###################################################################################







function packt_log 

{
    audit_name="Ensure suspicious packets are logged"
    l_output=""
    l_output2=""
    a_parlist=("net.ipv4.conf.all.log_martians=1" "net.ipv4.conf.default.log_martians=1")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() { 
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi
        unset A_out
        declare -A A_out # Check durable setting (files)
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi
        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"
        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then # Provide output from checks
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        # echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        # [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi
}














########################################################## 3.3.5 Ensure broadcast ICMP requests are ignored  ###########################################################################################





function brodcst_icmp {
    # Initialize output variables
    audit_name="Ensure broadcast ICMP requests are ignored"
    l_output=""
    l_output2=""

    # Define a list of kernel parameters to check
    l_parlist="net.ipv4.icmp_echo_ignore_broadcasts=1"

    # Define search locations for kernel parameter configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    KPC() {
        # Get the current value of the kernel parameter
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" 

        # Find the file where the parameter is correctly configured
        l_pafile="$(grep -Psl -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc)"

        # Find files where the parameter is incorrectly configured
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"

        # Check if the current value matches the desired value
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is set to \"$l_krp\" in the running configuration"
        fi

        # Check if the parameter is correctly configured in a file
        if [ -n "$l_pafile" ]; then
            l_output="$l_output\n - \"$l_kpname\" is set to \"$l_kpvalue\" in \"$l_pafile\""
        #else
            #l_output2="$l_output2\n - \"$l_kpname = $l_kpvalue\" is not set in a kernel parameter configuration file"
        fi

        # Check if the parameter is incorrectly configured in files
        [ -n "$l_fafile" ] && l_output2="$l_output2\n - \"$l_kpname\" is set incorrectly in \"$l_fafile\""
    }

    # Iterate through each kernel parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPC  # Call the function to check kernel parameter configurations
    done

    # print the results of the audit
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi

}






############################################################################# 3.3.6 Ensure bogus ICMP responses are ignored #################################################################################






function bogus_icmp {
    audit_name="Ensure bogus ICMP responses are ignored"
    l_output=""
    l_output2=""
    a_parlist=("net.ipv4.icmp_ignore_bogus_error_responses=1")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() {
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi
        unset A_out
        declare -A A_out # Check durable setting (files)
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi
        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"
        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then # Provide output from checks
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
        # echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        # [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}







############################################################################# 3.3.7 Ensure Reverse Path Filtering is enabled ###############################################################################








function rvrs_path_filtr {
    



    audit_name="Ensure Reverse Path Filtering is enabled"
    l_output=""
    l_output2=""
    a_parlist=("net.ipv4.conf.all.rp_filter=1" "net.ipv4.conf.default.rp_filter=1")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() {
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi
        unset A_out
        declare -A A_out # Check durable setting (files)
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi
        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"
        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then # Provide output from checks
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
        # echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        # [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}





############################################################################### 3.3.8 Ensure TCP SYN Cookies is enabled  ###################################################################################







function tcp_syn_cookies {
    


    audit_name="Ensure TCP SYN Cookies is enabled"
    l_output=""
    l_output2=""
    a_parlist=("net.ipv4.tcp_syncookies=1")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() {
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi
        unset A_out
        declare -A A_out # Check durable setting (files)
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi
        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"
        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi

}






####################################################################### 3.3.9 Ensure IPv6 router advertisements are not accepted #############################################################################################







function IPv6_router_ad {

    

    audit_name="Ensure IPv6 router advertisements are not accepted"
    l_output=""
    l_output2=""
    a_parlist=("net.ipv6.conf.all.accept_ra=0" "net.ipv6.conf.default.accept_ra=0")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() {
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi
        unset A_out
        declare -A A_out # Check durable setting (files)
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl -cat-config)
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi
        if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"
        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi
}







################################################################################ 3.4.1 Ensure DCCP is disabled ###############################################################################################





function dccp_disbl {
    # Initialize variables to store audit results
    audit_name="Ensure DCCP is disabled"
    l_output=""
    l_output2=""

    # Set the name of the module to be checked
    l_mname="dccp"

    # crete function to check status of a module
    mod_stat() {
    # Check how module will be loaded
        l_loadable="$(modprobe -n -v "$l_mname")"

        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable"
        fi

        # Check if the module is currently loaded
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
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
    }

    #check the status of the module
    mod_stat

    ## print the results of the audit
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi

}






##################################################################### 3.4.2 Ensure SCTP is disabled  #########################################################################################################






function sctp_disbl {
    # Initialize variables to store audit results
    audit_name="Ensure SCTP is disabled"
    l_output=""     # Store audit results indicating issues
    l_output2=""    # Store audit results indicating successful checks

    # Set the name of the module to be checked
    l_mname="sctp"

    # crete function to check status of a module
    mod_stat() {
    # Check how module will be loaded
        l_loadable="$(modprobe -n -v "$l_mname")"

        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable"
        fi

        # Check if the module is currently loaded
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
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
    }

    #check the status of the module
    mod_stat

    ## Call the function to print the results of the audit
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi

}





########################################################### 3.4.3 Ensure RDS is disabled ###################################################################################






function rds_disbl {
    # Initialize variables to store output messages
    audit_name="Ensure RDS is disabled"
    l_output=""
    l_output2=""

    # Set the module name
    l_mname="rds"

    # crete function to check status of a module
    mod_stat() {
    # Check how module will be loaded
        l_loadable="$(modprobe -n -v "$l_mname")"

        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable"
        fi

        # Check if the module is currently loaded
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
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
    }

    #check the status of the module
    mod_stat

    # Report audit results
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi

}






################################################################### 3.4.4 Ensure TIPC is disabled ###################################################################################




function tipc_disbl {
    # Initialize variables to store output messages
    audit_name="Ensure TIPC is disabled"
    l_output=""
    l_output2=""

    # Set the module name
    l_mname="tipc"

    # crete function to check status of a module
    mod_stat() {
    # Check how module will be loaded
        l_loadable="$(modprobe -n -v "$l_mname")"

        if grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
            l_output="$l_output\n - module: \"$l_mname\" is not loadable"
        else
            l_output2="$l_output2\n - module: \"$l_mname\" is loadable"
        fi

        # Check if the module is currently loaded
        if ! lsmod | grep "$l_mname" > /dev/null 2>&1; then
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
    }

    #check the status of the module
    mod_stat

    # Report results. If no failures output in l_output2, we pass
    if [ -z "$l_output2" ]; then
        echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
    else
        echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$l_output2\n"
    fi
}



# 



###################################################################################################################################################################################
###################################################################################################################################################################################
######################################################## 3.5.2.1 Ensure nftables is installed #####################################################################################





# Define a function to check if nftables is installed
function nftabls_install {
    # Use dpkg-query to check the status of nftables package and grep for the installation status
    if dpkg-query -s nftables | grep -q 'Status: install ok installed'; then
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables is installed]\n"
    else
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables is installed]\n"
    fi
}





############################################### 3.5.2.2 Ensure ufw is uninstalled or disabled with nftables ###############################################




# Define a function to check if UFW is uninstalled or disabled
function ufw_status {
  # Check if ufw is installed and enabled
  if [[ $(dpkg-query -s ufw | grep 'Status: install ok installed') && $(ufw status | grep "active (enabled)") ]]; then
    echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw is uninstalled or disabled with nftables]\n"
  else
    echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw is uninstalled or disabled with nftables]\n"
  fi
}




################################################## 3.5.2.3 Ensure iptables are flushed with nftables ####################################################





function iptabl_flush {
  
    # Check if the default policy is set to ACCEPT in iptables and ip6tables
    if iptables -L | grep -q "Chain INPUT (policy ACCEPT)" && \iptables -L | grep -q "Chain FORWARD (policy ACCEPT)" && \iptables -L | grep -q "Chain OUTPUT (policy ACCEPT)" && \ip6tables -L | grep -q "Chain INPUT (policy ACCEPT)" && \ip6tables -L | grep -q "Chain FORWARD (policy ACCEPT)" && \ip6tables -L | grep -q "Chain OUTPUT (policy ACCEPT)"; then
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure iptables are flushed with nftables]\n"
    else
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure iptables are flushed with nftables]\n"
    fi

}





################################################### 3.5.2.4 Ensure a nftables table exists ###############################################################





# Define a function to verify if an nftables table exists
function nftabl_exist {
    # Run the command to list nftables tables and check if the specified table exists
    if nft list tables | grep -q "table inet filter"; then
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure a nftables table exists]\n"
    else
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure a nftables table exists]\n"
    fi
}




################################################## 3.5.2.5 Ensure nftables base chains exist ############################################################





# Define a function to verify that base chains exist for INPUT, FORWARD, OUTPUT
function base_chains_exist {
    # Initialize a variable to store failed criteria messages
    failure_con=""

    # Check if base chain exists for INPUT
    if ! nft list ruleset | grep -q 'hook input'; then
        failure_con+="Base chain for INPUT does not exist\n"  # Append message if base chain for INPUT does not exist
    fi

    # Check if base chain exists for FORWARD
    if ! nft list ruleset | grep -q 'hook forward'; then
        failure_con+="Base chain for FORWARD does not exist\n"  # Append message if base chain for FORWARD does not exist
    fi

    # Check if base chain exists for OUTPUT
    if ! nft list ruleset | grep -q 'hook output'; then
        failure_con+="Base chain for OUTPUT does not exist\n"  # Append message if base chain for OUTPUT does not exist
    fi

    # Print the collected failed criteria messages with each item in a separate line
    if [ -n "$failure_con" ]; then
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables base chains exist]\n"
        echo -e "Reason(s) for failure:\n"
        echo -e "$failure_con"
    else
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables base chains exist]\n"
    fi
}






######################################################### 3.5.2.6 Ensure nftables loopback traffic is configured #########################################





# Define a function to verify that the loopback interface is configured
function loopback_int {

    pass_msg="" # varible to store audit pass messages
    fail_msg="" #varible to store audit fail messages

    # Check if loopback interface is configured
    if nft list ruleset | awk '/hook input/,/}/' | grep -q 'iif "lo" accept' && \
       nft list ruleset | awk '/hook input/,/}/' | grep -q 'ip saddr 127.0.0.0/8'; then
        # Print message indicating audit PASS if loopback interface is configured
        pass_msg+="Loopback interface is configured\n"
    else
        # Print message indicating audit FAIL if loopback interface is not configured
        fail_msg+="Loopback interface is not configured\n"
    fi

    # Check if IPv6 is enabled on the system
    if [ -n "$(ip addr | grep -E '^\s*inet6')" ]; then
        # Check if loopback interface is configured for IPv6
        if nft list ruleset | awk '/hook input/,/}/' | grep -q 'ip6 saddr ::1'; then
            # Print message indicating audit PASS if IPv6 loopback interface is configured
            pass_msg+="IPv6 loopback interface is configured\n"
        else
            # Print message indicating audit FAIL if IPv6 loopback interface is not configured
            fail_msg+="IPv6 loopback interface is not configured\n"
        fi
    fi

    if [ -n "$fail_msg" ]; then
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables loopback traffic is configured]\n"
        echo -e "Reason(s) for failure:\n"
        echo -e "$fail_msg"
    else 
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables loopback traffic is configured]\n"
    fi
}





################################################### 3.5.2.7 Ensure nftables outbound and established connections are configured ############################




# Define a function to verify established incoming connections match the site policy
function est_connections {

    pass_msg="" # varible to store audit pass messages
    fail_msg="" #varible to store audit fail messages

    # Define the site policy for established connections
    site_policy="ip protocol (tcp|udp|icmp) ct state established accept"
    
    # Extract rules related to established connections from the ruleset and check if they match the site policy
    if nft list ruleset | awk '/hook input/,/}/' | grep -E -q "$site_policy"; then
        :
    else
        fail_msg+="Some rules for established incoming connections do not match the site policy\n"
    fi

    # Define the site policy for new and established outbound connections
    site_policy="ip protocol (tcp|udp|icmp) ct state established,related,new accept"
    
    # Extract rules related to outbound connections from the ruleset and check if they match the site policy
    if nft list ruleset | awk '/hook output/,/}/' | grep -E -q "$site_policy"; then
        :
    else
        fail_msg+="Some rules for new and established outbound connections do not match the site policy\n"
    fi

    # print results
    if [ -n "$fail_msg" ]; then
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables outbound and established connections are configured]\n"
        echo -e "Reason(s) for failure:\n"
        echo -e "$fail_msg"
    else 
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables outbound and established connections are configured]\n"
    fi
}






################################################# 3.5.2.8 Ensure nftables default deny firewall policy ####################################################






function nft_deny_polic {
    # Define an array to hold the base chain names
    base_chains=("input" "forward" "output")

    # Initialize a variable to store failure messages
    failure_con=""

    # Iterate over each base chain
    for chain in "${base_chains[@]}"; do
        # Run the command to check if the base chain contains a policy of DROP
        if ! nft list ruleset | grep -q "hook $chain" && ! nft list ruleset | grep -q "hook $chain.*policy drop"; then
            # Append failure message if policy of DROP is not found
            failure_con+="Base chain $chain does not contain a DROP policy\n"
        fi
    done

     # print results
    if [ -n "$failure_con" ]; then
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables default deny firewall policy]\n"
        echo -e "Reason(s) for failure:\n"
        echo -e "$failure_con"
    else 
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables default deny firewall policy]\n"
    fi
}





########################################### 3.5.2.9 Ensure nftables service is enabled ###############################################################




function nftables_enabled {
    # Check if the nftables service is enabled
    if systemctl is-enabled nftables &>/dev/null; then
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables service is enabled]\n"
    else
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables service is enabled]\n"
    fi
}





########################################## 3.5.2.10 Ensure nftables rules are permanent ################################################################





function nft_ruls_perme {
    # Initialize a variable to store failure messages
    fail_con=""

    # Check if input base chain is configured
    if [ -n "$(grep -E '^\s*include' /etc/nftables.conf)" ]; then
        input_base_chain=$(awk '/hook input/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/nftables.conf))
        if [[ -n "$input_base_chain" ]]; then
            :
        else
            fail_con+="Input Base Chain Not Configured\n"
        fi
    else
        fail_con+="No nftables.conf file found\n"
    fi

    # Check if forward base chain is configured
    if [ -n "$(grep -E '^\s*include' /etc/nftables.conf)" ]; then
        forward_base_chain=$(awk '/hook forward/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/nftables.conf))
        if [[ -n "$forward_base_chain" ]]; then
            :
        else
            fail_con+="Forward Base Chain Not Configured\n"
        fi
    else
        fail_con+="No nftables.conf file found\n"
    fi

    # Check if output base chain is configured
    if [ -n "$(grep -E '^\s*include' /etc/nftables.conf)" ]; then
        output_base_chain=$(awk '/hook output/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/nftables.conf))
        if [[ -n "$output_base_chain" ]]; then
            :
        else
            fail_con+="Output Base Chain Not Configured\n"
        fi
    else
        fail_con+="No nftables.conf file found\n"
    fi

    # print results
    if [ -n "$fail_con" ]; then
        echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables rules are permanent]\n"
        echo -e "Reason(s) for failure:\n"
        echo -e "$fail_con"
    else 
        echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables rules are permanent]\n"
    fi
}



# ##########################################################################################################################################################
# ##########################################################################################################################################################
# ##########################################################################################################################################################

# ############################################### 3.5.3.1.1 Ensure iptables packages are installed #########################################################





# function iptabls_installed {

#     # Initialize a variable to store failure messages
#     fail_con=""
#     # Check if iptables and iptables-persistent are installed
#     iptables_installed=$(dpkg -l iptables 2>/dev/null | grep -E '^ii' | wc -l)
#     iptables_persistent_installed=$(dpkg -l iptables-persistent 2>/dev/null | grep -E '^ii' | wc -l)

#     #  messages based on installation status
#     if [ "$iptables_installed" -gt 0 ]; then
#         :
#     else
#         fail_con+="iptables is not installed\n"
#     fi

#     if [ "$iptables_persistent_installed" -gt 0 ]; then
#         :
#     else
#         fail_con+="iptables-persistent is not installed\n"
#     fi

#     # print results
#     if [ -n "$fail_con" ]; then
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure iptables packages are installed]\n"
#         echo -e "Reason(s) for failure:\n"
#         echo -e "$fail_con"
#     else 
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure iptables packages are installed]\n"
#     fi
# }





# ############################################# 3.5.3.1.2 Ensure nftables is not installed with iptables ####################################################





# function nftbls_not_ins {
#     # Run dpkg-query to check the status of the nftables package
#     nftables_status=$(dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nftables 2>/dev/null)
    
#     # Check if the status indicates that nftables is not installed
#     if ! grep -q "nftables        unknown ok not-installed        not-installed" <<< "$nftables_status"; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure nftables is not installed with iptables]\n"  # Print message if nftables is not installed
#         return 0  # Return success status
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure nftables is not installed with iptables]\n"  # Print message if nftables is installed
#         return 1  # Return failure status
#     fi
# }





# ##################################################### 3.5.3.1.3 Ensure ufw is uninstalled or disabled with iptables #######################################





# ufw_not_inst_disbld() {
#     # Check if ufw is not installed
#     ufw_status_ins=$(dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw 2>/dev/null)
#     #Check if ufw is disabled
#     ufw_status_dis=$(ufw status)

#     if grep -q "not-installed" <<< "$ufw_status_ins"; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw is uninstalled or disabled with iptables]\n"

    
#     elif grep -q "Status: inactive" <<< "$ufw_status_dis"; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw is uninstalled or disabled with iptables]\n"

#     # Check if ufw service is masked
#     elif systemctl is-enabled ufw | grep -q "masked"; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw is uninstalled or disabled with iptables]\n"

#     else
#         # If none of the above conditions are met, return failure
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw is uninstalled or disabled with iptables]\n" 

#     fi
# }





# ############################################## 3.5.3.2.1 Ensure iptables default deny firewall policy #################################################




# function iptbl_deny_policy {
#     # Declare an array to hold the chain names
#     chains=("INPUT" "OUTPUT" "FORWARD")

#     # Initialize a variable to store failure messages
#     failure_con=""

#     # Run iptables -L command and store the output
#     iptables_output=$(iptables -L)

#     # Iterate over each chain
#     for chain in "${chains[@]}"; do
#         # Check the policy for the current chain
#         if ! echo "$iptables_output" | grep -q "Chain $chain.*policy DROP\|REJECT"; then
#             # Initialize a variable to store failure messages
#             failure_con+="Policy for $chain chain is not DROP or REJECT\n"
#         fi
#     done

#         # print results
#     if [ -n "$failure_con" ]; then
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure iptables default deny firewall policy]\n"
#         echo -e "Reason(s) for failure:\n"
#         echo -e "$failure_con"
#     else 
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure iptables default deny firewall policy]\n"
#     fi
# }





# ############################################### 3.5.3.2.2 Ensure iptables loopback traffic is configured ################################################




# function iptbl_lback_traf {

#     # Run iptables -L command for each chain and store the output
#     input_output=$(iptables -L INPUT -v -n | awk '{$1=$2=""; print $0}' | sed 's/^  *//')
#     output_output=$(iptables -L OUTPUT -v -n | awk '{$1=$2=""; print $0}' | sed 's/^  *//')

#     input_third_line=$(echo "$input_output" | sed -n '3p')
#     input_fourth_line=$(echo "$input_output" | sed -n '4p')
#     output_third_line=$(echo "$output_output" | sed -n '3p')
#     fail_con=""

#     if [ "$input_third_line" != "ACCEPT all -- lo * 0.0.0.0/0 0.0.0.0/0" ]; then
#         fail_con+="$input_third_line\n" 
#     fi

#     if [ "$input_fourth_line" != "DROP all -- * * 127.0.0.0/8 0.0.0.0/0" ]; then
#         fail_con+="$input_fourth_line\n"
#     fi

#     if [ "$output_third_line" != "ACCEPT all -- * lo 0.0.0.0/0 0.0.0.0/0" ]; then
#         fail_con+="$output_third_line\n"
#     fi

#         if [ -n "$fail_con" ]; then
#             echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure iptables loopback traffic is configured]\n"
#             echo -e "Reason(s) for failure:\n"
#         echo -e "The rules do not match"
#             echo -e "$fail_con"
#         else
#             echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure iptables loopback traffic is configured]\n"
#         fi

# }





# ######################################### 3.5.3.2.3 Ensure iptables outbound and established connections are configured ####################################





# function iptabls_site_policy {
#     # Run iptables -L -v -n command and store the output
#     iptables_output=$(iptables -L -v -n)

#     # Check if the output contains any rules that match the site policy
#     if echo "$iptables_output" | grep -qE 'NEW|ESTABLISHED'; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure iptables outbound and established connections are configured]\n"
        
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure iptables outbound and established connections are configured]\n"
#     fi
# }




# ######################################### 3.5.3.2.4 Ensure iptables firewall rules exist for all open ports ###############################################





# # Define a function to verify that firewall rules are configured for open ports
# function firewll_rule_exist {

#     audit_name="Ensure iptables firewall rules exist for all open ports"

#     # Get list of open ports with protocol
#     open_ports=$(ss -4tuln | awk '{print $1":"$4":"$5}')

#     # Loop through each open port and protocol
#     for line in $open_ports
#     do
#         # Extract protocol, port number (local and remote)
#         protocol=$(echo $line | cut -d ':' -f 1)

#         port=$(echo $line | cut -d ':' -f 4)
        
#         # Check firewall rule (unchanged)
#         rule_exists=$(sudo iptables -L INPUT -v -n | grep "dpt:$port" | wc -l)

#         # Print information (modified)
#         if [ $rule_exists -eq 0 ] && [ -n "$port" ]; then
            
#         message+="No firewall rule for port $port (protocol: $protocol)"$'\n'

#         fi

#     done


#     if [ -z "$message" ]; then
#     echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
#         else
#             echo -e "\n\e[91mAUDIT FAIL\e[0m [Name - $audit_name]\n \nReason(s) for audit failure:\n$message\n"
#         fi
# }





# ############################################# 3.5.3.3.1 Ensure ip6tables default deny firewall policy ####################################################






# # Define a function to verify IPv6 configuration
# function ipv6_default_poli {
#     audit_name="Ensure ip6tables default deny firewall policy "
#     # # Check if ip6tables policies are DROP or REJECT
#     # ip6tables_policies=$(ip6tables -L | grep -E 'Chain (INPUT|FORWARD|OUTPUT) (policy DROP|policy REJECT)')

#     # Declare an array to hold the chain names
#     chains=("INPUT" "OUTPUT" "FORWARD")

#     # Initialize a variable to store failure messages
#     failure_con=""

#     # Run iptables -L command and store the output
#     iptables_output=$(iptables -L)

#     # Iterate over each chain
#     for chain in "${chains[@]}"; do
#         # Check the policy for the current chain
#         if ! echo "$iptables_output" | grep -q "Chain $chain.*policy DROP\|REJECT"; then
#             # Initialize a variable to store failure messages
#             failure_con+="Policy for $chain chain is not DROP or REJECT\n"
#         fi
#     done


#     ip6_disable() {
#         # Initialize an empty string to store IPv6 disabled messages
#         output1=""

#         # Check if IPv6 is disabled in grub config
#         grubfile="$(find -L /boot -name 'grub.cfg' -type f)"
#         if [ -f "$grubfile" ] && ! grep "^\s*linux" "$grubfile" | grep -vq ipv6.disable=1; then
#             output1+="ipv6 disabled in grub config\n"
#         fi

#         # Check if IPv6 is disabled in sysctl config files
#         if grep -Eqs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         grep -Eqs "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" &&
#         sysctl net.ipv6.conf.default.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b"; then
#             output1+="ipv6 disabled in sysctl config\n"
#         fi
        
#         # print results
#         if [ -n "$output1" ]; then
#             echo -e "\n\e[32mAudit PASS\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for success:\n"
#             echo -e "$output1"
#         else 
#             echo -e "\n\e[91mAudit FAIL\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for failure:\n"
#             echo -e "IPv6 is enabled on the system\n"
#         fi
#     }

#     if [ -z "$failure_con" ]; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ip6tables default deny firewall policy]\n"
#         echo -e "Reason(s) for success:\n"
#         echo -e "IPv6 policies are set to DROP or REJECT\n"
#     else
#         # call function
#         ip6_disable
#     fi
# }





# ########################################## 3.5.3.3.2 Ensure ip6tables loopback traffic is configured ################################################





# # Define a function to verify ip6tables rules
# function ip6_lback_traff {
#     audit_name="Ensure ip6tables loopback traffic is configured"

#     ip6_disable() {
#         # Initialize an empty string to store IPv6 disabled messages
#         output1=""

#         # Check if IPv6 is disabled in grub config
#         grubfile="$(find -L /boot -name 'grub.cfg' -type f)"
#         if [ -f "$grubfile" ] && ! grep "^\s*linux" "$grubfile" | grep -vq ipv6.disable=1; then
#             output1+="ipv6 disabled in grub config\n"
#         fi

#         # Check if IPv6 is disabled in sysctl config files
#         if grep -Eqs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         grep -Eqs "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" &&
#         sysctl net.ipv6.conf.default.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b"; then
#             output1+="ipv6 disabled in sysctl config\n"
#         fi
        
#         # print results
#         if [ -n "$output1" ]; then
#             echo -e "\n\e[32mAudit PASS\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for success:\n"
#             echo -e "$output1"
#         else 
#             echo -e "\n\e[91mAudit FAIL\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for failure:\n"
#             echo -e "IPv6 is enabled on the system\n"
#         fi
#     }

#     # Run iptables -L command for each chain and store the output
#     input_output=$(ip6tables -L INPUT -v -n | awk '{$1=$2=""; print $0}' | sed 's/^  *//')
#     output_output=$(ip6tables -L OUTPUT -v -n | awk '{$1=$2=""; print $0}' | sed 's/^  *//')    
#     # Run iptables -L command for each chain and store the output

#     input_third_line=$(echo "$input_output" | sed -n '3p')
#     input_fourth_line=$(echo "$input_output" | sed -n '4p')
#     output_third_line=$(echo "$output_output" | sed -n '3p')
#     fail_con=""

#     if [ "$input_third_line" != "ACCEPT all lo * ::/0 ::/0" ]; then
#         fail_con+="$input_third_line\n" 
#     fi

#     if [ "$input_fourth_line" != "DROP all * * ::1 ::/0" ]; then
#         fail_con+="$input_fourth_line\n"
#     fi

#     if [ "$output_third_line" != "ACCEPT all * lo ::/0 ::/0" ]; then
#         fail_con+="$output_third_line\n"
#     fi

#     if [ -z "$fail_con" ]; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ip6tables loopback traffic is configured]\n"
#     else
#         ip6_disable
#     fi
    
# }





# ########################################## 3.5.3.3.3 Ensure ip6tables outbound and established connections are configured #################################





# function ip6_site_policy {
#     audit_name="Ensure ip6tables outbound and established connections are configured"

#     # Run ip6tables -L -v -n command and store the output
#     iptables_output=$(ip6tables -L -v -n)

#     ip6_disable() {
#         # Initialize an empty string to store IPv6 disabled messages
#         output1=""

#         # Check if IPv6 is disabled in grub config
#         grubfile="$(find -L /boot -name 'grub.cfg' -type f)"
#         if [ -f "$grubfile" ] && ! grep "^\s*linux" "$grubfile" | grep -vq ipv6.disable=1; then
#             output1+="ipv6 disabled in grub config\n"
#         fi

#         # Check if IPv6 is disabled in sysctl config files
#         if grep -Eqs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         grep -Eqs "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" &&
#         sysctl net.ipv6.conf.default.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b"; then
#             output1+="ipv6 disabled in sysctl config\n"
#         fi
        
#         # print results
#         if [ -n "$output1" ]; then
#             echo -e "\n\e[32mAudit PASS\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for success:\n"
#             echo -e "$output1"
#         else 
#             echo -e "\n\e[91mAudit FAIL\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for failure:\n"
#             echo -e "IPv6 is enabled on the system\n"
#         fi
#     }

#     # Check if the output contains any rules that match the site policy
#     if echo "$iptables_output" | grep -qE 'NEW|ESTABLISHED'; then
#         # Output audit pass message if the rules match the site policy
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ip6tables outbound and established connections are configured]\n"
#     else
#         # call function
#         ip6_disable
#     fi
# }





# ############################################# 3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports ##########################################






# # Define a function to verify that firewall rules are configured for open ports
# function ip6_firewll_rule_exist {
#     # name of the audit
#     audit_name="Ensure ip6tables firewall rules exist for all open ports"


#     ip6_disable() {
#         # Initialize an empty string to store IPv6 disabled messages
#         output1=""

#         # Check if IPv6 is disabled in grub config
#         grubfile="$(find -L /boot -name 'grub.cfg' -type f)"
#         if [ -f "$grubfile" ] && ! grep "^\s*linux" "$grubfile" | grep -vq ipv6.disable=1; then
#             output1+="ipv6 disabled in grub config\n"
#         fi

#         # Check if IPv6 is disabled in sysctl config files
#         if grep -Eqs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         grep -Eqs "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf &&
#         sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b" &&
#         sysctl net.ipv6.conf.default.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b"; then
#             output1+="ipv6 disabled in sysctl config\n"
#         fi
        
#         # print results
#         if [ -n "$output1" ]; then
#             echo -e "\n\e[32mAudit PASS\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for success:\n"
#             echo -e "$output1"
#         else 
#             echo -e "\n\e[91mAudit FAIL\e[0m [Name - $audit_name]\n"
#             echo -e "Reason(s) for failure:\n"
#             echo -e "IPv6 is enabled on the system\n"
#         fi
#     }



#     # Get list of open ports with protocol
#     open_ports=$(ss -6tuln | awk '{print $1":"$4":"$5}')

#     # Loop through each open port and protocol
#     for line in $open_ports;do
#     #echo "$line"
#     # Extract protocol, port number (local and remote)
#     protocol=$(echo $line | cut -d ':' -f 1)
#     #echo "$protocol"
#     port=$(echo $line | cut -d ':' -f 6)
    
    
#     # Check firewall rule (unchanged)
#     rule_exists=$(sudo ip6tables -L INPUT -v -n | grep "dpt:$port" | wc -l)

#     # Print information (modified)
#     if [ $rule_exists -eq 0 ] && [ -n "$port" ]; then   
#         message+="No firewall rule for port $port (protocol: $protocol)"$'\n'
#     fi
#     done


#     if [ -z "$message" ]; then
#         echo -e "\n\e[32mAUDIT PASS\e[0m [Name - $audit_name]\n"
#     else
#         # call function to verify ipv6 is disables
#         ip6_disable
#     fi

# }









# ###############################################################################################################################################################################
# ###############################################################################################################################################################################
# ###################################################################################################################################################################################
# ################################################################# 3.5.1.1 Ensure ufw is installed #################################################################################


# function ufw_ins {

#     # Use dpkg-query to check the status of the ufw package
#     local status=$(dpkg-query -W -f='${Status}' ufw 2>/dev/null)
    
#     # Check if the status contains "installed" substring
#     if [[ "$status" == *"installed"* ]]; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw is installed]\n"
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - UFW is not installed]\n"
#     fi
# }





# ######################################################### 3.5.1.2 Ensure iptables-persistent is not installed with ufw ########################################################





# function ip_tbl_persis {
#     # Execute dpkg-query command to check the status of the iptables-persistent package
#     dpkg-query -s iptables-persistent &>/dev/null
    
#     # Check the exit status of the dpkg-query command
#     if [[ $? -ne 0 ]]; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure iptables-persistent is not installed with ufw]\n"
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure iptables-persistent is not installed with ufw]\n"
#     fi
# }






# ######################################################### 3.5.1.3 Ensure ufw service is enabled ##############################################################################






# function ufw_enable {
#     # Check if UFW daemon is enabled using systemctl 
#     # then verify that the ufw daemon is active
#     # then ufw is active
#     if [ "$(systemctl is-enabled ufw.service)" = "enabled" ] && \
#        [ "$(systemctl is-active ufw)" = "active" ] && \
#        [ "$(ufw status | grep Status)" = "Status: active" ]; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw service is enabled]\n"  # If all checks pass, UFW is enabled
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw service is enabled]\n"  # If any check fails, UFW is not enabled
#     fi
# }





# ############################################################ 3.5.1.4 Ensure ufw loopback traffic is configured #################################################################





# # Define a function named verify_ufw_rules
# function ufw_lback_traf {
#     # Run the ufw status verbose command and store the output in the variable ufw_status_output
#     ufw_status_output=$(ufw status verbose)

#     # Define an array named expected_rules to hold the expected rules in the format "From To Action"
#     expected_rules=(
#         "Anywhere on lo             ALLOW IN    Anywhere"
#         "Anywhere                   DENY IN     127.0.0.0/8"
#         "Anywhere (v6) on lo        ALLOW IN    Anywhere (v6)"
#         "Anywhere (v6)              DENY IN     ::1"
#         "Anywhere                   ALLOW OUT   Anywhere on lo "
#         "Anywhere (v6)              ALLOW OUT   Anywhere (v6) on lo"
#     )

#     # Initialize a variable to store missing rules
#     missing_rules=""

#     # Iterate over each expected rule
#     for rule in "${expected_rules[@]}"; do
#         # Check if the current rule exists in the output of ufw status verbose command
#         if ! grep -q "$rule" <<< "$ufw_status_output"; then
#             # Append the missing rule to the variable missing_rules
#             missing_rules+="$rule\n"
#         fi
#     done

#     # Check if any expected rules are missing
#     if [ -n "$missing_rules" ]; then
#         # Print a message indicating the missing rules
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw loopback traffic is configured]"
#         echo -e "\nMissing Rules:\n"
#         echo -e "$missing_rules" | while IFS= read -r line; do echo "$line"; done
#         # Return with a non-zero exit status to indicate verification failure
#         return 1
#     else
#         # If all expected rules are found, print a success message
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw service is enabled]\n"
#     fi
# }






# ############################################################# 3.5.1.5 Ensure ufw outbound connections are configured ##############################################################





# # Define a function to verify ufw rules for outbound connections
# function ufw_outbound_conf {
#     # Run ufw status numbered command and filter the output to show only rules for outbound connections
#     ufw_status=$(ufw status numbered | grep -E 'ALLOW OUT')

#     # Check if there are any rules allowing outbound connections
#     if [ -n "$ufw_status" ]; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw outbound connections are configured]\n"
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw outbound connections are configured]\n"
#         echo -e "Reason(s) for failure:\n"
#         echo -e "No rules found for new outbound connections or they don't match the site policy\n"
#     fi
# }






# ################################################################ 3.5.1.6 Ensure ufw firewall rules exist for all open ports ##########################################################





# # Define a function to check for missing firewall rules in ufw configuration
# function mis_firewall_rules {
#     # Store the verbose output of 'ufw status' command in the variable ufw_out
#     ufw_out="$(ufw status verbose)"

#     # Use 'ss' to list all listening TCP and UDP sockets excluding localhost and loopback addresses,
#     # extract the port numbers, sort them, and remove duplicates
#     ports=$(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/::1/) {split($5, a, ":"); print a[2]}' | sort | uniq)
    
#     mis_rules="" #empty varible to store missing rules
#     found_missing_rule=false # Initialize a flag to indicate if any missing rule is found
    
#     # Iterate over each extracted port number
#     for lpn in $ports; do
#         # Check if the port number has a corresponding firewall rule in ufw_out
#         if ! grep -Pq "^\h*$lpn\b" <<< "$ufw_out"; then
#             # Append the missing rule to the variable missing_rules
#             mis_rules+="$lpn\n"
#             # Set the flag to indicate a missing rule is found
#             found_missing_rule=true
#         fi
#     done
    
#     # Check if any missing rule is found
#     if ! "$found_missing_rule"; then
#         # If no missing rule is found, print an "Audit PASS" message
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw firewall rules exist for all open ports]\n"
#     else
#         # If any missing rule is found, print an "Audit FAIL" message
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw firewall rules exist for all open ports]"
#         echo -e "\nPorts missing Rules:\n"
#         echo -e "$mis_rules" | while IFS= read -r line; do echo "$line"; done
#     fi
# }






# ############################################################### 3.5.1.7 Ensure ufw default deny firewall policy #####################################################################





# # Define a function to verify default UFW policies
# function ufw_deny_policies {
#     # Run the ufw status verbose command and filter for lines containing "Default:"
#     default_policies=$(ufw status verbose | grep Default:)

#     # Check if the default policies are set to deny for incoming, outgoing, and routed traffic
#     if echo "$default_policies" | grep -q "Default: deny (incoming), deny (outgoing), disabled (routed)"; then
#         echo -e "\n\e[32mAudit PASS\e[0m [Name - Ensure ufw default deny firewall policy]\n"
#     else
#         echo -e "\n\e[91mAudit FAIL\e[0m [Name - Ensure ufw default deny firewall policy]\n"
#     fi
# }






# # ############################################################################################################################################

IPv6_status 
wireless_int_check 
packet_re_send
ip_forwrd_dis
source_rt_pac       
icmp_redirect
sec_icmp_redirect   
packt_log           
brodcst_icmp   
bogus_icmp        
rvrs_path_filtr   
tcp_syn_cookies   
IPv6_router_ad    
dccp_disbl
sctp_disbl
rds_disbl
tipc_disbl
    
nftabls_install
ufw_status
iptabl_flush     
nftabl_exist     
base_chains_exist
loopback_int
est_connections       
nft_deny_polic 
nftables_enabled         
nft_ruls_perme

