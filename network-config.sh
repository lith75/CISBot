#!/bin/bash



############################################## 3.1.1 Ensure system is checked to determine if IPv6 is enabled ##################################################################





# Function to disable IPv6 through GRUB2 configuration
function IPv6_status_reme {
    echo -e "\n\e[33mManual process required [Name - Ensure system is checked to determine if IPv6 is enabled]\n\e[0m"
    echo -e "- Edit /etc/default/grub and add ipv6.disable=1 to the GRUB_CMDLINE_LINUX parameters.\n"
    echo -e "- Run update-grub to update the GRUB2 configuration.\n"
}





########################################### 3.1.2 Ensure wireless interfaces are disabled ###################################################################





# Function to disable wireless interfaces
function wireless_int_check_reme {
    # Check if nmcli command is available
    if command -v nmcli >/dev/null 2>&1; then
        # Turn off all radio devices using nmcli
        nmcli radio all off
        echo -e "\n\e[33mRemediation successful [Name - Ensure wireless interfaces are disabled].\n\e[0m"

    else
        # If nmcli is not available, check for wireless interfaces
        if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
            # Get the module names of wireless drivers
            mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
            # Disable each wireless driver by preventing its loading
            for dm in $mname; do
                echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            done
        fi
    fi
}





################################################ 3.2.1 Ensure packet redirect sending is disabled (Automated) ###############################################################################


function packet_re_send_reme {
    # Initialize variables to hold output messages
    l_output=""
    l_output2=""
    
    # Define the parameters to set
    l_parlist="net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0"
    
    # Define search locations for kernel parameter configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    
    # Define the kernel parameter file
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
    
    # Function to set kernel parameters
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }
    
    # Loop through each parameter in the list and call the function to set it
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}






################################################################### 3.2.2 Ensure IP forwarding is disabled ############################################################################################################






function ip_forwrd_dis_reme {

    # Initialize variables to hold output messages
    l_output=""
    l_output2=""

    # Define the parameters to set
    l_parlist="net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0"

    # Define search locations for kernel parameter configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    # Function to set kernel parameters
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Function to check IPv6 status and set parameters accordingly
    IPV6F_CHK() {
        l_ipv6s=""
        # Find the grub file
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi
        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi
        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    # Loop through each parameter in the list and call the function to set it
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done


}





###################################################### 3.3.1 Ensure source routed packets are not accepted ########################################################


function source_rt_pac_reme {

    l_output=""
    l_output2=""
    l_parlist="net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0"
    #l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    KPF() {
        # comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters" sysctl -w "$l_kpname=$l_kpvalue" sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    IPV6F_CHK() {
        l_ipv6s=""
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi
        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi
        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done

           
}





################################################################### 3.3.2 Ensure ICMP redirects are not accepted ###################################################





function icmp_redirect_reme {

    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.conf.all.accept_redirects=0
    net.ipv4.conf.default.accept_redirects=0
    net.ipv6.conf.all.accept_redirects=0
    net.ipv6.conf.default.accept_redirects=0"
    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf
    /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf
    /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/
    {print $2}' /etc/default/ufw)"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Function to check IPv6 settings
    IPV6F_CHK() {
        l_ipv6s=""
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi

        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi

        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        # Check if the parameter is related to IPv6
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done
}






############################################################## 3.3.3 Ensure secure ICMP redirects are not accepted ########################################################################




function sec_icmp_redirect {

    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.conf.default.secure_redirects=0 net.ipv4.conf.all.secure_redirects=0"

    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}






################################################################## 3.3.4 Ensure suspicious packets are logged ###################################################################################






function packt_log_reme {

    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1"
    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"

        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$"$l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"

        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done

}





########################################################## 3.3.5 Ensure broadcast ICMP requests are ignored  ###########################################################################################





function brodcst_icmp_reme {
    # Initialize variables
    l_output=""
    l_output2=""
    # List of parameters to set
    l_parlist="net.ipv4.icmp_echo_ignore_broadcasts=1"
    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"
    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}




############################################################################# 3.3.6 Ensure bogus ICMP responses are ignored #################################################################################





function bogus_icmp_reme {
    # Function to set the parameter in sysctl.conf or a file in sysctl.d
    set_sysctl_parameter() {
        local parameter="$1"
        local value="$2"
        local file="/etc/sysctl.conf"

        # Check if sysctl.d directory exists
        if [ -d "/etc/sysctl.d" ]; then
            # Find the latest file in sysctl.d
            local latest_file=$(ls -1 /etc/sysctl.d/ | grep -E '^[0-9]+.*\.conf$' | sort -r | head -n 1)
            if [ -n "$latest_file" ]; then
                file="/etc/sysctl.d/$latest_file"
            fi
        fi

        # Check if parameter already exists in the file
        if grep -q "^$parameter" "$file"; then
            # Parameter exists, update its value
            sed -i "s/^$parameter.*/$parameter = $value/" "$file"
        else
            # Parameter doesn't exist, append it to the file
            echo "$parameter = $value" >> "$file"
        fi
    }

    # Set the parameter in sysctl.conf or sysctl.d
    set_sysctl_parameter "net.ipv4.icmp_ignore_bogus_error_responses" "1"

    # Apply the active kernel parameters
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl -w net.ipv4.route.flush=1

    echo "Remediation complete."

}


############################################################################# 3.3.7 Ensure Reverse Path Filtering is enabled ###############################################################################






function rvrs_path_filtr_reme {

    # Initialize variables to store output
    l_output=""
    l_output2=""

    # List of kernel parameters to set
    l_parlist="net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"

    # Locations to search for sysctl configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    # File to store kernel parameter settings
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to handle kernel parameter setting
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through each parameter in the list and call KPF function
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done

}





############################################################################### 3.3.8 Ensure TCP SYN Cookies is enabled  ###################################################################################



function tcp_syn_cookies_reme {

    # Initialize variables
    l_output=""
    l_output2=""

    # List of kernel parameters to be configured
    l_parlist="net.ipv4.tcp_syncookies=1"

    # Locations to search for kernel parameter configuration files
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    # File to write kernel parameter configurations to
    l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"

    # Function to update kernel parameter configurations
    KPF() {
        # Comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    # Loop through the list of kernel parameters
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        KPF
    done
}





####################################################################### 3.3.9 Ensure IPv6 router advertisements are not accepted #############################################################################################





function IPv6_router_ad_reme {
    #!/bin/bash

    # Initialize variables
    l_output=""
    l_output2=""
    l_parlist="net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0"
    l_searchloc="/run/sysctl.d/*.conf /etc/sysctl.d/*.conf/usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf/etc/sysctl.conf $([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/{print $2}' /etc/default/ufw)"

    KPF() {
        # Function to comment out incorrect parameter(s) in kernel parameter file(s)
        l_fafile="$(grep -s -- "^\s*$l_kpname" $l_searchloc | grep -Pv -- "\h*=\h*$l_kpvalue\b\h*" | awk -F: '{print $1}')"
        for l_bkpf in $l_fafile; do
            echo -e "\n - Commenting out \"$l_kpname\" in \"$l_bkpf\""
            sed -ri "/$l_kpname/s/^/# /" "$l_bkpf"
        done
        
        # Set correct parameter in a kernel parameter file
        if ! grep -Pslq -- "^\h*$l_kpname\h*=\h*$l_kpvalue\b\h*(#.*)?$" $l_searchloc; then
            echo -e "\n - Setting \"$l_kpname\" to \"$l_kpvalue\" in \"$l_kpfile\""
            echo "$l_kpname = $l_kpvalue" >> "$l_kpfile"
        fi
        
        # Set correct parameter in active kernel parameters
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"
        if [ "$l_krp" != "$l_kpvalue" ]; then
            echo -e "\n - Updating \"$l_kpname\" to \"$l_kpvalue\" in the active kernel parameters"
            sysctl -w "$l_kpname=$l_kpvalue"
            sysctl -w "$(awk -F'.' '{print $1"."$2".route.flush=1"}' <<< "$l_kpname")"
        fi
    }

    IPV6F_CHK() {
        # Function to check IPv6 settings
        l_ipv6s=""
        grubfile=$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl -- '^\h*(kernelopts=|linux|kernel)' {} \;)
        if [ -s "$grubfile" ]; then
            ! grep -P -- "^\h*(kernelopts=|linux|kernel)" "$grubfile" | grep -vq -- ipv6.disable=1 && l_ipv6s="disabled"
        fi

        if grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$" $l_searchloc && \
        sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\h*(#.*)?$" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\h*(#.*)?$"; then
            l_ipv6s="disabled"
        fi

        if [ -n "$l_ipv6s" ]; then
            echo -e "\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            KPF
        fi
    }

    # Loop through each parameter in the parameter list
    for l_kpe in $l_parlist; do
        l_kpname="$(awk -F= '{print $1}' <<< "$l_kpe")"
        l_kpvalue="$(awk -F= '{print $2}' <<< "$l_kpe")"
        if grep -q '^net.ipv6.' <<< "$l_kpe"; then
            l_kpfile="/etc/sysctl.d/60-netipv6_sysctl.conf"
            IPV6F_CHK
        else
            l_kpfile="/etc/sysctl.d/60-netipv4_sysctl.conf"
            KPF
        fi
    done


}





################################################################################ 3.4.1 Ensure DCCP is disabled ###############################################################################################






function dccp_disbl_reme {


    # Set module name
    l_mname="dccp"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi


}







##################################################################### 3.4.2 Ensure SCTP is disabled  #########################################################################################################




function sctp_disbl_reme {

    # Set module name
    l_mname="sctp"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi

}





########################################################### 3.4.3 Ensure RDS is disabled ###################################################################################




function rds_disbl_reme {

    # Set module name
    l_mname="rds"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""
        modprobe -r "$l_mname"
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
    fi

}





################################################################### 3.4.4 Ensure TIPC is disabled ###################################################################################




function tipc_disbl_reme {
    # Set module name
    l_mname="tipc"

    # Check if module can be loaded
    if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then
        echo -e " - Setting module: \"$l_mname\" to be not loadable"  # Print message indicating that module is set to be not loadable
        echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf  # Set module to be not loadable
    fi

    # Unload the module if it is already loaded
    if lsmod | grep "$l_mname" > /dev/null 2>&1; then
        echo -e " - Unloading module \"$l_mname\""  # Print message indicating unloading of the module
        modprobe -r "$l_mname"  # Unload the module
    fi

    # Check if module is blacklisted
    if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
        echo -e " - Deny listing \"$l_mname\""  # Print message indicating denial of listing for the module
        echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf  # Blacklist the module
    fi

}




# 


####################################################################################################################################################################################
####################################################################################################################################################################################
############################################################################  nftables configuration ##########################################################



# Function to save the provided nftables rules into the /etc/nftables.rules file and enable them
function nftables_conf {

    #install nfatbles
    apt install nftables
    #disable ufw
    ufw disable
    #flush iptables
    iptables -F
    #flush ip6tables
    ip6tables -F

    # write the nftables rules into a file
    cat << EOF > /etc/nftables.rules
#!/sbin/nft -f
# This nftables.rules config should be saved as /etc/nftables.rules

# Flush nftables ruleset
flush ruleset

# Load nftables ruleset
# nftables config with inet table named filter
table inet filter {

    # Base chain for input hook named input (Filters inbound network packets)
    chain input {
        type filter hook input priority 0; policy drop;

        # Ensure loopback traffic is configured
        iif "lo" accept
        ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop
        ip6 saddr ::1 counter packets 0 bytes 0 drop

        # Ensure established connections are configured
        ip protocol tcp ct state established accept
        ip protocol udp ct state established accept
        ip protocol icmp ct state established accept

        # Accept port 22(SSH) traffic from anywhere
        tcp dport ssh accept

        # Accept ICMP and IGMP from anywhere
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, ind-neighbor-solicit, ind-neighbor-advert, mld2-listener-report } accept
        icmp type { destination-unreachable, router-advertisement, router-solicitation, time-exceeded, parameter-problem } accept
        ip protocol igmp accept
    }

    # Base chain for hook forward named forward (Filters forwarded network packets)
    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    # Base chain for hook output named output (Filters outbound network packets)
    chain output {
        type filter hook output priority 0; policy drop;

        # Ensure outbound and established connections are configured
        ip protocol tcp ct state established,related,new accept
        ip protocol udp ct state established,related,new accept
        ip protocol icmp ct state established,related,new accept
    }
}
EOF

    # load the file into nftables
    nft -f /etc/nftables.rules
    # create the nftables.rules file
    nft list ruleset > /etc/nftables.rules
    # Add the following line to /etc/nftables.conf
    echo 'include "/etc/nftables.rules"' | sudo tee -a /etc/nftables.conf > /dev/null
    # enable the nftables service
    systemctl enable nftables

}














# ####################################################################################################################################################################################
# ####################################################################################################################################################################################
# ####################################################################################################################################################################################
# ################################################################### ufw configuration #########################################################################################



# function ufw_conf {

#     sudo apt update
#     sudo apt install ufw # command to install ufw

#     apt purge iptables-persistent # code to remove iptable persistent package


#     # Unmask the ufw daemon
#     systemctl unmask ufw.service
#     # Enable and start the ufw daemon
#     systemctl --now enable ufw.service
#     # Enable ufw
#     ufw enable


#     # Allow incoming and outgoing traffic on loopback interface
#     ufw allow in on lo
#     ufw allow out on lo
#     # Deny incoming traffic from loopback addresses
#     ufw deny in from 127.0.0.0/8
#     ufw deny in from ::1

#     echo -e "\n\e[33mManual process required [Name - Ensure ufw outbound connections are configured]\n\e[0m"
#     echo -e "\nConfigure ufw in accordance with site policy.\nCurrently all outbound connections on all interfaces will be allowed."
#     ufw allow out on all


#     function mis_firewall_rules_reme {

#         # Store the verbose output of 'ufw status' command in the variable ufw_out
#         ufw_out="$(ufw status verbose)"

#         # Use 'ss' to list all listening TCP and UDP sockets excluding localhost and loopback addresses,
#         # extract the port numbers, sort them, and remove duplicates
#         ports=$(ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/::1/) {split($5, a, ":"); print a[2]}' | sort | uniq)
            
#         mis_rules="" # Empty variable to store missing rules
#         found_missing_rule=false # Initialize a flag to indicate if any missing rule is found

#         # Iterate over each extracted port number
#         for lpn in $ports; do
#             # Check if the port number has a corresponding firewall rule in ufw_out
#             if ! grep -Pq "^\h*$lpn\b" <<< "$ufw_out"; then
#                 # Append the missing rule to the variable missing_rules
#                 mis_rules+="$lpn "
#                 # Set the flag to indicate a missing rule is found
#                 found_missing_rule=true
#             fi
#         done

#         # Split the mis_rules variable by spaces
#         read -r -a ports_array <<< "$mis_rules"

#         # Iterate over each port in the array
#         for port in "${ports_array[@]}"; do
#             # Check if the port is a valid number
#             if [[ "$port" =~ ^[0-9]+$ ]]; then
#                 # Allow traffic on the port using ufw for both TCP and UDP protocols
#                 sudo ufw allow in "$port/tcp"
#                 sudo ufw allow in "$port/udp"
#             else
#                 echo "ERROR: Bad port - $port"
#             fi
#         done


#     }
#     mis_firewall_rules_reme 


#     ufw allow git 
#     ufw allow in http 
#     ufw allow out http 
#     ufw allow in https 
#     ufw allow out https 
#     ufw allow out 53 
#     ufw logging on
#     ufw allow ssh

#     # Set default deny rules for incoming, outgoing, and routed traffic
#     sudo ufw default deny incoming
#     sudo ufw default deny outgoing
#     sudo ufw default deny routed

#     # Enable the UFW firewall
#     sudo ufw enable
# }








####################################################################################################################################################################################
####################################################################################################################################################################################
############################################################################  iptables configuration ##########################################################


# function iptables_softwar_conf {

#     # install iptables and iptables-persistent
#     apt install iptables iptables-persistent

#     # remove nftables
#     apt purge nftables

#     # disable ufw
#     ufw disable 
#     systemctl stop ufw 
#     systemctl mask ufw

# }


# ######################################################################## Configure IPv4 iptables #####################################################################





# function ipv4_tables_conf {

#     # Flush IPtables rules
#     iptables -F

#     # Ensure default deny firewall policy
#     iptables -P INPUT DROP
#     iptables -P OUTPUT DROP
#     iptables -P FORWARD DROP

#     # Ensure loopback traffic is configured
#     iptables -A INPUT -i lo -j ACCEPT
#     iptables -A OUTPUT -o lo -j ACCEPT
#     iptables -A INPUT -s 127.0.0.0/8 -j DROP

#     # Ensure outbound and established connections are configured
#     iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#     iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#     iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#     iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#     iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#     iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

#     # Open inbound ssh(tcp port 22) connections
#     iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT


#     # Get list of open ports with protocol
#     open_ports=$(ss -4tuln | awk '{print $1":"$4":"$5}')

#     # Loop through each open port and protocol
#     for line in $open_ports; do
#     # Extract protocol, port number (local and remote)
#         protocol=$(echo $line | cut -d ':' -f 1)

#         port=$(echo $line | cut -d ':' -f 4)
        
#         # Check firewall rule (unchanged)
#         rule_exists=$(sudo iptables -L INPUT -v -n | grep "dpt:$port" | wc -l)

#         # remidiation
#         if [ $rule_exists -eq 0 ] && [ -n "$port" ]; then
#             iptables -A INPUT -p $protocol --dport $port -m state --state NEW -j ACCEPT
#         fi
    
#     done

# }





# ######################################################################## Configure IPv6 iptables #####################################################################




# function ipv6_tables_conf {

#     # Flush ip6tables rules
#     ip6tables -F

#     # Ensure default deny firewall policy
#     ip6tables -P INPUT DROP
#     ip6tables -P OUTPUT DROP
#     ip6tables -P FORWARD DROP

#     # Ensure loopback traffic is configured
#     ip6tables -A INPUT -i lo -j ACCEPT
#     ip6tables -A OUTPUT -o lo -j ACCEPT
#     ip6tables -A INPUT -s ::1 -j DROP

#     # Ensure outbound and established connections are configured
#     ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
#     ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
#     ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
#     ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
#     ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
#     ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

#     # Open inbound ssh(tcp port 22) connections
#     ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT



#     # Get list of open ports with protocol
#     open_ports=$(ss -6tuln | awk '{print $1":"$4":"$5}')

#     # Loop through each open port and protocol
#     for line in $open_ports; do
#         # Extract protocol, port number (local and remote)
#         protocol=$(echo $line | cut -d ':' -f 1)

#         port=$(echo $line | cut -d ':' -f 6)
        
#         # Check firewall rule (unchanged)
#         rule_exists=$(sudo ip6tables -L INPUT -v -n | grep "dpt:$port" | wc -l)

#         # remidiation
#         if [ $rule_exists -eq 0 ] && [ -n "$port" ]; then 
#             ip6tables -A INPUT -p $protocol --dport $port -m state --state NEW -j ACCEPT
#         fi
    
#     done

# }






IPv6_status_reme 
wireless_int_check_reme
packet_re_send_reme 
ip_forwrd_dis_reme 
source_rt_pac_reme 
icmp_redirect_reme
sec_icmp_redirect  
packt_log_reme    
brodcst_icmp_reme
bogus_icmp_reme    
rvrs_path_filtr_reme  
tcp_syn_cookies_reme   
IPv6_router_ad_reme    
dccp_disbl_reme
sctp_disbl_reme
rds_disbl_reme 
tipc_disbl_reme

nftables_conf
