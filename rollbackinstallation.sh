#!/usr/bin/expect
#expect requires the expect package that needs top be installed in the system for automating processes that require human intervention# Set timeout for waiting for responses
set timeout -1

# Function to restore with "y" responses
proc restore {snapshot} {
    spawn timeshift --restore --snapshot $snapshot
    expect {
        "Press ENTER to continue..." { send "\r"; exp_continue }
        "Re-install GRUB2 bootloader? (recommended) (y/n): " { send "y\r"; exp_continue }
        "Continue with restore?" { send "y\r"; exp_continue }
        "Select GRUB device:" { send "\r"; exp_continue }
        "Enter device name or number (a=Abort):" { send "0\r"; exp_continue }
        eof
    }
}

# Main body
set snapshot [lindex $argv 0]
restore $snapshot
