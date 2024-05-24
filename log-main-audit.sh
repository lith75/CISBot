#!/bin/bash

#import of the sources
source audit-log.sh

#####Importing the Audit Functions#####

verify-auditd-installed #4.1.1.1
verify-auditd-enabled
verify-auditd-active
find-grub2
check-backlog-limit
check-data-retention      #4.1.2
check-changes-admin-scope #4.1.3.1

# check-other-user-actions-logged

check-changes-to-sudo-log-file     #4.1.3.3
check-events-modify-date-time-info #4.1.3.4

# check-privileged-commands-logged #4.1.3.6 has to be checked manually

# check-unsuccessful-access-attempt-logged-disk #4.1.3.7
# check-unsuccessful-access-attempt-logged-running #4.1.3.7

check-changes-user-group-information         #4.1.3.8
check-changes-user-group-information-running #4.1.3.8

# check-changes-dac-permission-modification #4.1.3.9 

check-file-system-mounts                   #4.1.3.10
check-audit-session-initiation-information #4.1.3.11
check-audit-login-logout                   #4.1.3.12
check-audit-file-deletion                  #4.1.3.13
check-audit-modify-mac                     #4.1.3.14
check-audit-attempts-chcon-use             #4.1.3.15
check-audit-attempts-setfacl-usage         #4.1.3.16
check-audit-attempts-chacl-usage           #4.1.3.17
check-audit-attempts-usermod-usage         #4.1.3.18
check-audit-kernel-changes-1               #4.1.3.19
check-audit-kernel-changes-2               #4.1.3.19
check-audit-immutable                      #4.1.3.20

# check-audit-running-ondisk #4.1.3.21 NEED TO CHECK WITH DIFFERENT VM LASTLY AFTER ALL CONFIGURATIONS (AUGENRULES --CHECK AND LOAD)

check-audit-log-file-permission           #4.1.4.1
check-audit-log-file-ownership            #4.1.4.2
check-audit-group-ownership               #4.1.4.3
check-audit-log-directory-restricted      #4.1.4.4
check-audit-config-file-restrictions      #4.1.4.5
check-audit-config-owned-by-root          #4.1.4.6
check-audit-config-file-group-root        #4.1.4.7
check-audit-audit-tools-restrictive       #4.1.4.8
check-audit-tools-owned-root              #4.1.4.9
check-audit-tools-group-root              #4.1.4.10
check-cryptographicmechanisms-audit-tools #4.1.4.11
check-systemd-journal-remote-installed    #4.2.1.1.1
journald-restrict-remote-logs             #4.2.1.1.4
check-audit-enable-journald-service       #4.2.1.2
check-audit-journald-compress-check       #4.2.1.3
check-audit-journal-persistent-disk       #4.2.1.4
check-audit-journald-not-rsyslog          #4.2.1.5
check_logfiles_permissions_ownership      #4.2.3
