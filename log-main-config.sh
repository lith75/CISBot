#!/bin/bash
source configure-log.sh

#####Importing configure scripts#####

configure-auditd            
add_grub_options
set_audit_parameters
configure-audit-rules
configure-changes-sudo-log-file #4.1.3.3
configure-modify-datetime-logged #4.1.3.4
configure-privileged-command-logs #4.1.3.6
configure-audit-file-access-attempts #4.1.3.7
configure-audit-modify-user-group-information  #4.1.3.8
configure-audit-dac-permission-modification #4.1.3.9
configure-audit-file-system-mounts #4.1.3.10
configure-audit-session-initiation #4.1.3.11
configure-audit-login-logout #4.1.3.12
configure-audit-file-deletion #4.1.3.13
config-audit-modify-mac #4.1.3.14
config-audit-chcon-usage-attempts #4.1.3.15
config-audit-setfacl-usage-attempts #4.1.3.16
config-audit-chacl-usage-attempts #4.1.3.17
config-audit-usermod-usage-attempts #4.1.3.18
config-audit-kernel-module-changes #4.1.3.19
config-audit-immutable #4.1.3.20
config-audit-running-ondisk #4.1.3.21
config-permission-log-files #4.1.4.1
config-audit-log-file-owner #4.1.4.2
config-audit-group-ownership #4.1.4.3
config-audit-log-directory-restriction #4.1.4.4
config-audit-config-file #4.1.4.5
config-audit-config-files-owned-by-root #4.1.4.6
config-audit-config-files-owned-group-root #4.1.4.7
config-restriction-audit-tools #4.1.4.8
configure-audit-tools-owned-root #4.1.4.9
configure-audit-tools-group-root #4.1.4.10
configure-cryptographic-mechanisms-audit-tools #4.1.4.11
install-systemd-journal-remote #4.2.1.1.1
config-reject-remote-logs-journald #4.2.1.1.4
config-compress-large-log-files #4.2.1.3
config-journald-write-persistant-disk #4.2.1.4
config-journald-restrict-sending-to-rsyslog #4.2.1.5
remediate_logfiles_permissions_ownership #4.2.3