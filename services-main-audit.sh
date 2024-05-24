#!/bin/bash

source services-audit.sh

#audit functions
sync
x_window_system
avahi_server
cups
dhcp_server
LDAP_server
NFS
DNS_server
FTP_server
HTTP_server
IMAP_and_POP3
samba
HTTP_proxy_server
SNMP
NIS
mail_transfer
rsync_service_installed
rsync_service_inactive
rsync_service_masked
NIS_client
rsh_client
talk_client
telnet_client
LDAP_client
RPC
nonessential_services

