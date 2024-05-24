#!/bin/bash


#VARIABLES
USERNAME='fresh' #user account is already set up
PASSWORD='fresh@1234'
IP='192.168.1.5' #local IP used for demo purpose
PORT=22 #Need to change this variable if a different port is being used to listen for SSH  traffic
PATH_TO_LOCAL_DIRECTORY='/home/host/Desktop' #Local path where remotely execute files report back


























##CONSTANTS

#Constants that run functions
INSTALL_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -x'
SET_ROLLBACK_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -r'
ROLLBACK_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -R'
NETWORK_AUDIT_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -n'
NETWORK_CONFIG_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -N'
LOGGING_AUDIT_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -l'
LOGGING_CONFIG_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -L'
INITIAL_SETUP_AUDIT_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -i'
INITIAL_SETUP_CONFIG_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -I'
SERVICES_AUDIT_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -s'
SERVICES_CONFIG_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -S'
SMAINTENANCE_AUDIT_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -m'
SMAINTENANCE_CONFIG_COMMAND='cd /home/'$USERNAME'/CISBOT && sudo ./main.sh -M'
