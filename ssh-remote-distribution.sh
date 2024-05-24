#!/bin/bash

source ssh-config.sh

function remote-installation() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "cd /home/$USERNAME/ && mkdir CISBOT"
    scp -r * $USERNAME@$IP:/home/$USERNAME/CISBOT
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$INSTALL_COMMAND"
}

function remote-set-rollback() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$SET_ROLLBACK_COMMAND"
}

function remote-rollback() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$ROLLBACK_COMMAND"
}

function remote-network-audit() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$NETWORK_AUDIT_COMMAND"
}

function remote-network-config(){
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$NETWORK_CONFIG_COMMAND"
}

function remote-logging-audit() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$LOGGING_AUDIT_COMMAND"
}

function remote-logging-config() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$LOGGING_CONFIG_COMMAND"
}

function remote-initial-setup-audit() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$INITIAL_SETUP_AUDIT_COMMAND"
}

function remote-initial-setup-config() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$INITIAL_SETUP_CONFIG_COMMAND"
}

function remote-services-audit() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$SERVICES_AUDIT_COMMAND"
}

function remote-services-config() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$SERVICES_CONFIG_COMMAND"
}


function remote-system-maintenance-audit() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$SMAINTENANCE_AUDIT_COMMAND"
}

function remote-system-maintenance-config() {
    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "$SMAINTENANCE_CONFIG_COMMAND"
}

function remote-report-back() {
    scp -r $USERNAME@$IP:/home/$USERNAME/CISBOT/results $PATH_TO_LOCAL_DIRECTORY
    cd $PATH_TO_LOCAL_DIRECTORY/results
    total_passed=0
    total_failed=0
    filenames=(
        "initial-audit-results.txt"
        "log-audit-results.txt"
        "network-audit-results.txt"
        "services-audit-results.txt"
        "system-maintenance-audit-results.txt"
    )
    for filename in "${filenames[@]}"; do
        echo "Findings: $filename"
        audit_passed=$(grep -Eio "Audit Passed|Audit:.*PASS|Audit PASS" "$PATH_TO_LOCAL_DIRECTORY/results/$filename" | wc -l)
        audit_failed=$(grep -Eio "Audit Failed|Audit:.*FAIL|Audit FAIL" "$PATH_TO_LOCAL_DIRECTORY/results/$filename" | wc -l)
        ((total_passed += audit_passed))
        ((total_failed += audit_failed))
        echo "Audit Passed: $audit_passed"
        echo "Audit Failed: $audit_failed"
    done
    echo "---------------------------------"
    echo "Total passed: $total_passed"
    echo "Total Failed: $total_failed"
    echo "---------------------------------"
    total_scripts=$((total_passed + total_failed))
    cis_compliance=$(awk "BEGIN {printf \"%.2f\", ($total_passed / $total_scripts) * 100}")
    echo 'Remote System '$cis_compliance'% Secure according to standards.'

    sshpass -p $PASSWORD ssh -p $PORT $USERNAME@$IP "cd /home/$USERNAME/CISBOT && sudo rm -r results"
}



while getopts "iacrR" opt; do
    case $opt in
        i)
            remote-installation
            remote-set-rollback
            ;;
        a)
            remote-network-audit
            remote-logging-audit
            remote-initial-setup-audit
            remote-services-audit
            remote-system-maintenance-audit
            ;;
        c)
            remote-network-config
            remote-logging-config
            remote-initial-setup-config
            remote-services-config
            remote-system-maintenance-config
            ;;
        r)
            remote-report-back
            ;;
        R)
            remote-rollback
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            ;;
    esac
done