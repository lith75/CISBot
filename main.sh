#!/bin/bash

LOG_AUDIT="./log-main-audit.sh"
LOG_CONFIG="./log-main-config.sh"
INITIAL_AUDIT="./initial-setup-main-audit.sh"
INITIAL_CONFIG="./initial-setup-main-config.sh"
SERVICES_AUDIT="./services-main-audit.sh"
SERVICES_CONFIG="./services-main-config.sh"
NETWORK_AUDIT="./network-audit.sh"
NETWORK_CONFIG="./network-config.sh"
RUN_ROLLBACK="./rollback-main.sh"
INSTALLATION="./installation-main.sh"
SYS_CONFIG_AUDIT='./system-maintenance-audit.sh'
SYS_CONFIG_CONFIG='./system-maintenance-config.sh'
OTHER_CONFIG='other-config.sh'


# Defining functions to execute the scripts

function execute_log_audit() {
    echo "executing Audit Log Script...."
    bash "$LOG_AUDIT"
}

function execute_log_config() {
    echo "executing Config Log Script...."
    bash "$LOG_CONFIG"
}

function execute_initial_audit() {
    echo "executing Initial Audit Script...."
    bash "$INITIAL_AUDIT"
}

function execute_initial_config() {
    echo "executing Initial Config Script...."
    bash "$INITIAL_CONFIG"
}

function execute_services_audit() {
    echo "executing Audit Services Script...."
    bash "$SERVICES_AUDIT"
}

function execute_services_config() {
    echo "executing Config Services Script...."
    bash "$SERVICES_CONFIG"
}

function execute_network_audit() {
    echo "executing Audit network Script...."
    bash "$NETWORK_AUDIT"
}

function execute_network_config() {
    echo "execute Config network Script...."
    bash "$NETWORK_CONFIG"
}

function execute_system_maintenance_audit() {
    echo "executing Audit system maintenance...."
    bash "$SYS_CONFIG_AUDIT"
}

function execute_system_maintenance_config() {
    echo "execute Config system maintenance...."
    bash "$SYS_CONFIG_CONFIG"
}

function displayhelp() {
    cat help.txt /n
}

function setrollback () {
    timeshift --create --comments "CISRestorePoint"
}

function execute_run_rollback() {
    echo "execute Run rolback Script...."
    bash "$RUN_ROLLBACK"
}

function execute_installation() {
    echo "execute Installation script...."
    bash "$INSTALLATION"
    echo "Installation Complete."
}

function report_back() {
    mkdir -p results && cd results
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
        audit_passed=$(grep -Eio "Audit Passed|Audit:.*PASS|Audit PASS" "$filename" | wc -l)
        audit_failed=$(grep -Eio "Audit Failed|Audit:.*FAIL|Audit FAIL" "$filename" | wc -l)
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
}

function execute_other_scripts(){
    while true; do
    echo "WARNING: EXECUTING THESE SCRIPTS MAY AFFECT YOUR SYSTEM STABILITY! do you want to proceed?"
    read $choice
    case $choice in 
        [yY])
            bash "$OTHER_CONFIG"
            break
            ;;
        [nN])
            echo "Execution of script cancelled by user. Quitting..."
            break
            ;;
        *)
            echo "Invalid Input. Enter (Y/N)"
            ;;
    esac
    done

}

# Check if the script is not being run as root
if [ "$EUID" -ne 0 ]; then
    echo "Script is not running as root."
else
    mkdir -p results
    # Process command line options
    while getopts "lLiIsSnNmMhrRxzo" opt; do
        case $opt in
            l)
                execute_log_audit >> 'results/log-audit-results.txt'
                ;;
            L)
                execute_log_config                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            te_log_config
                ;;
            i)
                execute_initial_audit >> 'results/initial-audit-results.txt'
                ;;
            I)
                execute_initial_config
                ;;
            s)
                execute_services_audit >> 'results/services-audit-results.txt'
                ;;
            S)
                execute_services_config
                ;;
            n)
                execute_network_audit >> 'results/network-audit-results.txt'
                ;;
            N)
                execute_network_config
                ;;
            m)
                execute_system_maintenance_audit >> 'results/system-maintenance-audit-results.txt'
                ;;
            M)
                execute_system_maintenance_config
                ;;

            h)
                displayhelp
                ;;
            r)
                setrollback
                ;;
            R)
                execute_run_rollback
                ;;
            x)
                execute_installation
                ;;
            z)
                report_back
                ;;
            o)
                execute_other_scripts
                ;;
            \?)
                echo "Invalid Option: -$OPTARG" >&2
                ;;
        esac
    done
fi
