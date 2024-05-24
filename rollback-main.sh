#!/bin/bash

function restore {
    timeshift --list >> temp.txt
    grep_output=$(grep -e "CISRestorePoint" temp.txt | awk '{print $3}')
    echo $grep_output
    rm temp.txt
    ./rollbackinstallation.sh $grep_output
}


restore
