                                                                                                                                            
TheCISBot

This is a Tool that automates the flow of configuring a ubuntu system to the Center of internet security Benchmarks. The tool can both audit and configure the the system according to these standards




Below flags determine which scripts will be run (what audit/configuration will be done) - The results of the scripts will be saved in the same directory where the tool is being executed.

Flags must be passed as arguments alongside the execution of the tool.

Before Using the tool to harden security make sure that you run the installation process this can simply be done using the -x flag

Flags:

    -i :Audits Initial configuration.
    
    -I :Configures Initial Configuration.
    
    -l :Audits Logging rules.
    
    -L :Configures Logging rules.
    
    -s :Audits services installed and running on the system.
    
    -S :Configures services installed and running on the system.
    
    -n :Audits network configurations on the system.
    
    -N :Configures Network configurations on the system.
    
    -x :Installs necessary dependant packages for the tool and grants file permissions for the necessary scripts.
    
    -h :Displays this help message.
