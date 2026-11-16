# Detection Logic & SPL Queries

This file contains the Splunk Processing Language (SPL) queries used to detect the simulated attack.

## 1. SMB Brute Force Detection (Aggregated)
This query identifies brute-force attempts by looking for more than 5 failed logins (EventCode 4625) from the same source IP within a 5-minute window. It excludes machine accounts and SYSTEM to reduce noise.

    index=main sourcetype=WinEventLog:Security EventCode=4625
    | where NOT match(Account_Name, "\$$") AND Account_Name!="SYSTEM"
    | bin _time span=5m
    | stats count AS failed_attempts values(ComputerName) AS targets BY _time, Source_Network_Address, Account_Name
    | where failed_attempts > 5

## 2. Brute Force Success (Correlation)
This query correlates failed logins with a subsequent successful login (EventCode 4624) from the same source IP. This is crucial to determine if the brute force attack was successful.

    index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
    | eval outcome=if(EventCode=4625,"failure","success")
    | stats count(eval(outcome="failure")) AS failures 
            count(eval(outcome="success")) AS successes 
            values(ComputerName) AS target 
            BY Source_Network_Address, Account_Name
    | where failures > 5 AND successes > 0
    | table Source_Network_Address, Account_Name, target, failures, successes

## 3. Post-Exploitation Reconnaissance (Sysmon)
This query leverages Sysmon (EventCode 1) to detect discovery commands executed by the attacker (e.g., whoami, ipconfig). It uses regex to extract the command line from the raw XML data.

    index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" whoami OR "net user" OR ipconfig
    | rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
    | rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
    | table _time, ComputerName, Image, CommandLine