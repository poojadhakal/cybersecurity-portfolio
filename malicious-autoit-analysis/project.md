# Malicious AutoIT Analysis 

## Project Description

Our organization's Security Operations Center (SOC) detected suspicious activity originating from an AutoIT script embedded in an executable file. AutoIT scripts, typically used for legitimate automation, have increasingly been exploited by attackers to deliver malicious payloads. In this analysis, the goal was to examine the provided executable file, uncover its true behavior, and answer the following questions:

Is the file malicious?
What techniques or payloads are being deployed?
What Indicators of Compromise (IoCs) can be extracted?


## Methodology
The approach consisted of the following key phases:

1. File Acquisition & Preparation

Extracted the file (sample.zip) provided in the location C:\Users\LetsDefend\Desktop\ChallengeFile.
Scanned the file for basic properties such as hashes and metadata.

3. Static Analysis

Used VirusTotal to check the file's reputation, hash details, and vendor detections.
Performed further investigation using Detect It Easy (DIE) to analyze the file structure, determine its type, and identify potential packers or obfuscation techniques.

4. Dynamic Analysis

Executed the file in a controlled environment (sandbox) and monitored behavior using PowerShell scripts to log file interactions, network connections, and processes initiated.
Observed suspicious activity such as file drops, registry changes, or PowerShell abuse.

5. Indicators of Compromise (IoCs) Identification

Extracted relevant artifacts including:
 - File hashes
 - Suspicious strings or commands
 - Network indicators (IP addresses, domains)

5. Findings Validation

Correlated findings across tools and logs to confirm malicious activity.


## Tools Used

1. VirusTotal

For file hash analysis, detection rates, and malware identification by antivirus engines.

2. Detect It Easy (DIE)

Static analysis to check executable type, packing methods, and entropy.

3. PowerShell

Used to observe runtime behavior, extract strings, log file activities, and identify registry/network anomalies.


## Recommendations:

1. Containment: Immediately isolate affected systems and block the IP 192.168.100.10.
2. Mitigation:
 - Remove malicious files and registry keys.
 - Scan for persistence mechanisms on impacted machines.
3. Prevention:
- Monitor PowerShell usage for encoded commands.
- Regularly update antivirus signatures and enable behavioral detection.

By leveraging VirusTotal, Detect It Easy, and PowerShell tools, we successfully identified and analyzed the malicious behavior of the AutoIT script. These findings can be used to update the organization's threat detection mechanisms and strengthen security controls.

