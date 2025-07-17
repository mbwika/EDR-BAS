<h2> EDR (Endpoint Detection and Response): BAS (Breach and Attack Simulation) </h2>

A simple tool to automate the testing of EDR (Microsoft Windows Defender) bypass techniques using PowerShell commands. It generates an interactive HTML report 
and displays Window Defender logs. 
You're free to play around with the payloads (custom_payloads.json) and customize them.

SETUP
Prerequisites for Remote Testing:
WinRM Enabled: Target system must have WinRM enabled and configured
Network Access: Port 5985 (WinRM) must be accessible
Authentication: Appropriate credentials for remote system access
PowerShell Remoting: PowerShell remoting must be enabled on target

EXECUTION
python scripts/edr_test.py                              # Prompts for target IP
python scripts/edr_test.py --target localhost          # Local testing
python scripts/edr_test.py --target 192.168.1.100      # Remote testing
python scripts/edr_test.py --payloads custom.json --target 192.168.1.50
python scripts/edr_test.py --no-logscan --output report.html

<img width="1177" height="987" alt="edr_test_results" src="https://github.com/user-attachments/assets/bdca58e9-5120-4347-aef1-9808308b9ba7" />

<img width="1920" height="1140" alt="edr_vs_code" src="https://github.com/user-attachments/assets/f2ebb9e5-8886-4104-a103-8605ba331e24" />

