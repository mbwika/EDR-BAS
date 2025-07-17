
# EDR Bypass Automation Script
# This script automates the testing of EDR bypass techniques using PowerShell commands.
# It automatically reads payloads and MITRE ATT&CK mappings from payloads/custom_payloads.json 
# and generates an interactive HTML report in the reports/ folder.
# Windows Defender log scanning is enabled by default.
# The script prompts for a target IP address to test remote systems via WinRM.

# Usage examples:
# python scripts/edr_test.py                              # Prompts for target IP
# python scripts/edr_test.py --target localhost          # Local testing
# python scripts/edr_test.py --target 192.168.1.100      # Remote testing
# python scripts/edr_test.py --payloads custom.json --target 192.168.1.50
# python scripts/edr_test.py --no-logscan --output report.html

# Prerequisites for Remote Testing:
# WinRM Enabled: Target system must have WinRM enabled and configured
# Network Access: Port 5985 (WinRM) must be accessible
# Authentication: Appropriate credentials for remote system access
# PowerShell Remoting: PowerShell remoting must be enabled on target

import subprocess
import base64
import json
from datetime import datetime
from pathlib import Path
import argparse

# Status constants
STATUS_SUCCESS = "✅ Bypassed"
STATUS_FAILED = "❌ Detected" 
STATUS_TIMEOUT = "⏰ Timeout"
DIV_CLOSE = "</div>"

# PowerShell executable constant
POWERSHELL_EXE = 'powershell.exe'

def load_payloads_from_json(json_path):
    """Load payloads and their MITRE ATT&CK mappings from JSON file"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        payloads = []
        payload_mappings = {}
        
        for item in data.get('payloads', []):
            command = item.get('command', '')
            if command:
                payloads.append(command)
                payload_mappings[command] = {
                    'technique': item.get('technique', ''),
                    'tactic': item.get('tactic', ''),
                    'id': item.get('id', '')
                }
        
        return payloads, payload_mappings
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"❌ Error loading JSON file: {e}")
        return None, None

def get_mitre_technique(payload, payload_mappings=None):
    """Map payload to appropriate MITRE ATT&CK technique with detailed information"""
    if payload_mappings is None:
        payload_mappings = {}

    payload_stripped = payload.strip()

    # Check for exact match first
    if payload_stripped in payload_mappings:
        mapping = payload_mappings[payload_stripped]
        return f"{mapping['id']} - {mapping['technique']} ({mapping['tactic']})"

    return _fallback_mitre_technique(payload)

MITRE_POWERSHELL_EXECUTION = "T1059.001 - Command and Scripting Interpreter: PowerShell (Execution)"

def _fallback_mitre_technique(payload):
    """Helper for fallback pattern matching for MITRE ATT&CK technique mapping"""
    payload_lower = payload.lower()

    if 'start-process calc.exe' in payload_lower:
        return MITRE_POWERSHELL_EXECUTION
    if 'write-output' in payload_lower and 'hello world' in payload_lower:
        return MITRE_POWERSHELL_EXECUTION
    if 'invoke-expression' in payload_lower and '+' in payload:
        return "T1027 - Obfuscated Files or Information (Defense Evasion)"
    if 'start-sleep' in payload_lower:
        return "T1562.006 - Indicator Blocking (Defense Evasion)"
    if 'notepad' in payload_lower and 'start-process' in payload_lower:
        return "T1202 - Indirect Command Execution (Execution)"
    if 'encodedcommand' in payload_lower:
        return "T1027.001 - Obfuscated Files or Information: Command Obfuscation (Defense Evasion)"
    if 'mshta' in payload_lower:
        return "T1218.005 - Signed Binary Proxy Execution: Mshta (Execution)"
    if '+' in payload and 'calc' in payload_lower:
        return "T1027 - Obfuscated Files or Information (Defense Evasion)"
    if 'downloadstring' in payload_lower or 'webclient' in payload_lower:
        return "T1105 - Ingress Tool Transfer (Command and Control)"
    if 'set-alias' in payload_lower:
        return "T1036.003 - Masquerading (Defense Evasion)"
    # Default fallback
    return MITRE_POWERSHELL_EXECUTION

def encode_powershell_command(command):
    return base64.b64encode(command.encode('utf-16le')).decode('utf-8')

def prompt_continue(message):
    choice = input(message).strip().lower()
    return choice in ['y', 'yes']

def test_winrm_connectivity(target_ip):
    test_cmd = f"Test-WsMan -ComputerName {target_ip}"
    try:
        result = subprocess.run([POWERSHELL_EXE, '-Command', test_cmd],
                                capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and 'True' in result.stdout
    except subprocess.TimeoutExpired:
        return None

def validate_ip(target_ip):
    import ipaddress
    if not target_ip:
        print("❌ IP address cannot be empty. Please try again.")
        return None
    if target_ip.lower() == 'localhost':
        print("✅ Target set to localhost (local testing)")
        return 'localhost'
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"❌ Invalid IP address format: {target_ip}. Please try again.")
        return None
    return target_ip

def handle_connectivity(connectivity, target_ip):
    if connectivity is True:
        print(f"✅ Successfully connected to {target_ip}")
        return target_ip
    elif connectivity is None:
        print(f"⚠️  Warning: Connection test to {target_ip} timed out")
        if prompt_continue("Continue anyway? (y/n): "):
            return target_ip
        return None
    else:
        print(f"⚠️  Warning: Could not establish WinRM connection to {target_ip}")
        if prompt_continue("Continue anyway? (y/n): "):
            return target_ip
        return None

def get_validated_ip(target_ip):
    valid_ip = validate_ip(target_ip)
    if not valid_ip or valid_ip == 'localhost':
        return valid_ip
    print(f"🔍 Testing connectivity to {valid_ip}...")
    connectivity = test_winrm_connectivity(valid_ip)
    return handle_connectivity(connectivity, valid_ip)

def get_target_ip():
    """Prompt user for target IP address and validate it"""
    print("\n🎯 Target Configuration")
    print("=" * 50)
    while True:
        target_ip = input("Enter target IP address (or 'localhost' for local testing): ").strip()
        validated_ip = get_validated_ip(target_ip)
        if validated_ip:
            return validated_ip

def run_powershell(encoded_command, target_ip=None):
    if target_ip and target_ip.lower() != 'localhost':
        # Remote execution using Invoke-Command
        remote_cmd = f"Invoke-Command -ComputerName {target_ip} -ScriptBlock {{powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_command}}}"
        cmd = [
            POWERSHELL_EXE,
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-Command', remote_cmd
        ]
    else:
        # Local execution
        cmd = [
            POWERSHELL_EXE,
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', encoded_command
        ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, '', 'Timeout')

def extract_defender_logs(target_ip=None):
    if target_ip and target_ip.lower() != 'localhost':
        # Remote log extraction
        ps_cmd = f"""
        Invoke-Command -ComputerName {target_ip} -ScriptBlock {{
            Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116}} -MaxEvents 10 |
            Select-Object TimeCreated, Message |
            Format-List
        }} -ErrorAction SilentlyContinue
        """
    else:
        # Local log extraction
        ps_cmd = r"""
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; ID=1116} -MaxEvents 10 |
        Select-Object TimeCreated, Message |
        Format-List
        """
    try:
        result = subprocess.run([POWERSHELL_EXE, '-Command', ps_cmd], capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.replace('\n', '<br>')
        else:
            target_info = f" on {target_ip}" if target_ip and target_ip.lower() != 'localhost' else ""
            return f"No recent Windows Defender detection events found{target_info}.<br>This could indicate successful evasion or that Windows Defender is not active."
    except (subprocess.TimeoutExpired, FileNotFoundError):
        target_info = f" on {target_ip}" if target_ip and target_ip.lower() != 'localhost' else ""
        return f"Unable to retrieve Windows Defender logs{target_info}.<br>This may be due to insufficient permissions, Windows Defender not being installed, network connectivity issues, or running on a non-Windows system."

def generate_html_report(results, defender_logs, report_path, target_ip='localhost'):
    total_payloads = len(results)
    successful = sum(1 for r in results if r['status'] == STATUS_SUCCESS)
    failed = sum(1 for r in results if r['status'] == STATUS_FAILED)
    timeout = sum(1 for r in results if r['status'] == STATUS_TIMEOUT)
    
    target_display = "Local System" if target_ip == 'localhost' else f"Target: {target_ip}"
    
    html = [
        """<html>
<head>
    <title>EDR BAS Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 10px; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; border-radius: 8px; min-width: 100px; }
        .success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .failed { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .timeout { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .total { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
        table { width: 100%; max-width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; word-wrap: break-word; overflow-wrap: break-word; }
        th { background-color: #007acc; color: white; position: sticky; top: 0; }
        tr:hover { background-color: #f5f5f5; }
        .payload-cell { width: 45%; max-width: 300px; word-wrap: break-word; font-family: monospace; font-size: 12px; }
        th:nth-child(1), td:nth-child(1) { width: 45%; }
        th:nth-child(2), td:nth-child(2) { width: 12%; }
        th:nth-child(3), td:nth-child(3) { width: 10%; }
        th:nth-child(4), td:nth-child(4) { width: 33%; font-size: 11px; }
        .status-success { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-timeout { color: #ffc107; font-weight: bold; }
        .logs-section { margin-top: 30px; }
        .logs-content { background-color: #f8f9fa; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 12px; }
        .filter-controls { margin: 20px 0; }
        .filter-btn { padding: 8px 15px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .filter-btn.active { background-color: #007acc; color: white; }
        .filter-btn:not(.active) { background-color: #e9ecef; color: #333; }
    </style>
    <script>
        function filterTable(status) {
            const rows = document.querySelectorAll('#resultsTable tbody tr');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update button states
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            rows.forEach(row => {
                if (status === 'all' || row.cells[1].textContent.includes(status)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        function toggleLogs() {
            const logsDiv = document.getElementById('logsSection');
            logsDiv.style.display = logsDiv.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</head>
<body>
    <div class="container">""",
        "<h1>🛡️ EDR Bypass Test Results</h1>",
        f"<p style='text-align: center; color: #666; font-size: 14px;'>Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        f"<p style='text-align: center; color: #007acc; font-size: 16px; font-weight: bold; margin: 10px 0;'>{target_display}</p>",
        
        "<div class='summary'>",
        f"<div class='stat-box total'><h3>{total_payloads}</h3><p>Total Payloads</p>{DIV_CLOSE}",
        f"<div class='stat-box success'><h3>{successful}</h3><p>Successful</p>{DIV_CLOSE}",
        f"<div class='stat-box failed'><h3>{failed}</h3><p>Failed</p>{DIV_CLOSE}",
        f"<div class='stat-box timeout'><h3>{timeout}</h3><p>Timeout</p>{DIV_CLOSE}",
        DIV_CLOSE,
        
        "<div class='filter-controls'>",
        "<strong>Filter Results:</strong>",
        "<button class='filter-btn active' onclick='filterTable(\"all\")'>All</button>",
        "<button class='filter-btn' onclick='filterTable(\"✅ Bypassed\")'>Bypassed</button>",
        "<button class='filter-btn' onclick='filterTable(\"❌ Detected\")'>Detected</button>",
        "<button class='filter-btn' onclick='filterTable(\"⏰ Timeout\")'>Timeout</button>",
        DIV_CLOSE,
        
        "<table id='resultsTable'>",
        "<thead><tr><th>Payload</th><th>Status</th><th>Return Code</th><th>MITRE Details</th></tr></thead>",
        "<tbody>"
    ]

    for r in results:
        status_class = ""
        if r['status'] == STATUS_SUCCESS:
            status_class = "status-success"
        elif r['status'] == STATUS_FAILED:
            status_class = "status-failed"
        elif r['status'] == STATUS_TIMEOUT:
            status_class = "status-timeout"
        
        html.append(f"<tr><td class='payload-cell'>{r['payload']}</td><td class='{status_class}'>{r['status']}</td><td>{r['code']}</td><td style='font-family: monospace; font-weight: bold; color: #007acc;'>{r['mitre_technique']}</td></tr>")

    html.append("</tbody></table>")

    if defender_logs:
        html.append("<div class='logs-section'>")
        html.append("<h2>🔍 Recent Windows Defender Logs <button onclick='toggleLogs()' style='margin-left: 10px; padding: 5px 10px; background-color: #007acc; color: white; border: none; border-radius: 3px; cursor: pointer;'>Toggle</button></h2>")
        html.append(f"<div id='logsSection' class='logs-content'>{defender_logs}{DIV_CLOSE}")
        html.append(f"{DIV_CLOSE}")
    else:
        html.append("<div class='logs-section' style='display: none;'>")
        html.append("<h2>🔍 Windows Defender Logs</h2>")
        html.append(f"<p style='color: #666; font-style: italic;'>Log scanning was disabled. Remove --no-logscan flag to include Windows Defender logs.{DIV_CLOSE}")
        html.append(f"{DIV_CLOSE}")

    html.append(f"{DIV_CLOSE}</body></html>")
    Path(report_path).write_text('\n'.join(html), encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description="EDR Bypass Automation Script")
    parser.add_argument('--payloads', type=str, help='Path to a JSON file with payloads and MITRE mappings (default: payloads/custom_payloads.json)')
    parser.add_argument('--no-logscan', action='store_true', help='Disable Windows Defender log scanning (enabled by default)')
    parser.add_argument('--output', type=str, default='final_report.html', help='Name of the HTML report file (saved in reports folder)')
    parser.add_argument('--target', type=str, help='Target IP address (if not provided, will prompt at runtime)')
    args = parser.parse_args()

    # Get target IP address
    if args.target:
        target_ip = args.target
        print(f"🎯 Using target IP from command line: {target_ip}")
    else:
        target_ip = get_target_ip()

    # Determine the workspace root (assuming script is in scripts/ folder)
    script_dir = Path(__file__).parent
    workspace_root = script_dir.parent
    
    # Load payloads from JSON file by default
    if args.payloads:
        payloads_path = workspace_root / args.payloads
    else:
        payloads_path = workspace_root / 'payloads' / 'custom_payloads.json'
    
    if payloads_path.exists():
        payloads, payload_mappings = load_payloads_from_json(payloads_path)
        if payloads is not None:
            print(f"📂 Loaded {len(payloads)} payloads from {payloads_path}")
        else:
            print(f"⚠️  Failed to load payloads from JSON file: {payloads_path}")
            print("� Using default sample payload")
            payloads = ['Start-Process calc.exe']
            payload_mappings = {}
    else:
        print(f"⚠️  Payloads file not found: {payloads_path}")
        print("🔄 Using default sample payload")
        payloads = ['Start-Process calc.exe']
        payload_mappings = {}

    # Ensure reports directory exists
    reports_dir = workspace_root / 'reports'
    reports_dir.mkdir(exist_ok=True)
    
    # Set output path in reports folder
    output_path = reports_dir / args.output

    results = []
    target_info = f" on {target_ip}" if target_ip != 'localhost' else " locally"
    print(f"🚀 Starting EDR bypass tests{target_info} with {len(payloads)} payload(s)...")
    
    for i, payload in enumerate(payloads, 1):
        print(f"⚡ Testing payload {i}/{len(payloads)}: {payload[:50]}{'...' if len(payload) > 50 else ''}")
        encoded = encode_powershell_command(payload)
        result = run_powershell(encoded, target_ip)
        
        if result.returncode == 0:
            status = STATUS_SUCCESS
        elif result.returncode == -1:
            status = STATUS_TIMEOUT
        else:
            status = STATUS_FAILED
        
        # Get MITRE ATT&CK technique for this payload
        mitre_technique = get_mitre_technique(payload, payload_mappings)
        
        results.append({
            "payload": payload,
            "status": status,
            "code": result.returncode,
            "mitre_technique": mitre_technique
        })

    defender_logs = extract_defender_logs(target_ip) if not args.no_logscan else None
    generate_html_report(results, defender_logs, str(output_path), target_ip)
    print(f"✅ Interactive report generated: {output_path}")

def was_payload_detected(event_log_data, technique_id):
    # Naive match: extend with regex/contextual checks
    if technique_id == 'T1027' and 'ScriptBlock' in event_log_data:
        return "❌ Detected"
    elif technique_id == 'T1105' and 'DownloadString' in event_log_data:
        return "⚠️ Possibly Detected"
    elif technique_id == 'T1036.003':
        return STATUS_SUCCESS
    return STATUS_SUCCESS

if __name__ == '__main__':
    main()
