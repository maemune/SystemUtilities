# -*- coding: utf-8 -*-

import sys
import subprocess
import platform
import re
from datetime import datetime
import speedtest
import threading
import os
import ctypes  # For admin check
import win32api  # Requires pywin32
import win32con  # Requires pywin32
import win32event  # Requires pywin32
import win32process  # Requires pywin32

# Suppress bytecode generation
sys.dont_write_bytecode = True

def run_subprocess_command (command, encoding='cp932', errors='ignore'):
    """Execute subprocess command and return stdout/stderr."""
    try:
        # Set encoding for non-Windows OS
        if platform.system ().lower () != "windows":
            encoding = 'utf-8'
            errors = 'replace'

        process = subprocess.run (command, capture_output=True, check=False, text=True, encoding=encoding, errors=errors)
        output = process.stdout
        error_output = process.stderr

        full_output = output
        if error_output and error_output.strip ():
            full_output += f"\n--- Error Output ---\n{error_output.strip ()}"

        if process.returncode != 0:
            full_output += f"\nWarning: Command '{' '.join (command)}' exited with error code {process.returncode}."

        return full_output.strip ()
    except FileNotFoundError:
        return f"Error: Command '{command[0]}' not found. Check your PATH."
    except Exception as e:
        return f"Error: Unexpected error during command '{' '.join (command)}' execution: {e}"

def get_ipconfig_info ():
    """Get ipconfig /all (Windows) or ip a / ifconfig (Linux/macOS) info."""
    result = "--- IP Configuration Information ---\n"
    if platform.system ().lower () == "windows":
        result += run_subprocess_command (['ipconfig', '/all'])
    else:
        result += run_subprocess_command (['ip', 'a']) + "\n"
        result += run_subprocess_command (['ifconfig'])
    return result

def get_interface_link_speed_ps ():
    """Get network interface link speed using OS native commands."""
    result = "--- Link Speed ---\n"
    os_name = platform.system ().lower ()
    if os_name == "windows":
        command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                   "Get-NetAdapter | Format-Table -AutoSize Name, LinkSpeed, Status"]
        result += run_subprocess_command (command)
    elif os_name == "linux":
        result += "For Linux, use 'ethtool <interface>' to check link speed.\n"
        try:
            interfaces_output = run_subprocess_command (['ip', 'link', 'show'])
            interface_names = re.findall (r"\d+: (\w+):", interfaces_output)
            for iface in interface_names:
                if iface != "lo":
                    ethtool_output = run_subprocess_command (['ethtool', iface])
                    result += f"--- {iface} ---\n{ethtool_output}\n"
        except Exception as e:
            result += f"Error: Problem running ethtool or getting interfaces: {e}\n"
    elif os_name == "darwin":  # macOS
        result += "For macOS, use 'networksetup -getinfo <networkservice>' to check link speed.\n"
        try:
            network_services_output = run_subprocess_command (['networksetup', '-listallnetworkservices'])
            service_lines = network_services_output.splitlines ()
            for line in service_lines:
                if "An asterisk" not in line and line.strip ():
                    service_name = line.strip ()
                    if service_name not in ["Bluetooth DUN", "Thunderbolt Bridge"]:
                        info_output = run_subprocess_command (['networksetup', '-getinfo', service_name])
                        link_speed_match = re.search (r"Speed: (\d+)", info_output)
                        if link_speed_match:
                            result += f"Link speed for {service_name}: {link_speed_match.group (1)} Mbps\n"
                        else:
                            result += f"Could not get link speed info for {service_name}.\n{info_output}\n"
        except Exception as e:
            result += f"Error: Problem running networksetup or getting service info: {e}\n"
    else:
        result += "Link speed retrieval is not currently supported on your OS."
    return result

def get_hop_count (target_host="8.8.8.8"):
    """Perform traceroute to target host and return hop count."""
    os_name = platform.system ().lower ()
    command = []
    if os_name == "windows":
        command = ["tracert", "-d", target_host]
    elif os_name == "linux" or os_name == "darwin":
        command = ["traceroute", "-n", "-m", "30", target_host]
    else:
        return f"Error: Traceroute is not supported on your OS ({os_name})."

    result = f"--- Traceroute to {target_host} ---\n"
    output = run_subprocess_command (command)
    result += output

    hop_pattern = re.compile (r"^\s*\d+\s+")
    hop_count = sum (1 for line in output.splitlines () if hop_pattern.match (line))
    result += f"\nHops: {hop_count}"
    return result

def run_speed_test_and_display_results ():
    """Run Speedtest and return results."""
    output_lines = ["--- Speedtest ---"]
    try:
        stest = speedtest.Speedtest ()
        output_lines.append ("Speedtest: Getting server info...")
        print ("Speedtest: Getting server info...")
        stest.get_servers ()
        output_lines.append ("Speedtest: Server info obtained.")

        output_lines.append ("Speedtest: Selecting best server...")
        print ("Speedtest: Selecting best server...")
        stest.get_best_server ()
        server_info = stest.best
        output_lines.append (f"Using server: {server_info['sponsor']} ({server_info['name']}, {server_info['country']})")

        output_lines.append ("Speedtest: Measuring download speed...")
        print ("Speedtest: Measuring download speed...")
        stest.download ()
        output_lines.append ("Speedtest: Download measured.")

        output_lines.append ("Speedtest: Measuring upload speed...")
        print ("Speedtest: Measuring upload speed...")
        stest.upload ()
        output_lines.append ("Speedtest: Upload measured.")

        results_dict = stest.results.dict ()
        down_mbps = results_dict['download'] / 1_000_000
        up_mbps = results_dict['upload'] / 1_000_000
        ping_ms = results_dict['ping']

        final_results = []
        final_results.append (f"Latency (ping): {ping_ms:.2f} ms")
        final_results.append (f"Download: {down_mbps:.2f} Mbps")
        final_results.append (f"Upload: {up_mbps:.2f} Mbps")
        output_lines.extend (final_results)

    except speedtest.SpeedtestException as e:
        output_lines.append (f"Error: Speedtest execution failed: {e}")
    except Exception as e:
        output_lines.append (f"Error: Unexpected error during Speedtest: {e}")
    return "\n".join (output_lines)

def is_admin ():
    """Check if script is running with administrator privileges (Windows only)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin ()
    except:
        return False

def run_as_admin ():
    """Restart current script with administrator privileges (Windows only)."""
    if platform.system ().lower () != "windows":
        print ("Warning: Admin restart supported only on Windows.")
        return False

    if is_admin ():
        return True

    script = os.path.abspath (sys.argv[0])
    params = " ".join ([script] + sys.argv[1:])

    try:
        win32api.ShellExecute (
            0,
            "runas",
            sys.executable,
            params,
            os.path.dirname (script),
            win32con.SW_SHOWNORMAL
        )
        sys.exit (0)
    except Exception as e:
        print (f"Error: Failed to restart as admin: {e}")
        return False

def get_network_adapter_names ():
    """Get active network adapter names on Windows."""
    command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name"]
    output = run_subprocess_command (command)
    if "エラー" in output: # This check might need adjustment if error output is in English
        return []
    return [line.strip () for line in output.splitlines () if line.strip ()]

def get_current_dns_servers (adapter_name):
    """Get current DNS servers for a specified adapter."""
    command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               f"(Get-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -AddressFamily IPv4).ServerAddresses"]
    output = run_subprocess_command (command)
    if "エラー" in output: # This check might need adjustment if error output is in English
        return []
    return [addr.strip () for addr in output.splitlines () if re.match (r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr.strip ())]

def set_dns_servers (adapter_name, primary_dns, secondary_dns):
    """Set DNS servers for a specified adapter."""
    print (f"Setting DNS servers for [{adapter_name}] to {primary_dns} (primary), {secondary_dns} (secondary)...")
    command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               f"Set-DnsClientServerAddress -InterfaceAlias '{adapter_name}' -ServerAddresses ('{primary_dns}', '{secondary_dns}')"]
    output = run_subprocess_command (command)
    if "警告" in output or "エラー" in output: # This check might need adjustment if error output is in English
        print (f"Warning/Error: Problem setting DNS for [{adapter_name}]: \n{output}")
        return False
    print (f"Successfully set DNS servers for [{adapter_name}].")
    return True

def manage_dns_settings (preferred_primary="8.8.8.8", preferred_secondary="1.1.1.1"):
    """Manage DNS settings, setting preferred primary and secondary DNS servers."""
    result = "--- DNS Settings Management ---\n"
    if platform.system ().lower () != "windows":
        result += "This feature is currently supported only on Windows.\n"
        return result

    adapters = get_network_adapter_names ()
    if not adapters:
        result += "No active network adapters found.\n"
        return result

    result += f"Target DNS servers: Primary={preferred_primary}, Secondary={preferred_secondary}\n"

    for adapter in adapters:
        result += f"\nAdapter: {adapter}\n"
        current_dns = get_current_dns_servers (adapter)
        result += f"Current DNS servers: {', '.join (current_dns) if current_dns else 'Not set'}\n"

        if len (current_dns) < 2 or current_dns[0] != preferred_primary or (len (current_dns) >= 2 and current_dns[1] != preferred_secondary):
            print (f"DNS settings for [{adapter}] differ from target. Attempting to change...")
            success = set_dns_servers (adapter, preferred_primary, preferred_secondary)
            if success:
                result += "DNS servers changed to target settings.\n"
            else:
                result += "Failed to change DNS servers.\n"
        else:
            result += "DNS servers are already at target settings.\n"
    return result

if __name__ == '__main__':
    # Admin privilege elevation logic
    if platform.system ().lower () == "windows":
        if not is_admin ():
            print ("Admin privileges required. Restarting as administrator...")
            if not run_as_admin ():
                print ("Failed to restart as administrator. Exiting program.")
                input ("Press Enter to exit")
                sys.exit (1)
            print ("Running with administrator privileges.")
        else:
            print ("Running with administrator privileges.")

    print ("--- Starting Network Diagnostics (some tasks run in parallel) ---")
    now = datetime.now ()

    # Log file name (created in current working directory)
    log_filename = f"Netcheck{now.strftime ('%y%m%d%H%M')}.log"

    # Set target host from arguments or use default
    default_target_host = "8.8.8.8"
    if len (sys.argv) > 1:
        target_host = sys.argv[1]
        print (f"Traceroute target host set to '{target_host}'.")
    else:
        target_host = default_target_host
        print (f"Traceroute target host is default: '{target_host}'.")

    tasks = {
        "DNS Settings Management": manage_dns_settings,
        "IP Configuration Info": get_ipconfig_info,
        "Link Speed": get_interface_link_speed_ps,
        "Traceroute": lambda: get_hop_count (target_host),
        "Speedtest": run_speed_test_and_display_results
    }

    results = {}
    threads = []

    def worker (name, func):
        print (f"[{name}] Starting...")
        results[name] = func ()
        print (f"[{name}] Completed.")

    # DNS settings management should run before other network tasks
    dns_thread = threading.Thread (target=worker, args=("DNS Settings Management", tasks["DNS Settings Management"]))
    dns_thread.start ()
    dns_thread.join () # Wait for DNS settings to complete

    # Run other tasks in parallel
    for name, func in tasks.items ():
        if name != "DNS Settings Management":
            thread = threading.Thread (target=worker, args=(name, func))
            threads.append (thread)
            thread.start ()

    for thread in threads:
        thread.join ()

    print ("\n--- All diagnostics completed ---")

    # Ensure DNS settings management results are first
    final_output_parts = [results["DNS Settings Management"]] + [results[name] for name in tasks if name != "DNS Settings Management"]
    final_output = "\n\n".join (final_output_parts)

    try:
        # Save log file in the script's directory
        script_dir = os.path.dirname (os.path.abspath (__file__))
        log_filepath = os.path.join (script_dir, log_filename)

        with open (log_filepath, 'w', encoding='utf-8') as f:
            f.write (f"--- Network Diagnostic Results {now.strftime ('%Y-%m-%d %H:%M:%S')} ---\n\n")
            f.write (final_output)
            f.write ("\n\n--- Network Diagnostics Completed ---")
        print (f"\n--- Results saved to {log_filepath} ---")
    except IOError as e:
        print (f"Error: Failed to write log file '{log_filepath}': {e}")

    input ("Press Enter to exit")
