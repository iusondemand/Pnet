import socket
import subprocess
import json
from typing import List, Dict
import requests  # For public IP lookup
import platform

def get_hostname() -> str:
    """Get the current hostname."""
    return socket.gethostname()

def get_ip_addresses() -> Dict[str, List[str]]:
    """Fetch IPv4 and IPv6 addresses for the hostname."""
    hostname = get_hostname()
    
    ipv4_addresses = []
    try:
        host_info = socket.gethostbyname_ex(hostname)
        if host_info[2]:  # Address list
            for addr in host_info[2]:
                if ':' not in addr:  # Exclude IPv6
                    ipv4_addresses.append(addr)
    except socket.gaierror:
        pass
    
    ipv6_addresses = []
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr_info in addrs:
            if addr_info[0] == socket.AF_INET6:  # IPv6
                ipv6_addresses.append(addr_info[4][0])
    except Exception:
        pass
    
    return {'ipv4': ipv4_addresses, 'ipv6': ipv6_addresses}

def get_public_ip() -> str:
    """Get the public IPv4 address (via api.ipify.org)."""
    try:
        response = requests.get('https://api.ipify.org?format=json')
        data = response.json()
        return data['ip']
    except Exception:
        return None

def get_isp_from_ip(ip: str) -> str:
    """Use ipinfo.io API to fetch ISP info based on public IP."""
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        return data.get('org', 'ISP info unavailable').split(',')[0].strip()
    except Exception:
        return 'ISP info unavailable'

def traceroute(destination: str, max_hops: int = 30) -> List[Dict]:
    """
    Perform a traceroute to a destination and return hop information.
    
    Args:
        destination (str): The target hostname or IP address.
        max_hops (int): Maximum number of hops to trace (default: 30).
    
    Returns:
        List[Dict]: List of hop information containing hop number, IP, and hostname.
    """
    os_type = platform.system().lower()
    hops = []
    
    try:
        if os_type == 'windows':
            cmd = ['tracert', '-h', str(max_hops), destination]
        else:
            cmd = ['traceroute', '-m', str(max_hops), destination]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            
            # Parse hop information
            hop_data = {'raw': line}
            
            if os_type == 'windows':
                # Windows tracert format: "1    <1 ms    <1 ms    <1 ms    example.com [192.168.1.1]"
                parts = line.split()
                if parts and parts[0].isdigit():
                    hop_data['hop'] = int(parts[0])
                    # Try to extract IP and hostname
                    for part in parts:
                        if '[' in part and ']' in part:
                            hop_data['ip'] = part.strip('[]')
                        elif '.' in part and all(c.isdigit() or c == '.' for c in part):
                            hop_data['ip'] = part
            else:
                # Unix traceroute format: "1  router.local (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms"
                parts = line.split()
                if parts and parts[0].isdigit():
                    hop_data['hop'] = int(parts[0])
                    if len(parts) > 1:
                        hop_data['host'] = parts[1]
                    # Extract IP from parentheses
                    if '(' in line and ')' in line:
                        start = line.index('(') + 1
                        end = line.index(')')
                        hop_data['ip'] = line[start:end]
            
            hops.append(hop_data)
        
        process.wait()
    
    except Exception as e:
        return [{'error': f"Error running traceroute: {e}"}]
    
    return hops

def do_traceroute(destination='cyberkit.it') -> str:
    """Perform traceroute (Windows: tracert, Others: traceroute)."""
    os_type = platform.system().lower()
    cmd = ['traceroute'] if os_type != 'windows' else ['tracert']
    cmd.extend([destination])
    
    result = ""
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            line = process.stdout.readline()
            if not line:
                break
            result += line
        process.wait()
    except Exception as e:
        result = f"Error running traceroute: {e}"
    
    return result.strip()

def get_dns_servers() -> List[str]:
    """
    Get currently used DNS servers, optimized for Win11 (uses modern commands).
    Returns a list of DNS server IPs.
    """
    os_type = platform.system().lower()
    dns_servers = []
    
    if os_type == 'windows':
        try:
            # Try netsh (modern method for Win11)
            output = subprocess.check_output(
                ['netsh', 'interface', 'show', 'dns'],
                text=True
            )
            
            # Fallback to ipconfig /all if netsh doesn't work
            if not dns_servers:
                output = subprocess.check_output(
                    ['ipconfig', '/all'],
                    text=True
                )
                
                # Parse DNS Servers from ipconfig /all
                lines = output.split('\n')
                for line in lines:
                    if 'DNS Servers' in line:
                        parts = [part.strip() for part in line.split(':')[1].split()]
                        for part in parts:
                            if part.replace('.', '', 3).isdigit():  # Check if it's an IP
                                dns_servers.append(part)
                        break
        
        except Exception:
            dns_servers = ['DNS info unavailable (Win11)']
    
    elif os_type == 'darwin' or os_type == 'linux':
        # Keep existing logic for macOS/Linux
        try:
            if os_type == 'darwin':
                output = subprocess.check_output(
                    ['scutil', '--dns'],
                    text=True
                )
                lines = output.split('\n')
                for line in lines:
                    if 'nameserver' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            dns_servers.append(parts[1])
            
            elif os_type == 'linux':
                with open('/etc/resolv.conf') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if line.startswith('nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_servers.append(parts[1])
        
        except Exception:
            dns_servers = ['DNS info unavailable (macOS/Linux)']
    
    return dns_servers

def get_connections_outside_ports_80_https(max_count=100) -> List[str]:
    """Fetch active network connections and filter those not using ports 80/443 (HTTP/HTTPS)."""
    os_type = platform.system().lower()
    connections = []
    
    if os_type == 'windows':
        try:
            output = subprocess.check_output(
                ['netstat', '-ano'],
                text=True
            )
            lines = output.split('\n')[1:]  # Skip header
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    local_port = parts[3].split(':')[1] if ':' in parts[3] else parts[3]
                    remote_host = parts[2] if len(parts) > 2 else 'N/A'
                    if local_port not in ('80', '443') and local_port.isdigit():
                        connections.append(f"{parts[0]} {local_port} {remote_host}")
                        if len(connections) >= max_count:
                            break
        except Exception:
            connections = ['Connection history unavailable (Windows)']
    
    elif os_type == 'darwin' or os_type == 'linux':
        try:
            output = subprocess.check_output(
                ['ss', '-tan'],
                text=True
            )
            lines = output.split('\n')[1:]  # Skip header
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    local_port = parts[3].split(':')[1] if ':' in parts[3] else parts[3]
                    remote_host = parts[2] if len(parts) > 2 else 'N/A'
                    if local_port not in ('80', '443') and local_port.isdigit():
                        connections.append(f"{parts[0]} {local_port} {remote_host}")
                        if len(connections) >= max_count:
                            break
        except Exception:
            connections = ['Connection history unavailable (macOS/Linux)']
    
    return connections[:max_count]

def get_ipconfig_all() -> str:
    """
    Generate detailed network configuration output similar to 'ipconfig /all'.
    Works cross-platform and returns comprehensive network interface information.
    
    Returns:
        str: Formatted network configuration details.
    """
    os_type = platform.system().lower()
    output = []
    
    try:
        # Get all network interfaces
        import netifaces
        
        output.append("\n" + "=" * 70)
        output.append("Network Configuration - All Adapters")
        output.append("=" * 70 + "\n")
        
        interfaces = netifaces.interfaces()
        
        for iface in interfaces:
            output.append(f"\nAdapter: {iface}")
            output.append("-" * 70)
            
            try:
                addr_info = netifaces.ifaddresses(iface)
                
                # MAC Address (Link layer)
                if netifaces.AF_LINK in addr_info:
                    mac_info = addr_info[netifaces.AF_LINK][0]
                    output.append(f"  MAC Address: {mac_info.get('addr', 'N/A')}")
                
                # IPv4 Information
                if netifaces.AF_INET in addr_info:
                    for ipv4 in addr_info[netifaces.AF_INET]:
                        output.append(f"\n  IPv4 Address: {ipv4.get('addr', 'N/A')}")
                        output.append(f"  Subnet Mask: {ipv4.get('netmask', 'N/A')}")
                        if 'broadcast' in ipv4:
                            output.append(f"  Broadcast Address: {ipv4.get('broadcast', 'N/A')}")
                else:
                    output.append(f"  IPv4 Address: (No IPv4 configured)")
                
                # IPv6 Information
                if netifaces.AF_INET6 in addr_info:
                    for ipv6 in addr_info[netifaces.AF_INET6]:
                        ipv6_addr = ipv6.get('addr', 'N/A')
                        # Remove scope ID if present
                        if '%' in ipv6_addr:
                            ipv6_addr = ipv6_addr.split('%')[0]
                        output.append(f"\n  IPv6 Address: {ipv6_addr}")
                        output.append(f"  IPv6 Netmask: {ipv6.get('netmask', 'N/A')}")
                
            except Exception as e:
                output.append(f"  Error reading interface info: {e}")
        
        # Gateway information
        output.append("\n" + "=" * 70)
        output.append("Gateway Information")
        output.append("=" * 70)
        
        gateways = netifaces.gateways()
        if gateways.get('default'):
            for af, (gateway, iface) in gateways.get('default', {}).items():
                if af == netifaces.AF_INET:
                    output.append(f"Default Gateway (IPv4): {gateway} (via {iface})")
                elif af == netifaces.AF_INET6:
                    output.append(f"Default Gateway (IPv6): {gateway} (via {iface})")
        
        # DNS Information
        output.append("\n" + "=" * 70)
        output.append("DNS Server Information")
        output.append("=" * 70)
        
        dns_servers = get_dns_servers()
        if dns_servers and dns_servers[0] != 'DNS info unavailable (Win11)' and dns_servers[0] != 'DNS info unavailable (macOS/Linux)':
            for i, dns in enumerate(dns_servers, 1):
                output.append(f"DNS Server {i}: {dns}")
        else:
            output.append("DNS Servers: Could not retrieve")
        
        output.append("\n" + "=" * 70 + "\n")
        
        return "\n".join(output)
    
    except ImportError:
        # Fallback if netifaces is not installed
        return get_ipconfig_all_fallback()

def get_ipconfig_all_fallback() -> str:
    """
    Fallback function when netifaces is not available.
    Uses system commands to gather network information.
    """
    os_type = platform.system().lower()
    output = []
    
    try:
        output.append("\n" + "=" * 70)
        output.append("Network Configuration - All Adapters (System Command)")
        output.append("=" * 70 + "\n")
        
        if os_type == 'windows':
            result = subprocess.check_output(['ipconfig', '/all'], stderr=subprocess.DEVNULL, text=False)
            output.append(result.decode('utf-8', errors='replace'))
        
        elif os_type == 'darwin':
            # macOS
            result = subprocess.check_output(['ifconfig'], stderr=subprocess.DEVNULL, text=False)
            output.append(result.decode('utf-8', errors='replace'))
        
        elif os_type == 'linux':
            # Linux - try multiple commands
            try:
                result = subprocess.check_output(['ip', 'addr', 'show'], stderr=subprocess.DEVNULL, text=False)
                output.append("=== IP Address Configuration ===\n")
                output.append(result.decode('utf-8', errors='replace'))
            except:
                pass
            
            try:
                result = subprocess.check_output(['ip', 'route', 'show'], stderr=subprocess.DEVNULL, text=False)
                output.append("\n=== Routing Information ===\n")
                output.append(result.decode('utf-8', errors='replace'))
            except:
                pass
            
            try:
                result = subprocess.check_output(['cat', '/etc/resolv.conf'], stderr=subprocess.DEVNULL, text=False)
                output.append("\n=== DNS Configuration ===\n")
                output.append(result.decode('utf-8', errors='replace'))
            except:
                pass
        
        output.append("\n" + "=" * 70 + "\n")
        return "\n".join(output)
    
    except Exception as e:
        return f"Failed to retrieve network configuration: {e}"

def main():
    print("")
    print("=== Pnet v1.2 - @IusOnDemand srl 2025 - GPL => 3.0 ===")
    print("List some infos on your connections")
    print("")
    print("=== Network Information ===")
    
    # Hostname
    hostname = get_hostname()
    print(f"Hostname: {hostname}")
    
    # IP Addresses
    ips = get_ip_addresses()
    print("\nIP Addresses:")
    print(f"  IPv4: {ips['ipv4'] or ['None']}")  # Empty list means none found
    print(f"  IPv6: {ips['ipv6'] or ['None']}")
    
    # Public IP and ISP (using external API for ISP)
    public_ip = get_public_ip()
    if public_ip:
        isp = get_isp_from_ip(public_ip)
        print(f"\nPublic IP (IPv4): {public_ip}")
        print(f"ISP Name: {isp}")
    else:
        print("\nCould not retrieve public IP.")
    
    # DNS Servers Report
    print("\n=== Current DNS Servers ===")
    dns_servers = get_dns_servers()
    if isinstance(dns_servers, list):
        print(f"  Found {len(dns_servers)} DNS servers: {', '.join(dns_servers)}")
    else:
        print(dns_servers)
    
    # IPConfig All Output
    print("\n=== IPConfig /all Output ===")
    ipconfig_output = get_ipconfig_all()
    print(ipconfig_output)
    
    # Traceroute
    print("\n=== Traceroute to cyberkit.it ===")
    trace_result = do_traceroute()
    print(trace_result)
    
    # Connection History Outside Ports 80/443
    print("\n=== Active Connections Outside Ports 80/443 (Last 100) ===")
    connections = get_connections_outside_ports_80_https(100)
    if isinstance(connections, list):
        if connections[0] == 'Connection history unavailable':
            print(connections[0])
        else:
            print(f"Found {len(connections)} connections:")
            for conn in connections:
                print(conn)
    else:
        print(connections)

if __name__ == "__main__":
    main()
    
    print("")
    print("=== Pnet v1.2 - @IusOnDemand srl 2025 - GPL => 3.0 ===")
    print("List some infos on your connections")
    print("")
    print("=== Network Information ===")
