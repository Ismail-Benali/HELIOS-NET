"""
HELIOS-NET :: Authorized Engagement Runner (strike.py)
Executes authorized attack surface management and route planning against user-specified targets.
Includes comprehensive coverage for Web, Databases, Infrastructure, and Industrial SCADA/ICS protocols.
Defaults to local loopback (127.0.0.1) for safety.
"""

import asyncio
import sys
import argparse
import ipaddress
from modules.discovery.dns_resolver import EliteDNSResolver
from core.async_engine import enterprise_adaptive_recon
from engine.graph.core import AssetGraph
from engine.killchain.pathfinder import KillChainEngine

async def execute_engagement(target: str = "127.0.0.1"):
    print(f"[HELIOS-NET] Initializing authorized engagement orchestration for target: {target}")
    
    # Check if target is already an IP address
    ips = []
    try:
        ipaddress.ip_address(target)
        ips = [target]
        print(f"[+] Target is a direct IP address: {target}")
    except ValueError:
        resolver = EliteDNSResolver()
        ips = await resolver.resolve(target)
        print(f"[+] Resolved target domain to IP addresses: {ips}")
    
    if not ips:
        print("[-] Could not resolve target addresses.")
        return
        
    primary_ip = ips[0]
    print(f"[+] Focusing on primary node: {primary_ip}")
    
    # Expanded port list covering Web, Infrastructure, Databases, and Industrial SCADA/ICS
    ports = [
        # Web & Proxy
        80, 443, 8080, 8443, 8888,
        # Infrastructure & Remote Access
        21, 22, 23, 25, 53, 110, 445, 3389, 5900,
        # Databases & Big Data
        1433, 1521, 3306, 5432, 6379, 27017, 9200,
        # Industrial Control Systems (SCADA / ICS)
        102,    # Siemens S7Comm
        502,    # Modbus TCP
        1883,   # MQTT (IoT / ICS telemetry)
        2404,   # IEC 60870-5-104
        4840,   # OPC UA
        20000,  # DNP3
        44818,  # EtherNet/IP (CIP)
    ]
    
    active_services = await enterprise_adaptive_recon(primary_ip, ports)
    print(f"[+] Active services observed: {active_services}")
    
    g = AssetGraph()
    host_node = f"host:{primary_ip}"
    g.add_node(host_node, "host", ip=primary_ip, domain=target)
    
    for svc in active_services:
        p = svc["port"]
        svc_node = f"svc:{primary_ip}:{p}/tcp"
        
        # Categorize service name for rich asset graph labeling
        if p in [80, 443, 8080, 8443, 8888]:
            svc_name = "web-service"
        elif p in [3306, 5432, 1433, 1521, 27017, 6379, 9200]:
            svc_name = "database"
        elif p in [502, 102, 44818, 20000, 4840, 2404, 1883]:
            svc_name = "scada-ics"
        else:
            svc_name = "infrastructure-service"
            
        g.add_node(svc_node, "service", port=p, name=svc_name)
        g.add_edge(host_node, svc_node, "runs")
        
    engine = KillChainEngine(g)
    if active_services:
        target_svc = f"svc:{primary_ip}:{active_services[0]['port']}/tcp"
        path, cost = engine.find_attack_path(host_node, target_svc)
        print(f"[+] Computed engagement route plan: {path} with impedance cost: {cost}")
        
        plan = engine.generate_kill_chain_plan(host_node, target_svc)
        print("\n" + "="*50)
        print(plan)
        print("="*50)
    else:
        print("[-] No open active ports observed for route planning (target protected or ports closed).")

def main():
    parser = argparse.ArgumentParser(description="HELIOS-NET Authorized Engagement Runner")
    parser.add_argument("--target", default="127.0.0.1", help="Target domain or IP (default: 127.0.0.1)")
    args = parser.parse_args()
    
    asyncio.run(execute_engagement(args.target))

if __name__ == "__main__":
    main()
