"""
HELIOS-NET :: Authorized Engagement Runner (strike.py)
Executes authorized attack surface management and route planning against user-specified targets.
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
    
    ports = [80, 443, 21, 22, 3306]
    active_services = await enterprise_adaptive_recon(primary_ip, ports)
    print(f"[+] Active services observed: {active_services}")
    
    g = AssetGraph()
    host_node = f"host:{primary_ip}"
    g.add_node(host_node, "host", ip=primary_ip, domain=target)
    
    for svc in active_services:
        p = svc["port"]
        svc_node = f"svc:{primary_ip}:{p}/tcp"
        g.add_node(svc_node, "service", port=p, name="web-service" if p in [80, 443] else "service")
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
