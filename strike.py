import asyncio
from modules.discovery.dns_resolver import EliteDNSResolver
from core.async_engine import enterprise_adaptive_recon
from engine.graph.core import AssetGraph
from engine.killchain.pathfinder import KillChainEngine

async def execute_strike():
    target_domain = "hackthissite.org"
    print(f"[DEMIURG] بدء الحملة الهجومية الشاملة على الهدف: {target_domain}")
    
    resolver = EliteDNSResolver()
    ips = await resolver.resolve(target_domain)
    print(f"[+] عناوين IP الحية المستخرجة: {ips}")
    
    if not ips:
        print("[-] تعذر الوصول لعناوين IP للهدف.")
        return
        
    primary_ip = ips[0]
    print(f"[+] التركيز على العقدة الأساسية: {primary_ip}")
    
    ports = [80, 443, 21, 22, 3306]
    active_services = await enterprise_adaptive_recon(primary_ip, ports)
    print(f"[+] الخدمات النشطة المرصودة: {active_services}")
    
    g = AssetGraph()
    host_node = f"host:{primary_ip}"
    g.add_node(host_node, "host", ip=primary_ip, domain=target_domain)
    
    for svc in active_services:
        p = svc["port"]
        svc_node = f"svc:{primary_ip}:{p}/tcp"
        g.add_node(svc_node, "service", port=p, name="web-service" if p in [80, 443] else "service")
        g.add_edge(host_node, svc_node, "runs")
        
    engine = KillChainEngine(g)
    if active_services:
        target_svc = f"svc:{primary_ip}:{active_services[0]['port']}/tcp"
        path, cost = engine.find_attack_path(host_node, target_svc)
        print(f"[+] مسار الاختراق المحسوب: {path} بتكلفة مقاومة: {cost}")
        
        plan = engine.generate_kill_chain_plan(host_node, target_svc)
        print("\n" + "="*50)
        print(plan)
        print("="*50)
    else:
        print("[-] لم يتم رصد منافذ مفتوحة نشطة للاختراق المباشر (هدف محمي أو مغلق المنافذ المستهدفة).")

if __name__ == "__main__":
    asyncio.run(execute_strike())
