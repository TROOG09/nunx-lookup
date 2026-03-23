#!/usr/bin/env python3

import asyncio, aiohttp, socket, json, re
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import dns.resolver
import whois

init(autoreset=True)

# -------------------- ASCII --------------------
BANNER = Fore.RED + r"""
████████╗██╗  ██╗███████╗███████╗██╗██╗  ██╗
╚══██╔══╝██║  ██║██╔════╝██╔════╝██║╚██╗██╔╝
   ██║   ███████║█████╗  █████╗  ██║ ╚███╔╝ 
   ██║   ██╔══██║██╔══╝  ██╔══╝  ██║ ██╔██╗ 
   ██║   ██║  ██║███████╗███████╗██║██╔╝ ██╗
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝

        THESIXCLOWN RECON TOOL
        creators: :333G
========================================
""" + Style.RESET_ALL

# -------------------- RESOLVE --------------------
async def resolve(domain):
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, domain)
    except:
        return None

# -------------------- IP INTEL --------------------
async def ip_intel(session, ip):
    result = {}
    try:
        async with session.get(f"http://ip-api.com/json/{ip}") as r:
            data = await r.json()
            result.update(data)
    except:
        pass

    try:
        result["reverse"] = socket.gethostbyaddr(ip)[0]
    except:
        result["reverse"] = None

    return result

# -------------------- DNS --------------------
def dns_lookup(domain):
    records = {}
    for r in ["A","AAAA","MX","NS","TXT","CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, r)
            records[r] = [str(a) for a in answers]
        except:
            records[r] = []
    return records

# -------------------- WHOIS --------------------
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar),
            "created": str(w.creation_date),
            "expires": str(w.expiration_date)
        }
    except:
        return {}

# -------------------- PORT SCAN --------------------
async def scan_port(ip, port):
    try:
        r, w = await asyncio.open_connection(ip, port)
        w.close()
        return port
    except:
        return None

async def port_scan(ip):
    ports = [21,22,25,53,80,110,139,143,443,445,3389]
    results = await asyncio.gather(*[scan_port(ip,p) for p in ports])
    return sorted([p for p in results if p])

# -------------------- SUBDOMAINS --------------------
async def crtsh(session, domain):
    subs = set()
    try:
        async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as r:
            text = await r.text()
            text = text.replace("}{","},{")
            data = json.loads(f"[{text}]")
            for e in data:
                for s in e.get("name_value","").split("\n"):
                    if s and "*" not in s:
                        subs.add(s.strip())
    except:
        pass
    return sorted(list(subs))

# -------------------- EMAILS --------------------
async def emails(session, domain):
    subs = await crtsh(session, domain)
    return sorted([s for s in subs if "@" in s])

# -------------------- SCRAPER --------------------
async def scraper(session, domain):
    data = {"title":None,"links":[]}
    try:
        async with session.get(f"http://{domain}") as r:
            html = await r.text()
            soup = BeautifulSoup(html,"html.parser")
            if soup.title:
                data["title"] = soup.title.string
            data["links"] = [a.get("href") for a in soup.find_all("a",href=True)[:10]]
    except:
        pass
    return data

# -------------------- OUTPUT --------------------
def show(data):
    print(Fore.CYAN + "\n========== TARGET ==========")
    print(f"Domain: {data['domain']}")
    print(f"IP: {data['ip']}")

    print(Fore.CYAN + "\n========== IP INFO ==========")
    intel = data["intel"]
    print(f"ASN: {intel.get('as')}")
    print(f"ISP: {intel.get('isp')}")
    print(f"ORG: {intel.get('org')}")
    print(f"Country: {intel.get('country')}")
    print(f"City: {intel.get('city')}")
    print(f"Reverse: {intel.get('reverse')}")

    print(Fore.CYAN + "\n========== NETWORK ==========")
    print(f"Proxy/VPN: {intel.get('proxy')}")
    print(f"Hosting: {intel.get('hosting')}")

    print(Fore.CYAN + "\n========== PORTS ==========")
    for p in data["ports"]:
        print(f"[OPEN] {p}")

    print(Fore.CYAN + "\n========== DNS ==========")
    for k,v in data["dns"].items():
        for i in v:
            print(f"{k}: {i}")

    print(Fore.CYAN + "\n========== SUBDOMAINS ==========")
    for s in data["subs"][:20]:
        print(s)

    print(Fore.CYAN + "\n========== EMAILS ==========")
    for e in data["emails"]:
        print(e)

    print(Fore.CYAN + "\n========== WEB ==========")
    print("Title:", data["web"]["title"])
    for l in data["web"]["links"]:
        print(l)

    print(Fore.CYAN + "\n========== END ==========\n")

# -------------------- FULL RECON --------------------
async def full_recon(domain):
    async with aiohttp.ClientSession() as session:

        ip = await resolve(domain)
        if not ip:
            return

        intel = await ip_intel(session, ip)
        ports = await port_scan(ip)
        subs = await crtsh(session, domain)
        emails_list = await emails(session, domain)
        web = await scraper(session, domain)

        dns_data = dns_lookup(domain)
        whois_data = whois_lookup(domain)

        data = {
            "domain": domain,
            "ip": ip,
            "intel": intel,
            "ports": ports,
            "subs": subs,
            "emails": emails_list,
            "dns": dns_data,
            "whois": whois_data,
            "web": web
        }

        show(data)

        with open(f"{domain}.json","w") as f:
            json.dump(data, f, indent=4)

# -------------------- MASS DOMAIN --------------------
async def mass_domains():
    with open("targets.txt") as f:
        targets = [t.strip() for t in f if t.strip()]
    await asyncio.gather(*(full_recon(t) for t in targets))

# -------------------- IP SCAN --------------------
async def ip_scan(ip):
    async with aiohttp.ClientSession() as session:
        intel = await ip_intel(session, ip)
        ports = await port_scan(ip)

        print(Fore.YELLOW + f"\n=== IP: {ip} ===")
        print(f"ASN: {intel.get('as')}")
        print(f"ISP: {intel.get('isp')}")
        print(f"Ports: {ports}")

# -------------------- MASS IP --------------------
async def mass_ips():
    with open("ips.txt") as f:
        ips = [i.strip() for i in f if i.strip()]
    await asyncio.gather(*(ip_scan(ip) for ip in ips))

# -------------------- MAIN --------------------
def main():
    print(BANNER)

    print("""
[1] FULL DOMAIN
[2] MASS DOMAINS
[3] MASS IPS
[4] EXIT
""")

    op = input(">> ")

    if op == "1":
        d = input("Domain: ")
        asyncio.run(full_recon(d))

    elif op == "2":
        asyncio.run(mass_domains())

    elif op == "3":
        asyncio.run(mass_ips())

main()
