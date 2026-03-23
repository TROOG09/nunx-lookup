#!/usr/bin/env python3
# nunx lookup ULTRA FINAL

import asyncio, aiohttp, socket, json, re
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import dns.resolver
import whois

init(autoreset=True)

# -------------------- UI --------------------
def print_section(title):
    print(Fore.CYAN + f"\n[+] {title}")

def panel(domain, ip):
    print(Fore.GREEN + f"\nTARGET: {domain} ({ip})\n")

# -------------------- RESOLVE --------------------
async def resolve(domain):
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return ip
    except:
        return None

# -------------------- IP INTEL --------------------
async def ip_intel(session, ip):
    print_section("IP INTEL")

    result = {}

    try:
        async with session.get(f"http://ip-api.com/json/{ip}") as r:
            data = await r.json()
            result.update(data)

            print(f"ASN: {data.get('as')}")
            print(f"ISP: {data.get('isp')}")
            print(f"ORG: {data.get('org')}")
            print(f"Pais: {data.get('country')}")
            print(f"Ciudad: {data.get('city')}")

            lat, lon = data.get("lat"), data.get("lon")
            if lat and lon:
                print(Fore.GREEN + f"MAP: https://www.google.com/maps?q={lat},{lon}")

            if data.get("proxy"):
                print(Fore.YELLOW + "[!] VPN/PROXY")

            if data.get("hosting"):
                print(Fore.YELLOW + "[!] HOSTING")

    except:
        print("Error IP intel")

    try:
        host = socket.gethostbyaddr(ip)[0]
        print("Reverse:", host)
        result["reverse"] = host
    except:
        pass

    return result

# -------------------- DNS --------------------
async def dns_full(domain):
    print_section("DNS")
    for r in ["A","AAAA","MX","NS","TXT","CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, r)
            for a in answers:
                print(f"{r}: {a}")
        except:
            pass

# -------------------- WHOIS --------------------
def whois_lookup(domain):
    print_section("WHOIS")
    try:
        w = whois.whois(domain)
        print(f"Registrar: {w.registrar}")
        print(f"Creado: {w.creation_date}")
        print(f"Expira: {w.expiration_date}")
    except:
        print("Error whois")

# -------------------- HEADERS --------------------
async def headers(session, domain):
    print_section("HEADERS")
    try:
        async with session.get(f"http://{domain}") as r:
            for k,v in r.headers.items():
                print(f"{k}: {v}")
    except:
        pass

# -------------------- PORT SCAN --------------------
async def scan_port(ip, port):
    try:
        r, w = await asyncio.open_connection(ip, port)
        w.close()
        return port
    except:
        return None

async def port_scan(ip):
    print_section("PORTS")
    ports = [21,22,25,53,80,110,139,143,443,445,3389]
    results = await asyncio.gather(*[scan_port(ip,p) for p in ports])
    open_ports = [p for p in results if p]
    for p in open_ports:
        print(Fore.RED + f"[OPEN] {p}")
    return open_ports

# -------------------- CRT.SH --------------------
async def crtsh(session, domain):
    print_section("SUBDOMAINS")
    try:
        async with session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as r:
            text = await r.text()
            text = text.replace("}{","},{")
            data = json.loads(f"[{text}]")
            subs = set()
            for e in data:
                for s in e.get("name_value","").split("\n"):
                    if s and "*" not in s:
                        subs.add(s.strip())
            for s in list(subs)[:20]:
                print(s)
            return list(subs)
    except:
        return []

# -------------------- EMAILS --------------------
async def emails(session, domain):
    print_section("EMAILS")
    subs = await crtsh(session, domain)
    found = set()
    for s in subs:
        if "@" in s:
            found.add(s)
    for e in found:
        print(Fore.MAGENTA + e)
    return list(found)

# -------------------- SCRAPER --------------------
async def scraper(session, domain):
    print_section("SCRAPING")
    try:
        async with session.get(f"http://{domain}") as r:
            html = await r.text()
            soup = BeautifulSoup(html,"html.parser")

            if soup.title:
                print("Title:", soup.title.string)

            for a in soup.find_all("a",href=True)[:10]:
                print(a['href'])

    except:
        pass

# -------------------- FULL RECON --------------------
async def full_recon(domain):
    print(Fore.YELLOW + f"\n=== {domain} ===")

    async with aiohttp.ClientSession() as session:

        ip = await resolve(domain)
        if not ip:
            print("Error dominio")
            return

        panel(domain, ip)

        tasks = [
            ip_intel(session, ip),
            headers(session, domain),
            port_scan(ip),
            crtsh(session, domain),
            emails(session, domain),
            scraper(session, domain)
        ]

        results = await asyncio.gather(*tasks)

        await dns_full(domain)
        whois_lookup(domain)

        report = {
            "domain": domain,
            "ip": ip,
            "intel": results[0],
            "ports": results[2],
            "subs": results[3],
            "emails": results[4]
        }

        with open(f"{domain}.json","w") as f:
            json.dump(report, f, indent=4)

        print(Fore.GREEN + "Reporte guardado")

# -------------------- MASS SCAN --------------------
async def mass_scan():
    print_section("MASS SCAN")

    try:
        with open("targets.txt") as f:
            targets = [t.strip() for t in f if t.strip()]
    except:
        print("No targets.txt")
        return

    await asyncio.gather(*(full_recon(t) for t in targets))

# -------------------- MAIN --------------------
def main():
    print("""
[1] FULL RECON
[2] MASS SCAN 🔥
[3] EXIT
""")

    op = input(">> ")

    if op == "1":
        d = input("Dominio: ")
        asyncio.run(full_recon(d))

    elif op == "2":
        asyncio.run(mass_scan())

main()
