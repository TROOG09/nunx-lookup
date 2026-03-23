#!/usr/bin/env python3

import socket
import requests
import dns.resolver
import sys
import json

BANNER = """
========================================
        NUNX LOOKUP PRO
   creators: thesixclown / lapsus group
========================================
"""

# -------------------- GEO + ASN --------------------
def geolocation(ip):
    print("\n[+] Geolocalización / ASN:")

    try:
        url = f"http://ip-api.com/json/{ip}"
        data = requests.get(url, timeout=5).json()

        info = {
            "Pais": data.get("country"),
            "Region": data.get("regionName"),
            "Ciudad": data.get("city"),
            "ISP": data.get("isp"),
            "ASN": data.get("as"),
            "Proxy/VPN": data.get("proxy"),
            "Hosting": data.get("hosting"),
            "Lat": data.get("lat"),
            "Lon": data.get("lon")
        }

        for k, v in info.items():
            print(f"{k}: {v}")

        return info

    except:
        print("[-] Error GEO")
        return {}

# -------------------- DNS --------------------
def dns_lookup(domain):
    print("\n[+] DNS Records:")
    records_data = {}

    for record in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record)
            records_data[record] = [str(r) for r in answers]

            for r in answers:
                print(f"{record}: {r}")

        except:
            pass

    return records_data

# -------------------- SUBDOMAINS --------------------
def subdomain_lookup(domain):
    print(f"\n[+] Subdominios (crt.sh):")

    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = requests.get(url, timeout=10).json()

        for entry in data:
            if "name_value" in entry:
                for sub in entry["name_value"].split("\n"):
                    sub = sub.strip()
                    if sub:
                        subdomains.add(sub)

        for sub in sorted(subdomains):
            try:
                ip = socket.gethostbyname(sub)
                print(f"{sub} --> {ip}")
            except:
                print(sub)

    except:
        print("[-] Error crt.sh")

    return list(subdomains)

# -------------------- PORT SCAN --------------------
def port_scan(ip):
    print("\n[+] Escaneo de puertos:")

    open_ports = []
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[OPEN] {port}")
            open_ports.append(port)

        sock.close()

    return open_ports

# -------------------- REVERSE DNS --------------------
def reverse_dns(ip):
    print("\n[+] Reverse DNS:")
    try:
        host = socket.gethostbyaddr(ip)
        print(host[0])
        return host[0]
    except:
        print("No disponible")
        return None

# -------------------- DETECCIÓN --------------------
def detect_tech(domain):
    print("\n[+] Detección de tecnologías / seguridad:")

    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)

        headers = response.headers

        tech = {
            "Server": headers.get("Server"),
            "Powered-By": headers.get("X-Powered-By"),
            "Via": headers.get("Via")
        }

        for k, v in tech.items():
            if v:
                print(f"{k}: {v}")

        # Detectar protecciones
        headers_str = str(headers).lower()

        if "cloudflare" in headers_str:
            print("[+] Cloudflare detectado")

        if "akamai" in headers_str:
            print("[+] Akamai detectado")

        if "sucuri" in headers_str:
            print("[+] Sucuri WAF detectado")

        # HTTPS check
        try:
            requests.get(f"https://{domain}", timeout=5)
            print("[+] HTTPS disponible")
        except:
            print("[-] HTTPS no disponible")

    except:
        print("[-] Error detección")

# -------------------- RESOLVE --------------------
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[+] IP: {ip}")
        return ip
    except:
        print("[-] Error resolviendo dominio")
        return None

# -------------------- EXPORT --------------------
def export_data(data):
    try:
        with open("resultado_nunx.json", "w") as f:
            json.dump(data, f, indent=4)
        print("\n[+] Guardado en resultado_nunx.json")
    except:
        print("[-] Error guardando archivo")

# -------------------- FULL RECON --------------------
def full_recon(domain):
    results = {}

    ip = resolve_domain(domain)
    if not ip:
        return

    results["ip"] = ip
    results["geo"] = geolocation(ip)
    results["dns"] = dns_lookup(domain)
    results["reverse"] = reverse_dns(ip)
    results["ports"] = port_scan(ip)
    results["subdomains"] = subdomain_lookup(domain)

    detect_tech(domain)

    export_data(results)

# -------------------- IP LOOKUP --------------------
def ip_lookup():
    ip = input("\nIP: ")

    geolocation(ip)
    reverse_dns(ip)
    port_scan(ip)

# -------------------- MENU --------------------
def menu():
    print(BANNER)

    while True:
        print("""
[1] Link lookup (FULL RECON)
[2] IP lookup
[3] Subdomain lookup
[4] Exit
        """)

        choice = input(">> ")

        if choice == "1":
            domain = input("Dominio: ")
            full_recon(domain)

        elif choice == "2":
            ip_lookup()

        elif choice == "3":
            domain = input("Dominio: ")
            subdomain_lookup(domain)

        elif choice == "4":
            print("Bye 👋")
            sys.exit()

        else:
            print("Opción inválida")

if __name__ == "__main__":
    menu()
