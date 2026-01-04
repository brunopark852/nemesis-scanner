#!/usr/bin/env python3
"""
NEMESIS V2.1 - GOD MODE (Interactive Edition)
Autor: Bruno Rodrigo
"""
import requests
import sys
import argparse
import socket
import concurrent.futures
import json
import time
import random
import os
from datetime import datetime

# Desativa avisos de SSL (Modo Silencioso)
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Colors:
    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; BLUE = "\033[96m"; 
    MAGENTA = "\033[95m"; CYAN = "\033[36m"; BOLD = "\033[1m"; RESET = "\033[0m"

# --- CONFIGURAÇÕES DE ELITE ---
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15"
]

BYPASS_HEADERS = {
    "X-Originating-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1", "X-Client-IP": "127.0.0.1"
}

JUICY_PATHS = [
    ".env", ".git/config", "docker-compose.yml", "config.php", "backup.sql", 
    "admin", "swagger-ui.html", "actuator/env", "api/v1/users", "phpinfo.php",
    "wp-config.php.bak", "sftp-config.json", ".vscode/sftp.json"
]

CRITICAL_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8888, 22, 21, 3306, 5432]

# --- ESTRUTURA DE RELATÓRIO ---
REPORT_DATA = {}

def log(msg, type="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    if type == "SUCCESS": print(f"[{ts}] {Colors.GREEN}[+] {msg}{Colors.RESET}")
    elif type == "ALERT":   print(f"[{ts}] {Colors.RED}[!] {msg}{Colors.RESET}")
    elif type == "INFO":    print(f"[{ts}] {Colors.BLUE}[*] {msg}{Colors.RESET}")
    elif type == "WARN":    print(f"[{ts}] {Colors.YELLOW}[~] {msg}{Colors.RESET}")
    elif type == "GHOST":   print(f"[{ts}] {Colors.MAGENTA}[👻] {msg}{Colors.RESET}")

def get_random_agent():
    return random.choice(USER_AGENTS)

# --- MÓDULO 1: RECONHECIMENTO AVANÇADO (MULTI-FONTE) ---
def recon_crtsh(target):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        if r.status_code == 200:
            for item in r.json():
                name = item['name_value']
                if "\n" in name: subs.update(name.split("\n"))
                else: subs.add(name)
    except: pass
    return subs

def recon_hackertarget(target):
    subs = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10)
        if r.status_code == 200:
            for line in r.text.split("\n"):
                if "," in line: subs.add(line.split(",")[0])
    except: pass
    return subs

def recon_alienvault(target):
    subs = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for item in r.json().get('passive_dns', []):
                subs.add(item['hostname'])
    except: pass
    return subs

def master_recon(target):
    log(f"Iniciando Recon Multi-Fonte em: {target}...", "INFO")
    all_subs = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        f1 = executor.submit(recon_crtsh, target)
        f2 = executor.submit(recon_hackertarget, target)
        f3 = executor.submit(recon_alienvault, target)
        
        all_subs.update(f1.result())
        all_subs.update(f2.result())
        all_subs.update(f3.result())

    # Limpeza (remove wildcards e emails)
    clean_subs = [s for s in all_subs if "*" not in s and "@" not in s]
    log(f"Total de subdomínios únicos encontrados: {len(clean_subs)}", "SUCCESS")
    return list(clean_subs)

# --- MÓDULO 2: WAF DETECTOR & FINGERPRINT ---
def detect_tech(url):
    techs = []
    waf = "Nenhum detectado"
    try:
        r = requests.get(url, headers={"User-Agent": get_random_agent()}, timeout=3, verify=False)
        headers = r.headers
        
        # WAF Detection
        if "CF-RAY" in headers: waf = "Cloudflare"
        elif "X-Amz-Cf-Id" in headers: waf = "AWS CloudFront"
        elif "Akamai" in headers.get("Server", ""): waf = "Akamai"
        
        # Tech Fingerprint
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        if server: techs.append(f"Server: {server}")
        if powered: techs.append(f"Powered: {powered}")
        
        return waf, techs, r.status_code
    except:
        return None, None, None

# --- MÓDULO 3: SCANNER & BYPASSER ---
def scan_target(sub):
    try:
        ip = socket.gethostbyname(sub)
    except: return None # Host morto

    log(f"Analisando: {sub} ({ip})", "INFO")
    
    target_data = {
        "ip": ip,
        "ports": [],
        "vulns": [],
        "waf": None,
        "tech": []
    }

    # 1. Port Scan Rápido
    for port in CRITICAL_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((sub, port)) == 0:
                target_data["ports"].append(port)

    # 2. Web Analysis (Se tiver porta 80/443)
    if 80 in target_data["ports"] or 443 in target_data["ports"]:
        proto = "https" if 443 in target_data["ports"] else "http"
        base_url = f"{proto}://{sub}"
        
        waf, tech, status = detect_tech(base_url)
        target_data["waf"] = waf
        target_data["tech"] = tech
        
        if waf != "Nenhum detectado":
            log(f"  > WAF Detectado: {Colors.RED}{waf}{Colors.RESET}", "WARN")
        
        # 3. Path Fuzzing + Ghost Mode
        for path in JUICY_PATHS:
            url = f"{base_url}/{path}"
            try:
                # Request Normal
                r = requests.get(url, headers={"User-Agent": get_random_agent()}, timeout=3, verify=False)
                
                if r.status_code == 200:
                    msg = f"VULN FOUND: {url}"
                    log(f"  > {msg}", "SUCCESS")
                    target_data["vulns"].append(msg)
                
                # Tenta Bypass se der 403
                elif r.status_code == 403:
                    # GHOST MODE ACTIVATION
                    for bh, bv in BYPASS_HEADERS.items():
                        headers = {"User-Agent": get_random_agent(), bh: bv}
                        r_bypass = requests.get(url, headers=headers, timeout=3, verify=False)
                        if r_bypass.status_code == 200:
                            msg = f"BYPASS SUCCESS ({bh}): {url}"
                            log(f"  > {msg}", "GHOST")
                            target_data["vulns"].append(msg)
                            break
            except: pass

    REPORT_DATA[sub] = target_data
    return target_data

# --- ENGINE PRINCIPAL ---
def start_engine(target, threads):
    # Garante que o alvo não tenha http/https ou barras
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    start = time.time()
    
    # Fase 1: Recon
    subs = master_recon(target)
    if not subs:
        log("Nenhum subdomínio encontrado. Abortando.", "ALERT")
        return

    # Fase 2: Ataque Massivo
    log(f"Iniciando varredura em {len(subs)} alvos com {threads} threads...", "INFO")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_target, sub) for sub in subs]
        concurrent.futures.wait(futures)

    # Fase 3: Relatório
    report_name = f"nemesis_report_{target}.json"
    try:
        with open(report_name, "w") as f:
            json.dump(REPORT_DATA, f, indent=4)
        elapsed = time.time() - start
        log(f"NEMESIS finalizado em {elapsed:.2f}s. Relatório salvo: {report_name}", "SUCCESS")
    except Exception as e:
        log(f"Erro ao salvar relatório: {e}", "ALERT")

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.RED}{Colors.BOLD}")
    print(r"""
     _   _ _____ __  __ _____ ____ ___ ____     ____  
    | \ | | ____|  \/  | ____/ ___|_ _/ ___|   |___ \ 
    |  \| |  _| | |\/| |  _| \___ \| |\___ \     __) |
    | |\  | |___| |  | | |___ ___) | | ___) |   / __/ 
    |_| \_|_____|_|  |_|_____|____/___|____/   |_____|
           [ GOD MODE EDITION - By Bruno Rodrigo ]
    """)
    print(f"{Colors.RESET}")

# --- MODO INTERATIVO (PREGUIÇA) ---
def interactive_mode():
    show_banner()
    try:
        target = input(f"{Colors.YELLOW}[?] Alvo (Domínio, ex: tesla.com): {Colors.RESET}")
        if not target: return

        threads_input = input(f"{Colors.YELLOW}[?] Threads (Enter para 20): {Colors.RESET}")
        threads = int(threads_input) if threads_input.isdigit() else 20
        
        start_engine(target, threads)
    except KeyboardInterrupt:
        print("\n[!] Saindo...")

# --- MAIN ---
if __name__ == "__main__":
    # Se não tiver argumentos, vai pro modo preguiça
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        # Modo Hacker (CLI) continua funcionando se quiser
        show_banner()
        parser = argparse.ArgumentParser()
        parser.add_argument("target", help="Domínio Alvo")
        parser.add_argument("-t", "--threads", type=int, default=20, help="Threads")
        args = parser.parse_args()

        start_engine(args.target, args.threads)
