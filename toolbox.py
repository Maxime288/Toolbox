import socket
import hashlib
import threading
import concurrent.futures
import requests
import os

# Configuration des couleurs pour le terminal
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def print_banner():
    banner = f"""
{BLUE}███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   {RESET}
 {YELLOW}--- Security ToolBox v1.0 | Démo Dev & Sec ---{RESET}
    """
    print(banner)

# ==========================================
# 1. SCANNER RÉSEAU (TCP Port Scanner)
# ==========================================
def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"[{GREEN}OPEN{RESET}] Port {port}")
        s.close()
    except Exception:
        pass

def network_scanner():
    print(f"\n{BLUE}--- SCANNER RÉSEAU ---{RESET}")
    target = input("Entrez l'IP cible ou le domaine (ex: 127.0.0.1) : ")
    ports_input = input("Ports à scanner (ex: 21,22,80,443 ou 1-100) : ")
    
    ports = []
    if "-" in ports_input:
        start, end = map(int, ports_input.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p.strip()) for p in ports_input.split(",")]

    print(f"\nScanning {target} pour {len(ports)} ports...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for port in ports:
            executor.submit(scan_port, target, port)
    print(f"{GREEN}Scan terminé.{RESET}")

# ==========================================
# 2. BRUTEFORCE TOOL (Simulé / Local)
# ==========================================
def bruteforce_tool():
    print(f"\n{BLUE}--- BRUTEFORCE TOOL (Simulation de dictionnaire) ---{RESET}")
    print("Idéal pour tester la robustesse d'un mot de passe face à une wordlist.")
    
    target_password = input("Entrez un mot de passe à simuler (ex: admin123) : ")
    wordlist_path = input("Chemin vers votre fichier wordlist (ou laissez vide pour une liste d'exemple) : ")
    
    # Liste par défaut si aucun fichier n'est fourni
    if not wordlist_path or not os.path.exists(wordlist_path):
        print(f"{YELLOW}Fichier non trouvé. Utilisation d'une liste d'exemple intégrée...{RESET}")
        words = ["password", "123456", "qwerty", "admin", "admin123", "security", "password123"]
    else:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f.readlines()]
            
    found = False
    for attempt, word in enumerate(words, 1):
        if word == target_password:
            print(f"\n{GREEN}[SUCCÈS]{RESET} Mot de passe trouvé : {YELLOW}{word}{RESET}")
            print(f"Trouvé en {attempt} tentatives.")
            found = True
            break
            
    if not found:
        print(f"\n{RED}[ÉCHEC]{RESET} Le mot de passe n'est pas dans la liste.")

# ==========================================
# 3. HASH CHECKER (Génération & Vérification)
# ==========================================
def hash_checker():
    print(f"\n{BLUE}--- HASH CHECKER ---{RESET}")
    print("1. Générer le hash d'un texte")
    print("2. Comparer un texte avec un hash existant")
    choix = input("Votre choix (1/2) : ")
    
    texte = input("Entrez le texte / mot de passe : ")
    
    hash_md5 = hashlib.md5(texte.encode()).hexdigest()
    hash_sha1 = hashlib.sha1(texte.encode()).hexdigest()
    hash_sha256 = hashlib.sha256(texte.encode()).hexdigest()
    
    if choix == "1":
        print(f"\nMD5    : {GREEN}{hash_md5}{RESET}")
        print(f"SHA-1  : {GREEN}{hash_sha1}{RESET}")
        print(f"SHA-256: {GREEN}{hash_sha256}{RESET}")
    elif choix == "2":
        user_hash = input("Entrez le hash à comparer : ").strip().lower()
        if user_hash in [hash_md5, hash_sha1, hash_sha256]:
            print(f"\n{GREEN}[CORRESPONDANCE TROUVÉE]{RESET} Le texte correspond au hash.")
        else:
            print(f"\n{RED}[ALERTE]{RESET} Le texte ne correspond pas au hash.")

# ==========================================
# 4. OSINT TOOL (IP Lookup & DNS Básique)
# ==========================================
def osint_tool():
    print(f"\n{BLUE}--- OSINT TOOL (IP Geolocation) ---{RESET}")
    ip = input("Entrez une adresse IP publique à analyser (laissez vide pour votre IP) : ")
    
    url = f"https://ipapi.co/{ip}/json/"
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "error" in data:
                print(f"{RED}Erreur : {data['reason']}{RESET}")
                return
                
            print(f"\n{GREEN}--- Informations OSINT ---{RESET}")
            print(f"IP          : {data.get('ip')}")
            print(f"Ville       : {data.get('city')}")
            print(f"Région      : {data.get('region')}")
            print(f"Pays        : {data.get('country_name')} ({data.get('country')})")
            print(f"Fournisseur : {data.get('org')}")
            print(f"Asn         : {data.get('asn')}")
        else:
            print(f"{RED}Impossible de joindre l'API (Code {response.status_code}){RESET}")
    except Exception as e:
        print(f"{RED}Erreur de connexion : {e}{RESET}")

# ==========================================
# MENU PRINCIPAL
# ==========================================
def main():
    while True:
        print_banner()
        print("1. 🌐 Network Scanner (Ports)")
        print("2. 🔑 Bruteforce Simulator")
        print("3. 🧮 Hash Checker")
        print("4. 🔍 OSINT Tool (IP Lookup)")
        print("5. ❌ Quitter")
        
        choix = input("\nChoisissez une option (1-5) : ")
        
        if choix == "1":
            network_scanner()
        elif choix == "2":
            bruteforce_tool()
        elif choix == "3":
            hash_checker()
        elif choix == "4":
            osint_tool()
        elif choix == "5":
            print(f"\n{YELLOW}Merci d'avoir utilisé la Security ToolBox. À bientôt !{RESET}")
            break
        else:
            print(f"{RED}Option invalide.{RESET}")
            
        input("\nAppuyez sur Entrée pour revenir au menu...")

if __name__ == "__main__":
    main()
