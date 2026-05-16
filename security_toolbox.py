#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import hashlib
import threading
import concurrent.futures
import requests
import os
import sys
import time
from typing import List, Union

# --- CONFIGURATION DE L'INTERFACE (COULEURS ANSI) ---
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

class Interface:
    @staticmethod
    def banner():
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""{BLUE}{BOLD}
 ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗███████╗
██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝
██║     ██║   ██║██╔████╔██║██████╔╝██║     █████╗     ██║   █████╗  
██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝     ██║   ██╔══╝  
╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝{RESET}
 {CYAN}🛠️  Security ToolBox v2.0 (All-In-One) | Profil Dev-Sec engagé{RESET}
        """)

    @staticmethod
    def menu():
        print(f"{BOLD}[ OPTIONS DISPONIBLES ]{RESET}\n")
        print(f" {BLUE}1.{RESET} 🌐 Scanner Réseau & Services (TCP)")
        print(f" {BLUE}2.{RESET} 🔑 Simulateur de Bruteforce (Dictionnaire)")
        print(f" {BLUE}3.{RESET} 🧮 Validateur & Générateur de Hashs")
        print(f" {BLUE}4.{RESET} 🔍 Module OSINT (Renseignement IP)")
        print(f" {RED}5. ❌ Quitter l'application{RESET}")
        print("-" * 60)


# =====================================================================
# 1. SCANNER RÉSEAU AVANCÉ (Avec détection basique de bannière/service)
# =====================================================================
class NetworkScanner:
    # Dictionnaire de services courants pour l'analyse
    COMMON_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
    }

    def __init__(self):
        self.lock = threading.Lock()

    def grab_banner(self, s: socket.socket) -> str:
        """Tente de récupérer la bannière du service connecté."""
        try:
            s.sendall(b"Hello\r\n")
            banner = s.recv(1024).decode(errors='ignore').strip()
            return f" | Bannière: {banner[:50]}"
        except Exception:
            return ""

    def scan_single_port(self, target: str, port: int, timeout: float):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = self.COMMON_SERVICES.get(port, "Inconnu")
                    banner_info = self.grab_banner(s) if port not in [80, 443] else ""
                    with self.lock:
                        print(f" [{GREEN}OUVERT{RESET}] Port {BOLD}{port:<5}{RESET} -> Service: {CYAN}{service:<10}{RESET}{banner_info}")
        except Exception:
            pass

    def run(self):
        print(f"\n{BLUE}{BOLD}--- MODULE 1 : SCANNER RÉSEAU ---{RESET}")
        target = input("Entrez l'IP cible ou le nom de domaine (ex: 127.0.0.1) : ").strip()
        if not target: return

        print(f"\n{YELLOW}Sélection des ports :{RESET}")
        print("1. Ports standards les plus communs (Top 15)")
        print("2. Plage personnalisée (ex: 1-1000)")
        print("3. Ports spécifiques (ex: 22,80,443)")
        
        choix = input("Votre choix : ").strip()
        ports = []

        if choix == "1":
            ports = list(self.COMMON_SERVICES.keys())
        elif choix == "2":
            try:
                start, end = map(int, input("Entrez la plage (ex: 1-1024) : ").split("-"))
                ports = list(range(start, end + 1))
            except ValueError:
                print(f"{RED}Format invalide.{RESET}"); return
        elif choix == "3":
            try:
                ports = [int(p.strip()) for p in input("Entrez les ports séparés par des virgules : ").split(",")]
            except ValueError:
                print(f"{RED}Format invalide.{RESET}"); return
        else:
            print(f"{RED}Option invalide.{RESET}"); return

        print(f"\n{YELLOW}[*] Lancement du scan sur {target} ({len(ports)} ports)...{RESET}")
        start_time = time.time()

        # Utilisation de la concurrence pour la vitesse d'exécution
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_single_port, target, port, 0.6) for port in ports]
            concurrent.futures.wait(futures)

        print(f"\n{GREEN}[+] Scan terminé en {time.time() - start_time:.2f} secondes.{RESET}")


# =====================================================================
# 2. OUTIL DE BRUTEFORCE (Analyse de robustesse locale)
# =====================================================================
class BruteforceSimulator:
    def run(self):
        print(f"\n{BLUE}{BOLD}--- MODULE 2 : SIMULATEUR DE BRUTEFORCE ---{RESET}")
        print("Utile pour auditer si un mot de passe est vulnérable à une attaque par dictionnaire.")
        
        target_password = input("Entrez le mot de passe cible (ex: password123) : ").strip()
        wordlist_path = input("Chemin vers un fichier wordlist (.txt) [Vide pour exemple intégré] : ").strip()

        if not wordlist_path or not os.path.exists(wordlist_path):
            print(f"{YELLOW}[!] Wordlist non fournie ou introuvable. Utilisation d'une liste de démo.{RESET}")
            wordlist = ["123456", "password", "admin", "123456789", "qwerty", "password123", "root", "superman"]
        else:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"{RED}Erreur lors de la lecture du fichier : {e}{RESET}"); return

        print(f"\n[*] Lancement du test face à {len(wordlist)} mots possibles...")
        found = False
        start_time = time.time()

        for index, candidate in enumerate(wordlist, 1):
            if candidate == target_password:
                elapsed = time.time() - start_time
                print(f"\n{GREEN}[🎉 SUCCÈS] Mot de passe trouvé dans le dictionnaire !{RESET}")
                print(f" -> Correspondance : {YELLOW}{BOLD}{candidate}{RESET}")
                print(f" -> Tentatives nécessaires : {index} / {len(wordlist)}")
                print(f" -> Temps écoulé : {elapsed:.4f} secondes")
                found = True
                break

        if not found:
            print(f"\n{RED}[❌ ÉCHEC] Le mot de passe n'apparaît pas dans la wordlist testée.{RESET}")


# =====================================================================
# 3. HASH CHECKER (Génération, Détection de format & Comparaison)
# =====================================================================
class HashChecker:
    def compute_hashes(self, text: str) -> dict:
        encoded = text.encode('utf-8')
        return {
            "MD5": hashlib.md5(encoded).hexdigest(),
            "SHA-1": hashlib.sha1(encoded).hexdigest(),
            "SHA-256": hashlib.sha256(encoded).hexdigest(),
            "SHA-512": hashlib.sha512(encoded).hexdigest()
        }

    def run(self):
        print(f"\n{BLUE}{BOLD}--- MODULE 3 : HASH CHECKER ---{RESET}")
        print("1. Générer des signatures numériques (Hachage)")
        print("2. Comparer un texte clair avec une signature existante (Vérification)")
        
        choix = input("Votre choix (1/2) : ").strip()
        
        if choix == "1":
            text = input("Entrez la chaîne de caractères à hacher : ")
            hashes = self.compute_hashes(text)
            print(f"\n{GREEN}[+] Signatures générées :{RESET}")
            for algo, val in hashes.items():
                print(f" {BOLD}{algo:<8}:{RESET} {YELLOW}{val}{RESET}")
                
        elif choix == "2":
            clear_text = input("Entrez le texte en clair à vérifier : ")
            target_hash = input("Entrez le hash de référence à comparer : ").strip().lower()
            
            hashes = self.compute_hashes(clear_text)
            matched = False
            
            for algo, val in hashes.items():
                if val == target_hash:
                    print(f"\n{GREEN}[✓ CORRESPONDANCE PARFAITE]{RESET} Le texte correspond au hash fourni via l'algorithme {BOLD}{algo}{RESET}.")
                    matched = True
                    break
            if not matched:
                print(f"\n{RED}[❌ ALERTE] Aucune correspondance.{RESET} Le texte clair ne génère pas ce hash.")
        else:
            print(f"{RED}Option inconnue.{RESET}")


# =====================================================================
# 4. MODULE OSINT (Géolocalisation & Métadonnées IP publiques)
# =====================================================================
class OSINTModule:
    def run(self):
        print(f"\n{BLUE}{BOLD}--- MODULE 4 : MODULE OSINT (Analyse IP) ---{RESET}")
        ip_target = input("Entrez une adresse IP publique (Laissez VIDE pour analyser votre IP) : ").strip()
        
        # Utilisation d'une API de géolocalisation IP ouverte
        url = f"https://ipapi.co/{ip_target}/json/"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

        print(f"[*] Requête API en cours vers ipapi.co...")
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if "error" in data:
                    print(f"{RED}[❌] Réponse de l'API : {data.get('reason', 'IP invalide ou privée')}{RESET}")
                    return

                print(f"\n{GREEN}{BOLD}[+] RENSEIGNEMENTS RÉCUPÉRÉS :{RESET}")
                print(f" 🎯 {BOLD}IP Publique : {RESET}{YELLOW}{data.get('ip')}{RESET}")
                print(f" 🏢 {BOLD}FAI / Organisation :{RESET} {data.get('org')} ({data.get('asn', 'ASN inconnu')})")
                print(f" 📍 {BOLD}Géolocalisation :   {RESET}{data.get('city')}, {data.get('region')} - {BOLD}{data.get('country_name')}{RESET}")
                print(f" 🌍 {BOLD}Code Pays :         {RESET}{data.get('country_code')}")
                print(f" 🌐 {BOLD}Coordonnées :       {RESET}Lat: {data.get('latitude')}, Lon: {data.get('longitude')}")
                print(f" ⏰ {BOLD}Fuseau Horaire :    {RESET}{data.get('timezone')}")
            else:
                print(f"{RED}[❌] Erreur serveur API (Code statut : {response.status_code}){RESET}")
        except requests.exceptions.RequestException as e:
            print(f"{RED}[❌] Erreur réseau lors de la requête : {e}{RESET}")


# =====================================================================
# PROGRAMME PRINCIPAL & ROUTAGE
# =====================================================================
def main():
    # Instanciation des composants logiques
    scanner = NetworkScanner()
    brute = BruteforceSimulator()
    hasher = HashChecker()
    osint = OSINTModule()

    while True:
        Interface.banner()
        Interface.menu()
        
        choix = input(f"{BOLD}Entrez le numéro de l'action à mener (1-5) : {RESET}").strip()
        
        if choix == "1":
            scanner.run()
        elif choix == "2":
            brute.run()
        elif choix == "3":
            hasher.run()
        elif choix == "4":
            osint.run()
        elif choix == "5":
            print(f"\n{PURPLE}[*] Extinction de la Security ToolBox. Mode Dev OFF.{RESET}\n")
            sys.exit(0)
        else:
            print(f"\n{RED}[!] Choix incorrect, merci de saisir un chiffre entre 1 et 5.{RESET}")
            
        input(f"\n{CYAN}Appuyez sur [Entrée] pour revenir au menu principal...{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Sortie forcée par l'utilisateur.{RESET}")
        sys.exit(0)
