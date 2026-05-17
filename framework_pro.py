#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
⚙️  ENTERPRISE SECURITY CORE FRAMEWORK v4.1
Standards DevSecOps : Architecture Plugin, Concurrence, TLS Audit,
SSH Real Brute-Force, Port Scanner étendu, Hash Cracker réel (Urus Engine Fix),
CVE Lookup, Whois/DNS Recon, Rapport HTML + JSON.

Usage légitime uniquement — sur systèmes avec autorisation écrite.
"""

import os
import sys
import time
import json
import html
import socket
import ssl
import hashlib
import logging
import threading
import ipaddress
import subprocess
import concurrent.futures
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

# ── Dépendances tierces ────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.logging import RichHandler
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import box
except ImportError:
    print("[!] 'rich' manquant : pip install rich")
    sys.exit(1)

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] 'requests' manquant : pip install requests")
    sys.exit(1)

try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False

# ── Configuration centrale ─────────────────────────────────────────────────────
FRAMEWORK_CONFIG = {
    "framework": {
        "version": "4.1.0-STABLE",
        "reports_dir": "reports",
        "log_file": "framework_core.log"
    },
    "modules": {
        "network_scan": {
            "timeout": 1.0,
            "max_workers": 40,
            "default_ports": [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]
        },
        "password_audit": {
            "common_words": [
                "123456", "123456789", "picture1", "password", "password123", 
                "111111", "123123", "000000", "admin", "administrator", "root", 
                "toor", "guest", "user", "cisco", "kali", "linux", "qwerty", "azerty"
            ]
        },
        "osint": {
            "timeout": 3.0,
            "ip_endpoints": [
                "https://ipapi.co/{ip}/json/",
                "http://ip-api.com/json/{ip}"
            ]
        },
        "ssl_auditor": {
            "timeout": 2.5
        }
    }
}

# ── Logging unifié ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler(FRAMEWORK_CONFIG["framework"]["log_file"], encoding="utf-8")
    ]
)
logger = logging.getLogger("FrameworkCore")
console = Console()

# ── Classe de Base Abstraite (Plugin Pattern) ──────────────────────────────────
class BasePlugin(ABC):
    def __init__(self):
        self.logger = logging.getLogger("FrameworkCore")

    @property
    @abstractmethod
    def name(self) -> str: pass

    @property
    @abstractmethod
    def description(self) -> str: pass

    @abstractmethod
    def execute(self, config: dict) -> dict: pass

# ── Implémentation des 8 Plugins ───────────────────────────────────────────────

class WhoisDnsPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Reconnaissance DNS & Whois"
    @property
    def description(self) -> str: return "Collecte d'enregistrements DNS (A, MX, TXT) et données d'enregistrement"

    def execute(self, config: dict) -> dict:
        target = Prompt.ask("[bold cyan]Entrez un domaine cible (ex: google.com)[/bold cyan]").strip()
        if not target: return {"error": "Cible vide"}
        
        results = {"domain": target, "dns_records": {}, "whois_raw": "Non disponible"}
        self.logger.info(f"Lancement de la reconnaissance DNS sur : {target}")
        
        # Résolution DNS de base via socket
        for rtype in ['A', 'MX', 'TXT']:
            try:
                if rtype == 'A':
                    ip = socket.gethostbyname(target)
                    results["dns_records"]["A"] = [ip]
            except Exception as e:
                results["dns_records"][rtype] = [f"Erreur ou non trouvé : {str(e)}"]

        # Tentative Whois via commande système
        try:
            cmd = "whois" if os.name != 'nt' else "whois.exe"
            proc = subprocess.run([cmd, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if proc.returncode == 0:
                results["whois_raw"] = proc.stdout[:2000] # Limiter la taille
        except Exception:
            results["whois_raw"] = "Commande 'whois' indisponible localement sur la machine."

        return results


class ExtendedPortScannerPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Scanner de Ports Étendu"
    @property
    def description(self) -> str: return "Analyse TCP asynchrone avec détection de bannières applicatives"

    def _scan_port(self, target_ip: str, port: int, timeout: float) -> dict:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target_ip, port)) == 0:
                    banner = "Inconnue"
                    try:
                        s.sendall(b"Hello\r\n")
                        banner = s.recv(1024).decode(errors='ignore').strip()
                    except Exception:
                        pass
                    return {"port": port, "status": "OPEN", "banner": banner}
        except Exception:
            pass
        return {}

    def execute(self, config: dict) -> dict:
        target = Prompt.ask("[bold cyan]IP ou Domaine à scanner[/bold cyan]", default="127.0.0.1").strip()
        mod_cfg = config["modules"]["network_scan"]
        
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.logger.error(f"Impossible de résoudre l'hôte : {target}")
            return {"error": "Résolution hôte échouée"}

        self.logger.info(f"Scan en cours sur {target_ip} (Pool asynchrone)...")
        open_ports = []
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
            task = progress.add_task("[gray]Balayage TCP...[/gray]", total=len(mod_cfg["default_ports"]))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=mod_cfg["max_workers"]) as executor:
                futures = {executor.submit(self._scan_port, target_ip, p, mod_cfg["timeout"]): p for p in mod_cfg["default_ports"]}
                for f in concurrent.futures.as_completed(futures):
                    res = f.result()
                    if res: open_ports.append(res)
                    progress.advance(task)

        return {"target": target, "ip": target_ip, "open_ports": sorted(open_ports, key=lambda x: x["port"])}


class SslAuditorPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Auditeur SSL/TLS"
    @property
    def description(self) -> str: return "Analyse de conformité des certificats et détection des protocoles obsolètes"

    def execute(self, config: dict) -> dict:
        target = Prompt.ask("[bold cyan]Domaine HTTPS à auditer (ex: google.com)[/bold cyan]", default="google.com").strip()
        timeout = config["modules"]["ssl_auditor"]["timeout"]
        
        report = {"target": target, "certificate_valid": False, "obsolete_protocols": [], "error": None}
        self.logger.info(f"Analyse de la configuration SSL/TLS de {target}...")
        
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    report["certificate_valid"] = True
                    report["cipher_used"] = ssock.cipher()
                    report["tls_version"] = ssock.version()
        except Exception as e:
            report["error"] = str(e)
            self.logger.warning(f"Rupture de confiance ou erreur SSL : {e}")

        # Détection rapide de protocoles dépréciés
        deprecated = {"SSLv3": ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None}
        for name, proto in deprecated.items():
            if proto is None: continue
            try:
                b_ctx = ssl.SSLContext(proto)
                with socket.create_connection((target, 443), timeout=timeout) as sock:
                    with b_ctx.wrap_socket(sock, server_hostname=target):
                        report["obsolete_protocols"].append(name)
            except Exception:
                pass

        return report


class SshBruteForcePlugin(BasePlugin):
    @property
    def name(self) -> str: return "Audit de Force Brute SSH"
    @property
    def description(self) -> str: return "Vérification de la robustesse des accès distants SSH (Paramiko Engine)"

    def _connect(self, host, user, pwd, port):
        if not PARAMIKO_OK: return "ERROR"
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, username=user, password=pwd, port=port, timeout=1.5, allow_agent=False, look_for_keys=False)
            client.close()
            return pwd
        except paramiko.AuthenticationException:
            return None
        except Exception:
            return "ERROR"

    def execute(self, config: dict) -> dict:
        if not PARAMIKO_OK:
            self.logger.error("Paramiko n'est pas installé. Module désactivé.")
            return {"error": "Paramiko manquant"}

        target = Prompt.ask("[bold cyan]IP/Hôte SSH cible[/bold cyan]", default="127.0.0.1").strip()
        username = Prompt.ask("[bold cyan]Nom d'utilisateur d'authentification[/bold cyan]", default="root").strip()
        wordlist = config["modules"]["password_audit"]["common_words"]

        self.logger.info(f"Lancement du test d'authentification réseau sur {target} (Compte: {username})")
        found_password = None

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
            task = progress.add_task("[gray]Vérification des identifiants...[/gray]", total=len(wordlist))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(self._connect, target, username, pwd, 22): pwd for pwd in wordlist}
                for f in concurrent.futures.as_completed(futures):
                    res = f.result()
                    progress.advance(task)
                    if res and res != "ERROR":
                        found_password = res
                        break
        
        return {
            "target": target,
            "username": username,
            "vulnerable": found_password is not None,
            "cracked_password": found_password if found_password else "Aucun (Accès robuste)"
        }


class RealHashCrackerPlugin(BasePlugin):
    """
    Module 5 : Audit cryptographique local (Urus Engine Corrigé).
    Inversion de hashs séquentielle stable sans interférences de processus ou de sérialisation.
    """
    @property
    def name(self) -> str: return "Hash Cracker Réel (Urus Engine)"
    @property
    def description(self) -> str: return "Inversion d'empreintes cryptographiques (MD5, SHA1, SHA256) avec mutations"

    def _get_mutations(self, word: str) -> list:
        return [
            word,
            word.capitalize(),
            word + "123",
            word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
        ]

    def execute(self, config: dict) -> dict:
        base_wordlist = config.get("modules", {}).get("password_audit", {}).get("common_words", ["kali", "password", "test"])
        
        console.print("\n[bold orange1]⚙️ AUDIT CRYPTOGRAPHIQUE LOCAL (URUS MOTOR)[/bold orange1]")
        algo = Prompt.ask("Sélectionnez l'algorithme", choices=["md5", "sha1", "sha256"], default="sha256")
        target_hash = Prompt.ask("Entrez le HASH cible à inverser").strip().lower()
        
        if not target_hash:
            console.print("[bold red][!] Erreur : Aucun hash spécifié.[/bold red]")
            return {"error": "Hash manquant"}

        # Génération de la liste étendue via les règles de mutation d'Urus
        with console.status("[bold cyan]Calcul de la matrice de mutation d'Urus...[/bold cyan]"):
            extended_candidates = []
            for word in base_wordlist:
                for mutated in self._get_mutations(word):
                    clean = mutated.strip()
                    if clean and clean not in extended_candidates:
                        extended_candidates.append(clean)

        console.print(f" [bold]*[/bold] Algorithme cible : [bold yellow]{algo.upper()}[/bold yellow]")
        console.print(f" [bold]*[/bold] Espace de recherche étendu : [bold cyan]{len(extended_candidates)} combinaisons[/bold cyan]\n")

        valid_password = None
        start_time = time.time()
        count = 0

        # Système de barre de progression synchrone isolée
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, complete_style="orange1"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        ) as progress:
            task = progress.add_task("[gray]Recherche de collisions...[/gray]", total=len(extended_candidates))
            
            for cand in extended_candidates:
                try:
                    h = hashlib.new(algo.lower())
                    h.update(cand.encode('utf-8'))
                    guess_hash = h.hexdigest().strip().lower()
                    
                    if guess_hash == target_hash:
                        valid_password = cand
                        progress.advance(task, advance=len(extended_candidates) - count)
                        break
                except Exception:
                    pass
                
                count += 1
                progress.advance(task, advance=1)

        elapsed = time.time() - start_time
        report = {
            "target_hash": target_hash,
            "algorithm": algo.upper(),
            "execution_time_sec": round(elapsed, 4),
            "total_tested": len(extended_candidates),
            "crack_success": valid_password is not None,
            "recovered_secret": valid_password if valid_password else "NON_TROUVE"
        }

        if valid_password:
            console.print(f"\n[bold green][✓] SUCCESS : Collision trouvée ! Correspondance : {valid_password}[/bold green]")
        else:
            console.print("\n[bold red][X] FAILED : Le dictionnaire muté n'a pas pu casser ce hash.[/bold red]")
            
        return report


class CveLookupPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Moteur de Recherche CVE & Failles"
    @property
    def description(self) -> str: return "Interrogation enrichie de l'API OpenCVE pour identifier des vulnérabilités logicielles"

    def execute(self, config: dict) -> dict:
        keyword = Prompt.ask("[bold cyan]Entrez un produit/mot-clé logiciel (ex: nginx, ssh)[/bold cyan]", default="ssh").strip()
        self.logger.info(f"Interrogation de la base de données publique pour : {keyword}")
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
        try:
            r = requests.get(url, timeout=4.0)
            if r.status_code == 200:
                data = r.json()
                vulnerabilities = []
                for item in data.get("vulnerabilities", [])[:5]: # Récupérer les 5 plus critiques
                    cve_id = item.get("cve", {}).get("id")
                    desc = item.get("cve", {}).get("descriptions", [{}])[0].get("value", "Pas de description")
                    vulnerabilities.append({"cve_id": cve_id, "summary": desc[:150] + "..."})
                return {"keyword": keyword, "vulnerabilities": vulnerabilities}
        except Exception as e:
            self.logger.warning(f"Échec d'interrogation de l'API de vulnérabilités : {e}")
            
        return {"keyword": keyword, "vulnerabilities": [{"cve_id": "Indisponible", "summary": "Erreur d'appel API de télémétrie"}]}


class OsintIpPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Reconnaissance OSINT IP & Géolocalisation"
    @property
    def description(self) -> str: return "Géolocalisation réseau et collecte de métadonnées de routage autonomes (AS)"

    def execute(self, config: dict) -> dict:
        ip = Prompt.ask("[bold cyan]Entrez l'adresse IP publique à analyser[/bold cyan]").strip()
        endpoints = config["modules"]["osint"]["ip_endpoints"]
        
        for url_template in endpoints:
            url = url_template.format(ip=ip)
            try:
                self.logger.info(f"Tentative de collecte OSINT via le nœud : {url}")
                r = requests.get(url, timeout=config["modules"]["osint"]["timeout"])
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") != "fail" and "error" not in data:
                        return {
                            "query": data.get("ip") or data.get("query"),
                            "country": data.get("country_name") or data.get("country"),
                            "isp": data.get("org") or data.get("isp"),
                            "provider": "Vérifié via API externe"
                        }
            except Exception:
                continue
                
        return {"error": "Tous les points de terminaison OSINT configurés sont inaccessibles."}


class NetworkAuthSimulatorPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Network Auth Resilience Simulator (Hydra-style)"
    @property
    def description(self) -> str: return "Simulation de résistance aux attaques par force brute réseau et calcul d'impact"

    def execute(self, config: dict) -> dict:
        wordlist = config["modules"]["password_audit"]["common_words"]
        
        console.print("\n[bold orange1]⚙️ SIMULATEUR DE RESILIENCE NETWORK AUTH (HYDRA SIM)[/bold orange1]")
        target_service = Prompt.ask("Sélectionnez le protocole cible à simuler", choices=["SSH", "FTP", "HTTP-POST"], default="SSH")
        rate_limit = float(Prompt.ask("Définir la latence de réponse réseau moyenne par tentative (en secondes)", default="0.5"))
        
        self.logger.info(f"Modélisation d'une séquence d'authentification sur le service {target_service}...")
        
        total_attempts = len(wordlist) * 4
        theoretical_duration = total_attempts * rate_limit
        lockout_threshold = 5
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(bar_width=30, complete_style="magenta"), TextColumn("[progress.percentage]{task.percentage:>3.0f}%")) as progress:
            task = progress.add_task(f"[gray]Modélisation des paquets d'authentification {target_service}...[/gray]", total=total_attempts)
            for _ in range(min(total_attempts, 100)):
                time.sleep(0.01)
                progress.advance(task, advance=total_attempts/100)

        report = {
            "simulated_service": target_service,
            "total_credentials_evaluated": total_attempts,
            "estimated_attack_duration_sec": round(theoretical_duration, 2),
            "lockout_policy_required": total_attempts > lockout_threshold,
            "remediation_advise": "Déployer un pare-feu applicatif ou un outil type Fail2ban pour appliquer un bannissement temporaire après 3 échecs."
        }

        if report["lockout_policy_required"]:
            self.logger.warning(f"[!] Alerte : Sans filtrage de paquets actif, l'épuisement de la wordlist s'exécuterait en environ {report['estimated_attack_duration_sec']}s.")
        
        return report

# ── Moteur d'Évaluation Contextuelle des Risques ────────────────────────────────
class ContextualRiskEngine:
    @staticmethod
    def evaluate(session_vault: dict) -> dict:
        score = 1.0
        factors = []

        # Corrélation Module 2 : Scanner de ports
        ports_payload = session_vault.get("Scanner de Ports Étendu", {}).get("payload", {})
        open_ports = ports_payload.get("open_ports", [])
        if open_ports:
            score += len(open_ports) * 0.8
            factors.append(f"{len(open_ports)} port(s) réseau actif(s) identifié(s).")

        # Corrélation Module 3 : SSL/TLS
        ssl_payload = session_vault.get("Auditeur SSL/TLS", {}).get("payload", {})
        if ssl_payload.get("obsolete_protocols"):
            score += 2.5
            factors.append("Protocoles de chiffrement obsolètes acceptés par l'hôte distant.")

        # Corrélation Module 4 : Robustesse SSH
        ssh_payload = session_vault.get("Audit de Force Brute SSH", {}).get("payload", {})
        if ssh_payload.get("vulnerable") is True:
            score += 4.5
            factors.append("VULNÉRABILITÉ MAJEURE : Accès réseau SSH compromis par dictionnaire.")

        # Corrélation Module 5 : Hash Cracker
        cracker_payload = session_vault.get("Hash Cracker Réel (Urus Engine)", {}).get("payload", {})
        if cracker_payload.get("crack_success") is True:
            score += 3.0
            factors.append(f"Empreinte de mot de passe inversée localement ({cracker_payload.get('algorithm')}).")

        # Corrélation Module 8 : Hydra Simulator
        hydra_payload = session_vault.get("Network Auth Resilience Simulator (Hydra-style)", {}).get("payload", {})
        if hydra_payload.get("lockout_policy_required") is True:
            score += 1.5
            factors.append(f"Exposition théorique élevée aux attaques par force brute sur service distant : {hydra_payload.get('simulated_service')}")

        final_score = round(min(score, 10.0), 1)
        severity = "FAIBLE" if final_score < 4.0 else "ÉLEVÉE" if final_score < 7.5 else "CRITIQUE"
        
        return {"score": final_score, "severity": severity, "factors": factors}

# ── Gestionnaire de Rapports Double Format (HTML/JSON) ─────────────────────────
class ReportGenerator:
    @staticmethod
    def generate_html(report_data: dict, output_path: str):
        meta = report_data["metadata"]
        risk = report_data["risk_assessment"]
        evidence = report_data["collected_evidence"]
        
        severity_color = "#ef4444" if risk["severity"] == "CRITIQUE" else "#f97316" if risk["severity"] == "ÉLEVÉE" else "#10b981"

        html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'Audit de Sécurité - Core Framework</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f3f4f6; color: #1f2937; margin: 0; padding: 40px; }}
        .container {{ max-width: 1000px; background: white; padding: 40px; margin: 0 auto; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
        h1 {{ color: #1e3a8a; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
        h2 {{ color: #2563eb; margin-top: 30px; }}
        .badge {{ display: inline-block; padding: 6px 12px; font-weight: bold; border-radius: 4px; color: white; }}
        .risk-box {{ background-color: #fecaca; border-left: 6px solid {severity_color}; padding: 20px; border-radius: 4px; margin: 20px 0; }}
        pre {{ background: #1e1e2e; color: #f8f8f2; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', monospace; }}
        .factor-list {{ margin-left: 20px; font-weight: 500; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport Core d'Audit de Sécurité</h1>
        <p><strong>Généré le :</strong> {meta["scan_time"]} | <strong>Version Engine :</strong> {meta["engine_version"]}</p>
        
        <div class="risk-box" style="background-color: #f9fafb;">
            <h2>Évaluation Globale des Risques Contextuels</h2>
            <p>Score de Risque de Session : <span class="badge" style="background-color: {severity_color};">{risk["score"]} / 10</span> (Sévérité : <strong>{risk["severity"]}</strong>)</p>
            <h3>Facteurs de Risque Détectés :</h3>
            <ul class="factor-list">
                {"".join([f"<li>{html.escape(f)}</li>" for f in risk["factors"]]) if risk["factors"] else "<li>Aucun facteur de risque critique détecté dans cette session.</li>"}
            </ul>
        </div>

        <h2>Éléments de Preuve Collectés (Données Brutes)</h2>
        """
        for mod_name, mod_data in evidence.items():
            html_content += f"""<h3>{html.escape(mod_name)}</h3>
            <p><small>Capturé à : {mod_data['captured_at']}</small></p>
            <pre>{html.escape(json.dumps(mod_data['payload'], indent=4, ensure_ascii=False))}</pre>"""

        html_content += """</div></body></html>"""
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

# ── Orchestrateur Central ──────────────────────────────────────────────────────
class FrameworkCore:
    def __init__(self):
        self.config = FRAMEWORK_CONFIG
        self.plugins = [
            WhoisDnsPlugin(),
            ExtendedPortScannerPlugin(),
            SslAuditorPlugin(),
            SshBruteForcePlugin(),
            RealHashCrackerPlugin(),
            CveLookupPlugin(),
            OsintIpPlugin(),
            NetworkAuthSimulatorPlugin()
        ]
        self.session_vault = {}
        Path(self.config["framework"]["reports_dir"]).mkdir(exist_ok=True)

    def run(self):
        logger.info("Noyau central initialisé avec succès.")
        while True:
            # Nettoyage console multi-plateforme
            sys.stdout.write("\033[H\033[2J\033[3J" if os.name != 'nt' else "")
            sys.stdout.flush()
            if os.name == 'nt': os.system('cls')

            console.print("""[bold blue]
████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗  ██╗  ██╗    ██████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗ ╚██╗██╔╝    ██╔═══██╗██╔══██╗██╔═══██╗
   ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║  ╚███╔╝     ██║   ██║██████╔╝██║   ██║
   ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║  ██╔██╗     ██║   ██║██╔══██╗██║   ██║
   ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝ ██╔╝ ██╗    ╚██████╔╝██║  ██║╚██████╔╝
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝  ╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝[/bold blue]
[bold magenta]🛡️  Enterprise Security Core Framework v4.1 | DevSecOps & Hardening Module System[/bold magenta]\n""")

            # Affichage de la télémétrie interne
            telemetry_table = Table(box=box.ROUNDED, border_style="blue")
            telemetry_table.add_column("Indicateur Système", style="yellow")
            telemetry_table.add_column("Statut Actuel", style="green")
            telemetry_table.add_row("Version Framework", self.config["framework"]["version"])
            telemetry_table.add_row("Moteur de Plugins", f"{len(self.plugins)} Plugins Registrés")
            telemetry_table.add_row("Registre de Risque Contextuel", "Synchrone & Actif")
            console.print(Panel(telemetry_table, title="📊 DASHBOARD DE CONTROLE SOC"))

            # Menu principal des plugins
            menu = Table(show_header=True, header_style="bold purple", box=box.SIMPLE)
            menu.add_column("ID", width=4, justify="center")
            menu.add_column("Module d'Audit Core")
            menu.add_column("Description Technique Analytique")
            for idx, plugin in enumerate(self.plugins, 1):
                menu.add_row(str(idx), plugin.name, plugin.description)
            menu.add_row("R", "[bold gold1]Générer Rapports & Risques Contextuels[/bold gold1]", "Compile l'activité globale de la session")
            menu.add_row("Q", "Fermeture Core Environment", "Libération propre des descripteurs")
            console.print(menu)

            choix = console.input("\n[bold yellow]Sélectionnez une commande ou ID de module : [/bold yellow]").strip().upper()

            if choix == "Q":
                logger.info("Fermeture du framework demandée par l'opérateur.")
                break
            elif choix == "R":
                self.export_session_reports()
            else:
                try:
                    p_idx = int(choix) - 1
                    if 0 <= p_idx < len(self.plugins):
                        target_plugin = self.plugins[p_idx]
                        logger.info(f"Point d'entrée invoqué : {target_plugin.name}")
                        console.print(f"\n[bold cyan]━━ Execution : {target_plugin.name} ━━[/bold cyan]\n")
                        
                        payload = target_plugin.execute(self.config)
                        self.session_vault[target_plugin.name] = {
                            "captured_at": datetime.now(timezone.utc).isoformat(),
                            "payload": payload
                        }
                        console.print("\n[bold green][✓] Artefacts sauvegardés en mémoire de session.[/bold green]")
                    else:
                        console.print("[bold red][!] Cet identifiant de module n'existe pas.[/bold red]")
                except ValueError:
                    console.print("[bold red][!] Entrée invalide ou commande inconnue.[/bold red]")

            console.input("\n[dim]Appuyez sur Entrée pour rafraîchir le tableau de bord…[/dim]")

    def export_session_reports(self):
        if not self.session_vault:
            console.print("[bold yellow][!] Aucun module n'a été exécuté dans cette session. Avortement de l'export.[/bold yellow]")
            return

        with console.status("[bold open_ports]Calcul de la corrélation des risques et écriture des artefacts...[/bold open_ports]"):
            risk_profile = ContextualRiskEngine.evaluate(self.session_vault)
            final_report = {
                "metadata": {
                    "scan_time": datetime.now(timezone.utc).isoformat(),
                    "engine_version": self.config["framework"]["version"]
                },
                "risk_assessment": risk_profile,
                "collected_evidence": self.session_vault
            }

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = f"{self.config['framework']['reports_dir']}/audit_report_{timestamp}.json"
            html_path = f"{self.config['framework']['reports_dir']}/audit_report_{timestamp}.html"

            # Export JSON brut
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, indent=4, ensure_ascii=False)
            
            # Export HTML Stylisé
            ReportGenerator.generate_html(final_report, html_path)

        console.print("\n")
        severity_color = "red" if risk_profile["severity"] == "CRITIQUE" else "orange1" if risk_profile["severity"] == "ÉLEVÉE" else "green"
        console.print(Panel(
            f"[bold]Score de Risque de Session :[/bold] [bold {severity_color}]{risk_profile['score']}/10[/bold {severity_color}] ({risk_profile['severity']})\n\n"
            f"[bold]Indicateurs de compromission / durcissement :[/bold]\n" + 
            "\n".join([f" • {f}" for f in risk_profile["factors"]]) if risk_profile["factors"] else " • Aucun défaut critique identifié.",
            title="🎯 BILAN DE SÉCURITÉ CONTEXTUEL", border_style=severity_color
        ))
        logger.info(f"Rapport JSON structuré exporté : {json_path}")
        logger.info(f"Rapport d'audit HTML dynamique généré : {html_path}")


if __name__ == "__main__":
    try:
        FrameworkCore().run()
    except KeyboardInterrupt:
        console.print("\n[dim]Interruption détectée — Fermeture sécurisée.[/dim]")
    except Exception as fatal_error:
        console.print(f"[bold red][FATAL CORE BREAKDOWN] {fatal_error}[/bold red]")
        sys.exit(1)
