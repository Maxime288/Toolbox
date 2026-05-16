#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
⚙️ SECURITY TOOLBOX FRAMEWORK v3.0 (Monolithic Core Edition)
Standard de l'industrie : POO, Concurrence, Fallback API, Contextual Risk Engine & Logs.
"""

import os
import sys
import time
import json
import socket
import ssl
import hashlib
import logging
import concurrent.futures
from abc import ABC, abstractmethod
from datetime import datetime

# Importations sécurisées de la suite Rich pour l'UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.logging import RichHandler
except ImportError:
    print("[!] Erreur : La bibliothèque 'rich' est requise. Installez-la via 'pip install rich'")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Erreur : La bibliothèque 'requests' est requise. Installez-la via 'pip install requests'")
    sys.exit(1)

# =====================================================================
# 1. EMULATION DU CONFIGURATION ENGINE (Yaml-Like embedded dict)
# =====================================================================
FRAMEWORK_CONFIG = {
    "framework": {
        "version": "3.0.0-ENTERPRISE (All-In-One)",
        "reports_dir": "reports",
        "log_file": "framework.log"
    },
    "modules": {
        "network_scan": {
            "timeout": 1.5,
            "max_workers": 20,
            "target_ports": [21, 22, 80, 443, 8080]
        },
        "password_audit": {
            "common_words": ["123456", "password", "admin", "secret", "password123", "qwerty"]
        },
        "osint_ip": {
            "timeout": 3,
            "endpoints": [
                "https://ipapi.co/{ip}/json/",
                "http://ip-api.com/json/{ip}"
            ]
        }
    }
}

# =====================================================================
# 2. CONFIGURATION DU LOGGING SYSTÈME STRUCTURÉ
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler(FRAMEWORK_CONFIG["framework"]["log_file"], encoding="utf-8")
    ]
)
logger = logging.getLogger("FrameworkPro")
console = Console()


# =====================================================================
# 3. INTERFACE ABSTRAITE (BASE PLUGIN PATTERN)
# =====================================================================
class BasePlugin(ABC):
    def __init__(self):
        self.logger = logging.getLogger("FrameworkPro")

    @property
    @abstractmethod
    def name(self) -> str: pass

    @property
    @abstractmethod
    def description(self) -> str: pass

    @abstractmethod
    def execute(self, config: dict) -> dict: pass


# =====================================================================
# 4. IMPLÉMENTATION DES PLUGINS DE SÉCURITÉ
# =====================================================================

class NetworkScannerPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Scanner Réseau & Services"
    @property
    def description(self) -> str: return "Scanner TCP avec Fingerprinting ciblé par protocole (HTTP/SSH/TLS)"

    def _probe(self, target: str, port: int, timeout: float) -> dict:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    self.logger.info(f"[🔬] Port {port} ouvert détecté sur {target}")
                    banner = ""
                    # Protocol-Aware Fingerprinting sans blocage de socket
                    if port == 80:
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                        banner = s.recv(512).decode(errors='ignore').split('\r\n')[0]
                    elif port == 443:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                        with ctx.wrap_socket(s, server_hostname=target) as ss:
                            banner = f"TLS Handshake Réussi ({ss.version()})"
                    elif port in [21, 22]:
                        banner = s.recv(512).decode(errors='ignore').strip()
                    return {"port": port, "status": "OPEN", "banner": banner}
        except (socket.timeout, socket.error) as e:
            self.logger.debug(f"Erreur socket port {port}: {e}")
        return {}

    def execute(self, config: dict) -> dict:
        mod_cfg = config["modules"]["network_scan"]
        target = Prompt.ask("[bold cyan]Cible d'analyse (IP/Domaine)[/bold cyan]", default="127.0.0.1")
        results = []

        self.logger.info(f"Lancement du scan asynchrone sur {target}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=mod_cfg["max_workers"]) as executor:
            futures = [executor.submit(self._probe, target, p, mod_cfg["timeout"]) for p in mod_cfg["target_ports"]]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res: results.append(res)

        return {"target": target, "open_ports": results}


class PasswordAuditPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Password Audit Simulator"
    @property
    def description(self) -> str: return "Évaluation de la robustesse des identifiants (Wordlist Matcher)"

    def execute(self, config: dict) -> dict:
        mod_cfg = config["modules"]["password_audit"]
        pwd = Prompt.ask("[bold cyan]Mot de passe à auditer[/bold cyan]", password=True)
        
        self.logger.info("Début de la séquence d'audit de mot de passe.")
        start = time.time()
        success = pwd in mod_cfg["common_words"]
        elapsed = time.time() - start
        
        return {
            "audit_success": success,
            "execution_time_sec": round(elapsed, 5),
            "verdict": "CRITIQUE / COMPROMIS" if success else "NON_DETECTE"
        }


class OsintIpPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Module OSINT Réseau"
    @property
    def description(self) -> str: return "Géolocalisation et métadonnées IP avec Fallback dynamique"

    def execute(self, config: dict) -> dict:
        mod_cfg = config["modules"]["osint_ip"]
        ip = Prompt.ask("[bold cyan]Entrez l'IP publique à analyser[/bold cyan]", default="")
        
        # Abstraction layer & Multi-API Routing Loop
        for endpoint in mod_cfg["endpoints"]:
            url = endpoint.format(ip=ip)
            try:
                self.logger.info(f"Requête nœud OSINT vers : {url}")
                r = requests.get(url, timeout=mod_cfg["timeout"])
                if r.status_code == 200:
                    data = r.json()
                    if "error" not in data and data.get("status") != "fail":
                        return {
                            "query": data.get("ip") or data.get("query"),
                            "isp": data.get("org") or data.get("isp"),
                            "country": data.get("country_name") or data.get("country"),
                            "resolved_via": url.split('/')[2]
                        }
            except requests.RequestException as e:
                self.logger.warning(f"Échec de bascule sur le nœud {url} : {type(e).__name__}")
                
        return {"error": "Tous les nœuds OSINT configurés sont hors-ligne"}


# =====================================================================
# 5. MOTEUR DE CORRÉLATION DE CONTEXTE ET RISQUE (RISK ENGINE)
# =====================================================================
class ContextualRiskEngine:
    @staticmethod
    def evaluate(session_vault: dict) -> dict:
        """ Algorithme de calcul de risque basé sur le croisement des findings """
        base_score = 1.0
        indicators = []

        # Facteur de corrélation 1 : Ports ouverts détectés
        net_data = session_vault.get("Scanner Réseau & Services", {}).get("payload", {})
        open_ports = net_data.get("open_ports", [])
        if open_ports:
            base_score += len(open_ports) * 1.2
            indicators.append(f"{len(open_ports)} port(s) actif(s) sur la cible réseau")

        # Facteur de corrélation 2 : Mot de passe compromis détecté
        audit_data = session_vault.get("Password Audit Simulator", {}).get("payload", {})
        if audit_data.get("audit_success") is True:
            base_score += 4.5
            indicators.append("Identifiant critique présent dans les bases de fuites de données")

        # Normalisation mathématique (Score plafonné à 10.0)
        final_score = round(min(base_score, 10.0), 1)
        
        if final_score < 4.0: severity = "FAIBLE"
        elif final_score < 7.5: severity = "ÉLEVÉE"
        else: severity = "CRITIQUE"

        return {
            "risk_score_cvss": final_score,
            "severity": severity,
            "risk_factors": indicators
        }


# =====================================================================
# 6. ORCHESTRATEUR CENTRAL (CORE ENGINE & SOC DASHBOARD)
# =====================================================================
class FrameworkCore:
    def __init__(self):
        self.config = FRAMEWORK_CONFIG
        
        # Simulation d'Auto-Discovery (Registre interne par inspection de classe)
        self.plugins = [
            NetworkScannerPlugin(),
            PasswordAuditPlugin(),
            OsintIpPlugin()
        ]
        
        # Base de données temporaire de session (State Vault)
        self.session_vault = {}
        os.makedirs(self.config["framework"]["reports_dir"], exist_ok=True)

    def display_banner(self):
        banner = """[bold blue]
████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗  ██╗  ██╗    ██████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗ ╚██╗██╔╝    ██╔═══██╗██╔══██╗██╔═══██╗
   ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║  ╚███╔╝     ██║   ██║██████╔╝██║   ██║
   ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║  ██╔██╗     ██║   ██║██╔══██╗██║   ██║
   ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝ ██╔╝ ██╗    ╚██████╔╝██║  ██║╚██████╔╝
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝  ╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝[/bold blue]
   [bold magenta]🛡️  Enterprise Security Core Framework v3.0 | Portfolio Architecture[/bold magenta]
        """
        console.print(banner)

    def display_soc_dashboard(self):
        """ Rendu UI d'un tableau de bord d'analyste SOC """
        table = Table(title="📊 TELEMETRIE CORE SYSTEM", title_style="bold cyan")
        table.add_column("Composant Système", style="yellow")
        table.add_column("Statut Runtime", style="green")
        
        table.add_row("Framework Version", self.config["framework"]["version"])
        table.add_row("Auto-Discovery Engine", f"{len(self.plugins)} Modules chargés")
        table.add_row("Contextual Risk Engine", "Online & Synchronisé")
        table.add_row("Fichier de journalisation", self.config["framework"]["log_file"])
        
        console.print(Panel(table, border_style="blue"))

    def finalize_report(self):
        """ Compile les résultats, calcule les risques et exporte en JSON """
        if not self.session_vault:
            logger.warning("Session vide. Aucun artefact n'a été généré pour le rapport.")
            return

        # Calcul du score croisé via le Risk Engine
        risk_profile = ContextualRiskEngine.evaluate(self.session_vault)
        
        report_data = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "engine_version": self.config["framework"]["version"]
            },
            "risk_assessment": risk_profile,
            "collected_evidence": self.session_vault
        }

        filename = f"{self.config['framework']['reports_dir']}/security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

        # Rendu visuel du rapport de risque
        console.print("\n")
        console.print(Panel(
            f"[bold]Score de Risque Global :[/bold] [bold red]{risk_profile['risk_score_cvss']}/10[/bold red]\n"
            f"[bold]Niveau de Sévérité :[/bold] {risk_profile['severity']}\n"
            f"[bold]Déclencheurs contextuels :[/bold]\n" + "\n".join([f" • {f}" for f in risk_profile['risk_factors']]),
            title="🎯 CONTEXTUAL RISK ASSESSMENT", border_style="red"
        ))
        logger.info(f"Rapport global de corrélation exporté : {filename}")

    def run(self):
        logger.info("Initialisation du noyau central réussie.")
        while True:
            console.clear()
            self.display_banner()
            self.display_soc_dashboard()

            # Menu de routage dynamique
            menu = Table(show_header=True, header_style="bold purple")
            menu.add_column("ID", width=4)
            menu.add_column("Module Core")
            menu.add_column("Description Architecturale")
            
            for i, p in enumerate(self.plugins, 1):
                menu.add_row(str(i), p.name, p.description)
            menu.add_row("R", "[bold gold1]Générer Rapport & Risque Contextuel[/bold gold1]", "Corrèle les modules de la session")
            menu.add_row("Q", "Shutdown Core", "Fermeture propre du système")
            
            console.print(menu)
            choix = console.input("\n[bold yellow]Sélectionnez une instruction : [/bold yellow]").strip().upper()

            if choix == "Q":
                logger.info("Arrêt du framework demandé par l'opérateur.")
                break
            elif choix == "R":
                self.finalize_report()
            else:
                try:
                    idx = int(choix) - 1
                    if 0 <= idx < len(self.plugins):
                        plugin = self.plugins[idx]
                        logger.info(f"Appel d'exécution du module : {plugin.name}")
                        
                        # Exécution isolée du plugin et archivage
                        raw_result = plugin.execute(self.config)
                        self.session_vault[plugin.name] = {
                            "captured_at": datetime.now().isoformat(),
                            "payload": raw_result
                        }
                        console.print("\n[bold green][✓] Télémétrie enregistrée dans la session.[/bold green]")
                except (ValueError, IndexError):
                    logger.error("Entrée utilisateur corrompue ou ID hors limites.")
            
            console.input("\n[cyan]Appuyez sur [Entrée] pour rafraîchir le dashboard...[/cyan]")


# =====================================================================
# 7. POINT D'ENTRÉE DU RUNTIME
# =====================================================================
if __name__ == "__main__":
    try:
        framework = FrameworkCore()
        framework.run()
    except Exception as fatal_error:
        print(f"[CRITICAL] Crash majeur de l'orchestrateur : {fatal_error}")
        sys.exit(1)
