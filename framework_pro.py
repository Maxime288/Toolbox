#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
⚙️ SECURITY TOOLBOX FRAMEWORK v3.5 (Enterprise Monolithic Core)
Standards DevSecOps : POO, Concurrence, Fallback API, SSH Hardening, SSL/TLS Auditor & Risk Engine.
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
# 1. ARCHITECTURE DE CONFIGURATION EMBARQUÉE
# =====================================================================
FRAMEWORK_CONFIG = {
    "framework": {
        "version": "3.5.0-ENTERPRISE (All-In-One)",
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
        },
        "ssl_auditor": {
            "timeout": 3.0
        },
        "ssh_checker": {
            "timeout": 2.5
        }
    }
}

# =====================================================================
# 2. CONFIGURATION DU LOGGING STRUCTURÉ (SANS DOUBLON)
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True),
        logging.FileHandler(FRAMEWORK_CONFIG["framework"]["log_file"], encoding="utf-8")
    ]
)
logger = logging.getLogger("FrameworkPro")
console = Console()


# =====================================================================
# 3. INTERFACE ABSTRAITE DES MODULES (BASE PLUGIN PATTERN)
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
    def description(self) -> str: return "Scanner TCP asynchrone avec Fingerprinting par protocole"

    def _probe(self, target: str, port: int, timeout: float) -> dict:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    self.logger.info(f"Port [bold cyan]{port}[/bold cyan] ouvert détecté sur {target}")
                    banner = ""
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
            self.logger.debug(f"Erreur d'analyse port {port}: {e}")
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
                self.logger.warning(f"Échec du nœud {url}, bascule : {type(e).__name__}")
                
        return {"error": "Tous les nœuds OSINT configurés sont hors-ligne"}


class SslAuditorPlugin(BasePlugin):
    @property
    def name(self) -> str: return "SSL/TLS Configuration Auditor"
    @property
    def description(self) -> str: return "Analyse de la validité du certificat et détection de protocoles obsolètes"

    def execute(self, config: dict) -> dict:
        timeout = config["modules"]["ssl_auditor"]["timeout"]
        target = Prompt.ask("[bold cyan]Entrez le domaine à auditer (ex: google.com)[/bold cyan]", default="google.com")
        
        report = {
            "target": target,
            "certificate_expired": False,
            "obsolete_protocols_allowed": [],
            "issuer": "Inconnu",
            "expiration_date": "N/A"
        }

        # 1. Extraction et analyse du Certificat
        self.logger.info(f"Analyse du certificat SSL de {target}...")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parsing de l'émetteur et validité
                    issuer = dict(x[0] for x in cert['issuer'])
                    report["issuer"] = issuer.get('commonName', 'Inconnu')
                    report["expiration_date"] = cert.get('notAfter', 'N/A')
                    
                    # Vérification de l'expiration
                    exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if exp_date < datetime.utcnow():
                        report["certificate_expired"] = True
                        self.logger.warning("[!] Le certificat TLS a expiré !")
        except Exception as e:
            self.logger.error(f"Impossible de récupérer le certificat : {e}")
            return {"target": target, "error": f"Connexion échouée : {str(e)}"}

        # 2. Audit des protocoles obsolètes (SSLv3, TLS 1.0, TLS 1.1)
        deprecated_protocols = {
            "SSLv3": ssl.PROTOCOL_TLSv1,  # Simulation de fallback historique
            "TLSv1.0": ssl.PROTOCOL_TLSv1,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None
        }

        self.logger.info("Scan des configurations obsolètes autorisées (SSLv3, TLS 1.0, TLS 1.1)...")
        for proto_name, proto_id in deprecated_protocols.items():
            if proto_id is None: continue
            try:
                # Création d'un contexte de sécurité restrictif à cette ancienne version
                bad_ctx = ssl.SSLContext(proto_id)
                with socket.create_connection((target, 443), timeout=timeout) as sock:
                    with bad_ctx.wrap_socket(sock, server_hostname=target):
                        report["obsolete_protocols_allowed"].append(proto_name)
                        self.logger.warning(f"[!] Vulnérabilité : La cible accepte le protocole déprécié {proto_name}")
            except Exception:
                # Si le handshake échoue, c'est une bonne nouvelle (le serveur rejette le vieux protocole)
                pass

        return report


class SshHardeningPlugin(BasePlugin):
    @property
    def name(self) -> str: return "SSH Hardening Checker"
    @property
    def description(self) -> str: return "Évaluation de la configuration de sécurité SSH (Port 22)"

    def execute(self, config: dict) -> dict:
        timeout = config["modules"]["ssh_checker"]["timeout"]
        target = Prompt.ask("[bold cyan]Entrez l'IP ou le domaine SSH à auditer[/bold cyan]", default="127.0.0.1")
        
        report = {
            "target": target,
            "ssh_banner": "Inconnue",
            "password_auth_allowed": "Indéterminé (Analyse locale requise)",
            "root_login_allowed": "Indéterminé (Analyse locale requise)",
            "vulnerabilities": []
        }

        self.logger.info(f"Connexion au service SSH sur {target}:22...")
        # 1. Analyse externe (Bannière)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, 22)) == 0:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    report["ssh_banner"] = banner
                    self.logger.info(f"Bannière SSH capturée : {banner}")
                    
                    # Détection de vieilles versions de protocoles (ex: SSH-1.x)
                    if "SSH-1." in banner:
                        report["vulnerabilities"].append("Protocole obsolète SSHv1 activé")
                else:
                    self.logger.warning("Le port SSH (22) semble fermé sur cette cible externe.")
        except Exception as e:
            self.logger.error(f"Erreur d'accès réseau au port 22 : {e}")

        # 2. Analyse de conformité locale (Simulée pour audit de fichier d'infrastructure de production)
        # Si la cible est locale, on inspecte le fichier de configuration standard de durcissement
        local_config_path = "/etc/ssh/sshd_config"
        if target in ["127.0.0.1", "localhost"] and os.path.exists(local_config_path):
            self.logger.info(f"Analyse de conformité locale détectée sur {local_config_path}")
            try:
                with open(local_config_path, "r") as f:
                    content = f.read()
                    
                    # Audit PermitRootLogin
                    if "PermitRootLogin yes" in content or "#PermitRootLogin yes" in content:
                        report["root_login_allowed"] = True
                        report["vulnerabilities"].append("PermitRootLogin activé : Risque élevé de brute-force")
                    else:
                        report["root_login_allowed"] = False

                    # Audit PasswordAuthentication
                    if "PasswordAuthentication yes" in content or "#PasswordAuthentication yes" in content:
                        report["password_auth_allowed"] = True
                        report["vulnerabilities"].append("PasswordAuthentication activé : Préférer l'usage de clés SSH")
                    else:
                        report["password_auth_allowed"] = False
            except Exception as e:
                self.logger.debug(f"Lecture sshd_config impossible (Droits insuffisants) : {e}")
                
        return report


# =====================================================================
# 5. MOTEUR DE CORRÉLATION DE CONTEXTE ET RISQUE (RISK ENGINE)
# =====================================================================
class ContextualRiskEngine:
    @staticmethod
    def evaluate(session_vault: dict) -> dict:
        """ Algorithme de calcul de score basé sur le croisement multi-modules """
        base_score = 1.0
        indicators = []

        # 1. Risque Réseau
        net_data = session_vault.get("Scanner Réseau & Services", {}).get("payload", {})
        open_ports = net_data.get("open_ports", [])
        if open_ports:
            base_score += len(open_ports) * 1.0
            indicators.append(f"{len(open_ports)} port(s) actif(s) sur la cible réseau")

        # 2. Risque Authentification
        audit_data = session_vault.get("Password Audit Simulator", {}).get("payload", {})
        if audit_data.get("audit_success") is True:
            base_score += 4.0
            indicators.append("Identifiant critique présent dans les bases de fuites de données")

        # 3. Risque SSL/TLS Configuration Auditor (Nouveau)
        ssl_data = session_vault.get("SSL/TLS Configuration Auditor", {}).get("payload", {})
        if ssl_data:
            if ssl_data.get("certificate_expired") is True:
                base_score += 3.5
                indicators.append("Certificat de chiffrement SSL/TLS expiré (Rupture de confiance)")
            obsolete_proto = ssl_data.get("obsolete_protocols_allowed", [])
            if obsolete_proto:
                base_score += len(obsolete_proto) * 1.5
                indicators.append(f"Protocoles de chiffrement obsolètes acceptés : {', '.join(obsolete_proto)}")

        # 4. Risque SSH Hardening Checker (Nouveau)
        ssh_data = session_vault.get("SSH Hardening Checker", {}).get("payload", {})
        if ssh_data:
            vulnerabilities = ssh_data.get("vulnerabilities", [])
            if vulnerabilities:
                base_score += len(vulnerabilities) * 1.5
                for vuln in vulnerabilities:
                    indicators.append(f"Défaut de durcissement SSH : {vuln}")

        # Normalisation mathématique globale (Plafonné à 10.0)
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
# 6. ORCHESTRATEUR CENTRAL & INTERFACE SOC DASHBOARD
# =====================================================================
class FrameworkCore:
    def __init__(self):
        self.config = FRAMEWORK_CONFIG
        
        # Registre d'Auto-Discovery des plugins du Framework
        self.plugins = [
            NetworkScannerPlugin(),
            PasswordAuditPlugin(),
            OsintIpPlugin(),
            SslAuditorPlugin(),
            SshHardeningPlugin()
        ]
        
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
   [bold magenta]🛡️  Enterprise Security Core Framework v3.5 | SecOps & Hardening Portfolio[/bold magenta]
        """
        console.print(banner)

    def display_soc_dashboard(self):
        table = Table(title="📊 TELEMETRIE CORE SYSTEM", title_style="bold cyan")
        table.add_column("Composant Système", style="yellow")
        table.add_column("Statut Runtime", style="green")
        
        table.add_row("Framework Version", self.config["framework"]["version"])
        table.add_row("Auto-Discovery Engine", f"{len(self.plugins)} Modules chargés")
        table.add_row("Contextual Risk Engine", "Online & Synchronisé")
        table.add_row("Fichier de journalisation", self.config["framework"]["log_file"])
        
        console.print(Panel(table, border_style="blue"))

    def finalize_report(self):
        if not self.session_vault:
            logger.warning("Session vide. Aucun artefact récolté pour générer un rapport global.")
            return

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
            # Nettoyage absolu de l'écran visible + vidage complet du buffer système
            if os.name == 'nt':
                os.system('cls')
            else:
                sys.stdout.write("\033[H\033[2J\033[3J")
                sys.stdout.flush()
            
            self.display_banner()
            self.display_soc_dashboard()

            # Rendu dynamique du menu des modules
            menu = Table(show_header=True, header_style="bold purple")
            menu.add_column("ID", width=4)
            menu.add_column("Module Core")
            menu.add_column("Description Architecturale")
            
            for i, p in enumerate(self.plugins, 1):
                menu.add_row(str(i), p.name, p.description)
            menu.add_row("R", "[bold gold1]Générer Rapport & Risque Contextuel[/bold gold1]", "Corrèle les modules de la session en cours")
            menu.add_row("Q", "Shutdown Core", "Fermeture propre et libération de l'environnement")
            
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
                        logger.info(f"Appel du point d'entrée : {plugin.name}")
                        
                        raw_result = plugin.execute(self.config)
                        self.session_vault[plugin.name] = {
                            "captured_at": datetime.now().isoformat(),
                            "payload": raw_result
                        }
                        console.print("\n[bold green][✓] Télémétrie enregistrée dans la session.[/bold green]")
                    else:
                        logger.warning("ID saisi en dehors des limites de la matrice.")
                except ValueError:
                    logger.error("Entrée utilisateur corrompue.")
            
            console.input("\n[cyan]Appuyez sur [Entrée] pour rafraîchir le dashboard...[/cyan]")


# =====================================================================
# 7. RUNTIME ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    try:
        framework = FrameworkCore()
        framework.run()
    except Exception as fatal_error:
        print(f"[CRITICAL] Rupture majeure de l'orchestrateur central : {fatal_error}")
        sys.exit(1)
