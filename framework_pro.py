#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
⚙️  ENTERPRISE SECURITY CORE FRAMEWORK v5.0
Standards DevSecOps : Architecture Plugin, Concurrence, TLS Audit,
SSH Real Brute-Force, Port Scanner étendu, Hash Cracker réel,
CVE Lookup (NVD), Web Scanner HTTP, Email Security Auditor,
Firewall Prober, Rapport HTML + PDF professionnel.

Usage légitime uniquement — sur systèmes avec autorisation écrite.
"""

import os
import re
import math
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

try:
    from fpdf import FPDF
    FPDF_OK = True
except ImportError:
    FPDF_OK = False

# ── Configuration centrale ─────────────────────────────────────────────────────
FRAMEWORK_CONFIG = {
    "framework": {
        "version": "5.0.0-ENTERPRISE",
        "reports_dir": "reports",
        "log_file":    "framework.log",
    },
    "modules": {
        "network_scan": {
            "timeout":     1.2,
            "max_workers": 150,
            "default_ports": [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                443, 445, 993, 995, 1080, 1433, 1521, 2222, 3306,
                3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017
            ],
        },
        "osint_ip": {
            "timeout": 5,
            "endpoints": [
                "https://ipapi.co/{ip}/json/",
                "http://ip-api.com/json/{ip}?fields=66846719",
            ],
        },
        "ssl_auditor": {"timeout": 4.0},
        "ssh_brute":   {"timeout": 10, "max_workers": 1, "delay": 0.3},
        "hash_cracker": {
            "algorithms": ["md5", "sha1", "sha224", "sha256", "sha512"],
            "mutations": True,
        },
        "dns_recon":    {"timeout": 3},
        "cve_lookup":   {"timeout": 8},
        "web_scanner":  {"timeout": 5, "max_workers": 15},
        "email_audit":  {"timeout": 4},
        "firewall":     {"timeout": 1.5},
    },
}

# ── Logging ────────────────────────────────────────────────────────────────────
Path(FRAMEWORK_CONFIG["framework"]["reports_dir"]).mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True, markup=True, show_path=False),
        logging.FileHandler(FRAMEWORK_CONFIG["framework"]["log_file"], encoding="utf-8"),
    ],
)
logger  = logging.getLogger("ESF")
console = Console()

# ── Utilitaires ────────────────────────────────────────────────────────────────
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2222: "SSH-alt",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}

LEET = str.maketrans("aeiloAEILO", "4310043100")

def _mutations(word: str) -> list[str]:
    """Génère des variantes de mutation pour une wordlist."""
    base  = word.strip()
    if not base:
        return []
    variants = {
        base,
        base.lower(),
        base.upper(),
        base.capitalize(),
        base + "1",
        base + "!",
        base + "123",
        base + "2024",
        base + "2025",
        base + "@",
        base.translate(LEET),
        base.translate(LEET) + "1",
        base[::-1],
        base[0].upper() + base[1:] + "1",
        base[0].upper() + base[1:] + "!",
    }
    return list(variants)


def _resolve(target: str) -> str:
    """Résout un nom de domaine en IP."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


# ══════════════════════════════════════════════════════════════════════════════
# BASE PLUGIN
# ══════════════════════════════════════════════════════════════════════════════
class BasePlugin(ABC):
    def __init__(self):
        self.logger = logging.getLogger("ESF")

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    def execute(self, config: dict) -> dict: ...


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — SCANNER RÉSEAU ÉTENDU
# ══════════════════════════════════════════════════════════════════════════════
class NetworkScannerPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Port Scanner (TCP/Banner)"
    @property
    def description(self) -> str: return "Scan TCP concurrent + fingerprinting bannière sur plage de ports libre"

    # ── Fingerprinting par service ─────────────────────────────────────────
    def _grab_banner(self, sock: socket.socket, port: int, target: str, timeout: float) -> str:
        try:
            sock.settimeout(timeout)
            if port == 80:
                sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
                return sock.recv(512).decode(errors="ignore").split("\r\n")[0]
            if port in (8080, 8888):
                sock.sendall(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                return sock.recv(256).decode(errors="ignore").split("\r\n")[0]
            if port == 443 or port == 8443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=target) as ss:
                    return f"TLS {ss.version()} — cipher {ss.cipher()[0]}"
            if port in (21, 22, 25, 110, 143):
                data = sock.recv(512).decode(errors="ignore").strip()
                return data[:200]
            if port == 6379:
                sock.sendall(b"PING\r\n")
                return sock.recv(64).decode(errors="ignore").strip()
            if port == 9200:
                sock.sendall(f"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                raw = sock.recv(2048).decode(errors="ignore")
                try:
                    body = raw.split("\r\n\r\n", 1)[1]
                    info = json.loads(body)
                    return f"Elasticsearch {info.get('version', {}).get('number', '?')}"
                except Exception:
                    return raw[:100]
        except Exception:
            pass
        return ""

    def _probe(self, target: str, port: int, timeout: float) -> dict | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    banner  = self._grab_banner(s, port, target, timeout)
                    service = SERVICE_MAP.get(port, "unknown")
                    return {"port": port, "service": service, "banner": banner or "(no banner)"}
        except Exception:
            pass
        return None

    def execute(self, config: dict) -> dict:
        cfg    = config["modules"]["network_scan"]
        target = Prompt.ask("[bold cyan]Cible (IP ou domaine)[/bold cyan]", default="127.0.0.1")
        port_input = Prompt.ask(
            "[bold cyan]Plage de ports[/bold cyan] (ex: 1-1024, 80,443,22, ou [Enter]=défaut)",
            default=""
        )

        # ── Parsing de la plage ────────────────────────────────────────────
        if not port_input.strip():
            ports = cfg["default_ports"]
        elif "-" in port_input and "," not in port_input:
            a, b  = port_input.split("-", 1)
            ports = list(range(int(a), int(b) + 1))
        else:
            ports = [int(p.strip()) for p in port_input.split(",") if p.strip().isdigit()]

        ip = _resolve(target)
        if ip != target:
            console.print(f"[dim]  → Résolution DNS : {target} → {ip}[/dim]")

        results = []
        self.logger.info(f"Scan de {len(ports)} ports sur {target} ({ip}) — workers={cfg['max_workers']}")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(bar_width=40), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task(f"[cyan]Scan {target}...", total=len(ports))

            with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["max_workers"]) as ex:
                futs = {ex.submit(self._probe, ip, p, cfg["timeout"]): p for p in ports}
                for fut in concurrent.futures.as_completed(futs):
                    prog.advance(task)
                    res = fut.result()
                    if res:
                        results.append(res)

        results.sort(key=lambda x: x["port"])

        # ── Affichage ──────────────────────────────────────────────────────
        if results:
            tbl = Table(title=f"Ports ouverts — {target}", box=box.SIMPLE_HEAVY)
            tbl.add_column("Port",    style="bold cyan", width=8)
            tbl.add_column("Service", style="yellow", width=14)
            tbl.add_column("Bannière / Info", style="white")
            for r in results:
                tbl.add_row(str(r["port"]), r["service"], r["banner"])
            console.print(tbl)
        else:
            console.print("[bold red]Aucun port ouvert détecté.[/bold red]")

        return {"target": target, "ip": ip, "ports_scanned": len(ports), "open_ports": results}


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — AUDIT SSL/TLS COMPLET
# ══════════════════════════════════════════════════════════════════════════════
class SslAuditorPlugin(BasePlugin):
    @property
    def name(self) -> str: return "SSL/TLS Auditor"
    @property
    def description(self) -> str: return "Validité cert, protocoles dépréciés, cipher suites, HSTS, CT logs"

    WEAK_CIPHERS = {
        "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
        "MD5", "PSK", "SRP", "IDEA", "SEED",
    }

    def _cert_info(self, target: str, port: int, timeout: float) -> dict:
        # CERT_REQUIRED est indispensable : avec CERT_NONE, getpeercert()
        # retourne un dict vide (pas de notAfter, pas de subject).
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_REQUIRED
        try:
            with socket.create_connection((target, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto  = ssock.version()
                    return {"cert": cert, "cipher": cipher, "proto": proto}
        except ssl.SSLCertVerificationError:
            # Cert auto-signé ou chaîne incomplète — on désactive la vérif
            # mais on récupère quand même les métadonnées via binary_form
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=timeout) as raw:
                with ctx2.wrap_socket(raw, server_hostname=target) as ssock:
                    der    = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    proto  = ssock.version()
            # Ré-extraire les métadonnées depuis le DER via un contexte de décodage
            pem  = ssl.DER_cert_to_PEM_cert(der)
            cert = ssl.PEM_cert_to_DER_cert  # juste pour vérifier la dispo
            # Utiliser x509 stdlib (Python 3.9+)
            import tempfile, os
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as tf:
                tf.write(pem)
                tf_name = tf.name
            try:
                cert = ssl._ssl._test_decode_cert(tf_name)
            except Exception:
                cert = {}
            finally:
                os.unlink(tf_name)
            return {"cert": cert, "cipher": cipher, "proto": proto}

    def _check_deprecated(self, target: str, port: int, timeout: float) -> list[str]:
        """Test réel des protocoles dépréciés via openssl s_client.

        OpenSSL 3.x a retiré TLS 1.0/1.1 côté client par défaut.
        La librairie ssl Python hérite de ce comportement : utiliser
        ctx.minimum_version = TLSv1 échoue côté LOCAL, pas côté serveur,
        ce qui génère des faux positifs. On délègue à openssl s_client
        qui peut forcer ces protocoles, et on interprète la réponse :
          - 'no protocols available' → client local incapable (indéterminable)
          - Cipher is (NONE)         → serveur a refusé (rejeté)
          - Cipher is <algo>         → serveur a accepté (vulnérable)
        """
        weak = []
        indeterminate = []

        for proto_flag, label in [("-tls1", "TLSv1"), ("-tls1_1", "TLSv1.1")]:
            try:
                result = subprocess.run(
                    ["openssl", "s_client", "-connect", f"{target}:{port}",
                     proto_flag, "-legacy_renegotiation"],
                    input=b"", capture_output=True, timeout=timeout,
                )
                output = (result.stdout + result.stderr).decode(errors="ignore")

                if "no protocols available" in output:
                    # OpenSSL 3.x local a désactivé ce protocole côté client
                    # → impossible de conclure depuis ce poste d'audit
                    indeterminate.append(label)
                elif re.search(r"Cipher is (?!\(NONE\))\S+", output):
                    # Handshake complet : le serveur accepte ce protocole
                    weak.append(label)
                # Sinon : alert / handshake failure = serveur a refusé → OK

            except FileNotFoundError:
                # openssl non disponible → fallback Python avec avertissement
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    ver_attr = "TLSv1" if label == "TLSv1" else "TLSv1_1"
                    ver = getattr(ssl.TLSVersion, ver_attr, None)
                if ver is None:
                    indeterminate.append(label)
                    continue
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx.check_hostname  = False
                        ctx.verify_mode     = ssl.CERT_NONE
                        ctx.maximum_version = ver
                        ctx.minimum_version = ver
                    with socket.create_connection((target, port), timeout=timeout) as raw:
                        with ctx.wrap_socket(raw, server_hostname=target):
                            weak.append(label)
                except Exception:
                    pass
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        # Stocker les protocoles indéterminables pour affichage
        self._tls_indeterminate = indeterminate
        return weak

    # Domaines connus comme preloaded (liste partielle — source: chromium.org/hsts)
    HSTS_PRELOADED = {
        "google.com", "youtube.com", "gmail.com", "android.com",
        "github.com", "facebook.com", "twitter.com", "instagram.com",
        "cloudflare.com", "stripe.com", "paypal.com", "apple.com",
        "microsoft.com", "amazon.com", "netflix.com", "linkedin.com",
        "dropbox.com", "reddit.com", "wikipedia.org", "mozilla.org",
    }

    def _check_hsts(self, target: str) -> dict:
        """Détection HSTS multi-stratégie :
        1. HEAD sans redirect (réponse initiale du serveur)
        2. GET avec suivi de redirects (vérification sur chaque étape)
        3. Vérification dans la liste statique HSTS Preload
        """
        ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"}
        result = {"present": False, "value": "ABSENT", "preloaded": False, "max_age_ok": False}

        # Stratégie 1 & 2 : HTTP
        for method, kwargs in [
            ("HEAD", {"allow_redirects": False}),
            ("GET",  {"allow_redirects": True}),
        ]:
            try:
                r = requests.request(
                    method, f"https://{target}",
                    timeout=5, verify=False, headers=ua, **kwargs
                )
                responses = getattr(r, "history", []) + [r]
                for resp in responses:
                    hsts = resp.headers.get("Strict-Transport-Security", "")
                    if hsts:
                        max_age = 0
                        try:
                            max_age = int(
                                hsts.split("max-age=")[1]
                                    .split(";")[0].split(",")[0].strip()
                            )
                        except Exception:
                            pass
                        result.update({
                            "present":    True,
                            "value":      hsts,
                            "max_age_ok": max_age >= 15768000,  # ≥ 6 mois
                        })
                        return result
            except Exception:
                pass

        # Stratégie 3 : liste statique preload
        apex = ".".join(target.split(".")[-2:])
        if target in self.HSTS_PRELOADED or apex in self.HSTS_PRELOADED:
            result.update({
                "present":    True,
                "preloaded":  True,
                "value":      "Présent via HSTS Preload List (navigateurs)",
                "max_age_ok": True,
            })

        return result

    def execute(self, config: dict) -> dict:
        timeout = config["modules"]["ssl_auditor"]["timeout"]
        target  = Prompt.ask("[bold cyan]Domaine à auditer[/bold cyan]", default="google.com")
        port    = int(Prompt.ask("[bold cyan]Port TLS[/bold cyan]", default="443"))

        report: dict = {
            "target": target, "port": port,
            "certificate": {}, "tls": {}, "hsts": {}, "findings": []
        }

        # ── Certificat ────────────────────────────────────────────────────
        self.logger.info(f"Récupération du certificat {target}:{port}…")
        try:
            info = self._cert_info(target, port, timeout)
            cert = info["cert"]

            issuer  = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            not_after_str = cert.get("notAfter", "")
            if not not_after_str:
                raise ValueError("notAfter vide — certificat non lisible")
            # ssl.cert_time_to_seconds gère correctement les jours < 10
            # (ex: "Jun  6 06:39:24 2026 GMT" avec double espace)
            ts        = ssl.cert_time_to_seconds(not_after_str)
            exp_date  = datetime.fromtimestamp(ts, tz=timezone.utc)
            now       = datetime.now(timezone.utc)
            days_left = (exp_date - now).days
            expired   = days_left < 0

            sans = [v for _, v in cert.get("subjectAltName", [])]

            report["certificate"] = {
                "subject":    subject.get("commonName", "?"),
                "issuer":     issuer.get("commonName", "?"),
                "not_before": cert.get("notBefore"),
                "not_after":  not_after_str,
                "days_left":  days_left,
                "expired":    expired,
                "san_count":  len(sans),
                "san_sample": sans[:5],
            }
            report["tls"] = {
                "protocol": info["proto"],
                "cipher":   info["cipher"][0],
                "key_bits": info["cipher"][2],
            }

            if expired:
                report["findings"].append("CRITIQUE — Certificat expiré")
            elif days_left < 14:
                report["findings"].append(f"ÉLEVÉ — Certificat expire dans {days_left} jours")
            elif days_left < 30:
                report["findings"].append(f"MOYEN — Certificat expire dans {days_left} jours")

            # Cipher faible ?
            cipher_name = info["cipher"][0].upper()
            if any(w in cipher_name for w in self.WEAK_CIPHERS):
                report["findings"].append(f"ÉLEVÉ — Cipher suite faible détectée : {info['cipher'][0]}")

        except Exception as e:
            report["certificate"]["error"] = str(e)
            report["findings"].append(f"CRITIQUE — Impossible de récupérer le certificat : {e}")
            self.logger.error(f"Cert error: {e}")

        # ── Protocoles dépréciés ───────────────────────────────────────────
        self.logger.info("Test des protocoles dépréciés (TLS 1.0, 1.1)…")
        self._tls_indeterminate = []
        weak_protos = self._check_deprecated(target, port, timeout)
        report["tls"]["deprecated_accepted"] = weak_protos
        report["tls"]["deprecated_indeterminate"] = self._tls_indeterminate
        for p in weak_protos:
            report["findings"].append(f"ÉLEVÉ — Protocole obsolète accepté : {p}")
        for p in self._tls_indeterminate:
            report["findings"].append(
                f"INFO — {p} : test impossible (OpenSSL 3.x local désactivé) "
                f"— vérifier manuellement avec : openssl s_client -connect {target}:{port} "
                f"-{p.lower().replace('.', '_')} -legacy_renegotiation"
            )

        # ── HSTS ──────────────────────────────────────────────────────────
        if port == 443:
            self.logger.info("Vérification HSTS…")
            report["hsts"] = self._check_hsts(target)
            if not report["hsts"]["present"]:
                report["findings"].append("MOYEN — En-tête HSTS absent (Strict-Transport-Security)")
            elif report["hsts"].get("preloaded"):
                report["findings"].append("✓ INFO — HSTS via Preload List (pas d'en-tête HTTP direct)")
            elif not report["hsts"]["max_age_ok"]:
                report["findings"].append("FAIBLE — HSTS présent mais max-age insuffisant (< 6 mois)")

        # ── Affichage résumé ───────────────────────────────────────────────
        cert_info = report["certificate"]
        tbl = Table(title=f"SSL/TLS — {target}:{port}", box=box.SIMPLE_HEAVY)
        tbl.add_column("Champ", style="yellow")
        tbl.add_column("Valeur")
        for k, v in cert_info.items():
            if k == "san_sample": continue
            color = "red" if k == "expired" and v else "green" if k == "expired" else ""
            tbl.add_row(k, f"[{color}]{v}[/{color}]" if color else str(v))
        console.print(tbl)

        if report["findings"]:
            console.print(Panel(
                "\n".join(f"  • {f}" for f in report["findings"]),
                title="[bold red]Findings SSL/TLS[/bold red]", border_style="red"
            ))

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — OSINT IP (WHOIS + GÉOLOC + ASN)
# ══════════════════════════════════════════════════════════════════════════════
class OsintIpPlugin(BasePlugin):
    @property
    def name(self) -> str: return "OSINT IP / Géoloc / ASN"
    @property
    def description(self) -> str: return "Géolocalisation, ISP, ASN, Whois, DNS inverse — Fallback multi-API"

    def _geoip(self, ip: str, cfg: dict) -> dict:
        for endpoint in cfg["endpoints"]:
            url = endpoint.format(ip=ip)
            try:
                r = requests.get(url, timeout=cfg["timeout"], verify=False)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("status") != "fail" and "error" not in d:
                        return {
                            "ip":      d.get("ip") or d.get("query") or ip,
                            "city":    d.get("city", "?"),
                            "region":  d.get("region") or d.get("regionName", "?"),
                            "country": d.get("country_name") or d.get("country", "?"),
                            "org":     d.get("org") or d.get("isp", "?"),
                            "asn":     d.get("asn") or d.get("as", "?"),
                            "lat":     d.get("latitude") or d.get("lat", "?"),
                            "lon":     d.get("longitude") or d.get("lon", "?"),
                            "source":  url.split("/")[2],
                        }
            except Exception as e:
                self.logger.warning(f"Failover depuis {url} : {e}")
        return {"error": "Tous les nœuds OSINT hors-ligne"}

    def _rdns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    def _whois_raw(self, ip: str) -> str:
        """Whois via socket natif (port 43) sans binaire externe."""
        servers = ["whois.iana.org"]
        try:
            # Résolution du whois server via IANA
            with socket.create_connection(("whois.iana.org", 43), timeout=5) as s:
                s.sendall(f"{ip}\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    data += chunk
            lines = data.decode(errors="ignore").splitlines()
            # Trouver le serveur référent
            refer = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("refer:")), None)
            if not refer:
                return "\n".join(lines[:30])
            # Interroger le serveur référent
            with socket.create_connection((refer, 43), timeout=5) as s:
                s.sendall(f"{ip}\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    data += chunk
            return data.decode(errors="ignore")[:3000]
        except Exception as e:
            return f"Whois indisponible : {e}"

    def execute(self, config: dict) -> dict:
        cfg = config["modules"]["osint_ip"]
        ip  = Prompt.ask("[bold cyan]IP publique à analyser[/bold cyan]", default="8.8.8.8")

        # Validation
        try:
            obj = ipaddress.ip_address(ip)
            if obj.is_private:
                console.print("[yellow]⚠ IP privée — géolocalisation indisponible.[/yellow]")
        except ValueError:
            ip = _resolve(ip)
            console.print(f"[dim]  Résolution → {ip}[/dim]")

        with console.status("[cyan]Collecte OSINT en cours…[/cyan]"):
            geo   = self._geoip(ip, cfg)
            rdns  = self._rdns(ip)
            whois = self._whois_raw(ip)

        report = {"ip": ip, "rdns": rdns, "geo": geo, "whois_excerpt": whois[:500]}

        # Affichage
        tbl = Table(title=f"OSINT — {ip}", box=box.SIMPLE_HEAVY)
        tbl.add_column("Champ", style="yellow")
        tbl.add_column("Valeur")
        tbl.add_row("rDNS",    rdns)
        for k, v in geo.items():
            if k != "source":
                tbl.add_row(k.upper(), str(v))
        tbl.add_row("Source API", geo.get("source", "N/A"))
        console.print(tbl)

        console.print(Panel(
            whois[:800],
            title="[cyan]Whois (extrait)[/cyan]", border_style="dim"
        ))

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — DNS RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════════════════
class DnsReconPlugin(BasePlugin):
    @property
    def name(self) -> str: return "DNS Reconnaissance"
    @property
    def description(self) -> str: return "Résolution multi-types (A/MX/NS/TXT/SPF), énumération sous-domaines"

    COMMON_SUBS = [
        "www", "mail", "ftp", "vpn", "api", "dev", "staging", "test",
        "admin", "portal", "remote", "secure", "app", "cdn", "ns1", "ns2",
        "mx", "smtp", "pop", "imap", "webmail", "autodiscover", "shop",
        "blog", "intranet", "git", "gitlab", "jenkins", "jira", "confluence",
    ]

    def _resolve_type(self, domain: str, qtype: str, timeout: int) -> list[str]:
        """Requête DNS via socket UDP brut (pas de dnspython requis)."""
        # Fallback simple : utiliser getaddrinfo pour A/AAAA, et requests sinon
        results = []
        try:
            if qtype in ("A", "AAAA"):
                family = socket.AF_INET if qtype == "A" else socket.AF_INET6
                infos  = socket.getaddrinfo(domain, None, family)
                results = list({i[4][0] for i in infos})
        except Exception:
            pass
        return results

    def _google_dns(self, name: str, rtype: str, timeout: int) -> list[str]:
        """DoH via Google (JSON API) — supporte A/MX/NS/TXT/AAAA."""
        try:
            r = requests.get(
                "https://dns.google/resolve",
                params={"name": name, "type": rtype},
                timeout=timeout, verify=True,
            )
            data = r.json()
            return [a["data"] for a in data.get("Answer", [])]
        except Exception:
            return []

    def _enum_subs(self, domain: str, timeout: int) -> list[dict]:
        found = []

        def check(sub):
            fqdn = f"{sub}.{domain}"
            ips  = self._google_dns(fqdn, "A", timeout)
            if ips:
                return {"subdomain": fqdn, "ips": ips}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(check, s): s for s in self.COMMON_SUBS}
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result()
                if r:
                    found.append(r)
        return found

    def execute(self, config: dict) -> dict:
        timeout = config["modules"]["dns_recon"]["timeout"]
        domain  = Prompt.ask("[bold cyan]Domaine cible[/bold cyan]", default="example.com")
        do_enum = Confirm.ask("[bold cyan]Énumération sous-domaines ?[/bold cyan]", default=True)

        report = {"domain": domain, "records": {}, "subdomains": []}

        with console.status("[cyan]Résolution DNS en cours…[/cyan]"):
            for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
                records = self._google_dns(domain, rtype, timeout)
                report["records"][rtype] = records

        tbl = Table(title=f"DNS — {domain}", box=box.SIMPLE_HEAVY)
        tbl.add_column("Type",   style="yellow", width=8)
        tbl.add_column("Valeur", style="white")
        for rtype, vals in report["records"].items():
            for v in vals:
                tbl.add_row(rtype, v)
        console.print(tbl)

        # SPF / DMARC / DKIM hints
        txt_records = report["records"].get("TXT", [])
        spf   = [r for r in txt_records if "v=spf1" in r]
        dmarc = self._google_dns(f"_dmarc.{domain}", "TXT", timeout)
        if spf:
            console.print(f"[green]✓ SPF détecté :[/green] {spf[0][:100]}")
        else:
            console.print("[yellow]⚠ Aucun enregistrement SPF — risque de spoofing e-mail[/yellow]")
        if dmarc:
            console.print(f"[green]✓ DMARC détecté :[/green] {dmarc[0][:100]}")
        else:
            console.print("[yellow]⚠ Pas de politique DMARC — e-mails falsifiables[/yellow]")

        report["spf"]   = spf
        report["dmarc"] = dmarc

        if do_enum:
            self.logger.info("Énumération des sous-domaines courants…")
            with console.status("[cyan]Énumération en cours…[/cyan]"):
                subs = self._enum_subs(domain, timeout)
            report["subdomains"] = subs

            if subs:
                stbl = Table(title="Sous-domaines trouvés", box=box.SIMPLE_HEAVY)
                stbl.add_column("Subdomain", style="cyan")
                stbl.add_column("IP(s)", style="white")
                for s in sorted(subs, key=lambda x: x["subdomain"]):
                    stbl.add_row(s["subdomain"], ", ".join(s["ips"]))
                console.print(stbl)
            else:
                console.print("[dim]Aucun sous-domaine commun trouvé.[/dim]")

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — SSH HARDENING + BRUTE-FORCE RÉEL (Paramiko)
# ══════════════════════════════════════════════════════════════════════════════
class SshAuditPlugin(BasePlugin):
    @property
    def name(self) -> str: return "SSH Audit + Brute-Force (Paramiko)"
    @property
    def description(self) -> str: return "Banner grab, audit sshd_config, attaque par dictionnaire réelle via Paramiko"

    def _get_banner(self, target: str, port: int, timeout: float) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    return s.recv(256).decode(errors="ignore").strip()
        except Exception:
            pass
        return ""

    def _audit_sshd_config(self, path: str) -> list[str]:
        findings = []
        if not os.path.exists(path):
            return findings
        try:
            with open(path) as f:
                content = f.read()
            checks = {
                "PermitRootLogin yes":          "CRITIQUE — PermitRootLogin activé",
                "PasswordAuthentication yes":   "ÉLEVÉ — PasswordAuthentication activé (préférer les clés)",
                "PermitEmptyPasswords yes":     "CRITIQUE — Mots de passe vides autorisés",
                "Protocol 1":                   "CRITIQUE — Protocole SSHv1 actif",
                "X11Forwarding yes":            "MOYEN — X11Forwarding activé",
                "AllowAgentForwarding yes":     "FAIBLE — AgentForwarding autorisé",
                "GatewayPorts yes":             "MOYEN — GatewayPorts activé",
                "UseDNS yes":                   "INFO — UseDNS activé (latence connexion)",
            }
            for pattern, msg in checks.items():
                if pattern in content:
                    findings.append(msg)
            # MaxAuthTries
            m = re.search(r"MaxAuthTries\s+(\d+)", content)
            if m and int(m.group(1)) > 3:
                findings.append(f"MOYEN — MaxAuthTries={m.group(1)} (recommandé ≤ 3)")
            if not re.search(r"AllowUsers\s+\S+|AllowGroups\s+\S+", content):
                findings.append("FAIBLE — Aucune restriction AllowUsers/AllowGroups définie")
        except Exception as e:
            findings.append(f"Lecture sshd_config impossible : {e}")
        return findings

    def _try_login(self, target: str, port: int, user: str, password: str,
                   timeout: float, delay: float = 0.3, retries: int = 2) -> bool:
        """
        Tente une auth SSH réelle via Paramiko.
        - Retry sur SSHException / EOFError (serveur saturé = bannière non lue)
        - Délai entre tentatives pour éviter le rate-limiting
        - Ne propage jamais d'exception vers l'appelant
        """
        if not PARAMIKO_OK:
            return False

        for attempt in range(retries):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    target, port=port,
                    username=user, password=password,
                    timeout=timeout,
                    banner_timeout=timeout + 5,  # plus généreux que le timeout TCP
                    auth_timeout=timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                client.close()
                return True

            except paramiko.AuthenticationException:
                # Mot de passe refusé — résultat définitif, pas de retry utile
                client.close()
                return False

            except (
                paramiko.SSHException,   # "Error reading SSH protocol banner"
                EOFError,                # connexion coupée brutalement
                OSError,                 # connexion refusée / timeout réseau
                socket.error,
            ):
                # Serveur surchargé ou connexion rejetée — on retente après délai
                try: client.close()
                except Exception: pass
                if attempt < retries - 1:
                    time.sleep(delay * (attempt + 1))  # back-off linéaire
                else:
                    return False  # abandon après tous les retries

            except Exception:
                try: client.close()
                except Exception: pass
                return False

        return False

    def execute(self, config: dict) -> dict:
        cfg    = config["modules"]["ssh_brute"]
        target = Prompt.ask("[bold cyan]Cible SSH (IP/domaine)[/bold cyan]", default="127.0.0.1")
        port   = int(Prompt.ask("[bold cyan]Port SSH[/bold cyan]", default="22"))

        report = {"target": target, "port": port, "banner": "", "sshd_findings": [], "brute_force": {}}

        # ── Bannière ───────────────────────────────────────────────────────
        banner = self._get_banner(target, port, cfg["timeout"])
        report["banner"] = banner
        console.print(f"[cyan]Bannière SSH :[/cyan] {banner or 'Port fermé / pas de réponse'}")

        if "SSH-1." in banner:
            report["sshd_findings"].append("CRITIQUE — Protocole SSHv1 détecté dans la bannière")

        # ── Audit sshd_config local ────────────────────────────────────────
        if target in ("127.0.0.1", "localhost"):
            findings = self._audit_sshd_config("/etc/ssh/sshd_config")
            report["sshd_findings"].extend(findings)
            if findings:
                console.print(Panel("\n".join(f"  • {f}" for f in findings),
                                    title="[bold red]sshd_config Audit[/bold red]", border_style="red"))
            else:
                console.print("[green]✓ sshd_config — aucun problème majeur détecté.[/green]")

        # ── Brute-force réel ───────────────────────────────────────────────
        if not PARAMIKO_OK:
            console.print("[yellow]⚠ Paramiko non disponible — brute-force désactivé.[/yellow]")
            return report

        do_brute = Confirm.ask("[bold red]Lancer le brute-force par dictionnaire ?[/bold red] (autorisation requise)", default=False)
        if not do_brute:
            report["brute_force"] = {"skipped": True}
            return report

        user = Prompt.ask("[bold cyan]Nom d'utilisateur à tester[/bold cyan]", default="root")
        wordlist_path = Prompt.ask(
            "[bold cyan]Chemin vers la wordlist[/bold cyan] (ou [Enter] pour wordlist intégrée)",
            default=""
        )

        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                base_words = [l.strip() for l in f if l.strip()]
        else:
            base_words = [
                "admin", "password", "123456", "root", "toor", "alpine",
                "raspberry", "ubuntu", "kali", "test", "pass", "1234",
                "letmein", "welcome", "changeme", "qwerty", "master",
            ]

        do_mutate = Confirm.ask("[bold cyan]Appliquer les règles de mutation ?[/bold cyan]", default=True)
        if do_mutate:
            candidates = []
            for w in base_words:
                for m in _mutations(w):
                    if m not in candidates:
                        candidates.append(m)
        else:
            candidates = base_words

        workers = int(Prompt.ask(
            "[bold cyan]Threads simultanés[/bold cyan] [dim](1=sûr, 2-3=rapide, >4=risque de bannissement)[/dim]",
            default="1"
        ))
        delay = cfg["delay"]

        console.print(f"[dim]Candidats : {len(candidates)} — cible : {user}@{target}:{port} — threads : {workers}[/dim]")

        found_event = threading.Event()
        cracked     = {"password": None, "attempt_count": 0}
        lock        = threading.Lock()

        def try_pwd(pwd: str) -> tuple[bool, str]:
            if found_event.is_set():
                return False, pwd
            ok = self._try_login(target, port, user, pwd, cfg["timeout"], delay=delay)
            with lock:
                cracked["attempt_count"] += 1
            if ok:
                found_event.set()
            return ok, pwd

        start = time.time()
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(bar_width=35), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task(f"[red]Brute SSH {user}@{target}…", total=len(candidates))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(try_pwd, p): p for p in candidates}
                for fut in concurrent.futures.as_completed(futs):
                    prog.advance(task)
                    ok, pwd = fut.result()
                    if ok:
                        cracked["password"] = pwd
                        for f2 in futs:
                            f2.cancel()
                        break

        elapsed = round(time.time() - start, 2)
        report["brute_force"] = {
            "user": user,
            "wordlist_size": len(candidates),
            "attempts": cracked["attempt_count"],
            "elapsed_sec": elapsed,
            "success": cracked["password"] is not None,
            "password_found": cracked["password"] or "Non trouvé",
        }

        if cracked["password"]:
            console.print(Panel(
                f"[bold red]✓ MOT DE PASSE TROUVÉ : {cracked['password']}[/bold red]\n"
                f"  Utilisateur : {user} — Cible : {target}:{port}",
                title="[red]BRUTE-FORCE SUCCESS[/red]", border_style="red"
            ))
            self.logger.warning(f"Accès SSH compromis : {user}@{target}:{port} → '{cracked['password']}'")
        else:
            console.print(f"[green]Brute-force terminé — mot de passe non trouvé ({len(candidates)} candidats en {elapsed}s)[/green]")

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6 — HASH CRACKER RÉEL (MD5/SHA/bcrypt)
# ══════════════════════════════════════════════════════════════════════════════
class HashCrackerPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Hash Cracker (dict + mutations)"
    @property
    def description(self) -> str: return "Cracking réel par dictionnaire — MD5, SHA1, SHA256, SHA512 + mutations Leet"

    ALGO_HEURISTICS = {
        32:  ["md5"],
        40:  ["sha1"],
        56:  ["sha224"],
        64:  ["sha256"],
        96:  ["sha384"],
        128: ["sha512"],
    }

    def _detect_algo(self, h: str) -> list[str]:
        return self.ALGO_HEURISTICS.get(len(h), ["md5", "sha1", "sha256"])

    def _crack_worker(self, target_hash: str, candidate: str, algos: list[str],
                      found: threading.Event) -> tuple[str | None, str | None]:
        if found.is_set():
            return None, None
        for algo in algos:
            try:
                digest = hashlib.new(algo, candidate.encode("utf-8")).hexdigest()
                if digest == target_hash:
                    found.set()
                    return candidate, algo
            except Exception:
                pass
        return None, None

    def execute(self, config: dict) -> dict:
        target_hash = Prompt.ask("[bold cyan]Hash à cracker[/bold cyan]").strip().lower()
        if not target_hash:
            return {"error": "Aucun hash fourni"}

        detected = self._detect_algo(target_hash)
        console.print(f"[dim]Algorithme(s) probable(s) : {', '.join(detected)}[/dim]")

        algo_input = Prompt.ask(
            f"[bold cyan]Algorithme(s) à tester[/bold cyan] (ex: md5,sha256 — [Enter]={','.join(detected)})",
            default=",".join(detected)
        )
        algos = [a.strip().lower() for a in algo_input.split(",") if a.strip()]

        # Validation
        for a in algos:
            try:
                hashlib.new(a)
            except ValueError:
                console.print(f"[red]Algorithme inconnu ignoré : {a}[/red]")
                algos.remove(a)

        wordlist_path = Prompt.ask(
            "[bold cyan]Chemin wordlist[/bold cyan] (ou [Enter] pour liste intégrée)",
            default=""
        )
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                base_words = [l.strip() for l in f if l.strip()]
        else:
            base_words = [
                "password", "123456", "admin", "root", "test", "letmein",
                "welcome", "qwerty", "monkey", "dragon", "master", "pass",
                "abc123", "iloveyou", "trustno1", "sunshine", "princess",
                "shadow", "superman", "batman", "football", "baseball",
                "solo", "access", "login", "hello", "charlie", "donald",
                "1234", "12345", "123456789", "111111", "000000",
            ]

        do_mutate = Confirm.ask("[bold cyan]Appliquer mutations Leet + variantes ?[/bold cyan]", default=True)
        if do_mutate:
            candidates: list[str] = []
            seen = set()
            for w in base_words:
                for m in _mutations(w):
                    if m not in seen:
                        seen.add(m)
                        candidates.append(m)
        else:
            candidates = list(set(base_words))

        console.print(f"[dim]Candidats : {len(candidates)} — Hash : {target_hash[:20]}…[/dim]")

        found_event = threading.Event()
        result_pwd  = None
        result_algo = None
        attempts    = 0
        lock        = threading.Lock()

        start = time.time()
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(bar_width=40), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("[cyan]Calcul des collisions…", total=len(candidates))
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                futs = {ex.submit(self._crack_worker, target_hash, c, algos, found_event): c
                        for c in candidates}
                for fut in concurrent.futures.as_completed(futs):
                    prog.advance(task)
                    with lock:
                        attempts += 1
                    pwd, algo_found = fut.result()
                    if pwd:
                        result_pwd  = pwd
                        result_algo = algo_found
                        for f2 in futs:
                            f2.cancel()
                        break

        elapsed = round(time.time() - start, 3)
        report = {
            "hash": target_hash,
            "algorithms_tested": algos,
            "candidates_tested": attempts,
            "elapsed_sec": elapsed,
            "success": result_pwd is not None,
            "plaintext": result_pwd or "Non trouvé",
            "algorithm_matched": result_algo or "N/A",
        }

        if result_pwd:
            console.print(Panel(
                f"[bold green]✓ HASH CRACKÉ[/bold green]\n"
                f"  Plaintext : [bold yellow]{result_pwd}[/bold yellow]\n"
                f"  Algorithme : {result_algo.upper()}\n"
                f"  Temps : {elapsed}s — {attempts} candidats testés",
                title="[green]HASH CRACKER — SUCCESS[/green]", border_style="green"
            ))
        else:
            console.print(f"[red]Hash non cracké — {attempts} candidats testés en {elapsed}s.[/red]")
            console.print("[dim]Conseil : utilisez une wordlist externe plus large (rockyou.txt)[/dim]")

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 7 — AUDIT POLITIQUE MOT DE PASSE (NIST 800-63B)
# ══════════════════════════════════════════════════════════════════════════════
class PasswordPolicyPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Password Policy Auditor (NIST 800-63B)"
    @property
    def description(self) -> str: return "Entropie, force réelle, HaveIBeenPwned (k-Anonymity), score NIST"

    COMMON = {
        "123456", "password", "qwerty", "admin", "letmein", "welcome",
        "monkey", "1234", "abc123", "iloveyou", "dragon", "master",
        "sunshine", "princess", "football", "shadow", "superman", "batman",
    }

    def _entropy_bits(self, pwd: str) -> float:
        charset = 0
        if any(c.islower() for c in pwd): charset += 26
        if any(c.isupper() for c in pwd): charset += 26
        if any(c.isdigit() for c in pwd): charset += 10
        if any(not c.isalnum() for c in pwd): charset += 32
        return round(len(pwd) * math.log2(charset) if charset > 0 else 0, 1)

    def _hibp_check(self, pwd: str) -> dict:
        """HaveIBeenPwned via k-Anonymity (n'envoie que 5 premiers chars du SHA1)."""
        sha1  = hashlib.sha1(pwd.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            r = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5,
                headers={"Add-Padding": "true"}
            )
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return {"leaked": True, "count": int(count)}
            return {"leaked": False, "count": 0}
        except Exception as e:
            return {"leaked": None, "error": str(e)}

    def execute(self, config: dict) -> dict:
        pwd = Prompt.ask("[bold cyan]Mot de passe à évaluer[/bold cyan]", password=True)

        report = {
            "length":  len(pwd),
            "entropy": self._entropy_bits(pwd),
            "hibp":    {},
            "findings": [],
            "score":    0,
            "grade":    "",
        }

        score = 0

        # Longueur
        if len(pwd) >= 16:   score += 3
        elif len(pwd) >= 12: score += 2
        elif len(pwd) >= 8:  score += 1
        else: report["findings"].append("CRITIQUE — Longueur < 8 caractères (NIST min)")

        # Complexité
        if any(c.isupper() for c in pwd):    score += 1
        if any(c.isdigit() for c in pwd):    score += 1
        if any(not c.isalnum() for c in pwd): score += 2

        # Entropie
        if report["entropy"] >= 60:   score += 3
        elif report["entropy"] >= 40: score += 1

        # Wordlist locale
        if pwd.lower() in self.COMMON:
            report["findings"].append("CRITIQUE — Mot de passe dans la liste des plus courants")
            score -= 4

        # HIBP
        with console.status("[cyan]Vérification HaveIBeenPwned (k-Anonymity)…[/cyan]"):
            hibp = self._hibp_check(pwd)
        report["hibp"] = hibp

        if hibp.get("leaked"):
            report["findings"].append(f"CRITIQUE — Mot de passe trouvé {hibp['count']:,}× dans des fuites (HIBP)")
            score -= 4
        elif hibp.get("leaked") is False:
            report["findings"].append("✓ Non trouvé dans HaveIBeenPwned")

        report["score"] = max(score, 0)

        if score >= 8:    grade = "A — Excellent"
        elif score >= 6:  grade = "B — Fort"
        elif score >= 4:  grade = "C — Moyen"
        elif score >= 2:  grade = "D — Faible"
        else:             grade = "F — Critique"
        report["grade"] = grade

        # Affichage
        grade_color = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange1", "F": "red"}[grade[0]]
        tbl = Table(title="Audit Mot de Passe", box=box.SIMPLE_HEAVY)
        tbl.add_column("Critère", style="yellow")
        tbl.add_column("Résultat")
        tbl.add_row("Longueur",   str(len(pwd)))
        tbl.add_row("Entropie",   f"{report['entropy']} bits")
        tbl.add_row("HIBP",       f"{'⚠ ' + str(hibp.get('count', '?')) + ' fuites' if hibp.get('leaked') else '✓ Propre'}")
        tbl.add_row("Score",      f"{report['score']}/10")
        tbl.add_row("Grade",      f"[{grade_color}]{grade}[/{grade_color}]")
        console.print(tbl)

        if report["findings"]:
            console.print(Panel("\n".join(f"  • {f}" for f in report["findings"]),
                                title="[red]Findings[/red]", border_style="red"))

        return report




# ══════════════════════════════════════════════════════════════════════════════
# MODULE 8 — CVE LOOKUP (NVD / NIST API v2)
# ══════════════════════════════════════════════════════════════════════════════
class CveLookupPlugin(BasePlugin):
    @property
    def name(self) -> str: return "CVE Lookup (NVD/NIST)"
    @property
    def description(self) -> str: return "Croise les bannières du scanner avec les CVE NVD — CVSS score + remediation"

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Mapping bannière → CPE keyword pour la recherche NVD
    BANNER_PATTERNS = [
        (r"OpenSSH[_/ ]?([\d.]+)",          "OpenSSH",     "openssh"),
        (r"Apache[/ ]([\d.]+)",             "Apache HTTPD","apache_http_server"),
        (r"nginx[/ ]([\d.]+)",              "nginx",       "nginx"),
        (r"OpenSSL ([\d.]+\w*)",            "OpenSSL",     "openssl"),
        (r"vsftpd ([\d.]+)",                "vsftpd",      "vsftpd"),
        (r"Exim ([\d.]+)",                  "Exim",        "exim"),
        (r"ProFTPD ([\d.]+)",               "ProFTPD",     "proftpd"),
        (r"Microsoft-IIS/([\d.]+)",         "IIS",         "iis"),
        (r"MySQL ([\d.]+)",                 "MySQL",       "mysql"),
        (r"PostgreSQL ([\d.]+)",            "PostgreSQL",  "postgresql"),
        (r"Elasticsearch ([\d.]+)",         "Elasticsearch","elasticsearch"),
        (r"Redis ([\d.]+)",                 "Redis",       "redis"),
        (r"MongoDB ([\d.]+)",               "MongoDB",     "mongodb"),
        (r"PHP/([\d.]+)",                   "PHP",         "php"),
        (r"Samba ([\d.]+)",                 "Samba",       "samba"),
    ]

    def _extract_services(self, open_ports: list) -> list[dict]:
        """Extrait les services et versions depuis les bannières du scanner."""
        services = []
        for port_info in open_ports:
            banner = port_info.get("banner", "")
            service = port_info.get("service", "")
            for pattern, label, keyword in self.BANNER_PATTERNS:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    services.append({
                        "port":    port_info["port"],
                        "label":   label,
                        "version": m.group(1),
                        "keyword": keyword,
                        "banner":  banner[:80],
                    })
                    break
            else:
                if service and service not in ("unknown", ""):
                    services.append({
                        "port":    port_info["port"],
                        "label":   service,
                        "version": "",
                        "keyword": service.lower(),
                        "banner":  banner[:80],
                    })
        return services

    def _query_nvd(self, keyword: str, version: str, timeout: int) -> list[dict]:
        """Requête NVD API v2 — recherche par keyword + version."""
        try:
            # Construit une query plus précise : "OpenSSH 8.9" > "openssh 8.9"
            search_term = f"{keyword} {version}".strip()
            params = {
                "keywordSearch":    search_term,
                "keywordExactMatch": False,
                "resultsPerPage":   5,
                "startIndex":       0,
            }
            r = requests.get(self.NVD_API, params=params, timeout=timeout,
                             headers={"User-Agent": "ESF-SecurityAuditor/5.0"})
            if r.status_code == 403:
                return [{"error": "Rate limit NVD — réessayez dans 30s ou ajoutez une API key"}]
            if r.status_code != 200:
                return []
            data = r.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve  = item.get("cve", {})
                cve_id = cve.get("id", "?")
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description"
                )
                metrics = cve.get("metrics", {})
                score, severity, vector = None, "?", "?"
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metric_key in metrics and metrics[metric_key]:
                        m = metrics[metric_key][0].get("cvssData", {})
                        score    = m.get("baseScore")
                        severity = m.get("baseSeverity", "?")
                        vector   = m.get("vectorString", "?")
                        break
                cves.append({
                    "id":          cve_id,
                    "score":       score,
                    "severity":    severity,
                    "vector":      vector,
                    "description": desc[:200],
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
            return sorted(cves, key=lambda x: (x["score"] or 0), reverse=True)
        except requests.Timeout:
            return [{"error": "Timeout NVD API"}]
        except Exception as e:
            return [{"error": str(e)}]

    def execute(self, config: dict) -> dict:
        timeout = config["modules"].get("cve_lookup", {}).get("timeout", 6)
        report = {"services_analyzed": [], "cve_findings": [], "total_critical": 0}

        # Récupérer les données du scanner si disponibles
        scanner_data = None
        # On passe la config avec le vault si disponible (injecté par le core)
        vault = config.get("_vault", {})
        scanner_entry = vault.get("Port Scanner (TCP/Banner)", {})
        if scanner_entry:
            scanner_data = scanner_entry.get("payload", {})

        if scanner_data and scanner_data.get("open_ports"):
            services = self._extract_services(scanner_data["open_ports"])
            console.print(f"[dim]Services détectés depuis le scanner : {len(services)}[/dim]")
        else:
            console.print("[yellow]Scanner non exécuté — saisie manuelle des services.[/yellow]")
            services = []
            while True:
                svc = Prompt.ask(
                    "[bold cyan]Service à analyser[/bold cyan] (ex: OpenSSH 8.9, nginx 1.18 — [Enter] pour terminer)",
                    default=""
                )
                if not svc.strip():
                    break
                parts = svc.strip().rsplit(" ", 1)
                label   = parts[0]
                version = parts[1] if len(parts) > 1 else ""
                # Utilise le label original (ex: "OpenSSH") comme keyword NVD — meilleur matching
                keyword = label.lower()
                services.append({"port": 0, "label": label, "version": version,
                                  "keyword": keyword, "banner": svc})

        if not services:
            console.print("[red]Aucun service à analyser.[/red]")
            return report

        report["services_analyzed"] = services

        for svc in services:
            label   = svc["label"]
            version = svc["version"]
            keyword = svc["keyword"]

            console.print(f"[cyan]→ NVD lookup :[/cyan] {label} {version}…")
            time.sleep(6.0)  # Respect du rate-limit NVD (sans API key : 5 req/30s → 6s de sécurité)
            # On passe le label (ex: "OpenSSH") pour un meilleur matching NVD
            cves = self._query_nvd(label, version, timeout)

            if cves and "error" not in cves[0]:
                sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for cve in cves:
                    sev = str(cve.get("severity", "")).upper()
                    if sev in sev_counts:
                        sev_counts[sev] += 1

                report["cve_findings"].append({
                    "service": f"{label} {version}".strip(),
                    "port":    svc["port"],
                    "cves":    cves,
                    "counts":  sev_counts,
                })
                report["total_critical"] += sev_counts["CRITICAL"]

                # Affichage
                tbl = Table(title=f"CVE — {label} {version} (port {svc['port']})",
                            box=box.SIMPLE_HEAVY)
                tbl.add_column("CVE ID",    style="bold red", width=18)
                tbl.add_column("Score",     width=7)
                tbl.add_column("Sévérité",  width=10)
                tbl.add_column("Description")
                for cve in cves[:5]:
                    score_str = str(cve["score"]) if cve["score"] else "N/A"
                    sev = cve["severity"].upper()
                    sev_color = {"CRITICAL":"red","HIGH":"orange1","MEDIUM":"yellow","LOW":"green"}.get(sev,"white")
                    tbl.add_row(
                        cve["id"],
                        f"[{sev_color}]{score_str}[/{sev_color}]",
                        f"[{sev_color}]{sev}[/{sev_color}]",
                        cve["description"][:80] + "…"
                    )
                console.print(tbl)
            elif cves and "error" in cves[0]:
                console.print(f"[yellow]  ⚠ {cves[0]['error']}[/yellow]")
            else:
                console.print(f"[dim]  Aucun CVE trouvé pour {label} {version}[/dim]")

        if report["total_critical"] > 0:
            console.print(Panel(
                f"[bold red]{report['total_critical']} CVE(s) CRITICAL détectés — action immédiate requise.[/bold red]",
                border_style="red"
            ))

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 9 — WEB SCANNER HTTP
# ══════════════════════════════════════════════════════════════════════════════
class WebScannerPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Web Scanner HTTP"
    @property
    def description(self) -> str: return "Headers sécurité, répertoires cachés, détection techno, vulnérabilités web"

    SECURITY_HEADERS = {
        "Strict-Transport-Security":      ("ÉLEVÉ",   "HSTS absent — attaques downgrade possibles"),
        "Content-Security-Policy":        ("ÉLEVÉ",   "CSP absent — risque XSS élevé"),
        "X-Frame-Options":                ("MOYEN",   "X-Frame-Options absent — risque Clickjacking"),
        "X-Content-Type-Options":         ("MOYEN",   "X-Content-Type-Options absent — MIME sniffing"),
        "Referrer-Policy":                ("FAIBLE",  "Referrer-Policy absent — fuite de données"),
        "Permissions-Policy":             ("FAIBLE",  "Permissions-Policy absent"),
        "X-XSS-Protection":               ("INFO",    "X-XSS-Protection absent (déprécié mais indicateur)"),
        "Cross-Origin-Embedder-Policy":   ("FAIBLE",  "COEP absent"),
        "Cross-Origin-Opener-Policy":     ("FAIBLE",  "COOP absent"),
    }

    SENSITIVE_PATHS = [
        "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/config.php",
        "/admin", "/admin/", "/administrator", "/phpmyadmin", "/phpinfo.php",
        "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
        "/.htaccess", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html", "/api-docs",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
        "/console", "/manager/html", "/jmx-console", "/.DS_Store",
        "/server-status", "/server-info", "/_profiler", "/debug",
        "/web.config", "/app.config", "/settings.py", "/config.yml",
        "/.well-known/security.txt", "/security.txt",
    ]

    TECH_SIGNATURES = {
        "WordPress":    ["wp-content", "wp-includes", "WordPress"],
        "Drupal":       ["Drupal", "drupal.js", "sites/default"],
        "Joomla":       ["Joomla", "/media/jui/", "joomla"],
        "Laravel":      ["laravel_session", "Laravel"],
        "Django":       ["csrftoken", "__django"],
        "Ruby on Rails":["_rails", "Phusion Passenger"],
        "ASP.NET":      ["ASP.NET", "__VIEWSTATE", "X-AspNet-Version"],
        "PHP":          ["PHP", "PHPSESSID", "X-Powered-By: PHP"],
        "nginx":        ["Server: nginx"],
        "Apache":       ["Server: Apache"],
        "Cloudflare":   ["cf-ray", "cloudflare"],
        "Varnish":      ["X-Varnish", "Via: varnish"],
    }

    def _check_headers(self, url: str, timeout: int) -> tuple[dict, list[str]]:
        ua = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"}
        try:
            r = requests.head(url, timeout=timeout, verify=False,
                              allow_redirects=True, headers=ua)
            headers = {k.lower(): v for k, v in r.headers.items()}
            findings = []
            for h, (severity, msg) in self.SECURITY_HEADERS.items():
                if h.lower() not in headers:
                    findings.append(f"{severity} — {msg}")
            # Server header info disclosure
            if "server" in headers:
                findings.append(f"INFO — Server header exposé : {headers['server']}")
            if "x-powered-by" in headers:
                findings.append(f"INFO — X-Powered-By exposé : {headers['x-powered-by']}")
            return dict(r.headers), findings
        except Exception as e:
            return {}, [f"Connexion impossible : {e}"]

    def _detect_tech(self, url: str, headers: dict, timeout: int) -> list[str]:
        detected = []
        headers_str = str(headers).lower()
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            body = r.text[:5000]
        except Exception:
            body = ""

        combined = headers_str + body.lower()
        for tech, sigs in self.TECH_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                detected.append(tech)
        return detected

    def _scan_paths(self, base_url: str, timeout: int) -> list[dict]:
        """Scan concurrent des répertoires/fichiers sensibles."""
        found = []
        lock  = threading.Lock()

        def check(path):
            url = base_url.rstrip("/") + path
            try:
                r = requests.get(url, timeout=timeout, verify=False,
                                 allow_redirects=False,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code in (200, 301, 302, 403, 500):
                    severity = "CRITIQUE" if r.status_code == 200 and any(
                        x in path for x in [".env", ".git", "config", "backup", "sql", "phpinfo"]
                    ) else "MOYEN" if r.status_code == 200 else "INFO"
                    with lock:
                        found.append({
                            "path":     path,
                            "status":   r.status_code,
                            "size":     len(r.content),
                            "severity": severity,
                        })
            except Exception:
                pass

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(bar_width=35), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("[cyan]Scan des chemins sensibles…", total=len(self.SENSITIVE_PATHS))
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
                futs = {ex.submit(check, p): p for p in self.SENSITIVE_PATHS}
                for fut in concurrent.futures.as_completed(futs):
                    prog.advance(task)

        return sorted(found, key=lambda x: x["status"])

    def execute(self, config: dict) -> dict:
        timeout = config["modules"]["ssl_auditor"]["timeout"]
        target  = Prompt.ask("[bold cyan]URL cible[/bold cyan]", default="http://127.0.0.1")
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        report = {"target": target, "headers": {}, "technologies": [],
                  "sensitive_paths": [], "findings": []}

        # ── Headers ──────────────────────────────────────────────────────
        self.logger.info(f"Audit des headers HTTP : {target}…")
        headers, findings = self._check_headers(target, timeout)
        report["headers"]  = headers
        report["findings"] = findings

        # ── Technologies ─────────────────────────────────────────────────
        self.logger.info("Détection des technologies…")
        techs = self._detect_tech(target, headers, timeout)
        report["technologies"] = techs
        if techs:
            console.print(f"[cyan]Technologies détectées :[/cyan] {', '.join(techs)}")

        # ── Répertoires sensibles ─────────────────────────────────────────
        do_scan = Confirm.ask("[bold cyan]Scanner les répertoires sensibles ?[/bold cyan]", default=True)
        if do_scan:
            self.logger.info("Scan des chemins sensibles…")
            paths = self._scan_paths(target, timeout)
            report["sensitive_paths"] = paths
            for p in paths:
                if p["severity"] == "CRITIQUE":
                    report["findings"].append(
                        f"CRITIQUE — Ressource sensible exposée : {p['path']} [{p['status']}]"
                    )

        # ── Affichage findings ────────────────────────────────────────────
        if report["findings"]:
            tbl = Table(title=f"Web Security — {target}", box=box.SIMPLE_HEAVY)
            tbl.add_column("Sévérité", width=10)
            tbl.add_column("Finding")
            for f in report["findings"]:
                sev = f.split(" — ")[0]
                color = {"CRITIQUE":"red","ÉLEVÉ":"orange1","MOYEN":"yellow","FAIBLE":"dim","INFO":"cyan"}.get(sev,"white")
                tbl.add_row(f"[{color}]{sev}[/{color}]", f.split(" — ", 1)[1] if " — " in f else f)
            console.print(tbl)

        if report["sensitive_paths"]:
            stbl = Table(title="Chemins accessibles", box=box.SIMPLE_HEAVY)
            stbl.add_column("Chemin",   style="cyan")
            stbl.add_column("Status",   width=8)
            stbl.add_column("Taille",   width=10)
            stbl.add_column("Sévérité", width=10)
            for p in report["sensitive_paths"]:
                color = {"CRITIQUE":"red","MOYEN":"yellow","INFO":"dim"}.get(p["severity"],"white")
                stbl.add_row(p["path"], str(p["status"]),
                             f"{p['size']} B", f"[{color}]{p['severity']}[/{color}]")
            console.print(stbl)

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 10 — EMAIL SECURITY AUDITOR
# ══════════════════════════════════════════════════════════════════════════════
class EmailSecurityPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Email Security Auditor"
    @property
    def description(self) -> str: return "SPF, DMARC, DKIM, MTA-STS, spoofing risk — audit complet anti-phishing"

    def _doh(self, name: str, rtype: str, timeout: int = 4) -> list[str]:
        try:
            r = requests.get("https://dns.google/resolve",
                             params={"name": name, "type": rtype},
                             timeout=timeout)
            return [a["data"] for a in r.json().get("Answer", [])]
        except Exception:
            return []

    def _audit_spf(self, domain: str) -> dict:
        records = self._doh(domain, "TXT")
        spf = next((r for r in records if "v=spf1" in r), None)
        result = {"record": spf, "findings": [], "risk": "OK"}

        if not spf:
            result["findings"].append("CRITIQUE — Aucun enregistrement SPF — domaine spoofable")
            result["risk"] = "CRITIQUE"
            return result

        # Analyse du mécanisme
        if "+all" in spf:
            result["findings"].append("CRITIQUE — SPF '+all' : TOUS les serveurs autorisés à envoyer — inutile")
            result["risk"] = "CRITIQUE"
        elif "?all" in spf:
            result["findings"].append("ÉLEVÉ — SPF '?all' : politique neutre, pas de rejet")
            result["risk"] = "ÉLEVÉ"
        elif "~all" in spf:
            result["findings"].append("MOYEN — SPF '~all' (softfail) : les spams ne sont pas rejetés")
            result["risk"] = "MOYEN"
        elif "-all" in spf:
            result["findings"].append("✓ SPF '-all' : politique stricte — correct")

        # Nombre de lookups DNS (max 10 selon RFC)
        lookups = spf.count("include:") + spf.count("redirect=") + spf.count("a:") + spf.count("mx")
        if lookups > 8:
            result["findings"].append(f"MOYEN — {lookups} lookups DNS dans SPF (limite RFC : 10)")

        return result

    def _audit_dmarc(self, domain: str) -> dict:
        records = self._doh(f"_dmarc.{domain}", "TXT")
        dmarc   = next((r for r in records if "v=DMARC1" in r), None)
        result  = {"record": dmarc, "findings": [], "risk": "OK"}

        if not dmarc:
            result["findings"].append("CRITIQUE — Aucun enregistrement DMARC — emails falsifiables")
            result["risk"] = "CRITIQUE"
            return result

        # Politique p=
        if "p=none" in dmarc:
            result["findings"].append("ÉLEVÉ — DMARC p=none : aucun rejet, monitoring only")
            result["risk"] = "ÉLEVÉ"
        elif "p=quarantine" in dmarc:
            result["findings"].append("MOYEN — DMARC p=quarantine : spam folder, pas de rejet")
            result["risk"] = "MOYEN"
        elif "p=reject" in dmarc:
            result["findings"].append("✓ DMARC p=reject : politique maximale — correct")

        # pct= (pourcentage d'application)
        m = re.search(r"pct=(\d+)", dmarc)
        if m and int(m.group(1)) < 100:
            result["findings"].append(f"MOYEN — DMARC pct={m.group(1)}% : politique partielle")

        # rua= (rapport agrégé)
        if "rua=" not in dmarc:
            result["findings"].append("FAIBLE — Pas de rua= : aucun rapport DMARC envoyé")

        return result

    def _audit_dkim(self, domain: str) -> dict:
        """Teste les sélecteurs DKIM courants."""
        selectors = ["default", "google", "k1", "mail", "key1", "dkim",
                     "s1", "s2", "smtp", "email", "selector1", "selector2"]
        found = []
        for sel in selectors:
            records = self._doh(f"{sel}._domainkey.{domain}", "TXT")
            for r in records:
                if "v=DKIM1" in r or "p=" in r:
                    found.append({"selector": sel, "record": r[:100]})
                    break
        return {
            "selectors_found": found,
            "count": len(found),
            "finding": "✓ DKIM configuré" if found else "MOYEN — Aucun sélecteur DKIM courant trouvé",
        }

    def _audit_mta_sts(self, domain: str) -> dict:
        """MTA-STS — force le chiffrement TLS pour la réception d'email."""
        records = self._doh(f"_mta-sts.{domain}", "TXT")
        sts_dns = next((r for r in records if "v=STSv1" in r), None)
        try:
            r = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                             timeout=4, verify=False)
            policy = r.text[:300] if r.status_code == 200 else None
        except Exception:
            policy = None
        return {
            "dns_record":  sts_dns,
            "policy_file": policy,
            "enabled":     bool(sts_dns and policy),
            "finding":     "✓ MTA-STS actif" if (sts_dns and policy) else "INFO — MTA-STS non configuré",
        }

    def _test_spoofing(self, domain: str) -> dict:
        """Évalue le risque de spoofing basé sur SPF + DMARC combinés."""
        spf_r   = self._doh(domain, "TXT")
        dmarc_r = self._doh(f"_dmarc.{domain}", "TXT")
        spf     = next((r for r in spf_r if "v=spf1" in r), None)
        dmarc   = next((r for r in dmarc_r if "v=DMARC1" in r), None)

        if not spf and not dmarc:
            return {"risk": "CRITIQUE", "msg": "Pas de SPF ni DMARC — spoofing trivial"}
        if not dmarc or "p=none" in (dmarc or ""):
            return {"risk": "ÉLEVÉ", "msg": "DMARC absent ou p=none — spoofing probable"}
        if "~all" in (spf or "") and "p=quarantine" in (dmarc or ""):
            return {"risk": "MOYEN", "msg": "SPF softfail + DMARC quarantine — risque résiduel"}
        if "-all" in (spf or "") and "p=reject" in (dmarc or ""):
            return {"risk": "FAIBLE", "msg": "SPF strict + DMARC reject — bonne protection"}
        return {"risk": "MOYEN", "msg": "Configuration partielle — vérifiez SPF et DMARC"}

    def execute(self, config: dict) -> dict:
        domain = Prompt.ask("[bold cyan]Domaine email à auditer[/bold cyan]", default="google.com")
        report = {"domain": domain, "spf": {}, "dmarc": {}, "dkim": {},
                  "mta_sts": {}, "spoofing_risk": {}, "findings": []}

        with console.status("[cyan]Audit SPF…[/cyan]"):
            report["spf"] = self._audit_spf(domain)
        with console.status("[cyan]Audit DMARC…[/cyan]"):
            report["dmarc"] = self._audit_dmarc(domain)
        with console.status("[cyan]Recherche DKIM…[/cyan]"):
            report["dkim"] = self._audit_dkim(domain)
        with console.status("[cyan]Vérification MTA-STS…[/cyan]"):
            report["mta_sts"] = self._audit_mta_sts(domain)

        report["spoofing_risk"] = self._test_spoofing(domain)

        # Consolidation findings
        for section in ("spf", "dmarc"):
            report["findings"].extend(report[section].get("findings", []))
        report["findings"].append(report["dkim"]["finding"])
        report["findings"].append(report["mta_sts"]["finding"])

        # Affichage
        risk     = report["spoofing_risk"]
        risk_col = {"CRITIQUE":"red","ÉLEVÉ":"orange1","MOYEN":"yellow","FAIBLE":"green"}.get(risk["risk"],"white")

        tbl = Table(title=f"Email Security — {domain}", box=box.SIMPLE_HEAVY)
        tbl.add_column("Composant", style="yellow", width=12)
        tbl.add_column("Statut")
        tbl.add_column("Détail")

        def _status(d, key="risk"):
            v = d.get(key, "?")
            c = {"OK":"green","CRITIQUE":"red","ÉLEVÉ":"orange1","MOYEN":"yellow","FAIBLE":"dim"}.get(v,"white")
            return f"[{c}]{v}[/{c}]"

        spf_rec   = report["spf"].get("record", "ABSENT") or "ABSENT"
        dmarc_rec = report["dmarc"].get("record", "ABSENT") or "ABSENT"
        tbl.add_row("SPF",     _status(report["spf"]),   spf_rec[:70])
        tbl.add_row("DMARC",   _status(report["dmarc"]), dmarc_rec[:70])
        tbl.add_row("DKIM",    "─", f"{report['dkim']['count']} sélecteur(s) trouvé(s)")
        tbl.add_row("MTA-STS", "─", report["mta_sts"]["finding"])
        tbl.add_row("Spoofing", f"[{risk_col}]{risk['risk']}[/{risk_col}]", risk["msg"])
        console.print(tbl)

        findings = [f for f in report["findings"] if not f.startswith("✓")]
        if findings:
            console.print(Panel(
                "\n".join(f"  • {f}" for f in findings),
                title="[red]Email Security Findings[/red]", border_style="red"
            ))

        return report


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 11 — FIREWALL / EXPOSURE PROBER
# ══════════════════════════════════════════════════════════════════════════════
class FirewallProberPlugin(BasePlugin):
    @property
    def name(self) -> str: return "Firewall / Exposure Prober"
    @property
    def description(self) -> str: return "Détecte les services critiques exposés sans auth (Redis, MongoDB, Jupyter…)"

    # Services qui ne devraient JAMAIS être exposés publiquement
    CRITICAL_EXPOSURES = [
        {"port": 6379,  "service": "Redis",          "probe": b"PING\r\n",
         "expected": "+PONG",   "auth_probe": b"AUTH wrongpassword\r\n", "auth_err": "NOAUTH"},
        {"port": 27017, "service": "MongoDB",         "probe": None,
         "expected": None,      "auth_probe": None, "auth_err": None},
        {"port": 9200,  "service": "Elasticsearch",   "probe": b"GET / HTTP/1.0\r\n\r\n",
         "expected": "cluster_name", "auth_probe": None, "auth_err": None},
        {"port": 8888,  "service": "Jupyter",         "probe": b"GET / HTTP/1.0\r\n\r\n",
         "expected": "jupyter", "auth_probe": None, "auth_err": None},
        {"port": 5432,  "service": "PostgreSQL",      "probe": None,
         "expected": None,      "auth_probe": None, "auth_err": None},
        {"port": 3306,  "service": "MySQL",           "probe": None,
         "expected": None,      "auth_probe": None, "auth_err": None},
        {"port": 5984,  "service": "CouchDB",         "probe": b"GET / HTTP/1.0\r\n\r\n",
         "expected": "couchdb", "auth_probe": None, "auth_err": None},
        {"port": 2375,  "service": "Docker API",      "probe": b"GET /version HTTP/1.0\r\n\r\n",
         "expected": "ApiVersion", "auth_probe": None, "auth_err": None},
        {"port": 2379,  "service": "etcd",            "probe": b"GET /version HTTP/1.0\r\n\r\n",
         "expected": "etcdserver", "auth_probe": None, "auth_err": None},
        {"port": 4243,  "service": "Docker alt",      "probe": b"GET /version HTTP/1.0\r\n\r\n",
         "expected": "ApiVersion", "auth_probe": None, "auth_err": None},
        {"port": 11211, "service": "Memcached",       "probe": b"stats\r\n",
         "expected": "STAT",    "auth_probe": None, "auth_err": None},
        {"port": 9042,  "service": "Cassandra",       "probe": None,
         "expected": None,      "auth_probe": None, "auth_err": None},
        {"port": 7474,  "service": "Neo4j HTTP",      "probe": b"GET / HTTP/1.0\r\n\r\n",
         "expected": "neo4j",   "auth_probe": None, "auth_err": None},
        {"port": 4848,  "service": "GlassFish Admin", "probe": b"GET / HTTP/1.0\r\n\r\n",
         "expected": "GlassFish", "auth_probe": None, "auth_err": None},
        {"port": 9090,  "service": "Prometheus",      "probe": b"GET /metrics HTTP/1.0\r\n\r\n",
         "expected": "# HELP",  "auth_probe": None, "auth_err": None},
        {"port": 3000,  "service": "Grafana",         "probe": b"GET /api/health HTTP/1.0\r\n\r\n",
         "expected": "database", "auth_probe": None, "auth_err": None},
    ]

    def _probe_service(self, target: str, svc: dict, timeout: float) -> dict | None:
        port = svc["port"]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) != 0:
                    return None  # Port fermé

                exposed   = False
                no_auth   = False
                banner    = ""

                if svc["probe"]:
                    s.sendall(svc["probe"])
                    try:
                        banner = s.recv(1024).decode(errors="ignore")
                    except Exception:
                        pass
                    if svc["expected"] and svc["expected"].lower() in banner.lower():
                        exposed = True
                        # Tester l'absence d'authentification
                        if svc["auth_probe"] and svc["auth_err"]:
                            try:
                                s.sendall(svc["auth_probe"])
                                auth_resp = s.recv(256).decode(errors="ignore")
                                # Si NOAUTH → auth requise (bon signe)
                                # Si pas d'erreur → pas d'auth (mauvais signe)
                                no_auth = svc["auth_err"] not in auth_resp
                            except Exception:
                                no_auth = True
                        else:
                            no_auth = True  # Pas de mécanisme d'auth connu
                else:
                    # Port ouvert suffit pour les DB avec protocole binaire
                    exposed = True
                    no_auth = True

                if exposed:
                    return {
                        "port":    port,
                        "service": svc["service"],
                        "no_auth": no_auth,
                        "banner":  banner[:100],
                        "severity": "CRITIQUE" if no_auth else "ÉLEVÉ",
                    }
        except Exception:
            pass
        return None

    def execute(self, config: dict) -> dict:
        cfg    = config["modules"]["network_scan"]
        target = Prompt.ask("[bold cyan]Cible à sonder[/bold cyan]", default="127.0.0.1")
        ip     = _resolve(target)
        report = {"target": target, "ip": ip, "exposed": [], "findings": []}

        console.print(f"[dim]Sondage de {len(self.CRITICAL_EXPOSURES)} services critiques sur {target}…[/dim]")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(bar_width=35), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("[red]Firewall Prober…", total=len(self.CRITICAL_EXPOSURES))
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                futs = {ex.submit(self._probe_service, ip, svc, cfg["timeout"]): svc
                        for svc in self.CRITICAL_EXPOSURES}
                for fut in concurrent.futures.as_completed(futs):
                    prog.advance(task)
                    result = fut.result()
                    if result:
                        report["exposed"].append(result)

        report["exposed"].sort(key=lambda x: x["port"])

        if report["exposed"]:
            tbl = Table(title=f"Services exposés — {target}", box=box.SIMPLE_HEAVY)
            tbl.add_column("Port",    width=8)
            tbl.add_column("Service", style="cyan", width=16)
            tbl.add_column("Auth",    width=10)
            tbl.add_column("Sévérité",width=10)
            tbl.add_column("Bannière")

            for svc in report["exposed"]:
                auth_str = "[red]ABSENT[/red]" if svc["no_auth"] else "[green]Présente[/green]"
                sev_col  = "red" if svc["severity"] == "CRITIQUE" else "orange1"
                tbl.add_row(
                    str(svc["port"]), svc["service"], auth_str,
                    f"[{sev_col}]{svc['severity']}[/{sev_col}]",
                    svc["banner"][:60] or "(connexion établie)"
                )
                report["findings"].append(
                    f"{svc['severity']} — {svc['service']} (port {svc['port']}) "
                    f"exposé{'sans authentification' if svc['no_auth'] else ''}"
                )
            console.print(tbl)

            critique_count = sum(1 for s in report["exposed"] if s["severity"] == "CRITIQUE")
            if critique_count:
                console.print(Panel(
                    f"[bold red]{critique_count} service(s) CRITIQUE(s) exposés sans authentification.[/bold red]\n"
                    "[dim]Ces services permettent un accès direct aux données — isolez-les immédiatement.[/dim]",
                    border_style="red"
                ))
        else:
            console.print("[green]✓ Aucun service critique exposé détecté.[/green]")

        return report


# ══════════════════════════════════════════════════════════════════════════════
# RISK ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class ContextualRiskEngine:
    WEIGHTS = {
        "Port Scanner (TCP/Banner)":            lambda d: len(d.get("open_ports", [])) * 0.8,
        "SSL/TLS Auditor":                      lambda d: sum(
            3.5 if "CRITIQUE" in f else 2.0 if "ÉLEVÉ" in f else 0.5
            for f in d.get("findings", [])
        ),
        "SSH Audit + Brute-Force (Paramiko)":   lambda d: (
            (5.0 if d.get("brute_force", {}).get("success") else 0) +
            sum(2.0 if "CRITIQUE" in f else 1.0 for f in d.get("sshd_findings", []))
        ),
        "Hash Cracker (dict + mutations)":      lambda d: 3.0 if d.get("success") else 0,
        "Password Policy Auditor (NIST 800-63B)": lambda d: (
            (4.0 if d.get("hibp", {}).get("leaked") else 0) +
            (3.0 if (d.get("score") or 10) < 3 else 0)
        ),
        "DNS Reconnaissance":                   lambda d: (
            0.5 * len(d.get("subdomains", [])) +
            (1.0 if not d.get("spf") else 0) +
            (1.0 if not d.get("dmarc") else 0)
        ),
        "CVE Lookup (NVD/NIST)":               lambda d: (
            d.get("total_critical", 0) * 2.5 +
            sum(1.0 for f in d.get("cve_findings", []) if f.get("counts", {}).get("HIGH", 0) > 0)
        ),
        "Web Scanner HTTP":                     lambda d: sum(
            3.0 if "CRITIQUE" in f else 1.5 if "ÉLEVÉ" in f else 0.5 if "MOYEN" in f else 0
            for f in d.get("findings", [])
        ),
        "Email Security Auditor":               lambda d: (
            (3.0 if d.get("spoofing_risk", {}).get("risk") == "CRITIQUE" else
             2.0 if d.get("spoofing_risk", {}).get("risk") == "ÉLEVÉ" else
             1.0 if d.get("spoofing_risk", {}).get("risk") == "MOYEN" else 0)
        ),
        "Firewall / Exposure Prober":           lambda d: (
            sum(3.5 if s.get("severity") == "CRITIQUE" else 2.0
                for s in d.get("exposed", []))
        ),
    }

    @classmethod
    def evaluate(cls, vault: dict) -> dict:
        total      = 1.0
        indicators = []

        for module_name, scorer in cls.WEIGHTS.items():
            entry = vault.get(module_name, {})
            if not entry:
                continue
            payload = entry.get("payload", {})
            delta   = scorer(payload)
            if delta > 0:
                total += delta
                indicators.append(f"[{module_name}] +{delta:.1f}")

        final    = round(min(total, 10.0), 1)
        severity = (
            "CRITIQUE" if final >= 7.5 else
            "ÉLEVÉE"   if final >= 4.0 else
            "MODÉRÉE"  if final >= 2.0 else
            "FAIBLE"
        )
        return {"risk_score": final, "severity": severity, "factors": indicators}


# ══════════════════════════════════════════════════════════════════════════════
# RAPPORT HTML
# ══════════════════════════════════════════════════════════════════════════════
def _generate_html_report(report_data: dict, filename: str) -> str:
    """Génère un rapport HTML standalone stylisé."""
    risk   = report_data["risk_assessment"]
    score  = risk["risk_score"]
    sev    = risk["severity"]
    color  = {"CRITIQUE": "#e53935", "ÉLEVÉE": "#fb8c00", "MODÉRÉE": "#fdd835", "FAIBLE": "#43a047"}.get(sev, "#888")

    evidence_html = ""
    for module, data in report_data.get("collected_evidence", {}).items():
        payload_str = html.escape(json.dumps(data.get("payload", {}), indent=2, ensure_ascii=False))
        evidence_html += f"""
        <details>
          <summary><strong>{html.escape(module)}</strong>
            <span class="ts">{data.get('captured_at','')}</span>
          </summary>
          <pre>{payload_str}</pre>
        </details>
        """

    factors_html = "".join(f"<li>{html.escape(f)}</li>" for f in risk.get("factors", []))

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESF — Rapport d'Audit Sécurité</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;padding:2rem;}}
  h1{{color:var(--accent);margin-bottom:.5rem;}}
  .meta{{color:#8b949e;font-size:.85rem;margin-bottom:2rem;}}
  .risk-card{{background:var(--card);border:2px solid {color};border-radius:8px;
              padding:1.5rem;margin-bottom:2rem;display:flex;gap:2rem;align-items:center;}}
  .score{{font-size:3.5rem;font-weight:700;color:{color};line-height:1;}}
  .severity{{font-size:1.4rem;font-weight:600;color:{color};}}
  ul{{list-style:none;padding:0;}}
  li::before{{content:"▸ ";color:var(--accent);}}
  li{{padding:.2rem 0;}}
  details{{background:var(--card);border:1px solid var(--border);border-radius:6px;
           margin:.5rem 0;overflow:hidden;}}
  summary{{padding:.8rem 1rem;cursor:pointer;user-select:none;
           display:flex;justify-content:space-between;}}
  summary:hover{{background:#1c2128;}}
  pre{{background:#010409;padding:1rem;overflow:auto;font-size:.8rem;max-height:400px;}}
  .ts{{color:#8b949e;font-size:.8rem;font-weight:400;}}
  h2{{color:var(--accent);margin:2rem 0 .8rem;border-bottom:1px solid var(--border);padding-bottom:.4rem;}}
</style>
</head>
<body>
  <h1>🛡️ Enterprise Security Core Framework</h1>
  <p class="meta">
    Généré le {report_data['metadata']['scan_time']} —
    Version {report_data['metadata']['engine_version']}
  </p>

  <div class="risk-card">
    <div>
      <div class="score">{score}/10</div>
    </div>
    <div>
      <div class="severity">{sev}</div>
      <ul style="margin-top:.8rem">
        {factors_html or "<li>Aucun facteur de risque détecté.</li>"}
      </ul>
    </div>
  </div>

  <h2>📦 Artefacts de Session</h2>
  {evidence_html or "<p>Aucune donnée collectée.</p>"}
</body>
</html>"""

    html_path = filename.replace(".json", ".html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_path



def _generate_pdf_report(report_data: dict, json_path: str) -> str | None:
    """Génère un rapport PDF professionnel avec fpdf2."""
    if not FPDF_OK:
        logger.warning("fpdf2 non disponible — pip install fpdf2")
        return None

    risk     = report_data["risk_assessment"]
    score    = risk["risk_score"]
    sev      = risk["severity"]
    sev_rgb  = {
        "CRITIQUE": (229, 57,  53),
        "ÉLEVÉE":   (251, 140,  0),
        "MODÉRÉE":  (253, 216, 53),
        "FAIBLE":   ( 67, 160, 71),
    }.get(sev, (100, 100, 100))

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Page de garde ──────────────────────────────────────────────────────
    pdf.set_fill_color(13, 17, 23)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(88, 166, 255)
    pdf.set_xy(15, 30)
    pdf.cell(0, 12, "Enterprise Security Framework", ln=True, align="C")

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(200, 200, 200)
    pdf.cell(0, 10, "Rapport d'Audit de Sécurité", ln=True, align="C")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(139, 148, 158)
    pdf.cell(0, 8, f"Version {report_data['metadata']['engine_version']}", ln=True, align="C")
    pdf.cell(0, 8, f"Généré le {report_data['metadata']['scan_time'][:19].replace('T', ' à ')}", ln=True, align="C")

    # Score de risque
    pdf.set_xy(15, 100)
    pdf.set_font("Helvetica", "B", 72)
    pdf.set_text_color(*sev_rgb)
    pdf.cell(0, 30, f"{score}/10", ln=True, align="C")

    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 12, sev, ln=True, align="C")

    # Ligne séparatrice
    pdf.set_draw_color(*sev_rgb)
    pdf.set_line_width(0.8)
    pdf.line(30, 165, 180, 165)

    # Facteurs
    pdf.set_xy(15, 170)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, "Facteurs de risque :", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(200, 200, 200)
    for factor in risk.get("factors", [])[:10]:
        pdf.set_x(20)
        pdf.cell(0, 6, f"  > {factor}", ln=True)

    # Disclaimer
    pdf.set_xy(15, 265)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, "Usage strictement autorise - sur systemes avec consentement ecrit explicite", align="C")

    # ── Pages de détail par module ─────────────────────────────────────────
    for module_name, module_data in report_data.get("collected_evidence", {}).items():
        pdf.add_page()
        pdf.set_fill_color(22, 27, 34)
        pdf.rect(0, 0, 210, 297, "F")

        # En-tête module
        pdf.set_fill_color(*sev_rgb)
        pdf.rect(0, 0, 210, 18, "F")
        pdf.set_xy(10, 4)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, f"Module : {module_name}", ln=True)

        pdf.set_xy(10, 20)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(139, 148, 158)
        pdf.cell(0, 5, f"Capturé le {module_data.get('captured_at','')[:19].replace('T',' ')}", ln=True)

        payload = module_data.get("payload", {})

        # Findings si présents
        findings = payload.get("findings", [])
        if findings:
            pdf.set_xy(10, 30)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(229, 57, 53)
            pdf.cell(0, 7, "Findings :", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for f in findings[:15]:
                pdf.set_text_color(200, 200, 200)
                sev_f = f.split(" — ")[0] if " — " in f else ""
                rgb   = {"CRITIQUE":(229,57,53),"ÉLEVÉ":(251,140,0),"MOYEN":(253,216,53),"FAIBLE":(67,160,71)}.get(sev_f,(150,150,150))
                pdf.set_text_color(*rgb)
                pdf.set_x(15)
                safe_f = f.encode('latin-1', errors='replace').decode('latin-1')
                pdf.cell(0, 5, f"  • {safe_f[:100]}", ln=True)

        # Données clés selon le module
        pdf.set_y(pdf.get_y() + 5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(88, 166, 255)
        pdf.cell(0, 6, "Données collectées :", ln=True)
        pdf.set_font("Courier", "", 7.5)
        pdf.set_text_color(180, 180, 180)

        # Sérialiser le payload de façon lisible
        def _safe(v):
            s = str(v)[:120]
            return s.encode('latin-1', errors='replace').decode('latin-1')

        for key, val in payload.items():
            if key in ("findings", "san_sample"):
                continue
            if isinstance(val, list):
                pdf.set_x(12)
                pdf.cell(0, 4.5, f"{key}: [{len(val)} items]", ln=True)
            elif isinstance(val, dict):
                pdf.set_x(12)
                pdf.cell(0, 4.5, f"{key}: {{...}}", ln=True)
            else:
                pdf.set_x(12)
                pdf.cell(0, 4.5, f"{key}: {_safe(val)}", ln=True)
            if pdf.get_y() > 270:
                break

    pdf_path = json_path.replace(".json", ".pdf")
    try:
        pdf.output(pdf_path)
        return pdf_path
    except Exception as e:
        logger.error(f"Erreur génération PDF : {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATEUR CENTRAL
# ══════════════════════════════════════════════════════════════════════════════
class FrameworkCore:
    def __init__(self):
        self.config  = FRAMEWORK_CONFIG
        self.plugins = [
            NetworkScannerPlugin(),
            SslAuditorPlugin(),
            OsintIpPlugin(),
            DnsReconPlugin(),
            SshAuditPlugin(),
            HashCrackerPlugin(),
            PasswordPolicyPlugin(),
            CveLookupPlugin(),
            WebScannerPlugin(),
            EmailSecurityPlugin(),
            FirewallProberPlugin(),
        ]
        self.session_vault: dict = {}
        Path(self.config["framework"]["reports_dir"]).mkdir(exist_ok=True)

    # ── Banner ─────────────────────────────────────────────────────────────
    def display_banner(self):
        banner = r"""[bold blue]
 ███████╗███████╗███████╗    ██╗   ██╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝    ██║   ██║██║  ██║
 █████╗  ███████╗█████╗      ██║   ██║███████║
 ██╔══╝  ╚════██║██╔══╝      ╚██╗ ██╔╝╚════██║
 ███████╗███████║██║          ╚████╔╝      ██║
 ╚══════╝╚══════╝╚═╝           ╚═══╝       ╚═╝[/bold blue]
  [bold magenta]Enterprise Security Framework v5.0 — DevSecOps / SecOps / 11 Modules[/bold magenta]
  [dim]Usage strictement autorisé — sur systèmes avec consentement écrit[/dim]
        """
        console.print(banner)

    # ── Dashboard ──────────────────────────────────────────────────────────
    def display_dashboard(self):
        tbl = Table(title="SOC Dashboard", title_style="bold cyan",
                    box=box.SIMPLE_HEAVY, show_lines=True)
        tbl.add_column("ID",      style="bold yellow", width=5)
        tbl.add_column("Module",  style="cyan")
        tbl.add_column("Statut",  style="green", width=12)
        tbl.add_column("Description", style="white")

        for i, p in enumerate(self.plugins, 1):
            status = "[green]✓ Données[/green]" if p.name in self.session_vault else "[dim]En attente[/dim]"
            tbl.add_row(str(i), p.name, status, p.description)

        tbl.add_row("R", "[bold gold1]Rapport + Risk Engine[/bold gold1]", "", "JSON + HTML — corrélation globale")
        tbl.add_row("Q", "[bold red]Shutdown[/bold red]", "", "Fermeture propre")
        console.print(tbl)

    # ── Rapport final ──────────────────────────────────────────────────────
    def finalize_report(self):
        if not self.session_vault:
            console.print("[yellow]Session vide — exécutez au moins un module.[/yellow]")
            return

        risk = ContextualRiskEngine.evaluate(self.session_vault)

        report_data = {
            "metadata": {
                "scan_time":      datetime.now().isoformat(),
                "engine_version": self.config["framework"]["version"],
            },
            "risk_assessment":  risk,
            "collected_evidence": self.session_vault,
        }

        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = f"{self.config['framework']['reports_dir']}/audit_{ts}"
        json_path = basename + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

        html_path = _generate_html_report(report_data, json_path)
        pdf_path  = _generate_pdf_report(report_data, json_path)

        sev_color = {
            "CRITIQUE": "bold red", "ÉLEVÉE": "bold orange1",
            "MODÉRÉE": "bold yellow", "FAIBLE": "bold green"
        }.get(risk["severity"], "white")

        pdf_line = f"\n[dim]PDF   → {pdf_path}[/dim]" if pdf_path else ""
        console.print(Panel(
            f"[bold]Score de Risque Global :[/bold] [{sev_color}]{risk['risk_score']}/10[/{sev_color}]\n"
            f"[bold]Sévérité :[/bold] [{sev_color}]{risk['severity']}[/{sev_color}]\n\n"
            f"[bold]Facteurs :[/bold]\n" + "\n".join(f"  • {f}" for f in risk["factors"]) +
            f"\n\n[dim]JSON  → {json_path}[/dim]\n"
            f"[dim]HTML  → {html_path}[/dim]{pdf_line}",
            title="🎯 CONTEXTUAL RISK ASSESSMENT", border_style="red"
        ))

    # ── Boucle principale ──────────────────────────────────────────────────
    def run(self):
        logger.info("ESF v5.0 — Noyau central initialisé.")
        while True:
            if os.name == "nt":
                os.system("cls")
            else:
                sys.stdout.write("\033[H\033[2J\033[3J")
                sys.stdout.flush()

            self.display_banner()
            self.display_dashboard()

            choix = console.input("\n[bold yellow]Instruction → [/bold yellow]").strip().upper()

            if choix == "Q":
                logger.info("Arrêt demandé.")
                console.print("[dim]Fermeture propre — Au revoir.[/dim]")
                break
            elif choix == "R":
                self.finalize_report()
            else:
                try:
                    idx = int(choix) - 1
                    if 0 <= idx < len(self.plugins):
                        plugin = self.plugins[idx]
                        logger.info(f"Module lancé : {plugin.name}")
                        console.print(f"\n[bold cyan]━━ {plugin.name} ━━[/bold cyan]\n")
                        try:
                            self.config["_vault"] = self.session_vault
                            result = plugin.execute(self.config)
                            self.session_vault[plugin.name] = {
                                "captured_at": datetime.now().isoformat(),
                                "payload":     result,
                            }
                            console.print("\n[bold green][✓] Données enregistrées dans la session.[/bold green]")
                        except KeyboardInterrupt:
                            console.print("\n[yellow]Module interrompu par l'opérateur.[/yellow]")
                        except Exception as e:
                            logger.error(f"Erreur module {plugin.name} : {e}", exc_info=True)
                    else:
                        console.print("[red]ID hors plage.[/red]")
                except ValueError:
                    console.print("[red]Entrée invalide.[/red]")

            console.input("\n[dim]Appuyez sur Entrée pour continuer…[/dim]")


# ── Point d'entrée ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        FrameworkCore().run()
    except KeyboardInterrupt:
        console.print("\n[dim]Interruption — arrêt propre.[/dim]")
    except Exception as e:
        console.print(f"[bold red][FATAL] {e}[/bold red]")
        sys.exit(1)
