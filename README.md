# 🛡️ Enterprise Security Core Framework (v5.0)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Profile](https://img.shields.io/badge/profile-DevSecOps_/_SecOps-orange.svg)]()
[![Version](https://img.shields.io/badge/version-5.0.0--ENTERPRISE-red.svg)]()

Un framework d'automatisation et d'audit de sécurité centralisé, conçu selon les standards de l'ingénierie logicielle professionnelle. Cet outil intègre un **moteur de calcul de risques contextuels (Risk Engine)**, une architecture orientée objet extensible (pattern Plugin / SOLID), un système de double journalisation structurée et une interface de type **SOC Dashboard** — le tout sans simulation : chaque module opère sur des cibles réelles.

---

## 🎯 Architecture & Concepts Implémentés

- **Pattern Plugin (Open/Closed SOLID) :** Classe de base abstraite `BasePlugin` — l'ajout d'un nouveau module ne nécessite aucune modification du noyau.
- **Contextual Risk Engine :** Algorithme de corrélation de session qui analyse les vulnérabilités croisées (port ouvert + mot de passe compromis + cert expiré…) pour produire un score de criticité global inspiré du standard CVSS.
- **Concurrence Optimisée (`ThreadPoolExecutor`) :** Scan réseau asynchrone avec contrôle du nombre de workers (jusqu'à 150 threads), thread-safety garantie sur les affichages console et back-off linéaire sur les modules SSH.
- **Fingerprinting Protocol-Aware :** Sondes adaptées par protocole — requêtes HTTP ciblées, interception de bannières SSH/FTP/Redis/Elasticsearch, handshake TLS natif.
- **Résilience & API Failover :** Le module OSINT bascule dynamiquement sur des nœuds secondaires en cas d'indisponibilité de l'API principale.
- **Journalisation & Télémétrie :** Double flux de logs (opérateur via `RichHandler` + persistance dans `framework.log`). Rapports exportés en **JSON**, **HTML standalone** et **PDF** dans `./reports/`.

---

## 🛠️ Modules Embarqués

| # | Module | Description |
|---|--------|-------------|
| 1 | 🌐 **Port Scanner TCP + Banner Grab** | Scan concurrent sur plage de ports libre (défaut : 29 ports stratégiques), fingerprinting par protocole (HTTP, SSH, FTP, Redis, Elasticsearch, TLS…). |
| 2 | 🔒 **SSL/TLS Auditor** | Validité et expiration du certificat, détection des protocoles dépréciés (TLS 1.0/1.1) via `openssl s_client`, audit des cipher suites faibles, vérification HSTS multi-stratégie. |
| 3 | 🔍 **OSINT IP / Géoloc / ASN** | Géolocalisation, ISP, ASN, DNS inverse et Whois natif (socket port 43) avec résolution du serveur référent IANA — Fallback multi-API. |
| 4 | 🧬 **DNS Reconnaissance** | Résolution multi-types (A / AAAA / MX / NS / TXT), détection SPF & DMARC, énumération de 30 sous-domaines courants via DoH (Google). |
| 5 | 🔑 **SSH Audit + Brute-Force (Paramiko)** | Banner grab, audit `sshd_config` local, attaque par dictionnaire réelle via Paramiko avec retry/back-off, wordlist externe ou intégrée + mutations Leet. |
| 6 | 💀 **Hash Cracker (dict + mutations)** | Cracking réel par dictionnaire — MD5, SHA1, SHA224, SHA256, SHA512 — avec détection automatique de l'algorithme et génération de mutations. |
| 7 | 🧪 **Password Policy Auditor (NIST 800-63B)** | Calcul d'entropie, score de force réelle, vérification **HaveIBeenPwned** (k-Anonymity — le mot de passe ne quitte jamais la machine), grade A–F. |
| 8 | 🩻 **CVE Lookup (NVD API v2)** | Extraction automatique des services depuis les bannières du scanner, requête NVD en temps réel (CVSS score, vecteur d'attaque, description), fallback saisie manuelle. |
| 9 | 🕸️ **Web Scanner HTTP** | Audit des headers de sécurité (CSP, HSTS, X-Frame-Options…), détection de technologies (WordPress, Laravel, nginx…), scan concurrent de chemins sensibles (`.env`, `.git`, `phpinfo`…). |
| 10 | 📧 **Email Security Auditor** | Audit complet anti-phishing — SPF (mécanisme + lookups RFC), DMARC (politique + pct), DKIM (sélecteurs courants), MTA-STS, évaluation du risque de spoofing. |
| 11 | 🧱 **Firewall Prober** | Détection de filtrage réseau par analyse comportementale (connexions TCP, timeouts différentiels), identification des ports bloqués vs filtrés. |

---

## 📦 Installation & Dépendances

### 1. Clonage du projet

```bash
git clone https://github.com/Maxime288/Toolbox.git
cd Toolbox
```

### 2. Installation des packages requis

```bash
pip install rich requests paramiko fpdf2
```

> **Notes :**
> - `paramiko` est requis uniquement pour le module SSH (module 5).
> - `fpdf2` est requis pour l'export PDF du rapport final. Sans lui, seuls les formats JSON et HTML sont générés.
> - Les modules 1 à 4 et 6 à 11 fonctionnent avec uniquement `rich` et `requests`.

---

## 🖥️ Utilisation

```bash
python framework_pro.py
```

### Déroulement nominal d'une session d'audit

1. **Sélection des modules** depuis le SOC Dashboard — chaque résultat est mémorisé dans le `session_vault`.
2. **Corrélation & Clôture** via l'option `R` — le Risk Engine croise les métadonnées de session, calcule le score de sévérité global et exporte le rapport dans `./reports/`.
3. **Quitter proprement** via l'option `Q`.

> **Astuce :** Exécutez le module 1 (Port Scanner) en premier. Le module 8 (CVE Lookup) en exploitera automatiquement les bannières pour identifier les services et interroger la NVD sans saisie manuelle.

---

## 📊 Artefacts Générés

Chaque session produit jusqu'à trois fichiers dans `./reports/` :

**`audit_<timestamp>.json`** — ingérable par un SIEM ou outil tiers :

```json
{
    "metadata": {
        "scan_time": "2026-05-17T01:13:44.123456",
        "engine_version": "5.0.0-ENTERPRISE"
    },
    "risk_assessment": {
        "risk_score": 7.4,
        "severity": "ÉLEVÉE",
        "factors": [
            "[Port Scanner] +2.4",
            "[SSL/TLS Auditor] +3.5",
            "[SSH Audit] +5.0"
        ]
    },
    "collected_evidence": { "...": "..." }
}
```

**`audit_<timestamp>.html`** — rapport standalone dark-mode, visualisable directement dans un navigateur, avec score de risque colorisé et toutes les preuves en accordéon.

**`audit_<timestamp>.pdf`** — rapport PDF professionnel dark-mode, généré via `fpdf2`, avec synthèse du score de risque, findings par sévérité et données collectées par module.

---

## 🛡️ Clause de non-responsabilité (Disclaimer)

> Cet outil est développé **exclusivement** à des fins d'enseignement, de démonstration d'architecture de code et d'audit interne légitime. L'utilisateur est seul responsable de l'usage des modules.
>
> **N'exécutez de tests que sur des infrastructures pour lesquelles vous possédez un consentement écrit et explicite.**

---

## 📝 Licence

Ce projet est distribué sous licence **MIT**. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.
