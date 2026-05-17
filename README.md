# 🛡️ Enterprise Security Core Framework (v4.0)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Profile](https://img.shields.io/badge/profile-DevSecOps_/_SecOps-orange.svg)]()
[![Version](https://img.shields.io/badge/version-4.0.0--ENTERPRISE-red.svg)]()

Un framework d'automatisation et d'audit de sécurité centralisé, conçu selon les standards de l'ingénierie logicielle professionnelle. Cet outil intègre un **moteur de calcul de risques contextuels (Risk Engine)**, une architecture orientée objet extensible (pattern Plugin / SOLID), un système de double journalisation structurée et une interface de type **SOC Dashboard** — le tout sans simulation : chaque module opère sur des cibles réelles.

---

## 🎯 Architecture & Concepts Implémentés

- **Pattern Plugin (Open/Closed SOLID) :** Classe de base abstraite `BasePlugin` — l'ajout d'un nouveau module ne nécessite aucune modification du noyau.
- **Contextual Risk Engine :** Algorithme de corrélation de session qui analyse les vulnérabilités croisées (port ouvert + mot de passe compromis + cert expiré…) pour produire un score de criticité global inspiré du standard CVSS.
- **Concurrence Optimisée (`ThreadPoolExecutor`) :** Scan réseau asynchrone avec contrôle du nombre de workers, thread-safety garantie sur les affichages console et back-off linéaire sur les modules SSH.
- **Fingerprinting Protocol-Aware :** Sondes adaptées par protocole — requêtes HTTP ciblées, interception de bannières SSH/FTP/Redis/Elasticsearch, handshake TLS natif.
- **Résilience & API Failover :** Le module OSINT bascule dynamiquement sur des nœuds secondaires en cas d'indisponibilité de l'API principale.
- **Journalisation & Télémétrie :** Double flux de logs (opérateur via `RichHandler` + persistance dans `framework.log`). Rapports exportés en **JSON** et **HTML standalone** dans `./reports/`.

---

## 🛠️ Modules Embarqués

| # | Module | Description |
|---|--------|-------------|
| 1 | 🌐 **Port Scanner TCP + Banner Grab** | Scan concurrent sur plage de ports libre (défaut : 29 ports stratégiques), fingerprinting par protocole (HTTP, SSH, FTP, Redis, Elasticsearch, TLS…). |
| 2 | 🔒 **SSL/TLS Auditor** | Validité et expiration du certificat, détection des protocoles dépréciés (TLS 1.0/1.1), audit des cipher suites faibles, vérification HSTS. |
| 3 | 🔍 **OSINT IP / Géoloc / ASN** | Géolocalisation, ISP, ASN, DNS inverse et Whois natif (socket port 43) avec résolution du serveur référent IANA — Fallback multi-API. |
| 4 | 🧬 **DNS Reconnaissance** | Résolution multi-types (A / AAAA / MX / NS / TXT), détection SPF & DMARC, énumération de 30 sous-domaines courants via DoH (Google). |
| 5 | 🔑 **SSH Audit + Brute-Force (Paramiko)** | Banner grab, audit `sshd_config` local, attaque par dictionnaire réelle via Paramiko avec retry/back-off, wordlist externe ou intégrée + mutations Leet. |
| 6 | 💀 **Hash Cracker (dict + mutations)** | Cracking réel par dictionnaire — MD5, SHA1, SHA224, SHA256, SHA512 — avec détection automatique de l'algorithme et génération de mutations. |
| 7 | 🧪 **Password Policy Auditor (NIST 800-63B)** | Calcul d'entropie, score de force réelle, vérification **HaveIBeenPwned** (k-Anonymity — le mot de passe ne quitte jamais la machine), grade A–F. |

---

## 📦 Installation & Dépendances

### 1. Clonage du projet

```bash
git clone https://github.com/Maxime288/Toolbox.git
cd Toolbox
```

### 2. Installation des packages requis

```bash
pip install rich requests paramiko
```

> **Note :** `paramiko` est requis uniquement pour le module SSH (module 5). Les autres modules fonctionnent sans lui.

---

## 🖥️ Utilisation

```bash
python framework_pro.py
```

### Déroulement nominal d'une session d'audit

1. **Sélection des modules** depuis le SOC Dashboard — chaque résultat est mémorisé dans le `session_vault`.
2. **Corrélation & Clôture** via l'option `R` — le Risk Engine croise les métadonnées de session, calcule le score de sévérité global et exporte le rapport dans `./reports/`.

---

## 📊 Artefacts Générés

Chaque session produit deux fichiers dans `./reports/` :

**`audit_<timestamp>.json`** — ingérable par un SIEM ou outil tiers :

```json
{
    "metadata": {
        "scan_time": "2026-05-17T01:13:44.123456",
        "engine_version": "4.0.0-ENTERPRISE"
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

---

## 🛡️ Clause de non-responsabilité (Disclaimer)

> Cet outil est développé **exclusivement** à des fins d'enseignement, de démonstration d'architecture de code et d'audit interne légitime. L'utilisateur est seul responsable de l'usage des modules.
>
> **N'exécutez de tests que sur des infrastructures pour lesquelles vous possédez un consentement écrit et explicite.**

---

## 📝 Licence

Ce projet est distribué sous licence **MIT**. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.
