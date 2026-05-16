# 🛡️ Enterprise Security Core Framework (v3.0)

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Profile](https://img.shields.io/badge/profile-DevSecOps_/_SecOps-orange.svg)]()

Un framework d'automatisation et d'audit de sécurité centralisé, conçu selon les standards de l'ingénierie logicielle. Loin du simple script d'automatisation, cet outil intègre un **moteur de calcul de risques contextuels (Risk Engine)**, une architecture orientée objet extensible, un système de double journalisation structurée et une interface utilisateur de type **SOC Dashboard**.

---

## 🎯 Architecture & Concepts "Pro" Implémentés

Ce projet a été développé avec une attention stricte portée à la qualité du code, à la résilience et à la maintenabilité :

- **Pattern Plugin (Extensibilité) :** Utilisation d'une classe de base abstraite (`BasePlugin`) appliquant le principe *Open/Closed* de SOLID. L'ajout d'une nouvelle capacité fonctionnelle ne nécessite aucune modification du noyau principal.
- **Contextual Risk Engine :** Le framework ne se contente pas d'aligner des résultats bruts. Il implémente un algorithme de corrélation de session qui analyse les vulnérabilités croisées (ex: un port ouvert combiné à un mot de passe compromis) pour calculer un score de criticité global (équivalent à une logique CVSS).
- **Concurrence Optimisée (`ThreadPoolExecutor`) :** Le scanner réseau effectue ses requêtes de manière asynchrone pour optimiser les performances d'I/O réseau, tout en garantissant la *Thread-Safety* lors des affichages consoles.
- **Fingerprinting Protocol-Aware :** Le module réseau évite les blocages et les faux positifs en adaptant ses sondes selon le protocole détecté (requêtes HTTP ciblées, interception de signatures SSH/FTP et handshake TLS natif).
- **Résilience & API Failover :** Le module OSINT encapsule une couche d'abstraction réseau capable de basculer dynamiquement (*Fallback*) sur des nœuds d'API secondaires transparents en cas de panne ou de coupure de service.
- **Journalisation & Télémétrie :** Implémentation d'un double flux de logs : un flux asynchrone formaté pour l'opérateur (via `RichHandler`) et une persistance détaillée dans `framework.log`. Les résultats consolidés sont sérialisés au format standard JSON.

---

## 🛠️ Modules Embarqués

| # | Module | Description |
|---|--------|-------------|
| 1 | 🌐 **Scanner Réseau & Services** | Identification d'état des ports TCP stratégiques avec extraction de bannières applicatives et détection des versions TLS. |
| 2 | 🔑 **Password Audit Simulator** | Évaluation locale de la robustesse des politiques d'authentification face aux dictionnaires de fuites de données standards. |
| 3 | 🔍 **Module OSINT Réseau** | Collecte de métadonnées, FAI, ASN et géolocalisation des adresses IP publiques cibles avec routage dynamique. |

---

## 📦 Installation & Dépendances

Le framework limite au maximum l'usage de dépendances tierces pour garantir une portabilité optimale.

### 1. Clonage du projet

```bash
git clone https://github.com/Maxime288/Toolbox.git
cd Toolbox
```

### 2. Installation des packages requis

```bash
pip install rich requests
```

---

## 🖥️ Utilisation

Lancez le framework principal via votre terminal :

```bash
python framework_pro.py
```

### Déroulement nominal d'une session d'audit

1. **Exécution des modules :** Sélectionnez et exécutez les modules de votre choix depuis le tableau de bord. Chaque résultat est chiffré et mémorisé dans le coffre d'état (`session_vault`).

2. **Corrélation & Clôture :** Utilisez l'option `R` *(Générer Rapport & Risque Contextuel)*. Le Risk Engine s'active, croise les métadonnées de la session, génère le verdict de sévérité et exporte un rapport d'audit global structuré dans `./reports/`.

---

## 📊 Exemple d'Artefact Généré (Rapport JSON)

Les rapports générés sous `./reports/audit_security_*.json` adoptent une structure normalisée prête à être ingérée par un outil tiers ou un SIEM :

```json
{
    "metadata": {
        "scan_time": "2026-05-17T01:13:44.123456",
        "engine_version": "3.0.0-ENTERPRISE (All-In-One)"
    },
    "risk_assessment": {
        "risk_score_cvss": 6.7,
        "severity": "ÉLEVÉE",
        "risk_factors": [
            "2 port(s) actif(s) sur la cible réseau",
            "Identifiant critique présent dans les bases de fuites de données"
        ]
    },
    "collected_evidence": { "..." : "..." }
}
```

---

## 🛡️ Clause de non-responsabilité (Disclaimer)

> Cet outil est développé **exclusivement** à des fins d'enseignement, de démonstration d'architecture de code et d'audit interne légitime. L'utilisateur est seul responsable de l'usage des modules.
>
> **N'exécutez de tests que sur des infrastructures pour lesquelles vous possédez un consentement écrit et explicite.**

---

## 📝 Licence

Ce projet est distribué sous licence **MIT**. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.
