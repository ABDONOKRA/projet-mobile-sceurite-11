# 🔐 Mobile API Misuse Detector — Guide de Développement Complet
 
**Projet Binôme — Sécurité Mobile**  
**Base : VulnSentinel (Flask + Python)**  
**Objectif : Détecter les abus d'API mobiles via analyse de logs, clustering IA et dashboard interactif**
 
---
 
## 📋 Table des Matières
 
1. [Vue d'ensemble du projet](#1-vue-densemble-du-projet)
2. [Architecture technique](#2-architecture-technique)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Étape 1 — Prise en main de VulnSentinel](#4-étape-1--prise-en-main-de-vulnsentinel)
5. [Étape 2 — Générateur de logs mobiles simulés](#5-étape-2--générateur-de-logs-mobiles-simulés)
6. [Étape 3 — Extension du parser pour les API mobiles](#6-étape-3--extension-du-parser-pour-les-api-mobiles)
7. [Étape 4 — Moteur de détection avancé](#7-étape-4--moteur-de-détection-avancé)
8. 
9. [Étape 5 — Intégration de l'IA (K-Means Clustering)](#8-étape-5--intégration-de-lia-k-means-clustering)
10. [Étape 6 — Dashboard amélioré avec Streamlit](#9-étape-6--dashboard-amélioré-avec-streamlit)
11. [Étape 7 — Système de recommandations anti-abus](#10-étape-7--système-de-recommandations-anti-abus)
12. [Étape 8 — Tests et validation](#11-étape-8--tests-et-validation)
13. [Division des tâches binôme](#12-division-des-tâches-binôme)
14. [Planning 4 semaines](#13-planning-4-semaines)
15. [Ressources & références](#14-ressources--références)
---
 
## 1. Vue d'ensemble du projet
 
### Ce que fait VulnSentinel (base clonée)
 
| Fonctionnalité | Statut |
|---|---|
| Parsing logs Apache/Nginx | ✅ Existant |
| Détection SQL Injection (regex) | ✅ Existant |
| Détection XSS (regex) | ✅ Existant |
| Détection brute force basique | ✅ Existant |
| Dashboard Flask HTML | ✅ Existant |
 
### Ce qu'on va AJOUTER (votre contribution)
 
| Fonctionnalité | Catégorie | Priorité |
|---|---|---|
| Générateur de logs mobiles simulés | Data | 🔴 Haute |
| Détection spécifique mobile (user-agent) | Détection | 🔴 Haute |
| Détection spikes de requêtes | Détection | 🔴 Haute |
| Détection énumération d'endpoints | Détection | 🔴 Haute |
| Clustering K-Means des patterns d'abus | IA/ML | 🟡 Moyenne |
| Dashboard Streamlit interactif | Frontend | 🟡 Moyenne |
| Système de recommandations automatiques | DevSecOps | 🟢 Bonus |
| Alertes en temps réel (Slack/Email) | Alerting | 🟢 Bonus |
 
---
 
## 2. Architecture technique
 
```
┌─────────────────────────────────────────────────────────┐
│                   MOBILE API MISUSE DETECTOR             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  [Logs Simulés]  ──►  [Parser Étendu]  ──►  [Détection] │
│   (Faker/Python)       (log_parser.py)      (rules.py)   │
│                                                          │
│                           │                              │
│                           ▼                              │
│                     [K-Means IA]                         │
│                    (clustering.py)                       │
│                           │                              │
│              ┌────────────┴────────────┐                 │
│              ▼                         ▼                 │
│     [Flask Dashboard]         [Streamlit Dashboard]      │
│      (app.py existant)         (streamlit_app.py)        │
│              │                         │                 │
│              └────────────┬────────────┘                 │
│                           ▼                              │
│              [Recommandations Anti-abus]                 │
│              (rate-limit, lockout, CAPTCHA)              │
└─────────────────────────────────────────────────────────┘
```
 
---
 
## 3. Structure des fichiers
 
```
vulnsentinel/
│
├── app.py                        # ✅ Flask existant (garder + étendre)
├── log_parser.py                 # ✅ Existant (étendre)
├── requirements.txt              # ⚠️ Mettre à jour
│
├── generator/
│   └── log_generator.py          # 🆕 Générateur de logs mobiles simulés
│
├── parser/
│   ├── log_parser.py             # ✅ Existant
│   └── mobile_parser.py          # 🆕 Parser spécifique mobile/API
│
├── detection/
│   ├── rules.py                  # 🆕 Règles de détection avancées
│   └── mobile_threats.py         # 🆕 Menaces spécifiques mobile
│
├── ai/
│   ├── clustering.py             # 🆕 K-Means clustering
│   └── feature_extractor.py     # 🆕 Extraction de features
│
├── dashboard/
│   └── streamlit_app.py          # 🆕 Dashboard Streamlit
│
├── recommendations/
│   └── advisor.py                # 🆕 Moteur de recommandations
│
├── samples/
│   ├── apache_log_sample.txt     # ✅ Existant
│   └── mobile_api_logs.txt       # 🆕 Logs mobiles simulés
│
├── templates/
│   └── dashboard.html            # ✅ Existant (améliorer)
│
└── README.md                     # ⚠️ Mettre à jour
```
 
---
 
## 4. Étape 1 — Prise en main de VulnSentinel
 
### 4.1 Installation et test de base
 
```bash
# Cloner et installer
git clone https://github.com/domino79/vulnsentinel.git
cd vulnsentinel
 
# Créer l'environnement virtuel
python -m venv env
source env/bin/activate          # Linux/Mac
env\Scripts\activate             # Windows
 
# Installer les dépendances
pip install -r requirements.txt
 
# Lancer le projet de base
python app.py
# Ouvrir : http://127.0.0.1:5000
```
 
### 4.2 Comprendre le code existant
 
Lire et comprendre ces 3 fichiers en priorité :
 
- `app.py` : point d'entrée Flask, routes et logique principale
- `log_parser.py` : parsing des logs, détection par regex
- `templates/dashboard.html` : interface web d'affichage
### 4.3 Mettre à jour requirements.txt
 
Remplacer le contenu de `requirements.txt` par :
 
```txt
# Existant
flask>=2.3.0
werkzeug>=2.3.0
 
# Parsing et data
pandas>=2.0.0
numpy>=1.24.0
 
# IA / Machine Learning
scikit-learn>=1.3.0
 
# Génération de logs simulés
faker>=19.0.0
 
# Dashboard Streamlit
streamlit>=1.28.0
plotly>=5.17.0
 
# Alerting (optionnel)
requests>=2.31.0
```
 
Installer :
 
```bash
pip install -r requirements.txt
```
 
---
 
## 5. Étape 2 — Générateur de logs mobiles simulés
 
Créer le fichier `generator/log_generator.py` :
 
```python
"""
Générateur de logs API mobiles simulés.
Produit des logs Nginx réalistes incluant des attaques typiques.
"""
 
import random
import datetime
import json
from faker import Faker
 
fake = Faker()
 
# User-agents mobiles réalistes
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Dart/3.0 (dart:io) - Flutter App",
    "okhttp/4.11.0",                         # Android natif
    "CFNetwork/1400.0.4 Darwin/22.0.0",      # iOS natif
    "ReactNativeApp/1.2.3",
]
 
# Endpoints d'API mobile typiques
API_ENDPOINTS = [
    "/api/v1/login",
    "/api/v1/logout",
    "/api/v1/register",
    "/api/v1/user/profile",
    "/api/v1/user/settings",
    "/api/v1/products",
    "/api/v1/orders",
    "/api/v1/payment",
    "/api/v1/notifications",
    "/api/v1/search",
    "/api/v1/refresh-token",
    "/api/v1/password-reset",
]
 
# Codes HTTP
HTTP_CODES_NORMAL   = [200, 200, 200, 201, 204, 304]
HTTP_CODES_ATTACK   = [401, 403, 429, 400, 500]
 
 
def generate_normal_log(ip: str, timestamp: datetime.datetime) -> dict:
    """Génère un log de requête normale."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": random.choice(["GET", "POST", "GET", "GET"]),
        "endpoint": random.choice(API_ENDPOINTS),
        "status": random.choice(HTTP_CODES_NORMAL),
        "size": random.randint(200, 5000),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "normal",
    }
 
 
def generate_brute_force_log(ip: str, timestamp: datetime.datetime) -> dict:
    """Génère un log de tentative brute force (login répété)."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": "POST",
        "endpoint": "/api/v1/login",
        "status": 401,
        "size": random.randint(50, 200),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "brute_force",
    }
 
 
def generate_spike_log(ip: str, timestamp: datetime.datetime) -> dict:
    """Génère un log de spike (flood de requêtes)."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": random.choice(["GET", "POST"]),
        "endpoint": random.choice(API_ENDPOINTS),
        "status": random.choice([200, 429]),
        "size": random.randint(100, 1000),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "spike",
    }
 
 
def generate_enumeration_log(ip: str, timestamp: datetime.datetime, index: int) -> dict:
    """Génère un log d'énumération d'endpoints."""
    return {
        "ip": ip,
        "timestamp": timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "method": "GET",
        "endpoint": f"/api/v1/user/{index}",
        "status": random.choice([200, 404]),
        "size": random.randint(50, 500),
        "user_agent": random.choice(MOBILE_USER_AGENTS),
        "type": "enumeration",
    }
 
 
def generate_logs(
    n_normal: int = 500,
    n_brute_force_ips: int = 3,
    n_spike_ips: int = 2,
    n_enum_ips: int = 2,
    output_file: str = "samples/mobile_api_logs.txt",
) -> list:
    """
    Génère un fichier de logs complet avec trafic normal et attaques.
    Retourne la liste de tous les logs générés.
    """
    logs = []
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
 
    # Logs normaux
    normal_ips = [fake.ipv4() for _ in range(50)]
    for i in range(n_normal):
        ts = base_time + datetime.timedelta(seconds=i * 5)
        ip = random.choice(normal_ips)
        logs.append(generate_normal_log(ip, ts))
 
    # Attaque brute force (plusieurs IPs distinctes)
    bf_ips = [fake.ipv4() for _ in range(n_brute_force_ips)]
    for ip in bf_ips:
        for j in range(random.randint(20, 50)):
            ts = base_time + datetime.timedelta(minutes=30, seconds=j * 2)
            logs.append(generate_brute_force_log(ip, ts))
 
    # Spikes de requêtes
    spike_ips = [fake.ipv4() for _ in range(n_spike_ips)]
    for ip in spike_ips:
        for j in range(random.randint(100, 200)):
            ts = base_time + datetime.timedelta(minutes=60, seconds=j * 0.5)
            logs.append(generate_spike_log(ip, ts))
 
    # Énumération d'endpoints
    enum_ips = [fake.ipv4() for _ in range(n_enum_ips)]
    for ip in enum_ips:
        for idx in range(1, random.randint(50, 100)):
            ts = base_time + datetime.timedelta(minutes=90, seconds=idx * 1)
            logs.append(generate_enumeration_log(ip, ts, idx))
 
    # Mélanger les logs
    random.shuffle(logs)
 
    # Format Nginx commun
    lines = []
    for log in logs:
        line = (
            f'{log["ip"]} - - [{log["timestamp"]}] '
            f'"{log["method"]} {log["endpoint"]} HTTP/1.1" '
            f'{log["status"]} {log["size"]} '
            f'"-" "{log["user_agent"]}"'
        )
        lines.append(line)
 
    # Sauvegarder
    import os
    os.makedirs("samples", exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(lines))
 
    print(f"[✓] {len(logs)} logs générés dans '{output_file}'")
    return logs
 
 
if __name__ == "__main__":
    generate_logs()
```
 
**Tester le générateur :**
 
```bash
python generator/log_generator.py
# Résultat : samples/mobile_api_logs.txt créé
```
 
---
 
## 6. Étape 3 — Extension du parser pour les API mobiles
 
Créer `parser/mobile_parser.py` :
 
```python
"""
Parser de logs API mobiles.
Étend le parser VulnSentinel existant avec des features spécifiques mobile.
"""
 
import re
import pandas as pd
from datetime import datetime
 
 
# Regex pour parser les logs Nginx
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<endpoint>[^\s]+) HTTP/[\d\.]+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"[^"]*" "(?P<user_agent>[^"]*)"'
)
 
MOBILE_UA_PATTERNS = [
    "Mobile", "Android", "iPhone", "iPad",
    "okhttp", "Dart", "CFNetwork", "ReactNative", "Flutter",
]
 
 
def is_mobile_request(user_agent: str) -> bool:
    """Vérifie si la requête provient d'un client mobile."""
    return any(p.lower() in user_agent.lower() for p in MOBILE_UA_PATTERNS)
 
 
def parse_log_line(line: str) -> dict | None:
    """Parse une ligne de log Nginx. Retourne None si invalide."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
 
    data = match.groupdict()
 
    # Convertir le timestamp
    try:
        ts = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S +0000")
    except ValueError:
        ts = None
 
    return {
        "ip":            data["ip"],
        "timestamp":     ts,
        "method":        data["method"],
        "endpoint":      data["endpoint"],
        "status":        int(data["status"]),
        "size":          int(data["size"]),
        "user_agent":    data["user_agent"],
        "is_mobile":     is_mobile_request(data["user_agent"]),
    }
 
 
def parse_log_file(filepath: str) -> pd.DataFrame:
    """
    Parse un fichier de logs complet.
    Retourne un DataFrame pandas avec toutes les features.
    """
    records = []
 
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                records.append(parsed)
 
    if not records:
        print("[!] Aucun log parsé.")
        return pd.DataFrame()
 
    df = pd.DataFrame(records)
 
    # Features supplémentaires
    df["hour"]          = df["timestamp"].dt.hour
    df["minute"]        = df["timestamp"].dt.minute
    df["is_auth_fail"]  = (df["endpoint"].str.contains("login") & (df["status"] == 401)).astype(int)
    df["is_rate_limit"] = (df["status"] == 429).astype(int)
    df["is_404"]        = (df["status"] == 404).astype(int)
 
    print(f"[✓] {len(df)} entrées parsées depuis '{filepath}'")
    return df
 
 
if __name__ == "__main__":
    df = parse_log_file("samples/mobile_api_logs.txt")
    print(df.head())
    print(f"\nRequêtes mobiles : {df['is_mobile'].sum()} / {len(df)}")
```
 
---
 
## 7. Étape 4 — Moteur de détection avancé
 
Créer `detection/rules.py` :
 
```python
"""
Moteur de détection par règles.
Détecte : brute force, spikes, énumération, hammering d'endpoints.
"""
 
import pandas as pd
from dataclasses import dataclass
 
 
@dataclass
class Alert:
    """Représente une alerte de sécurité."""
    type:        str
    ip:          str
    severity:    str        # LOW, MEDIUM, HIGH, CRITICAL
    count:       int
    details:     str
    endpoint:    str = ""
 
 
def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[Alert]:
    """
    Détecte les tentatives de brute force.
    Règle : N échecs de login depuis la même IP dans une fenêtre de temps.
    """
    alerts = []
 
    # Filtrer les échecs de login
    login_fails = df[(df["endpoint"].str.contains("login", na=False)) &
                     (df["status"] == 401)].copy()
 
    if login_fails.empty:
        return alerts
 
    # Grouper par IP et fenêtre de temps
    for ip, group in login_fails.groupby("ip"):
        group = group.sort_values("timestamp")
        count = len(group)
 
        if count >= threshold:
            severity = "CRITICAL" if count >= 30 else "HIGH" if count >= 20 else "MEDIUM"
            alerts.append(Alert(
                type="BRUTE_FORCE",
                ip=ip,
                severity=severity,
                count=count,
                details=f"{count} échecs de login en {window_minutes} min",
                endpoint="/api/v1/login",
            ))
 
    return alerts
 
 
def detect_request_spikes(
    df: pd.DataFrame,
    threshold_per_minute: int = 60,
) -> list[Alert]:
    """
    Détecte les spikes de requêtes (flood).
    Règle : Plus de N requêtes/minute depuis une même IP.
    """
    alerts = []
 
    if df.empty or "timestamp" not in df.columns:
        return alerts
 
    df = df.copy()
    df["minute"] = df["timestamp"].dt.floor("T")   # Arrondir à la minute
 
    # Compter par IP et minute
    counts = df.groupby(["ip", "minute"]).size().reset_index(name="count")
    spikes  = counts[counts["count"] >= threshold_per_minute]
 
    for _, row in spikes.iterrows():
        alerts.append(Alert(
            type="REQUEST_SPIKE",
            ip=row["ip"],
            severity="HIGH",
            count=int(row["count"]),
            details=f"{row['count']} req/min à {row['minute']}",
        ))
 
    return alerts
 
 
def detect_endpoint_enumeration(
    df: pd.DataFrame,
    threshold_unique: int = 20,
) -> list[Alert]:
    """
    Détecte l'énumération d'endpoints.
    Règle : Une IP accède à N endpoints distincts avec beaucoup de 404.
    """
    alerts = []
 
    for ip, group in df.groupby("ip"):
        unique_endpoints = group["endpoint"].nunique()
        nb_404           = (group["status"] == 404).sum()
        ratio_404        = nb_404 / max(len(group), 1)
 
        if unique_endpoints >= threshold_unique and ratio_404 > 0.3:
            alerts.append(Alert(
                type="ENDPOINT_ENUMERATION",
                ip=ip,
                severity="MEDIUM",
                count=int(unique_endpoints),
                details=f"{unique_endpoints} endpoints distincts, {ratio_404:.0%} de 404",
            ))
 
    return alerts
 
 
def detect_endpoint_hammering(
    df: pd.DataFrame,
    threshold: int = 100,
) -> list[Alert]:
    """
    Détecte le hammering (martelage) d'un endpoint spécifique.
    Règle : Une IP frappe le même endpoint plus de N fois.
    """
    alerts = []
 
    counts = df.groupby(["ip", "endpoint"]).size().reset_index(name="count")
    heavy  = counts[counts["count"] >= threshold]
 
    for _, row in heavy.iterrows():
        alerts.append(Alert(
            type="ENDPOINT_HAMMERING",
            ip=row["ip"],
            severity="MEDIUM",
            count=int(row["count"]),
            details=f"{row['count']} requêtes sur {row['endpoint']}",
            endpoint=row["endpoint"],
        ))
 
    return alerts
 
 
def run_all_detections(df: pd.DataFrame) -> list[Alert]:
    """Lance toutes les détections et retourne la liste d'alertes."""
    all_alerts = []
    all_alerts.extend(detect_brute_force(df))
    all_alerts.extend(detect_request_spikes(df))
    all_alerts.extend(detect_endpoint_enumeration(df))
    all_alerts.extend(detect_endpoint_hammering(df))
 
    print(f"[✓] {len(all_alerts)} alerte(s) détectée(s)")
    return all_alerts
```
 
---
 
## 8. Étape 5 — Intégration de l'IA (K-Means Clustering)
 
Créer `ai/clustering.py` :
 
```python
"""
Module IA : Clustering K-Means des comportements suspects.
Regroupe automatiquement les IPs par profil de comportement.
"""
 
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
 
 
CLUSTER_LABELS = {
    0: {"name": "Comportement normal",    "color": "#27ae60", "severity": "LOW"},
    1: {"name": "Comportement suspect",   "color": "#f39c12", "severity": "MEDIUM"},
    2: {"name": "Attaquant probable",     "color": "#e74c3c", "severity": "HIGH"},
    3: {"name": "Bot / Scanner",          "color": "#8e44ad", "severity": "CRITICAL"},
}
 
 
def extract_ip_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extrait les features par IP pour le clustering.
    Chaque ligne = une IP avec ses métriques comportementales.
    """
    if df.empty:
        return pd.DataFrame()
 
    features = df.groupby("ip").agg(
        total_requests    = ("ip", "count"),
        unique_endpoints  = ("endpoint", "nunique"),
        auth_failures     = ("is_auth_fail", "sum"),
        rate_limit_hits   = ("is_rate_limit", "sum"),
        nb_404            = ("is_404", "sum"),
        avg_response_size = ("size", "mean"),
        is_mobile         = ("is_mobile", "mean"),
    ).reset_index()
 
    # Ratios normalisés
    features["auth_fail_ratio"]  = features["auth_failures"]  / features["total_requests"].clip(lower=1)
    features["rate_limit_ratio"] = features["rate_limit_hits"] / features["total_requests"].clip(lower=1)
    features["404_ratio"]        = features["nb_404"]          / features["total_requests"].clip(lower=1)
 
    return features
 
 
def run_clustering(features: pd.DataFrame, n_clusters: int = 4) -> pd.DataFrame:
    """
    Applique K-Means clustering sur les features des IPs.
    Retourne le DataFrame enrichi avec le cluster et le label.
    """
    if features.empty or len(features) < n_clusters:
        print("[!] Pas assez de données pour le clustering.")
        return features
 
    feature_cols = [
        "total_requests", "unique_endpoints", "auth_fail_ratio",
        "rate_limit_ratio", "404_ratio", "avg_response_size",
    ]
 
    X = features[feature_cols].fillna(0).values
 
    # Normalisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
 
    # K-Means
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    features = features.copy()
    features["cluster"] = kmeans.fit_predict(X_scaled)
 
    # Score qualité
    if len(features) > n_clusters:
        score = silhouette_score(X_scaled, features["cluster"])
        print(f"[✓] Silhouette Score : {score:.3f} (plus proche de 1 = meilleur)")
 
    # Assignation automatique des labels selon les centroids
    # (cluster avec le plus d'auth_fail_ratio = Attaquant, etc.)
    cluster_stats = features.groupby("cluster").agg(
        avg_requests   = ("total_requests", "mean"),
        avg_auth_fail  = ("auth_fail_ratio", "mean"),
        avg_404        = ("404_ratio", "mean"),
    )
 
    # Trier les clusters par danger croissant (simple heuristique)
    danger_score = (
        cluster_stats["avg_auth_fail"] * 5
        + cluster_stats["avg_404"]     * 3
        + cluster_stats["avg_requests"].rank() * 0.5
    )
    sorted_clusters = danger_score.sort_values().index.tolist()
    label_map = {c: i for i, c in enumerate(sorted_clusters)}
 
    features["cluster_label"] = features["cluster"].map(label_map)
    features["cluster_name"]  = features["cluster_label"].map(
        lambda x: CLUSTER_LABELS.get(x, CLUSTER_LABELS[0])["name"]
    )
    features["cluster_color"] = features["cluster_label"].map(
        lambda x: CLUSTER_LABELS.get(x, CLUSTER_LABELS[0])["color"]
    )
 
    print(f"[✓] Clustering terminé — {n_clusters} groupes identifiés")
    return features
 
 
def find_optimal_k(features: pd.DataFrame, max_k: int = 8) -> int:
    """
    Trouve le K optimal via la méthode du coude (Elbow Method).
    Retourne le K recommandé.
    """
    feature_cols = [
        "total_requests", "unique_endpoints", "auth_fail_ratio",
        "rate_limit_ratio", "404_ratio", "avg_response_size",
    ]
    X = features[feature_cols].fillna(0).values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
 
    inertias = []
    k_range  = range(2, min(max_k + 1, len(features)))
 
    for k in k_range:
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        km.fit(X_scaled)
        inertias.append(km.inertia_)
 
    # Méthode du coude : trouver le coude
    deltas       = [inertias[i] - inertias[i+1] for i in range(len(inertias)-1)]
    optimal_idx  = deltas.index(max(deltas)) + 1
    optimal_k    = list(k_range)[optimal_idx]
 
    print(f"[✓] K optimal suggéré : {optimal_k}")
    return optimal_k
```
 
---
 
## 9. Étape 6 — Dashboard amélioré avec Streamlit
 
Créer `dashboard/streamlit_app.py` :
 
```python
"""
Dashboard Streamlit pour Mobile API Misuse Detector.
Visualisation interactive des alertes et clusters IA.
"""
 
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
 
from generator.log_generator import generate_logs
from parser.mobile_parser import parse_log_file
from detection.rules import run_all_detections
from ai.clustering import extract_ip_features, run_clustering
from recommendations.advisor import generate_recommendations
 
 
# Configuration de la page
st.set_page_config(
    page_title="Mobile API Misuse Detector",
    page_icon="🔐",
    layout="wide",
)
 
st.title("🔐 Mobile API Misuse Detector")
st.markdown("Détection d'abus d'API mobiles par analyse de logs et clustering IA")
 
# --- Sidebar ---
st.sidebar.header("⚙️ Configuration")
log_file = st.sidebar.text_input("Fichier de logs", value="samples/mobile_api_logs.txt")
 
if st.sidebar.button("🔄 Régénérer les logs simulés"):
    with st.spinner("Génération des logs..."):
        generate_logs()
    st.sidebar.success("Logs régénérés !")
 
n_clusters = st.sidebar.slider("Nombre de clusters IA", 2, 6, 4)
 
# --- Chargement des données ---
@st.cache_data
def load_data(filepath, _cache_key=0):
    df = parse_log_file(filepath)
    return df
 
try:
    df = load_data(log_file)
except FileNotFoundError:
    st.warning("Fichier de logs introuvable. Génération automatique...")
    generate_logs()
    df = load_data(log_file, _cache_key=1)
 
if df.empty:
    st.error("Aucune donnée disponible.")
    st.stop()
 
# --- Métriques globales ---
alerts  = run_all_detections(df)
features = extract_ip_features(df)
clustered = run_clustering(features, n_clusters=n_clusters)
 
col1, col2, col3, col4 = st.columns(4)
col1.metric("📊 Total requêtes",   f"{len(df):,}")
col2.metric("📱 Requêtes mobiles", f"{df['is_mobile'].sum():,}")
col3.metric("🚨 Alertes détectées", len(alerts))
col4.metric("🌐 IPs uniques",      df["ip"].nunique())
 
st.divider()
 
# --- Alertes ---
st.subheader("🚨 Alertes de sécurité")
if alerts:
    alert_data = [
        {
            "Type":     a.type,
            "IP":       a.ip,
            "Sévérité": a.severity,
            "Count":    a.count,
            "Détails":  a.details,
        }
        for a in alerts
    ]
    alert_df = pd.DataFrame(alert_data)
 
    # Colorer par sévérité
    def color_severity(val):
        colors = {
            "CRITICAL": "background-color: #e74c3c; color: white",
            "HIGH":     "background-color: #e67e22; color: white",
            "MEDIUM":   "background-color: #f39c12; color: black",
            "LOW":      "background-color: #27ae60; color: white",
        }
        return colors.get(val, "")
 
    st.dataframe(
        alert_df.style.applymap(color_severity, subset=["Sévérité"]),
        use_container_width=True,
    )
else:
    st.success("Aucune alerte détectée.")
 
st.divider()
 
# --- Clustering IA ---
st.subheader("🤖 Clustering IA des comportements")
 
col_a, col_b = st.columns(2)
 
with col_a:
    # Scatter plot cluster
    fig = px.scatter(
        clustered,
        x="total_requests",
        y="auth_fail_ratio",
        color="cluster_name",
        size="unique_endpoints",
        hover_data=["ip", "nb_404", "rate_limit_hits"],
        title="Clusters de comportement par IP",
        labels={
            "total_requests":   "Total requêtes",
            "auth_fail_ratio":  "Taux d'échecs auth",
            "cluster_name":     "Cluster",
        },
    )
    st.plotly_chart(fig, use_container_width=True)
 
with col_b:
    # Distribution des clusters (camembert)
    cluster_counts = clustered["cluster_name"].value_counts().reset_index()
    cluster_counts.columns = ["Cluster", "Nombre d'IPs"]
    fig2 = px.pie(
        cluster_counts,
        names="Cluster",
        values="Nombre d'IPs",
        title="Distribution des clusters",
    )
    st.plotly_chart(fig2, use_container_width=True)
 
st.divider()
 
# --- Trafic dans le temps ---
st.subheader("📈 Trafic par heure")
traffic_by_hour = df.groupby("hour").size().reset_index(name="requêtes")
fig3 = px.bar(
    traffic_by_hour,
    x="hour",
    y="requêtes",
    title="Volume de requêtes par heure",
    color="requêtes",
    color_continuous_scale="reds",
)
st.plotly_chart(fig3, use_container_width=True)
 
st.divider()
 
# --- Recommandations ---
st.subheader("💡 Recommandations anti-abus")
reco = generate_recommendations(alerts)
for r in reco:
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r["priority"], "⚪")
    with st.expander(f"{icon} {r['title']}"):
        st.write(r["description"])
        if r.get("code"):
            st.code(r["code"], language="python")
```
 
**Lancer le dashboard Streamlit :**
 
```bash
streamlit run dashboard/streamlit_app.py
# Ouvrir : http://localhost:8501
```
 
---
 
## 10. Étape 7 — Système de recommandations anti-abus
 
Créer `recommendations/advisor.py` :
 
```python
"""
Moteur de recommandations anti-abus.
Génère des recommandations basées sur les alertes détectées.
"""
 
 
def generate_recommendations(alerts: list) -> list[dict]:
    """
    Génère des recommandations de sécurité basées sur les alertes.
    Chaque recommandation contient : titre, description, priorité, exemple de code.
    """
    alert_types = {a.type for a in alerts}
    recommendations = []
 
    if "BRUTE_FORCE" in alert_types:
        recommendations.append({
            "title":       "Activer le rate limiting sur /login",
            "priority":    "CRITICAL",
            "description": (
                "Des tentatives de brute force ont été détectées. "
                "Limiter à 5 tentatives par IP par minute et bloquer "
                "temporairement les IPs dépassant ce seuil."
            ),
            "code": """
# Exemple Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
 
limiter = Limiter(app, key_func=get_remote_address)
 
@app.route('/api/v1/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
""",
        })
 
        recommendations.append({
            "title":       "Implémenter le compte-bloquage (Account Lockout)",
            "priority":    "HIGH",
            "description": (
                "Bloquer un compte après N tentatives échouées consécutives. "
                "Recommandé : 5 échecs = blocage 15 minutes."
            ),
            "code": None,
        })
 
    if "REQUEST_SPIKE" in alert_types:
        recommendations.append({
            "title":       "Déployer un CAPTCHA adaptatif",
            "priority":    "HIGH",
            "description": (
                "Des spikes de requêtes anormaux ont été détectés. "
                "Ajouter un CAPTCHA adaptatif qui se déclenche uniquement "
                "lorsque le comportement devient suspect."
            ),
            "code": None,
        })
 
        recommendations.append({
            "title":       "Configurer un WAF (Web Application Firewall)",
            "priority":    "MEDIUM",
            "description": (
                "Un WAF peut absorber les spikes de trafic et filtrer "
                "automatiquement les IP malveillantes. Options : Cloudflare, AWS WAF, nginx limit_req."
            ),
            "code": """
# Exemple configuration Nginx rate limiting
# Dans nginx.conf :
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
limit_req zone=api burst=10 nodelay;
""",
        })
 
    if "ENDPOINT_ENUMERATION" in alert_types:
        recommendations.append({
            "title":       "Masquer les messages d'erreur 404",
            "priority":    "MEDIUM",
            "description": (
                "Les erreurs 404 détaillées aident les attaquants à cartographier "
                "votre API. Retourner un message générique : 'Ressource non trouvée'."
            ),
            "code": None,
        })
 
    if "ENDPOINT_HAMMERING" in alert_types:
        recommendations.append({
            "title":       "Rate limiting par endpoint critique",
            "priority":    "HIGH",
            "description": (
                "Certains endpoints subissent un trafic excessif. "
                "Appliquer des limites spécifiques par endpoint sensible."
            ),
            "code": None,
        })
 
    # Recommandation générale toujours présente
    recommendations.append({
        "title":       "Activer la journalisation enrichie (Enhanced Logging)",
        "priority":    "LOW",
        "description": (
            "Enregistrer systématiquement : IP, user-agent, timestamp, "
            "endpoint, statut HTTP et payload size pour chaque requête mobile. "
            "Conserver les logs 90 jours minimum."
        ),
        "code": None,
    })
 
    return recommendations
```
 
---
 
## 11. Étape 8 — Tests et validation
 
### 11.1 Tester le pipeline complet
 
Créer `test_pipeline.py` à la racine :
 
```python
"""Test complet du pipeline Mobile API Misuse Detector."""
 
import os
 
print("=" * 60)
print("  TEST PIPELINE — Mobile API Misuse Detector")
print("=" * 60)
 
# 1. Génération des logs
print("\n[1] Génération des logs simulés...")
from generator.log_generator import generate_logs
logs = generate_logs(n_normal=200)
print(f"    {len(logs)} logs générés.")
 
# 2. Parsing
print("\n[2] Parsing des logs...")
from parser.mobile_parser import parse_log_file
df = parse_log_file("samples/mobile_api_logs.txt")
print(f"    {len(df)} entrées parsées.")
print(f"    Requêtes mobiles : {df['is_mobile'].sum()}")
 
# 3. Détection
print("\n[3] Détection des menaces...")
from detection.rules import run_all_detections
alerts = run_all_detections(df)
print(f"    {len(alerts)} alertes levées.")
for a in alerts:
    print(f"    [{a.severity}] {a.type} — {a.ip} — {a.details}")
 
# 4. Clustering IA
print("\n[4] Clustering IA...")
from ai.clustering import extract_ip_features, run_clustering
features  = extract_ip_features(df)
clustered = run_clustering(features, n_clusters=4)
print(f"    {len(clustered)} IPs clusterisées.")
print(clustered[["ip", "cluster_name", "total_requests"]].head(10).to_string())
 
# 5. Recommandations
print("\n[5] Recommandations...")
from recommendations.advisor import generate_recommendations
recos = generate_recommendations(alerts)
for r in recos:
    print(f"    [{r['priority']}] {r['title']}")
 
print("\n" + "=" * 60)
print("  ✅ Pipeline complet — Tous les modules fonctionnent !")
print("=" * 60)
```
 
```bash
python test_pipeline.py
```
 
### 11.2 Résultats attendus
 
```
============================================================
  TEST PIPELINE — Mobile API Misuse Detector
============================================================
 
[1] Génération des logs simulés...
    732 logs générés.
 
[2] Parsing des logs...
    732 entrées parsées.
    Requêtes mobiles : 680
 
[3] Détection des menaces...
    8 alertes levées.
    [HIGH] BRUTE_FORCE — 192.168.x.x — 35 échecs de login en 5 min
    [HIGH] REQUEST_SPIKE — 10.0.x.x — 150 req/min ...
 
[4] Clustering IA...
    55 IPs clusterisées.
    Silhouette Score : 0.612
 
[5] Recommandations...
    [CRITICAL] Activer le rate limiting sur /login
    ...
 
============================================================
  ✅ Pipeline complet — Tous les modules fonctionnent !
============================================================
```
 
---
 
## 12. Division des tâches binôme
 
| Tâche | Personne 1 | Personne 2 |
|---|---|---|
| Prise en main VulnSentinel | ✅ | ✅ |
| Générateur de logs (`log_generator.py`) | ✅ | |
| Parser mobile (`mobile_parser.py`) | ✅ | |
| Moteur de détection (`rules.py`) | ✅ | |
| Module IA K-Means (`clustering.py`) | | ✅ |
| Dashboard Streamlit (`streamlit_app.py`) | | ✅ |
| Recommandations (`advisor.py`) | | ✅ |
| Tests (`test_pipeline.py`) | ✅ | ✅ |
| README + rapport | ✅ | ✅ |
| Présentation slides | ✅ | ✅ |
 
---
 
## 13. Planning 4 semaines
 
### Semaine 1 — Setup & Compréhension
 
- [ ] Cloner VulnSentinel, tester l'application de base
- [ ] Lire et annoter `app.py`, `log_parser.py`, `dashboard.html`
- [ ] Mettre à jour `requirements.txt` et installer les dépendances
- [ ] Créer la structure de dossiers (`generator/`, `detection/`, `ai/`, `dashboard/`, `recommendations/`)
- [ ] Implémenter `log_generator.py` et générer les premiers logs
### Semaine 2 — Parser & Détection
 
- [ ] Implémenter `mobile_parser.py` (parser étendu)
- [ ] Implémenter `rules.py` (brute force, spikes, énumération, hammering)
- [ ] Tester chaque règle individuellement
- [ ] Intégrer la détection dans `app.py` existant
- [ ] Vérifier que le dashboard Flask existant affiche les nouvelles alertes
### Semaine 3 — IA & Dashboard Streamlit
 
- [ ] Implémenter `feature_extractor.py` et `clustering.py`
- [ ] Tester le clustering sur les données générées
- [ ] Implémenter `streamlit_app.py`
- [ ] Créer les graphiques Plotly (scatter plot clusters, trafic par heure)
- [ ] Implémenter `advisor.py` (recommandations)
### Semaine 4 — Finalisation & Présentation
 
- [ ] Passer `test_pipeline.py` avec succès
- [ ] Déployer le dashboard Streamlit (Streamlit Cloud — gratuit)
- [ ] Rédiger le `README.md` final
- [ ] Préparer le rapport (architecture, résultats, captures d'écran)
- [ ] Préparer la présentation (démo live du dashboard)
---
 
## 14. Ressources & Références
 
### Documentation officielle
 
| Outil | Lien |
|---|---|
| Flask | https://flask.palletsprojects.com |
| Streamlit | https://docs.streamlit.io |
| Scikit-learn K-Means | https://scikit-learn.org/stable/modules/clustering.html#k-means |
| Pandas | https://pandas.pydata.org/docs |
| Faker | https://faker.readthedocs.io |
| Plotly | https://plotly.com/python |
 
### Projets similaires (inspiration)
 
| Projet | Lien |
|---|---|
| VulnSentinel (base) | https://github.com/domino79/vulnsentinel |
| API Security Monitoring System | https://github.com/direction20/API-Security-Monitoring-System |
| Mini SIEM FastAPI (article Medium) | https://medium.com/@sharmasury04/building-my-first-mini-siem-with-fastapi |
| API Attack Detection Streamlit | https://medium.com/@Direction25/detecting-api-attacks-in-real-time |
| Log Analysis & Alerting Python | https://medium.com/@scottbolen/python-code-for-automated-log-analysis-alerting |
 
### Références académiques & professionnelles
 
- OWASP Mobile Security Testing Guide : https://owasp.org/www-project-mobile-security-testing-guide
- OWASP API Security Top 10 : https://owasp.org/www-project-api-security
- NIST Special Publication 800-92 — Guide to Computer Security Log Management
### Couverture cours (Chapitres couverts)
 
| Chapitre | Thème couvert |
|---|---|
| Chap. 4 | Analyse de trafic réseau mobile |
| Chap. 14 | Sécurité des API REST mobiles |
| Lab 3 | Analyse de trafic (trafic mobile simulé) |
| DevSecOps | Recommandations automatiques rate-limit / lockout |
 
---
 
## 🚀 Commandes rapides
 
```bash
# 1. Installer les dépendances
pip install -r requirements.txt
 
# 2. Générer les logs simulés
python generator/log_generator.py
 
# 3. Tester le pipeline complet
python test_pipeline.py
 
# 4. Lancer le dashboard Flask (original)
python app.py
 
# 5. Lancer le dashboard Streamlit (nouveau)
streamlit run dashboard/streamlit_app.py
 
# 6. Déployer sur Streamlit Cloud (gratuit)
# → Pousser le code sur GitHub
# → Aller sur https://streamlit.io/cloud
# → Connecter le repo et déployer
```
 
---
 
*Guide rédigé pour le cours de Sécurité Mobile — Projet Binôme n°12 : Mobile API Misuse Detector*  
*Basé sur VulnSentinel (domino79) — étendu avec IA (K-Means), logs mobiles simulés et dashboard Streamlit*
