# 🚀 PoC - Automatisation de l'Accès aux APIs d'Administration (Gateways SFR/Box)
## 🎯 Objectif du PoC

Ce Proof of Concept démontre la capacité d'automatiser le processus d'authentification d'une Box pour accéder, via des scripts Python, à des APIs internes qui révèlent des informations système sensibles (comme le Serial Number, l'adresse MAC, et la configuration réseau).

L'exploit repose sur l'ingénierie inverse du mécanisme de hachage propriétaire et l'orchestration d'un flux de requête sessionnel précis.
## 🔬 Ingénierie Inverse du Protocole d'Authentification
1. Découverte de la Logique de Hachage Personnalisée (HMAC)

L'authentification ne repose pas sur le protocole standard HTTP Digest, mais sur un schéma de signature personnalisé découvert via l'analyse du code JavaScript (login.js). La "signature" (Digest) est calculée à partir des identifiants et d'un Nonce de session :
Digest=SHA256(HMAC(Nonce,SHA256(User)) ∣∣ HMAC(Nonce,SHA256(Pass)))
2. Le Détail Critique (Encodage)

La clé du succès du PoC réside dans la reproduction fidèle de l'implémentation du hachage HMAC-SHA256. Le framework web (via forge.js) traite les hachages SHA256 intermédiaires (qui sont des chaînes hexadécimales) comme de simples chaînes de caractères UTF-8 pour le calcul HMAC, un comportement non standard qui devait être répliqué dans le script Python.
3. Orchestration Sessionnelle (Anti-CSRF/Anti-Replay)

Pour valider le Digest, le serveur exige un flux de requêtes strictes au sein de la même session HTTP, nécessitant :

    L'obtention et le maintien du cookie SESSIONID.

    L'obtention d'un Nonce frais associé à ce SESSIONID juste avant la tentative de connexion.

    L'envoi d'un en-tête Accept: application/json, text/plain, */* pour simuler l'appel API du navigateur.

## ⚙️ Chaîne d'Exploitation (Automatisation)

Le PoC utilise deux scripts Python pour diviser la tâche :
### Script 1 : Authentification et Extraction des Clés de Session (SFR_Cookies.py)

    Rôle : Exécute les étapes 0, 1 et 2 pour s'authentifier avec succès et extraire les cookies SESSIONID et XSRF-TOKEN nécessaires à la persistance de la session administrateur.

### Script 2 : Accès aux APIs Post-Authentification (get_summary_flag.py)

    Rôle : Utilise les cookies de la session authentifiée pour interroger l'API /ss-json/fgw.summary.json?bypass=1.

    Résultat : Le script obtient la réponse JSON complète révélant des informations critiques sur la Box (numéro de série, MAC, état WAN/LAN, configuration DHCP), prouvant l'accès non surveillé aux données d'administration.

## 📦 Utilisation du PoC
Prérequis

    Python 3.x

    Librairie requests : pip install requests

1. Générer les Cookies d'Authentification (SFR_Cookies.py)

Ce script automatise la séquence de login.
```bash
python3 SFR_Cookies.py
```

2. Exploiter la Session pour l'Extraction de Données (get_summary_flag.py)

Après avoir copié le SESSIONID et le XSRF-TOKEN générés dans le second script, exécutez l'extraction :

```bash
python3 get_summary_flag.py
```

Le résultat est l'affichage structuré du JSON des informations système :

```json
{
    "router": {
        "swVersion": "...",
        "serialNumber": "5054494E5CXXXXXX",
        "mac": "5C:7B:5C:XX:XX:XX",
        // ... (Autres informations)
    },
    // ... (Configuration WAN/LAN/WiFi)
}
```

Testé sur une SFR Box 7 
