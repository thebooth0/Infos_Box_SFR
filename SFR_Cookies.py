from creds import IP, User, Password
import requests
import hashlib
import hmac
import re
import json
import time

# Pour ignorer les avertissements SSL/TLS si vous utilisez 'verify=False'
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# --- Configuration du Challenge ---
GATEWAY_IP = IP
NONCE_ENDPOINT = "ss-json/fgw.nonce.json"
LOGIN_ENDPOINT = "index.html"

# Identifiants Cible (Flag)
USERNAME = User
PASSWORD = Password
# ---------------------------------

# --- Fonctions de Hachage Validées ---
# Ces fonctions sont correctes, nous les conservons.

def compute_hmac_sha256(key_str: str, data_str: str) -> str:
    key = key_str.encode('utf-8')
    data = data_str.encode('utf-8') 
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def calculate_credentials(username, password, nonce):
    # Logique complexe HMAC-SHA256 validée
    sha256_usr = hashlib.sha256(username.encode('utf-8')).hexdigest()
    hmac_usr = compute_hmac_sha256(nonce, sha256_usr)
    sha256_pass = hashlib.sha256(password.encode('utf-8')).hexdigest()
    hmac_pass = compute_hmac_sha256(nonce, sha256_pass)
    final_payload = hmac_usr + hmac_pass
    return hashlib.sha256(final_payload.encode('utf-8')).hexdigest()


# --- Fonctions de Requête (Orchestration du Flux) ---

def get_nonce_in_session(ip_gateway, session):
    """
    Récupère le nonce en utilisant la session fournie, garantissant que 
    le nonce est associé au SESSIONID de l'étape 0.
    """
    # L'API est souvent en HTTPS, on tente ça en premier
    url = f"https://{ip_gateway}/{NONCE_ENDPOINT}" 
    
    try:
        # Utilisation de la session pour la requête
        response = session.get(url, timeout=3, verify=False) 
        response.raise_for_status()
        
        data = response.json()
        if 'nonce' in data:
            return data['nonce']
        
    except Exception as e:
        # En cas d'échec, vous pouvez décommenter si vous voulez voir la cause exacte de l'échec de récupération
        # print(f"   [Erreur Nonce] : {e}")
        pass
    return None

def attempt_login_hmac(ip_gateway, credentials, session):
    """
    Envoie la requête de connexion finale en simulant l'en-tête du navigateur.
    """
    url = f"https://{ip_gateway}/{LOGIN_ENDPOINT}" 
    
    # Reproduction EXACTE des en-têtes critiques du curl du navigateur
    headers = {
        'Authorization': f'Digest {credentials}', # Le Digest
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
        'Accept': 'application/json, text/plain, */*', # CRITIQUE : Simuler l'appel XHR/API
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Connection': 'keep-alive',
        'Referer': url, # Le Referer pointe vers la même URL
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Sec-Fetch-Dest': 'empty', # Ajout d'en-têtes XHR
    }
    
    try:
        # La session envoie automatiquement le cookie SESSIONID
        response = session.get(url, headers=headers, timeout=5, allow_redirects=False, verify=False) 

        if response.status_code in [200, 302]:
            print(f"✅ SUCCÈS : Connexion réussie (Statut {response.status_code}).")
            if response.status_code == 200:
                print("\n--- Début du Flag (Contenu de la page) ---")
                #print(response.text)
                print(response.cookies)
                print("--- Fin du Flag ---")
            return True
        
        elif response.status_code in [401, 403]:
            # Échec : Le Nonce a expiré ou la session n'est pas reconnue
            return False
        
        else:
            print(f"⚠️ STATUT INATTENDU : {response.status_code}. Réponse : {response.text[:100]}...")
            return False

    except requests.exceptions.RequestException:
        return False

# --- Fonction Principale (Flux) ---

def main_login(max_retries=5):
    
    with requests.Session() as session:
        
        for attempt in range(1, max_retries + 1):
            start_time = time.time()
            print(f"\n--- TENTATIVE DE CONNEXION #{attempt} (ADMIN) ---")
            
            # 0. INITIALISATION DE SESSION/COOKIE (Requête 1)
            print("0. Initialisation Session...")
            try:
                # Tente de visiter la page d'accueil sans auth pour obtenir le SESSIONID
                session.get(f"https://{GATEWAY_IP}/{LOGIN_ENDPOINT}", verify=False, timeout=2)
            except requests.exceptions.RequestException:
                pass # L'échec ici est acceptable, la session peut quand même être initialisée
            
            if not session.cookies.get_dict():
                 print("   [Avertissement] Aucun cookie de session ('SESSIONID') obtenu après l'initialisation. Poursuite...")
                 
            # 1. RÉCUPÉRATION DU NONCE (Requête 2)
            print("1. Récupération du Nonce frais (dans la session)...")
            nonce_value = get_nonce_in_session(GATEWAY_IP, session)
            
            if not nonce_value:
                print("   [Échec] Nonce non récupéré. Le serveur n'a peut-être pas initialisé la session.")
                time.sleep(1) # Attendre avant de retenter d'initialiser une nouvelle session
                continue

            # 2. CALCUL (Instantané)
            credentials = calculate_credentials(USERNAME, PASSWORD, nonce_value)
            print(f"   Nonce : {nonce_value[:8]}... Digest : {credentials[:8]}...")
            
            # 3. TENTATIVE DE CONNEXION (Requête 3)
            if attempt_login_hmac(GATEWAY_IP, credentials, session):
                return

            time.sleep(0.5) # Pause entre les tentatives d'initialisation de session

        print(f"\n🔴 ÉCHEC DÉFINITIF : Connexion non réussie après {max_retries} tentatives.")

if __name__ == "__main__":
    main_login()
