from creds import IP
from SFR_Cookies import cookie
import requests
import json
import re
# Pour ignorer les avertissements SSL/TLS
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
GATEWAY_IP = IP
SUMMARY_ENDPOINT = "ss-json/fgw.summary.json?bypass=1"

# URL cible
TARGET_URL = f"https://{GATEWAY_IP}/{SUMMARY_ENDPOINT}"

# --- Fonction pour Extraire les Cookies (Facultatif mais robuste) ---

def extract_cookies_from_output(output_text):
    """
    Parse l'output de votre premier script pour extraire les valeurs des cookies.
    """
    cookies = {}
    
    # Regex pour SESSIONID
    match_session = re.search(r'SESSIONID=([a-fA-F0-9]+)', output_text)
    if match_session:
        cookies['SESSIONID'] = match_session.group(1)
    
    # Regex pour XSRF-TOKEN
    match_xsrf = re.search(r'XSRF-TOKEN=([a-zA-Z0-9]+)', output_text)
    if match_xsrf:
        cookies['XSRF-TOKEN'] = match_xsrf.group(1)
        
    if 'SESSIONID' in cookies and 'XSRF-TOKEN' in cookies:
        return cookies
    else:
        print("❌ Erreur de Parsing: Impossible de trouver les deux cookies.")
        return None

# --- Fonction Principale de Requête ---

def request_summary_with_cookies(session_id, xsrf_token, target_url):
    
    print(f"2. Tentative de requête sur l'URL : {target_url}")
    print(f"   Utilisation de SESSIONID : {session_id[:8]}... et XSRF-TOKEN : {xsrf_token[:8]}...")
    
    # 1. Définir les cookies pour la session (méthode de la librairie requests)
    cookies = {
        'SESSIONID': session_id,
        'XSRF-TOKEN': xsrf_token 
    }

    # 2. Définir les headers pour simuler le navigateur (y compris X-XSRF-TOKEN)
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
        'Accept': 'application/json, text/plain, */*', 
        'Accept-Language': 'fr', 
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'X-XSRF-TOKEN': xsrf_token, # L'en-tête séparé est CRITIQUE
        'Connection': 'keep-alive',
        'Referer': f'https://{GATEWAY_IP}/index.html',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache'
    }

    try:
        # Envoi de la requête GET
        response = requests.get(target_url, headers=headers, cookies=cookies, verify=False, timeout=10)
        response.raise_for_status() # Lève une erreur si le statut est 4xx ou 5xx
        
        data = response.json()
        
        print("✅ Requête réussie. Réponse JSON obtenue.")
        
        # 3. Recherche du Flag dans la réponse JSON
        # La réponse que vous avez fournie NE contient PAS un flag CTF standard.
        # Le flag pourrait être dans une clé cachée ou l'une des chaînes de valeur.
        
        print("\n--- Début de la Réponse JSON ---")
        
        # On affiche le JSON complet pour la recherche manuelle
        print(json.dumps(data, indent=4)) 
        
        return data

    except requests.exceptions.HTTPError as e:
        print(f"❌ Erreur HTTP: {e.response.status_code}. Les cookies ont peut-être expiré ou l'accès est refusé.")
        return None
    except json.JSONDecodeError:
        print("❌ Erreur de décodage JSON: La réponse n'est pas un JSON valide.")
        return None
    except Exception as e:
        print(f"❌ Une erreur inattendue s'est produite : {e}")
        return None


# --- Exécution ---
COOKIES_OUTPUT_STRING = cookie
# 1. Extraction des cookies
extracted_cookies = extract_cookies_from_output(COOKIES_OUTPUT_STRING)

if extracted_cookies:
    request_summary_with_cookies(
        session_id=extracted_cookies['SESSIONID'],
        xsrf_token=extracted_cookies['XSRF-TOKEN'],
        target_url=TARGET_URL
    )
