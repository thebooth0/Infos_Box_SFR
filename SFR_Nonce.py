from creds import IP
import requests
import json
import re

# --- Configuration ---
# Remplacez ceci par l'adresse IP de votre Box/Gateway (typiquement l'adresse de la page de login)
GATEWAY_IP = IP
# L'URL où l'application va chercher le nonce, tel que vu dans login.js
NONCE_ENDPOINT = "ss-json/fgw.nonce.json"

def recuperer_nonce(ip_gateway):
    """
    Récupère le jeton 'nonce' en envoyant une requête GET au point de terminaison
    spécifié par le code JavaScript.

    Args:
        ip_gateway (str): L'adresse IP ou le nom d'hôte de la gateway.

    Returns:
        str or None: Le nonce si la requête réussit, sinon None.
    """
    url = f"http://{ip_gateway}/{NONCE_ENDPOINT}"
    #print(f"Tentative de récupération du nonce à l'URL : {url}")

    try:
        # 1. Envoi de la requête GET
        # Le code login.js n'ajoute pas d'en-têtes spéciaux, une requête simple suffit.
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Lève une exception si le statut HTTP est un échec (4xx ou 5xx)

        # 2. Vérification et parsing de la réponse
        data = response.json()
        
        # Le code JS indique que le nonce est dans `response.data.nonce`.
        # Nous supposons donc que la structure JSON est similaire à: {"nonce": "..."}
        if 'nonce' in data:
            nonce = data['nonce']
            #print(f"✅ Nonce récupéré avec succès : {nonce}")
            print(f"{nonce}")
            return nonce
        else:
            print(f"❌ Erreur: Clé 'nonce' non trouvée dans la réponse JSON.")
            print(f"Réponse complète : {data}")
            return None

    except requests.exceptions.HTTPError as e:
        print(f"❌ Erreur HTTP: Impossible d'accéder à {url}. Statut: {e.response.status_code}")
        print("Assurez-vous que l'adresse IP est correcte et que vous êtes sur le bon réseau.")
        return None
    except requests.exceptions.ConnectionError:
        print("❌ Erreur de connexion: Le serveur est injoignable. Vérifiez l'IP ou la connectivité.")
        return None
    except json.JSONDecodeError:
        print("❌ Erreur de décodage JSON: La réponse n'est pas un JSON valide.")
        # Parfois, la réponse peut ne pas être un JSON pur (ex: si une redirection a lieu)
        # On essaie de l'extraire manuellement si nécessaire
        match = re.search(r'{"nonce":"([a-fA-F0-9]+)"}', response.text)
        if match:
             nonce = match.group(1)
             print(f"✅ Nonce récupéré par expression régulière : {nonce}")
             return nonce
        return None
    except Exception as e:
        print(f"❌ Une erreur inattendue s'est produite : {e}")
        return None

# --- Exécution ---
# Vous pouvez tester cette fonction :
jeton_nonce = recuperer_nonce(GATEWAY_IP)
if jeton_nonce:
    #print(f"Le nonce est prêt à être utilisé pour l'authentification.")
    pass
