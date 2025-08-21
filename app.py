# File: app.py (Versione 3 - Debug delle variabili)
import os
import requests
from functools import wraps
from waitress import serve
from flask import Flask, request, jsonify, render_template, Response

app = Flask(__name__, template_folder='templates')

# --- INIZIO SEZIONE DEBUG ---
print("--- AVVIO APPLICAZIONE: CONTROLLO VARIABILI D'AMBIENTE ---")

# Leggiamo le variabili
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
DASHBOARD_USER = os.getenv("DASHBOARD_USER")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")

# Stampiamo nei log di Render cosa stiamo leggendo
print(f"PAYPAL_CLIENT_ID letto: {'Sì' if PAYPAL_CLIENT_ID else 'NO'}")
print(f"PAYPAL_CLIENT_SECRET letto: {'Sì' if PAYPAL_CLIENT_SECRET else 'NO'}")
print(f"DASHBOARD_USER letto: {'Sì' if DASHBOARD_USER else 'NO'}")
print(f"DASHBOARD_PASS letto: {'Sì' if DASHBOARD_PASS else 'NO'}")

# Controlliamo se manca qualcosa di fondamentale
if not all([PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DASHBOARD_USER, DASHBOARD_PASS]):
    print("🚨 ERRORE CRITICO: Una o più variabili d'ambiente non sono state trovate!")
    # In un'app reale, qui potresti voler fermare l'avvio, ma per ora andiamo avanti.

print("--- FINE CONTROLLO VARIABILI ---")
# --- FINE SEZIONE DEBUG ---


PAYPAL_API_BASE = "https://api-m.paypal.com"

def check_auth(username, password):
    # Ci assicuriamo che le variabili non siano nulle prima di confrontarle
    return username == DASHBOARD_USER and password == DASHBOARD_PASS

def authenticate():
    return Response('Accesso negato.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Aggiungiamo un controllo per assicurarci che le variabili di login esistano
        if not DASHBOARD_USER or not DASHBOARD_PASS:
            # Se le variabili di login non sono impostate, neghiamo l'accesso a prescindere
            return "Errore di configurazione del server: credenziali di accesso non impostate.", 500
            
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ... il resto del codice rimane identico ...

def get_access_token():
    auth_response = requests.post(
        f"{PAYPAL_API_BASE}/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
        headers={"Accept": "application/json", "Accept-Language": "en_US"},
        data={"grant_type": "client_credentials"},
    )
    auth_response.raise_for_status()
    return auth_response.json()["access_token"]

@app.route("/")
@auth_required
def index():
    return render_template("index.html")

@app.route("/api/search", methods=["POST"])
@auth_required
def search_transactions():
    try:
        token = get_access_token()
        params = request.get_json()
        headers = { "Authorization": f"Bearer {token}", "Content-Type": "application/json" }
        search_params = { "start_date": params['start_date'], "end_date": params['end_date'], "fields": "all" }
        response = requests.get(f"{PAYPAL_API_BASE}/v1/reporting/transactions", headers=headers, params=search_params)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/payout", methods=["POST"])
@auth_required
def create_payout():
    try:
        token = get_access_token()
        payout_data = request.get_json()
        payload = {
            "sender_batch_header": { "sender_batch_id": "batch-" + os.urandom(8).hex(), "email_subject": "Hai ricevuto un pagamento!", },
            "items": [ { "recipient_type": "EMAIL", "amount": {"value": item["value"], "currency": "EUR"}, "receiver": item["email"], } for item in payout_data ]
        }
        headers = { "Authorization": f"Bearer {token}", "Content-Type": "application/json" }
        response = requests.post(f"{PAYPAL_API_BASE}/v1/payments/payouts", headers=headers, json=payload)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # Render ci dice su quale porta ascoltare tramite una variabile d'ambiente.
    # Usiamo 10000 come default se non la trova.
    port = int(os.environ.get("PORT", 10000))
    # Usiamo Waitress per servire l'app. '0.0.0.0' è necessario per Render.
    serve(app, host='0.0.0.0', port=port)
