# File: app.py (Versione 2 - Con Sicurezza)
import os
import requests
from functools import wraps # Import necessario per la sicurezza
from flask import Flask, request, jsonify, render_template, Response

app = Flask(__name__, template_folder='templates')

# Legge le credenziali dalle Variabili d'Ambiente di Render
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")

# --- NUOVO: Leggiamo utente e password per il nostro dashboard ---
DASHBOARD_USER = os.getenv("DASHBOARD_USER")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")

PAYPAL_API_BASE = "https://api-m.paypal.com"

# --- NUOVO: Logica per la richiesta di autenticazione ---
def check_auth(username, password):
    """Controlla se utente e password sono corretti."""
    return username == DASHBOARD_USER and password == DASHBOARD_PASS

def authenticate():
    """Invia una risposta 401 per chiedere l'autenticazione al browser."""
    return Response(
    'Accesso negato. Autenticazione richiesta.\n', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated
# --- FINE NUOVA LOGICA ---


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
@auth_required  # <-- NUOVO: Questa pagina ora richiede la password
def index():
    return render_template("index.html")

@app.route("/api/search", methods=["POST"])
@auth_required  # <-- NUOVO: Anche questa funzione è protetta
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
@auth_required  # <-- NUOVO: E anche questa
def create_payout():
    try:
        token = get_access_token()
        payout_data = request.get_json()
        payload = {
            "sender_batch_header": {
                "sender_batch_id": "batch-" + os.urandom(8).hex(),
                "email_subject": "Hai ricevuto un pagamento!",
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {"value": item["value"], "currency": "EUR"},
                    "receiver": item["email"],
                } for item in payout_data
            ]
        }
        headers = { "Authorization": f"Bearer {token}", "Content-Type": "application/json" }
        response = requests.post(f"{PAYPAL_API_BASE}/v1/payments/payouts", headers=headers, json=payload)
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500