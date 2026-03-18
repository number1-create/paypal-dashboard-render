import os
import re
import time
import requests
from functools import wraps
from waitress import serve
from flask import Flask, request, jsonify, render_template, Response

app = Flask(__name__, template_folder='templates')

# --- Configurazione ---
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
DASHBOARD_USER = os.getenv("DASHBOARD_USER")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")
PAYPAL_API_BASE = "https://api-m.paypal.com"

if not all([PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DASHBOARD_USER, DASHBOARD_PASS]):
    print("ERRORE: Una o piu variabili d'ambiente mancanti (PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DASHBOARD_USER, DASHBOARD_PASS)")

# --- Token caching ---
_token_cache = {"token": None, "expires_at": 0}


def get_access_token():
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]

    auth_response = requests.post(
        f"{PAYPAL_API_BASE}/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
        headers={"Accept": "application/json", "Accept-Language": "en_US"},
        data={"grant_type": "client_credentials"},
    )
    auth_response.raise_for_status()
    data = auth_response.json()
    _token_cache["token"] = data["access_token"]
    # Cache per la durata indicata da PayPal meno 60 secondi di margine
    _token_cache["expires_at"] = now + data.get("expires_in", 3600) - 60
    return _token_cache["token"]


# --- Autenticazione ---
def check_auth(username, password):
    return username == DASHBOARD_USER and password == DASHBOARD_PASS


def authenticate():
    return Response('Accesso negato.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not DASHBOARD_USER or not DASHBOARD_PASS:
            return "Errore di configurazione: credenziali di accesso non impostate.", 500
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# --- Validazione ---
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def validate_payout_items(items):
    """Valida la lista di pagamenti. Ritorna (items_puliti, errori)."""
    errors = []
    clean_items = []
    seen_emails = set()

    if not items or not isinstance(items, list):
        return [], ["Nessun pagamento fornito."]

    if len(items) > 500:
        return [], ["Massimo 500 destinatari per batch."]

    for i, item in enumerate(items, 1):
        email = (item.get("email") or "").strip().lower()
        value_str = (item.get("value") or "").strip()

        if not email or not value_str:
            errors.append(f"Riga {i}: email o importo mancante.")
            continue

        if not EMAIL_REGEX.match(email):
            errors.append(f"Riga {i}: email non valida '{email}'.")
            continue

        try:
            value = float(value_str)
        except ValueError:
            errors.append(f"Riga {i}: importo non valido '{value_str}'.")
            continue

        if value <= 0:
            errors.append(f"Riga {i}: importo deve essere positivo ({value_str}).")
            continue

        if value > 10000:
            errors.append(f"Riga {i}: importo troppo alto ({value_str}). Max 10.000 EUR.")
            continue

        if email in seen_emails:
            errors.append(f"Riga {i}: email duplicata '{email}'.")
            continue

        seen_emails.add(email)
        clean_items.append({"email": email, "value": f"{value:.2f}"})

    return clean_items, errors


# --- Routes ---
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
        start_date = params.get('start_date', '').strip()
        end_date = params.get('end_date', '').strip()

        if not start_date or not end_date:
            return jsonify({"error": "Date di inizio e fine obbligatorie."}), 400

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        search_params = {"start_date": start_date, "end_date": end_date, "fields": "all"}
        response = requests.get(f"{PAYPAL_API_BASE}/v1/reporting/transactions", headers=headers, params=search_params)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"Errore PayPal: {e.response.status_code} - {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/payout", methods=["POST"])
@auth_required
def create_payout():
    try:
        payout_data = request.get_json()
        clean_items, errors = validate_payout_items(payout_data)

        if errors:
            return jsonify({"error": "Errori di validazione", "details": errors}), 400

        token = get_access_token()
        batch_id = "batch-" + os.urandom(8).hex()
        payload = {
            "sender_batch_header": {
                "sender_batch_id": batch_id,
                "email_subject": "Hai ricevuto un pagamento!",
            },
            "items": [
                {
                    "recipient_type": "EMAIL",
                    "amount": {"value": item["value"], "currency": "EUR"},
                    "receiver": item["email"],
                }
                for item in clean_items
            ],
        }
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.post(f"{PAYPAL_API_BASE}/v1/payments/payouts", headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        result["_batch_id"] = batch_id
        result["_items_count"] = len(clean_items)
        result["_total_eur"] = sum(float(item["value"]) for item in clean_items)
        return jsonify(result)
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"Errore PayPal: {e.response.status_code} - {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/payout-status/<payout_batch_id>", methods=["GET"])
@auth_required
def get_payout_status(payout_batch_id):
    try:
        token = get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.get(f"{PAYPAL_API_BASE}/v1/payments/payouts/{payout_batch_id}", headers=headers)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"Errore PayPal: {e.response.status_code} - {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    serve(app, host='0.0.0.0', port=port)
