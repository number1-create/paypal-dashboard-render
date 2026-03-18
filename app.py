import os
import re
import time
import hmac
import secrets
import hashlib
import requests
from functools import wraps
from collections import defaultdict
from waitress import serve
from flask import (
    Flask, request, jsonify, render_template, Response,
    session, redirect, url_for, abort
)

app = Flask(__name__, template_folder='templates')

# --- Configurazione ---
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=3600,  # 1 ora
)

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
DASHBOARD_USER = os.getenv("DASHBOARD_USER")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")
PAYPAL_API_BASE = "https://api-m.paypal.com"

if not all([PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DASHBOARD_USER, DASHBOARD_PASS]):
    print("ERRORE: Variabili d'ambiente mancanti (PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DASHBOARD_USER, DASHBOARD_PASS)")


# --- Security headers ---
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


# --- Rate limiting (in-memory) ---
_login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300  # 5 minuti


def _is_rate_limited(ip):
    now = time.time()
    attempts = _login_attempts[ip]
    # Rimuovi tentativi vecchi
    _login_attempts[ip] = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    return len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_attempt(ip):
    _login_attempts[ip].append(time.time())


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
    _token_cache["expires_at"] = now + data.get("expires_in", 3600) - 60
    return _token_cache["token"]


# --- Autenticazione sessione ---
def check_credentials(username, password):
    if not DASHBOARD_USER or not DASHBOARD_PASS:
        return False
    # Timing-safe comparison per prevenire timing attacks
    user_ok = hmac.compare_digest(username.encode(), DASHBOARD_USER.encode())
    pass_ok = hmac.compare_digest(password.encode(), DASHBOARD_PASS.encode())
    return user_ok and pass_ok


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            if request.is_json:
                return jsonify({"error": "Sessione scaduta. Effettua il login."}), 401
            return redirect(url_for('login_page'))
        # Controlla timeout sessione
        last_active = session.get('last_active', 0)
        if time.time() - last_active > app.config['PERMANENT_SESSION_LIFETIME']:
            session.clear()
            if request.is_json:
                return jsonify({"error": "Sessione scaduta."}), 401
            return redirect(url_for('login_page'))
        session['last_active'] = time.time()
        return f(*args, **kwargs)
    return decorated


# --- CSRF protection ---
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf():
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not token or not hmac.compare_digest(token, session.get('_csrf_token', '')):
        abort(403, description="Token CSRF non valido.")


# Rendi csrf_token disponibile nei template Jinja2
app.jinja_env.globals['csrf_token'] = generate_csrf_token


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
            errors.append(f"Riga {i}: email non valida.")
            continue

        try:
            value = float(value_str)
        except ValueError:
            errors.append(f"Riga {i}: importo non valido.")
            continue

        if value <= 0:
            errors.append(f"Riga {i}: importo deve essere positivo.")
            continue

        if value > 10000:
            errors.append(f"Riga {i}: importo troppo alto. Max 10.000 EUR.")
            continue

        if email in seen_emails:
            errors.append(f"Riga {i}: email duplicata.")
            continue

        seen_emails.add(email)
        clean_items.append({"email": email, "value": f"{value:.2f}"})

    return clean_items, errors


# --- Routes: Login / Logout ---
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get('authenticated'):
            return redirect(url_for('index'))
        return render_template("login.html")

    # POST - login attempt
    ip = request.remote_addr
    if _is_rate_limited(ip):
        return render_template("login.html",
                               error="Troppi tentativi. Riprova tra qualche minuto.")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        _record_attempt(ip)
        return render_template("login.html", error="Inserisci username e password.")

    if check_credentials(username, password):
        session.clear()
        session['authenticated'] = True
        session['last_active'] = time.time()
        session['_csrf_token'] = secrets.token_hex(32)
        session.permanent = True
        return redirect(url_for('index'))
    else:
        _record_attempt(ip)
        return render_template("login.html", error="Credenziali non valide.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))


# --- Routes: App ---
@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["POST"])
@login_required
def search_transactions():
    validate_csrf()
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
        status = e.response.status_code if e.response is not None else 500
        return jsonify({"error": f"Errore PayPal ({status})."}), status
    except Exception as e:
        return jsonify({"error": "Errore interno del server."}), 500


@app.route("/api/payout", methods=["POST"])
@login_required
def create_payout():
    validate_csrf()
    try:
        payout_data = request.get_json()
        clean_items, errors = validate_payout_items(payout_data)

        if errors:
            return jsonify({"error": "Errori di validazione", "details": errors}), 400

        token = get_access_token()
        batch_id = "batch-" + secrets.token_hex(8)
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
        status = e.response.status_code if e.response is not None else 500
        return jsonify({"error": f"Errore PayPal ({status})."}), status
    except Exception as e:
        return jsonify({"error": "Errore interno del server."}), 500


@app.route("/api/payout-status/<payout_batch_id>", methods=["GET"])
@login_required
def get_payout_status(payout_batch_id):
    # Validazione batch_id: solo alfanumerici e trattini
    if not re.match(r'^[a-zA-Z0-9\-]+$', payout_batch_id):
        return jsonify({"error": "ID batch non valido."}), 400
    try:
        token = get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.get(f"{PAYPAL_API_BASE}/v1/payments/payouts/{payout_batch_id}", headers=headers)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else 500
        return jsonify({"error": f"Errore PayPal ({status})."}), status
    except Exception as e:
        return jsonify({"error": "Errore interno del server."}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    serve(app, host='0.0.0.0', port=port)
