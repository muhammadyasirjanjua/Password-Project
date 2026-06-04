import csv
import json
import io

def generate_txt_report(data):
    lines = [
        "========================================",
        "      PASSWORD SECURITY ANALYZER      ",
        "              ANALYSIS REPORT           ",
        "========================================",
        f"Date: {data.get('timestamp')}",
        f"Platform: {data.get('platform')}",
        f"Username: {data.get('username')}",
        f"Password: {data.get('password')}",
        f"Password Length: {data.get('length')}",
        f"Security Score: {data.get('score')}/100",
        f"Entropy: {data.get('entropy')} bits",
        f"Rating: {data.get('rating')}",
        "",
        "--- ESTIMATED CRACK TIMES ---",
        f"Common List Attack: {data.get('crack_times', {}).get('common_list')}",
        f"Dictionary Attack: {data.get('crack_times', {}).get('dictionary')}",
        f"Brute Force Attack: {data.get('crack_times', {}).get('brute_force')}",
        f"GPU Attack: {data.get('crack_times', {}).get('gpu')}",
        f"Advanced Attacker: {data.get('crack_times', {}).get('advanced')}",
        "",
        "--- RECOMMENDATIONS ---"
    ]
    for r in data.get('recommendations', []):
        lines.append(f"- {r}")
        
    lines.extend([
        "",
        "========================================",
        "NOTE: Passwords are saved per user request.",
        "========================================"
    ])
    return "\n".join(lines)

def generate_csv_report(data):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Platform", "Username", "Password", "Length", "Score", "Entropy", "Rating", "Common List Crack", "GPU Crack"])
    writer.writerow([
        data.get('timestamp'),
        data.get('platform'),
        data.get('username'),
        data.get('password'),
        data.get('length'),
        data.get('score'),
        data.get('entropy'),
        data.get('rating'),
        data.get('crack_times', {}).get('common_list'),
        data.get('crack_times', {}).get('gpu')
    ])
    return output.getvalue()

def generate_json_report(data):
    return json.dumps(data, indent=4)
