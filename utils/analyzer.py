import math
import re

COMMON_WORDS = ['password', '123456', 'qwerty', 'admin', 'welcome', 'login', 'letmein', 'monkey', 'dragon', 'football']
SEQUENCES = ['123456', 'abcdef', 'qwerty', 'asdfgh', 'zxcvbn', '123456789', '987654321']

def analyze_password(password, username=""):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_number = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))
    
    # Character Diversity
    diversity = sum([has_upper, has_lower, has_number, has_special])
    
    # Repeated Characters
    repeated = len(password) - len(set(password))
    
    # Dictionary word
    lower_pass = password.lower()
    has_dict_word = any(word in lower_pass for word in COMMON_WORDS)
    
    # Sequences
    has_sequence = any(seq in lower_pass for seq in SEQUENCES)
    
    # Personal Info
    has_personal = False
    if username and len(username) > 2 and username.lower() in lower_pass:
        has_personal = True

    # Entropy
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_number: pool_size += 10
    if has_special: pool_size += 32
    
    entropy = 0
    if pool_size > 0 and length > 0:
        entropy = length * math.log2(pool_size)
        
    # Score calculation (0-100)
    score = min(100, entropy)
    
    # Penalties
    if has_dict_word: score -= 20
    if has_sequence: score -= 20
    if has_personal: score -= 30
    score -= (repeated * 2)
    
    score = max(0, min(100, score))
    
    # Rating
    if score < 20: rating = "Very Weak"
    elif score < 40: rating = "Weak"
    elif score < 60: rating = "Moderate"
    elif score < 80: rating = "Strong"
    else: rating = "Very Strong"
    
    # Crack Times
    crack_times = calculate_crack_times(entropy)
    
    # Recommendations
    recs = []
    if length < 12: recs.append("Increase password length to at least 12 characters.")
    if not has_special: recs.append("Add special characters (e.g., @, #, $, !).")
    if not has_upper: recs.append("Add uppercase letters.")
    if not has_number: recs.append("Add numbers.")
    if has_dict_word: recs.append("Avoid common dictionary words.")
    if has_personal: recs.append("Avoid using personal information like your username.")
    if has_sequence: recs.append("Avoid sequential patterns (e.g., 123456, qwerty).")
    recs.append("Enable Multi-Factor Authentication (MFA) where possible.")
    
    return {
        "length": length,
        "entropy": round(entropy, 2),
        "score": round(score),
        "rating": rating,
        "crack_times": crack_times,
        "recommendations": recs
    }

def calculate_crack_times(entropy):
    # Combinations = 2^entropy
    combinations = 2 ** entropy if entropy > 0 else 0
    
    # Speeds (guesses per second)
    speeds = {
        "common_list": 100000, # 100k/s
        "dictionary": 10000000, # 10M/s
        "brute_force": 1000000000, # 1B/s
        "gpu": 100000000000, # 100B/s
        "advanced": 10000000000000 # 10T/s
    }
    
    times = {}
    for attacker, speed in speeds.items():
        seconds = combinations / speed if speed > 0 else 0
        times[attacker] = format_time(seconds)
        
    return times

def format_time(seconds):
    if seconds < 1: return "Instantly"
    if seconds < 60: return f"{int(seconds)} Seconds"
    if seconds < 3600: return f"{int(seconds/60)} Minutes"
    if seconds < 86400: return f"{int(seconds/3600)} Hours"
    if seconds < 2592000: return f"{int(seconds/86400)} Days"
    if seconds < 31536000: return f"{int(seconds/2592000)} Months"
    if seconds < 3153600000: return f"{int(seconds/31536000)} Years"
    return f"{int(seconds/3153600000)} Centuries"
