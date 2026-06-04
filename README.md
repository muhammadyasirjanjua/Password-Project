# Password Security Analyzer

A professional cybersecurity-themed web application to analyze password strength, estimate cracking times, and generate secure passwords. This is an educational tool designed to raise awareness about password security best practices.

## Disclaimer
**This tool is strictly educational.** All password analysis happens locally or in-memory. Passwords are **never stored, saved, or logged.**

## Features
- **Comprehensive Password Analysis**: Evaluates length, entropy, character diversity, and flags common dictionary words, sequential patterns, or personal info.
- **Estimated Crack Times**: Provides realistic cracking estimates for common list attacks, dictionary attacks, brute force, and GPU/advanced attacks.
- **Recommendations Engine**: Suggests actionable steps to improve password security.
- **Secure Password Generator**: Generates strong, very strong, or enterprise-grade passwords with one-click copy.
- **Analysis Reports**: Export results securely to TXT, CSV, or JSON formats.
- **Analytics Dashboard**: Global overview of all analyzed sessions locally (metrics only, no passwords).
- **Security Best Practices applied**: CSRF Protection, Rate Limiting, Security Headers, Secure Session configuration.

## Requirements
- Python 3.8+
- Requirements listed in `requirements.txt`

## Installation

1. Navigate to the project directory:
```bash
cd Password
```

2. (Optional) Create and activate a virtual environment:
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

4. Run the Flask application:
```bash
python app.py
```

5. Access the application:
Open your web browser and navigate to `http://127.0.0.1:5000`

## Structure
- `app.py`: Main Flask application.
- `utils/`: Core logic for analysis, reporting, and generation.
- `templates/`: HTML templates.
- `static/`: CSS styling and client-side JavaScript.
