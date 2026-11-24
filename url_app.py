"""
CyberGuard AI - Real-World URL Phishing Detection Web Application.
Powered by Hybrid Real-World AI Engine and 32-Feature Random Forest Classifier.
"""

from flask import Flask, request, render_template_string, jsonify
from realworld_detector import analyze_url

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard AI - URL Phishing Detector</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --card-border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #3b82f6;
            --safe-green: #10b981;
            --safe-bg: rgba(16, 185, 129, 0.12);
            --danger-red: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.12);
            --warning-orange: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.12);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 40px 20px;
        }

        .container {
            width: 100%;
            max-width: 860px;
        }

        header {
            text-align: center;
            margin-bottom: 35px;
        }

        .logo-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 15px;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        h1 {
            font-size: 32px;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 10px;
        }

        header p {
            color: var(--text-secondary);
            font-size: 16px;
        }

        .search-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 28px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            margin-bottom: 30px;
        }

        .input-group {
            display: flex;
            gap: 12px;
            position: relative;
        }

        input[type="text"] {
            flex: 1;
            background: #0f172a;
            border: 1.5px solid #334155;
            border-radius: 10px;
            padding: 14px 18px;
            color: #fff;
            font-size: 15px;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        input[type="text"]:focus {
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }

        button.btn-scan {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            color: #fff;
            border: none;
            border-radius: 10px;
            padding: 14px 28px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.15s, opacity 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        button.btn-scan:hover {
            opacity: 0.95;
            transform: translateY(-1px);
        }

        .quick-tests {
            margin-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            padding-top: 16px;
        }

        .quick-tests span {
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 500;
            margin-right: 10px;
        }

        .pill-group {
            display: inline-flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }

        .test-pill {
            background: #283548;
            border: 1px solid #3d4d65;
            color: #cbd5e1;
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
        }

        .test-pill:hover {
            background: #334155;
            color: #fff;
            border-color: var(--accent-blue);
        }

        .result-card {
            background: var(--card-bg);
            border-radius: 16px;
            border: 1px solid var(--card-border);
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .verdict-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--card-border);
            margin-bottom: 24px;
        }

        .verdict-badge {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 8px 18px;
            border-radius: 30px;
            font-size: 17px;
            font-weight: 700;
            letter-spacing: 0.2px;
        }

        .verdict-badge.legitimate {
            background: var(--safe-bg);
            color: var(--safe-green);
            border: 1.5px solid var(--safe-green);
        }

        .verdict-badge.phishing {
            background: var(--danger-bg);
            color: var(--danger-red);
            border: 1.5px solid var(--danger-red);
        }

        .verdict-badge.suspicious {
            background: var(--warning-bg);
            color: var(--warning-orange);
            border: 1.5px solid var(--warning-orange);
        }

        .scores-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 25px;
        }

        .score-box {
            background: #111827;
            padding: 16px;
            border-radius: 10px;
            border: 1px solid #1f2937;
            text-align: center;
        }

        .score-label {
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .score-value {
            font-size: 24px;
            font-weight: 700;
        }

        .score-value.safe { color: var(--safe-green); }
        .score-value.danger { color: var(--danger-red); }
        .score-value.neutral { color: #60a5fa; }

        .analyzed-url {
            word-break: break-all;
            background: #0f172a;
            padding: 12px 16px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            color: #93c5fd;
            margin-bottom: 24px;
            border: 1px solid #1e293b;
        }

        .section-title {
            font-size: 15px;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .findings-list {
            list-style: none;
            margin-bottom: 25px;
        }

        .findings-list li {
            padding: 10px 14px;
            background: #111827;
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 14px;
            border-left: 4px solid #3b82f6;
            color: #cbd5e1;
        }

        .features-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .features-table tr {
            border-bottom: 1px solid #1e293b;
        }

        .features-table td {
            padding: 8px 12px;
        }

        .features-table td:first-child {
            color: var(--text-secondary);
            width: 50%;
        }

        .features-table td:last-child {
            color: #fff;
            font-weight: 500;
            text-align: right;
        }

        footer {
            margin-top: 40px;
            text-align: center;
            color: #64748b;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-badge">🛡️ AI URL SECURITY ENGINE v3.0</div>
            <h1>Phishing & Legitimate URL Detector</h1>
            <p>Real-Time Deep Lexical, Brand Spoofing & Domain Intelligence Analysis</p>
        </header>

        <div class="search-card">
            <form method="POST" action="/">
                <div class="input-group">
                    <input type="text" name="url" placeholder="Enter website URL (e.g., https://student.glauniversity.in/Main/Index)" value="{{ query_url }}" required autocomplete="off">
                    <button type="submit" class="btn-scan">
                        <span>Analyze URL</span>
                    </button>
                </div>
            </form>

            <div class="quick-tests">
                <span>⚡ Quick Test Benchmarks:</span>
                <div class="pill-group">
                    <a href="/?sample=gla" class="test-pill">🎓 GLA University Portal</a>
                    <a href="/?sample=sbi" class="test-pill">🏦 SBI NetBanking Portal</a>
                    <a href="/?sample=google" class="test-pill">🔍 Google Search</a>
                    <a href="/?sample=phish_metamask" class="test-pill">⚠️ MetaMask Webflow Phish</a>
                    <a href="/?sample=phish_r2" class="test-pill">⚠️ Cloudflare R2 Phish</a>
                    <a href="/?sample=phish_redirect" class="test-pill">⚠️ Credential Stealer</a>
                </div>
            </div>
        </div>

        {% if result %}
        <div class="result-card">
            <div class="verdict-header">
                <div>
                    <span class="score-label">Classification Verdict</span>
                    <div class="verdict-badge {{ result.badge_class }}">
                        {% if result.badge_class == 'legitimate' %}
                            ✅ {{ result.verdict }}
                        {% elif result.badge_class == 'phishing' %}
                            🚨 {{ result.verdict }}
                        {% else %}
                            ⚠️ {{ result.verdict }}
                        {% endif %}
                    </div>
                </div>
                <div style="text-align: right;">
                    <span class="score-label">Domain Authority</span>
                    <h3 style="font-size: 16px; color: #93c5fd;">{{ result.registered_domain }}</h3>
                </div>
            </div>

            <div class="analyzed-url">
                <strong>Analyzed URL:</strong> {{ result.url }}
            </div>

            <div class="scores-grid">
                <div class="score-box">
                    <div class="score-label">Safety Confidence</div>
                    <div class="score-value safe">{{ result.safety_score }}%</div>
                </div>
                <div class="score-box">
                    <div class="score-label">Phishing Risk</div>
                    <div class="score-value {% if result.risk_score >= 50 %}danger{% else %}neutral{% endif %}">{{ result.risk_score }}%</div>
                </div>
                <div class="score-box">
                    <div class="score-label">ML Prediction</div>
                    <div class="score-value neutral">{{ result.ml_legit_prob }}% Legit</div>
                </div>
            </div>

            <div class="section-title">🔍 Security Findings & Intelligence Analysis</div>
            <ul class="findings-list">
                {% for finding in result.findings %}
                    <li>{{ finding }}</li>
                {% endfor %}
            </ul>

            <div class="section-title">📊 Extracted Feature Matrix</div>
            <table class="features-table">
                {% for key, val in result.features.items() %}
                <tr>
                    <td>{{ key }}</td>
                    <td>{{ val }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <footer>
            <p>Real-World URL Phishing Detection System | Powered by Random Forest V3 & Hybrid Rules</p>
        </footer>
    </div>
</body>
</html>
"""

SAMPLES = {
    "gla": "https://student.glauniversity.in/Main/Index",
    "sbi": "https://onlinesbi.sbi.bank.in/",
    "google": "https://www.google.com",
    "phish_metamask": "https://help-app---metamask-usa.webflow.io/",
    "phish_r2": "https://pub-78a9a9d8b3b14d60a24c7025b7ffdbf2.r2.dev/scrot.html",
    "phish_redirect": "http://kdostjva.e-kei.pl/?https:/apps.rackspace.com/login"
}

@app.route("/", methods=["GET", "POST"])
def index():
    query_url = ""
    result = None

    if request.method == "POST":
        query_url = request.form.get("url", "").strip()
        if query_url:
            result = analyze_url(query_url)
    elif request.method == "GET":
        sample_key = request.args.get("sample", "")
        if sample_key in SAMPLES:
            query_url = SAMPLES[sample_key]
            result = analyze_url(query_url)

    return render_template_string(HTML_TEMPLATE, query_url=query_url, result=result)

@app.route("/api/check", methods=["GET", "POST"])
def api_check():
    """REST API endpoint for URL verification."""
    url = ""
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            url = data.get("url", "")
        else:
            url = request.form.get("url", "")
    else:
        url = request.args.get("url", "")

    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    result = analyze_url(url)
    return jsonify(result)

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting CyberGuard Phishing URL Detector Web App...")
    print("🌐 Open http://127.0.0.1:5000 in your browser.")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
