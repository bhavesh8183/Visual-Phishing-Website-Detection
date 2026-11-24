"""
Real-World Hybrid URL Phishing Detection Engine.
Combines:
1. Institutional Authority & Domain Whitelist Verification
2. High-Risk Security Tripwire Rules (IP in host, @ trick, Brand spoofing on free hosts)
3. 32-Feature Calibrated Random Forest Model (98.85% Accuracy)
4. Explainable Security Insights & Risk Scoring (0 - 100%)
"""

import os
import joblib
import pandas as pd
from urllib.parse import urlparse
from feature_extractor import extract_features, parse_domain_info, ABUSED_FREE_HOSTS, SUSPICIOUS_TLDS, OFFICIAL_BRAND_DOMAINS, PHISH_KEYWORDS

# Path to trained model package
MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_phishing_model_v3.joblib")

# Load model package
_model_data = None

def get_model_data():
    global _model_data
    if _model_data is None:
        if os.path.exists(MODEL_PATH):
            _model_data = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError(f"Model file '{MODEL_PATH}' not found. Please run train_robust_model.py first.")
    return _model_data

# Trusted high-authority apex domains (universities, banks, major platforms)
TRUSTED_AUTHORITIES = {
    "google.com", "google.co.in", "youtube.com", "microsoft.com", "apple.com",
    "github.com", "wikipedia.org", "amazon.in", "amazon.com", "flipkart.com",
    "glauniversity.in", "iitd.ac.in", "iitb.ac.in", "iitm.ac.in", "du.ac.in",
    "sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "rbi.org.in", "paypal.com", "netflix.com",
    "linkedin.com", "stackoverflow.com", "gov.in", "nic.in", "india.gov.in"
}

def analyze_url(raw_url):
    """
    Analyzes any URL and returns comprehensive detection results,
    risk score, safety level, model probabilities, and security findings.
    """
    raw_url = str(raw_url).strip()
    if not raw_url:
        return {"error": "Empty URL provided."}

    # Normalize URL scheme
    url = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    subdomain, domain, suffix, reg_domain = parse_domain_info(host)

    # 1. Extract ML features
    features = extract_features(url)
    model_info = get_model_data()
    feature_names = model_info["feature_names"]
    clf = model_info["model"]

    feats_df = pd.DataFrame([features])[feature_names]
    ml_probabilities = clf.predict_proba(feats_df)[0]
    # class 0 = Phishing, class 1 = Legitimate
    ml_phish_prob = float(ml_probabilities[0])
    ml_legit_prob = float(ml_probabilities[1])

    # 2. Heuristic Rules & Security Findings
    findings = []
    risk_adjust = 0.0

    # Rule A: Raw IP address in hostname
    if features["is_ip_address"] == 1:
        risk_adjust += 0.35
        findings.append("⚠️ Host is a raw IP address rather than a registered domain name (common in credential theft).")

    # Rule B: Free hosting / serverless abused platforms
    if features["is_free_hosting"] == 1:
        if features["brand_impersonation"] == 1 or features["has_phish_keywords"] > 0:
            risk_adjust += 0.45
            findings.append(f"🚨 Free hosting platform ({reg_domain}) hosting brand keywords or login targets (classic phishing signature).")
        else:
            findings.append(f"ℹ️ Hosted on a cloud/staging platform ({reg_domain}).")

    # Rule C: Brand Impersonation on untrusted domain
    if features["brand_impersonation"] == 1:
        risk_adjust += 0.35
        findings.append("🚨 Potential brand spoofing detected: A major brand name appears in subdomain/path on an unofficial domain.")

    # Rule D: Dangerous '@' credential trick
    if features["has_at_symbol"] == 1:
        risk_adjust += 0.40
        findings.append("🚨 Dangerous '@' character found in URL (used to trick browsers and hide actual destination).")

    # Rule E: Double slash redirect
    if features["has_double_slash_redirect"] == 1:
        risk_adjust += 0.25
        findings.append("⚠️ Open redirect pattern (double slash '//' inside path).")

    # Rule F: Punycode
    if features["is_punycode"] == 1:
        risk_adjust += 0.30
        findings.append("⚠️ Punycode ('xn--') detected in domain (potential homograph attack).")

    # Rule G: Suspicious TLD
    if features["has_suspicious_tld"] == 1:
        risk_adjust += 0.20
        findings.append(f"⚠️ Uses high-risk / spam-heavy top level domain (.{suffix}).")

    # Rule H: Official Institutional Trust (Academic / Government / Verified Bank)
    is_trusted_apex = (reg_domain in TRUSTED_AUTHORITIES) or (host in TRUSTED_AUTHORITIES)
    if is_trusted_apex or features["is_institutional_trust"] == 1:
        if features["is_free_hosting"] == 0 and features["has_at_symbol"] == 0 and features["is_ip_address"] == 0 and features["brand_impersonation"] == 0 and features["has_double_slash_redirect"] == 0:
            risk_adjust -= 0.50
            if is_trusted_apex:
                findings.append(f"✅ Verified authority / high-reputation domain ({reg_domain}).")
                # When verified authority domain has no tampering, cap risk to safe level
                final_risk_cap = 0.05
            else:
                final_risk_cap = 0.25

            if features["is_institutional_trust"] == 1:
                findings.append(f"✅ Official academic, governmental, or scheduled banking zone (.{suffix}).")
        else:
            final_risk_cap = 1.0
    else:
        final_risk_cap = 1.0

    # Calculate final calibrated risk score (0.0 to 1.0)
    final_risk = ml_phish_prob + risk_adjust
    final_risk = max(0.0, min(final_risk_cap, final_risk))

    # Convert to 0 - 100 percentage
    risk_percentage = round(final_risk * 100, 1)
    safety_percentage = round((1.0 - final_risk) * 100, 1)

    # Determine Verdict & Badge
    if risk_percentage >= 50.0:
        verdict = "Phishing Website"
        safety_status = "DANGER"
        badge_class = "phishing"
        summary = "This URL exhibits strong indicators of a malicious phishing attack."
    elif risk_percentage >= 30.0:
        verdict = "Suspicious Website"
        safety_status = "WARNING"
        badge_class = "suspicious"
        summary = "This URL has suspicious structural characteristics. Exercise caution before entering credentials."
    else:
        verdict = "Legitimate Website"
        safety_status = "SAFE"
        badge_class = "legitimate"
        summary = "This URL appears authentic and safe based on structural analysis and domain verification."

    if not findings:
        if verdict == "Legitimate Website":
            findings.append("✅ Clean URL structure with standard domain and path parameters.")
        else:
            findings.append("⚠️ Machine learning model identified anomalous URL characteristics.")

    return {
        "url": url,
        "hostname": host,
        "registered_domain": reg_domain,
        "verdict": verdict,
        "safety_status": safety_status,
        "badge_class": badge_class,
        "risk_score": risk_percentage,
        "safety_score": safety_percentage,
        "ml_phishing_prob": round(ml_phish_prob * 100, 1),
        "ml_legit_prob": round(ml_legit_prob * 100, 1),
        "summary": summary,
        "findings": findings,
        "features": {
            "URL Length": features["url_length"],
            "Domain Length": features["domain_length"],
            "Subdomains": features["num_subdomains"],
            "Directories": features["num_directories"],
            "Protocol": "HTTPS (Secure)" if features["is_https"] == 1 else "HTTP (Unencrypted)",
            "Has IP Address": "Yes" if features["is_ip_address"] == 1 else "No",
            "Free Cloud Host": "Yes" if features["is_free_hosting"] == 1 else "No",
            "Brand Impersonation": "Detected" if features["brand_impersonation"] == 1 else "None",
            "Institutional Trust": "Verified" if features["is_institutional_trust"] == 1 else "Standard",
            "Entropy Score": round(features["url_entropy"], 2)
        }
    }

if __name__ == "__main__":
    benchmark_urls = [
        "https://student.glauniversity.in/Main/Index",
        "https://onlinesbi.sbi.bank.in/",
        "https://www.google.com",
        "https://help-app---metamask-usa.webflow.io/",
        "https://pub-78a9a9d8b3b14d60a24c7025b7ffdbf2.r2.dev/scrot.html",
        "http://kdostjva.e-kei.pl/?https:/apps.rackspace.com/login"
    ]

    for u in benchmark_urls:
        res = analyze_url(u)
        print("\n" + "=" * 55)
        print(f"URL:     {res['url']}")
        print(f"Verdict: {res['verdict']} [{res['safety_status']}]")
        print(f"Risk:    {res['risk_score']}% | Safety: {res['safety_score']}%")
        print("Findings:")
        for f in res["findings"]:
            print(f"  {f}")
