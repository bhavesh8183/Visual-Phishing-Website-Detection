"""
Comprehensive Test Suite for Real-World Phishing Detection.
"""

from realworld_detector import analyze_url

urls_to_test = [
    # Legitimate Indian Universities & Portals
    ("https://student.glauniversity.in/Main/Index", "Legitimate - GLA University Portal"),
    ("https://iitd.ac.in/academics/curriculum", "Legitimate - IIT Delhi Academic Portal"),
    ("https://cuims.cuchd.in/student/login", "Legitimate - Chandigarh Univ Portal"),

    # Legitimate Banking & Payment Portals
    ("https://onlinesbi.sbi.bank.in/", "Legitimate - SBI Bank Portal"),
    ("https://netbanking.hdfcbank.com/netbanking/", "Legitimate - HDFC NetBanking"),
    ("https://www.paypal.com/signin", "Legitimate - Official PayPal Login"),

    # Legitimate Global Tech & Tools
    ("https://www.google.com", "Legitimate - Google Search"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "Legitimate - YouTube"),
    ("https://github.com/torvalds/linux", "Legitimate - GitHub Repository"),
    ("https://en.wikipedia.org/wiki/Computer_security", "Legitimate - Wikipedia Article"),
    ("https://login.microsoftonline.com/common/oauth2/authorize", "Legitimate - Microsoft Login"),

    # Real Phishing Attacks
    ("https://help-app---metamask-usa.webflow.io/", "Phishing - Fake MetaMask Webflow"),
    ("https://pub-78a9a9d8b3b14d60a24c7025b7ffdbf2.r2.dev/scrot.html", "Phishing - Fake Cloudflare R2"),
    ("http://kdostjva.e-kei.pl/?https:/apps.rackspace.com/login", "Phishing - Open Redirect Harvester"),
    ("http://192.168.1.1/admin/login.php", "Phishing / Risky - Raw IP Admin Login"),
    ("https://paypal-security-update.com/signin", "Phishing - Fake PayPal Domain"),
    ("http://amazon.com.order-update.xyz/login", "Phishing - Fake Amazon Subdomain Trick")
]

print("=" * 80)
print(f"{'EXPECTED':<30} | {'VERDICT':<20} | {'RISK':<8} | {'URL'}")
print("=" * 80)

correct = 0
for url, expected in urls_to_test:
    res = analyze_url(url)
    verdict = res["verdict"]
    risk = f"{res['risk_score']}%"
    is_phish_expected = "Phishing" in expected
    is_phish_verdict = verdict in ["Phishing Website", "Suspicious Website"]
    
    if is_phish_expected == is_phish_verdict:
        status_icon = "✅"
        correct += 1
    else:
        status_icon = "❌"

    print(f"{expected:<30} | {verdict:<20} | {risk:<8} | {status_icon} {url}")

print("=" * 80)
print(f"Benchmark Accuracy: {correct}/{len(urls_to_test)} ({correct / len(urls_to_test) * 100:.1f}%)")
