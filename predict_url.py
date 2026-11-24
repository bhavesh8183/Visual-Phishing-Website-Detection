"""
CLI Tool for Real-Time URL Phishing Detection.
Usage:
    python predict_url.py <URL>
    python predict_url.py  (interactive mode)
"""

import sys
from realworld_detector import analyze_url

def print_result(res):
    print("\n" + "=" * 60)
    print(f" URL ANALYSIS RESULT")
    print("=" * 60)
    print(f" Target URL:        {res['url']}")
    print(f" Registered Domain: {res['registered_domain']}")
    print(f" Verdict:           {res['verdict']} [{res['safety_status']}]")
    print(f" Safety Score:      {res['safety_score']}%")
    print(f" Phishing Risk:     {res['risk_score']}%")
    print(f" ML Probabilities:  Legitimate: {res['ml_legit_prob']}% | Phishing: {res['ml_phishing_prob']}%")
    print("-" * 60)
    print(" Security Findings & Analysis:")
    for finding in res["findings"]:
        print(f"   {finding}")
    print("-" * 60)
    print(" Extracted Features:")
    for k, v in res["features"].items():
        print(f"   - {k:22s}: {v}")
    print("=" * 60 + "\n")

def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1].strip()
        result = analyze_url(target_url)
        print_result(result)
    else:
        print("=" * 60)
        print("  AI Phishing URL Detector (Interactive Console)")
        print("  Type any URL to analyze it, or 'q' to quit.")
        print("=" * 60)
        while True:
            try:
                user_input = input("\nEnter URL: ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ["q", "quit", "exit"]:
                    print("Exiting Phishing Detector. Goodbye!")
                    break
                result = analyze_url(user_input)
                print_result(result)
            except (KeyboardInterrupt, EOFError):
                print("\nExiting.")
                break

if __name__ == "__main__":
    main()
