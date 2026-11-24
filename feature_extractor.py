"""
URL Feature Extraction Module for Phishing Detection.
Extracts lexical, structural, statistical, and security-heuristic features from URLs.
Runs completely offline without external network latency.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qsl
from collections import Counter
import tldextract

# Initialize offline TLD extractor with bundled snapshot
_extractor = tldextract.TLDExtract(suffix_list_urls=None)

# High-risk free hosting & staging platforms commonly abused by phishing kits
ABUSED_FREE_HOSTS = {
    "pages.dev", "webflow.io", "r2.dev", "workers.dev", "netlify.app",
    "vercel.app", "weeblysite.com", "weebly.com", "firebaseapp.com",
    "glitch.me", "duckdns.org", "ngrok.io", "000webhostapp.com",
    "surge.sh", "square.site", "render.com", "b-cdn.net", "wixsite.com",
    "godaddysites.com", "gitbook.io", "herokuapp.com"
}

# Suspicious / cheap / heavily abused TLDs
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "work", "click", "gq", "cf", "ml", "tk", "ga", "fit", "buzz", "cam", "icu"
}

# Common phishing keywords in path / query / subdomains
PHISH_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "banking",
    "security", "update", "wallet", "confirm", "confirmation", "metamask",
    "docusign", "password", "authenticate", "recover", "recovery", "billing",
    "invoice", "support", "violation", "suspended", "unlock", "security-alert"
]

# Legitimate official brand / institutional domains
OFFICIAL_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal.me"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in", "bank.in", "sbi"],
    "metamask": ["metamask.io"],
    "google": ["google.com", "google.co.in", "google.co.uk", "google.org", "googleapis.com"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "azure.com", "microsoftonline.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dropbox": ["dropbox.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "bankofamerica": ["bankofamerica.com"]
}

def calculate_entropy(text):
    """Calculates Shannon entropy of a given string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def parse_domain_info(host):
    """Accurately parses subdomain, domain, and suffix with support for banking and academic zones."""
    host = host.lower()
    
    # Special handling for specialized official zones
    for special_zone in [".bank.in", ".fin.in", ".ac.in", ".gov.in", ".nic.in", ".edu.in"]:
        if host.endswith(special_zone):
            prefix = host[:-len(special_zone)]
            parts = prefix.split(".")
            domain = parts[-1]
            subdomain = ".".join(parts[:-1]) if len(parts) > 1 else ""
            suffix = special_zone[1:]
            return subdomain, domain, suffix, f"{domain}.{suffix}"
            
    tld_res = _extractor(host)
    subdomain = tld_res.subdomain.lower()
    domain = tld_res.domain.lower()
    suffix = tld_res.suffix.lower()
    reg_domain = f"{domain}.{suffix}" if domain and suffix else host
    return subdomain, domain, suffix, reg_domain

def extract_features(url):
    """
    Extracts a feature dictionary from a URL string.
    Works for both clean and obfuscated URLs.
    """
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        url_for_parsing = "http://" + url_str
    else:
        url_for_parsing = url_str

    parsed = urlparse(url_for_parsing)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Parse domain components
    subdomain, domain, suffix, reg_domain = parse_domain_info(host)

    # Check if host is IP address
    is_ip = 0
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0

    # Count subdomains
    subdomain_parts = [s for s in subdomain.split(".") if s]
    subdomain_count = len(subdomain_parts)

    # Digits and ratios
    digits_host = sum(c.isdigit() for c in host)
    host_len = len(host)
    digit_ratio_host = (digits_host / host_len) if host_len > 0 else 0.0

    # Free hosting check
    is_free_host = 1 if reg_domain in ABUSED_FREE_HOSTS else 0

    # Suspicious TLD check
    is_suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0

    # Academic / Government / Official Banking trust check
    is_institutional_trust = 0
    if any(suffix.endswith(sfx) or suffix == sfx for sfx in [
        "gov", "gov.in", "nic.in", "edu", "ac.in", "edu.in", "mil", "bank.in", "bank", "fin.in"
    ]):
        is_institutional_trust = 1
    elif any(term in domain for term in ["university", "univ", "college", "school", "iit", "nit", "bits"]):
        is_institutional_trust = 1

    # Phishing keywords in path or subdomain
    subdomain_and_path = f"{subdomain} {path}".lower()
    has_keywords = sum(1 for kw in PHISH_KEYWORDS if kw in subdomain_and_path)

    # Brand impersonation detection:
    # A brand name appears in subdomain/path, BUT the host is NOT an official domain for that brand.
    brand_impersonation = 0
    for brand, legit_domains in OFFICIAL_BRAND_DOMAINS.items():
        if brand in subdomain_and_path or (brand in host and brand != domain):
            # Check if this host is actually legitimate for this brand
            is_official = any(host.endswith(ld) or host == ld or reg_domain == ld for ld in legit_domains)
            if not is_official:
                # Brand is present, but not on an official domain!
                brand_impersonation = 1
                break

    # Directories
    directories = [x for x in path.split("/") if x]

    # Special characters
    special_chars = len(re.findall(r"[^a-zA-Z0-9]", url_str))

    # Obfuscated characters (%20, %3D, etc.)
    obfuscated_count = len(re.findall(r"%[0-9a-fA-F]{2}", url_str))

    # Double slashes in path (redirection trick)
    double_slash = 1 if "//" in path else 0

    # Embedded credentials
    has_credentials = 1 if (parsed.username or parsed.password) else 0

    # Punycode check
    is_punycode = 1 if "xn--" in host else 0

    # Return structured feature dict
    features = {
        "url_length": len(url_str),
        "domain_length": host_len,
        "path_length": len(path),
        "query_length": len(query),
        "num_dots_host": host.count("."),
        "num_dots_url": url_str.count("."),
        "num_hyphens_domain": host.count("-"),
        "num_hyphens_url": url_str.count("-"),
        "num_underscores": url_str.count("_"),
        "num_slashes": url_str.count("/"),
        "num_digits_domain": digits_host,
        "num_digits_url": sum(c.isdigit() for c in url_str),
        "digit_ratio_domain": digit_ratio_host,
        "num_special_chars": special_chars,
        "num_subdomains": subdomain_count,
        "num_directories": len(directories),
        "is_ip_address": is_ip,
        "is_https": 1 if parsed.scheme.lower() == "https" else 0,
        "has_at_symbol": 1 if "@" in url_str else 0,
        "has_double_slash_redirect": double_slash,
        "has_credentials": has_credentials,
        "is_punycode": is_punycode,
        "url_entropy": calculate_entropy(url_str),
        "domain_entropy": calculate_entropy(host),
        "path_entropy": calculate_entropy(path),
        "num_params": len(parse_qsl(query)),
        "is_free_hosting": is_free_host,
        "has_suspicious_tld": is_suspicious_tld,
        "has_phish_keywords": has_keywords,
        "brand_impersonation": brand_impersonation,
        "is_institutional_trust": is_institutional_trust,
        "obfuscated_count": obfuscated_count
    }

    return features

if __name__ == "__main__":
    test_urls = [
        "https://student.glauniversity.in/Main/Index",
        "https://onlinesbi.sbi.bank.in/",
        "https://www.google.com",
        "https://help-app---metamask-usa.webflow.io/",
        "https://pub-78a9a9d8b3b14d60a24c7025b7ffdbf2.r2.dev/scrot.html"
    ]
    for u in test_urls:
        feats = extract_features(u)
        print(f"\n--- URL: {u} ---")
        for k in ["is_free_hosting", "brand_impersonation", "is_institutional_trust", "is_ip_address", "num_subdomains"]:
            print(f"  {k}: {feats[k]}")
