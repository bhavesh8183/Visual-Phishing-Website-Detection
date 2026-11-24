"""
Script to create a clean, robust, and balanced URL dataset for Phishing Detection.
Combines ~5,935 real-world phishing URLs from myDataSet.csv with ~6,000 diverse,
realistic legitimate URLs spanning universities, banks, SaaS, tech docs, government,
e-commerce, and deep content paths.
"""

import pandas as pd
import random
from urllib.parse import urlparse

# Set seed for reproducibility
random.seed(42)

def generate_legitimate_urls():
    """Generates a rich, realistic pool of legitimate URLs with deep paths, queries, subdomains."""
    
    # Base domains categorized
    universities = [
        "student.glauniversity.in", "glauniversity.in", "home.iitd.ac.in", "iitb.ac.in",
        "iitm.ac.in", "iitk.ac.in", "iitr.ac.in", "iitg.ac.in", "dtu.ac.in", "nsut.ac.in",
        "du.ac.in", "bits-pilani.ac.in", "annauniv.edu", "cuims.cuchd.in", "amizone.net",
        "vtop.vit.ac.in", "vit.ac.in", "srmist.edu.in", "mit.edu", "stanford.edu",
        "harvard.edu", "ox.ac.uk", "cam.ac.uk", "berkeley.edu", "cmu.edu", "caltech.edu",
        "princeton.edu", "yale.edu", "columbia.edu", "cornell.edu", "ucla.edu", "nyu.edu",
        "manipal.edu", "thapar.edu", "jnu.ac.in", "bhu.ac.in", "amu.ac.in", "tifr.res.in"
    ]
    
    univ_paths = [
        "/Main/Index", "/student/login", "/portal/dashboard", "/academics/curriculum",
        "/admissions/apply-now", "/faculty/directory", "/library/catalogue", "/results/semester-grades",
        "/exam/schedule", "/research/publications", "/campus/events", "/placement/statistics",
        "/fees/payment-gateway", "/hostel/allotment", "/syllabus/btech-cse", "/contact-us",
        "/about/leadership", "/alumni/network", "/notice/circular-2026", "/helpdesk/ticket"
    ]
    
    banks = [
        "onlinesbi.sbi.bank.in", "sbi.co.in", "retail.onlinesbi.sbi", "netbanking.hdfcbank.com",
        "hdfcbank.com", "infinity.icicibank.com", "icicibank.com", "axisbank.com",
        "kotak.com", "bankofbaroda.in", "pnbindia.in", "canarabank.com", "unionbankofindia.co.in",
        "idbibank.in", "indusind.com", "yesbank.in", "rbi.org.in", "paypal.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com", "barclays.co.uk",
        "hsbc.com", "stripe.com", "dashboard.stripe.com", "dashboard.razorpay.com", "razorpay.com",
        "paytm.com", "phonepe.com", "groww.in", "zerodha.com", "kite.zerodha.com"
    ]
    
    bank_paths = [
        "/", "/personal-banking", "/corporate-banking", "/retail/login.htm", "/netbanking/entry",
        "/cards/credit-card-apply", "/loans/home-loan-interest-rates", "/accounts/savings-account",
        "/security-tips/safe-banking", "/locate-us/atm-branch", "/customer-care/helpline",
        "/myaccount/transfer", "/dashboard/overview", "/payments/checkout", "/investments/mutual-funds"
    ]
    
    tech_dev = [
        "github.com", "gist.github.com", "docs.github.com", "gitlab.com", "bitbucket.org",
        "stackoverflow.com", "stackexchange.com", "docs.python.org", "pypi.org",
        "developer.mozilla.org", "en.cppreference.com", "w3schools.com", "geeksforgeeks.org",
        "kaggle.com", "huggingface.co", "hub.docker.com", "npmjs.com", "crates.io",
        "pkg.go.dev", "terraform.io", "kubernetes.io", "react.dev", "nextjs.org",
        "vuejs.org", "angular.dev", "pytorch.org", "tensorflow.org", "scikit-learn.org",
        "pandas.pydata.org", "numpy.org", "arxiv.org", "medium.com", "dev.to", "hashnode.com"
    ]
    
    tech_paths = [
        "/torvalds/linux", "/facebook/react", "/python/cpython", "/questions/1234567/python-url-parsing",
        "/3/library/urllib.parse.html", "/project/scikit-learn/", "/en-US/docs/Web/HTTP/Overview",
        "/learn/machine-learning", "/models/bert-base-uncased", "/blog/deep-learning-advances",
        "/abs/2301.00001", "/docs/installation", "/guide/quick-start", "/api/v1/reference",
        "/tutorials/getting-started", "/community/discussions", "/releases/tag/v2.0.0"
    ]
    
    cloud_saas = [
        "portal.azure.com", "login.microsoftonline.com", "docs.microsoft.com", "support.microsoft.com",
        "cloud.google.com", "console.cloud.google.com", "mail.google.com", "drive.google.com",
        "accounts.google.com", "calendar.google.com", "console.aws.amazon.com", "aws.amazon.com",
        "jira.atlassian.com", "confluence.atlassian.com", "slack.com", "app.slack.com",
        "zoom.us", "notion.so", "figma.com", "canva.com", "dropbox.com", "salesforce.com",
        "hubspot.com", "zendesk.com", "shopify.com", "trello.com", "asana.com"
    ]
    
    cloud_paths = [
        "/home/dashboard", "/mail/u/0/#inbox", "/drive/my-drive", "/signin/identifier",
        "/console/home?region=us-east-1", "/docs/storage/overview", "/pricing/calculator",
        "/support/tickets", "/settings/profile", "/workspace/team", "/downloads/latest"
    ]
    
    ecommerce_services = [
        "amazon.in", "amazon.com", "flipkart.com", "myntra.com", "swiggy.com", "zomato.com",
        "bookmyshow.com", "makemytrip.com", "irctc.co.in", "uber.com", "ola.cabs",
        "netflix.com", "youtube.com", "spotify.com", "hotstar.com", "primevideo.com",
        "apple.com", "support.apple.com", "samsung.com", "microsoft.com", "dell.com",
        "nike.com", "adidas.com", "walmart.com", "target.com", "ebay.com", "aliexpress.com"
    ]
    
    ecom_paths = [
        "/dp/B08N5WRWNW", "/search?q=laptop+gaming&ref=nb_sb_noss", "/cart/view",
        "/watch?v=dQw4w9WgXcQ", "/browse/genre/movie", "/playlist/top-hits",
        "/track-order?id=987654321", "/nget/train-search", "/flight-booking/delhi-mumbai",
        "/restaurant/delhi/top-rated", "/deal-of-the-day", "/category/electronics"
    ]
    
    gov_public = [
        "india.gov.in", "incometax.gov.in", "passportindia.gov.in", "uidai.gov.in",
        "epfindia.gov.in", "gst.gov.in", "digilocker.gov.in", "parivahan.gov.in",
        "cowin.gov.in", "upsc.gov.in", "ssc.nic.in", "cbse.gov.in", "nta.ac.in",
        "pmkisan.gov.in", "mygov.in", "gov.uk", "usa.gov", "irs.gov", "nih.gov",
        "cdc.gov", "un.org", "who.int", "nasa.gov", "europa.eu"
    ]
    
    gov_paths = [
        "/iec/foportal/", "/online-services", "/dashboard/stats", "/aadhaar-download",
        "/tax-calculator", "/apply-online", "/status-check?req_id=45231", "/downloads/forms",
        "/notifications/recruitment-2026", "/circulars/latest-guidelines", "/contact-directory"
    ]
    
    news_media = [
        "en.wikipedia.org", "wikipedia.org", "bbc.com", "cnn.com", "nytimes.com",
        "theguardian.com", "reuters.com", "bloomberg.com", "forbes.com", "wsj.com",
        "ndtv.com", "timesofindia.indiatimes.com", "thehindu.com", "indianexpress.com",
        "hindustantimes.com", "reddit.com", "linkedin.com", "twitter.com", "x.com", "quora.com"
    ]
    
    news_paths = [
        "/wiki/Phishing", "/wiki/Computer_security", "/wiki/Machine_learning",
        "/world/asia/india-tech-growth", "/business/markets-today", "/technology/ai-advancements",
        "/r/MachineLearning/comments/xyz123", "/r/programming/top", "/in/bhavya-developer",
        "/topic/cybersecurity-trends", "/news/national/education-update"
    ]
    
    legit_urls = set()
    
    # 1. Base homepages
    all_domains = universities + banks + tech_dev + cloud_saas + ecommerce_services + gov_public + news_media
    for d in all_domains:
        legit_urls.add(f"https://{d}")
        legit_urls.add(f"https://www.{d}" if not d.startswith("www.") and not "." in d[:-4] else f"https://{d}")
        legit_urls.add(f"http://{d}")
    
    # 2. Add university deep links
    for d in universities:
        for p in univ_paths:
            legit_urls.add(f"https://{d}{p}")
            if random.random() < 0.3:
                legit_urls.add(f"https://{d}{p}?session=2026&dept=cse")
    
    # 3. Add bank deep links
    for d in banks:
        for p in bank_paths:
            legit_urls.add(f"https://{d}{p}")
            if random.random() < 0.3:
                legit_urls.add(f"https://{d}{p}?lang=en")
                
    # 4. Add tech developer deep links
    for d in tech_dev:
        for p in tech_paths:
            legit_urls.add(f"https://{d}{p}")
            if random.random() < 0.3:
                legit_urls.add(f"https://{d}{p}?page=1&tab=readme")

    # 5. Add cloud & SaaS deep links
    for d in cloud_saas:
        for p in cloud_paths:
            legit_urls.add(f"https://{d}{p}")
            if random.random() < 0.3:
                legit_urls.add(f"https://{d}{p}?auth=saml2&tenant=org")

    # 6. Add ecommerce deep links
    for d in ecommerce_services:
        for p in ecom_paths:
            legit_urls.add(f"https://{d}{p}")
            if random.random() < 0.4:
                legit_urls.add(f"https://{d}{p}?src=search_nav&ref=home")

    # 7. Add gov & public deep links
    for d in gov_public:
        for p in gov_paths:
            legit_urls.add(f"https://{d}{p}")
            if random.random() < 0.3:
                legit_urls.add(f"https://{d}{p}?service_code=102&state=all")

    # 8. Add news & knowledge deep links
    for d in news_media:
        for p in news_paths:
            legit_urls.add(f"https://{d}{p}")

    # Generate additional combinatorial realistic legitimate deep URLs to reach ~6,000
    param_keys = ["id", "user", "page", "tab", "category", "lang", "view", "ref", "query", "filter"]
    subdirs = ["portal", "main", "account", "docs", "app", "dashboard", "api", "v2", "secure", "home", "en", "in", "content", "services"]
    
    while len(legit_urls) < 6200:
        d = random.choice(all_domains)
        depth = random.randint(1, 3)
        path = "/" + "/".join(random.choices(subdirs, k=depth))
        if random.random() < 0.4:
            p_key = random.choice(param_keys)
            p_val = random.randint(100, 99999)
            url = f"https://{d}{path}?{p_key}={p_val}"
        else:
            url = f"https://{d}{path}"
        legit_urls.add(url)
        
    return list(legit_urls)

def main():
    print("Loading original myDataSet.csv...")
    df_orig = pd.read_csv("myDataSet.csv")
    df_orig["label_num"] = pd.to_numeric(df_orig["label"], errors="coerce")
    df_orig = df_orig.dropna(subset=["label_num", "URL"])
    df_orig["label_num"] = df_orig["label_num"].astype(int)
    df_orig["URL"] = df_orig["URL"].astype(str).str.strip()
    df_orig = df_orig[df_orig["URL"] != ""]
    
    phishing_urls = df_orig[df_orig["label_num"] == 0]["URL"].drop_duplicates().tolist()
    orig_legit_urls = df_orig[df_orig["label_num"] == 1]["URL"].drop_duplicates().tolist()
    
    print(f"Original Phishing URLs: {len(phishing_urls)}")
    print(f"Original Legitimate URLs: {len(orig_legit_urls)}")
    
    # Generate rich legitimate URLs
    generated_legit = generate_legitimate_urls()
    print(f"Generated Realistic Legitimate URLs: {len(generated_legit)}")
    
    all_legit = list(set(orig_legit_urls + generated_legit))
    
    # Balance lengths
    # We have ~5935 phishing URLs, let's take ~5935 legitimate URLs
    target_count = len(phishing_urls)
    if len(all_legit) > target_count:
        all_legit = random.sample(all_legit, target_count)
        
    print(f"Final Legitimate URLs: {len(all_legit)}")
    print(f"Final Phishing URLs: {len(phishing_urls)}")
    
    # Build combined dataframe
    df_phish = pd.DataFrame({"URL": phishing_urls, "label": 0})
    df_legit = pd.DataFrame({"URL": all_legit, "label": 1})
    
    df_balanced = pd.concat([df_phish, df_legit], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    output_file = "balanced_url_dataset.csv"
    df_balanced.to_csv(output_file, index=False)
    print(f"\nSaved balanced dataset to '{output_file}' with {len(df_balanced)} rows.")
    print("Class distribution:")
    print(df_balanced["label"].value_counts())
    
    # Show samples
    print("\nSample Legitimate URLs (label=1):")
    for u in df_balanced[df_balanced["label"] == 1]["URL"].head(5):
        print("  -", u)
        
    print("\nSample Phishing URLs (label=0):")
    for u in df_balanced[df_balanced["label"] == 0]["URL"].head(5):
        print("  -", u)

if __name__ == "__main__":
    main()
