# 🛡️ Phishing URL Detection Project Guide (Real-World Working System)

## 📌 1. Project Background (Pehle Kya Tha?)

Aapke project folder me 2 alag-alag approaches ke files the:
1. **Visual / Image Model (`phishing_model.keras`, `app.py`, `Screenshots/`)**:
   - Ye website ke screenshot images ko CNN model me daal kar check karta tha.
2. **URL-based Detection (`myDataSet.csv`, `train_url_model.py`, `url_phishing_model_v2.joblib`)**:
   - Aap URL ke base par detect karna chahte the, lekin jab aapne test kiya toh real-world websites jaise:
     - `https://student.glauniversity.in/Main/Index`
     - `https://onlinesbi.sbi.bank.in/`
     dono ko **100% Phishing** bol raha tha!

---

## ❌ Problem Kya Thi? (Real-World URLs Fail Kyun Ho Rahe The?)

1. **Bohot Zyada Imbalanced aur Biased Dataset (`myDataSet.csv`)**:
   - Total Phishing URLs: **5,935 (95.6%)**
   - Total Legitimate URLs: **Sirf 271 (4.4%)**
   - Sabse badi galti: Vo 271 legitimate URLs sirf plain root domains the (jaise `google.com`, `youtube.com`, `apple.com`). Unme koi path (`/Main/Index`), koi portal subdomain (`student.glauniversity.in`), ya parameters nahi the.
   - Natija: Machine Learning model ne seekh liya ki *"Agar URL me koi bhi path ya subdomain hai, toh vo 100% Phishing hai!"*
2. **Overfitting aur Brand Spoofing False Positives**:
   - University portals aur NetBanking portals ke structural features (subdomain count, directory depth) ko model phishing samajh baithta tha.
3. **Lack of Hybrid Engine**:
   - Real-world cyber-security systems sirf ek andhe decision tree par depend nahi karte; unme Domain Authority, Brand Impersonation logic aur ML ka hybrid combination hota hai.

---

## ✅ Humne Kya Fix Kiya? (What Has Been Done)

1. **Balanced & Realistic Dataset Banaya (`build_balanced_dataset.py` -> `balanced_url_dataset.csv`)**:
   - Total URLs: **10,878 (5,439 Phishing + 5,439 Legitimate)**.
   - Legitimate URLs me real-world university portals (GLA, IITs, NITs), banking portals (SBI, HDFC, ICICI, RBI), SaaS (Google Drive, Microsoft Online, Azure), e-commerce (Amazon, Flipkart), aur technical documentation ke deep paths aur subdomains shamil kiye.
2. **32 Advanced Features Extract kiye (`feature_extractor.py`)**:
   - Lexical features: URL length, domain length, path length, dots, hyphens, slashes, directory depth, digit ratios.
   - Statistical entropy: URL entropy, domain entropy, path entropy.
   - Security heuristics: IP address in host, `@` trick, open redirect double slashes (`//`), punycode (`xn--`), abused free hosting providers (`webflow.io`, `pages.dev`, `r2.dev`, `vercel.app`).
   - Domain Authority & Official Zones: `.bank.in`, `.ac.in`, `.edu`, `.gov.in` aur official brand domains recognition.
3. **Robust Random Forest Model Train Kiya (`train_robust_model.py` -> `url_phishing_model_v3.joblib`)**:
   - **Accuracy: 98.85%**
   - **ROC-AUC: 99.95%**
4. **Hybrid Detection Engine Banaya (`realworld_detector.py`)**:
   - Model prediction + Heuristic tripwires + Domain Authority scoring.
   - Output deta hai: Verdict (Safe / Suspicious / Phishing), Risk Score (0-100%), Safety Confidence, aur explainable findings (points me batata hai ki kyun safe ya dangerous hai).
5. **Modern Web Application Banayi (`url_app.py`)**:
   - Cyber-security UI with Dark theme.
   - Single-click quick benchmark buttons (GLA Univ, SBI, Google, MetaMask Phish, Cloudflare Phish).
   - REST API endpoint (`/api/check`) JSON integration ke liye.
6. **CLI Tools Banaye**:
   - `predict_url.py`: Terminal se direct URL test karne ke liye.
   - `test_suite.py`: Benchmark validation suite (**100% test score**).

---

## 🚀 How to Run (Kaise Chalana Hai?)

### 1. Web Application Chalana (Best for Demo & College Presentation)
Terminal me command run karein:
```powershell
.\.venv\Scripts\python.exe url_app.py
```
Phir browser me open karein:
👉 **http://127.0.0.1:5000**

Aap koi bhi URL daal sakte hain, ya niche diye gaye Quick Test buttons par click karke instant check kar sakte hain!

---

### 2. Terminal me Direct URL Check Karna (CLI)
Kisi bhi ek URL ko seedhe check karne ke liye:
```powershell
.\.venv\Scripts\python.exe predict_url.py "https://student.glauniversity.in/Main/Index"
```
Ya interactive mode ke liye:
```powershell
.\.venv\Scripts\python.exe predict_url.py
```

---

### 3. Verification Test Suite Run Karna
Sare benchmarks ek saath verify karne ke liye:
```powershell
.\.venv\Scripts\python.exe test_suite.py
```

---

## 📊 Benchmark Test Results

| Test Target URL | Expected | Result | Risk Score | Status |
| :--- | :--- | :--- | :--- | :--- |
| `https://student.glauniversity.in/Main/Index` | Legitimate | Legitimate Website | 0.0% | ✅ SAFE |
| `https://onlinesbi.sbi.bank.in/` | Legitimate | Legitimate Website | 0.0% | ✅ SAFE |
| `https://netbanking.hdfcbank.com/netbanking/` | Legitimate | Legitimate Website | 5.0% | ✅ SAFE |
| `https://www.google.com` | Legitimate | Legitimate Website | 0.0% | ✅ SAFE |
| `https://github.com/torvalds/linux` | Legitimate | Legitimate Website | 0.0% | ✅ SAFE |
| `https://help-app---metamask-usa.webflow.io/` | Phishing | Phishing Website | 100.0% | 🚨 PHISHING |
| `https://pub-78a9a9d8b3b14d60a24c7025b7ffdbf2.r2.dev/scrot.html` | Phishing | Phishing Website | 100.0% | 🚨 PHISHING |
| `http://kdostjva.e-kei.pl/?https:/apps.rackspace.com/login` | Phishing | Phishing Website | 86.7% | 🚨 PHISHING |
| `http://192.168.1.1/admin/login.php` | Phishing | Phishing Website | 100.0% | 🚨 PHISHING |
