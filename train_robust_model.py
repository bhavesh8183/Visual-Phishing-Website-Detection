"""
Training script for the Robust URL Phishing Detection Model (V3).
Uses balanced real-world dataset and comprehensive feature engineering.
"""

import pandas as pd
import numpy as np
import joblib
from feature_extractor import extract_features
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score

def main():
    print("Loading balanced dataset...")
    df = pd.read_csv("balanced_url_dataset.csv")
    print(f"Total samples: {len(df)}")
    print("Class distribution:")
    print(df["label"].value_counts())

    print("\nExtracting features from URLs (this takes ~15-20 seconds)...")
    feature_list = []
    for idx, url in enumerate(df["URL"]):
        feature_list.append(extract_features(url))
        if (idx + 1) % 2500 == 0:
            print(f"  Processed {idx + 1}/{len(df)} URLs...")

    X = pd.DataFrame(feature_list)
    y = df["label"].astype(int)
    feature_names = list(X.columns)
    print(f"Features extracted: {len(feature_names)} features.")

    # Train-test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Testing set: {len(X_test)} samples")

    print("\nTraining Random Forest Classifier (200 trees)...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_proba)
    print("\n" + "=" * 50)
    print(f"MODEL PERFORMANCE EVALUATION:")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"ROC-AUC:   {roc * 100:.2f}%")
    print("=" * 50)

    print("\nClassification Report (0 = Phishing, 1 = Legitimate):")
    print(classification_report(y_test, y_pred, target_names=["Phishing", "Legitimate"], digits=4))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  [TN={cm[0][0]}  FP={cm[0][1]}]  (Phishing)")
    print(f"  [FN={cm[1][0]}  TP={cm[1][1]}]  (Legitimate)")

    # Top feature importances
    importances = pd.Series(clf.feature_importances_, index=feature_names).sort_values(ascending=False)
    print("\nTop 10 Most Predictive Features:")
    for feat, imp in importances.head(10).items():
        print(f"  - {feat:25s}: {imp:.4f}")

    # Save model package
    model_data = {
        "model": clf,
        "feature_names": feature_names
    }
    joblib.dump(model_data, "url_phishing_model_v3.joblib")
    print("\nModel saved to 'url_phishing_model_v3.joblib' successfully!")

    # Verify on Real-World Benchmark URLs
    print("\n" + "=" * 50)
    print("TESTING ON REAL-WORLD BENCHMARK URLs:")
    print("=" * 50)

    benchmark_urls = [
        ("https://student.glauniversity.in/Main/Index", "Legitimate University Portal"),
        ("https://onlinesbi.sbi.bank.in/", "Legitimate Banking Portal"),
        ("https://www.google.com", "Legitimate Search Engine"),
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "Legitimate YouTube Video"),
        ("https://github.com/torvalds/linux", "Legitimate GitHub Repo"),
        ("https://help-app---metamask-usa.webflow.io/", "Real Phishing (Webflow scam)"),
        ("https://pub-78a9a9d8b3b14d60a24c7025b7ffdbf2.r2.dev/scrot.html", "Real Phishing (R2 Cloudflare scam)"),
        ("https://pub-d03795620fac4676aa4b345b7ddece27.r2.dev/lisd.html", "Real Phishing (R2 scam)"),
        ("http://kdostjva.e-kei.pl/?https:/apps.rackspace.com/login", "Real Phishing (Open Redirect Credential Stealer)")
    ]

    for url, desc in benchmark_urls:
        feats_df = pd.DataFrame([extract_features(url)])[feature_names]
        pred = int(clf.predict(feats_df)[0])
        probs = clf.predict_proba(feats_df)[0]
        # label 0 = Phishing, 1 = Legitimate
        phish_prob = probs[0] * 100
        legit_prob = probs[1] * 100
        verdict = "LEGITIMATE ✅" if pred == 1 else "PHISHING ⚠️"
        print(f"\nTarget: {desc}")
        print(f"URL:    {url}")
        print(f"Result: {verdict} (Legitimate: {legit_prob:.1f}%, Phishing: {phish_prob:.1f}%)")

if __name__ == "__main__":
    main()
