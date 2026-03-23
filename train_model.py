import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import os
from features import extract_advanced_features

def generate_synthetic_data(filename):
    print("Generating advanced synthetic dataset...")
    # Legitimate URLs
    legit = [
        "https://www.google.com", "https://youtube.com", "https://facebook.com",
        "https://github.com/login", "https://stackoverflow.com/questions", "https://en.wikipedia.org/wiki/Phishing",
        "https://www.amazon.com/gp/cart/view.html", "https://twitter.com/home", "https://www.apple.com/iphone",
        "https://news.ycombinator.com", "https://www.netflix.com/browse", "https://reddit.com/r/learnpython",
        "https://medium.com", "https://www.microsoft.com", "https://www.linkedin.com/feed",
        "https://www.openai.com", "https://www.cloudflare.com", "https://reactjs.org"
    ] * 25
    
    # Phishing URLs (incorporating advanced techniques)
    phish = [
        # Typosquatting
        "https://www.googIe.com", "https://faceb00k.com", "http://amzon.com", "http://netflix-update.com",
        "http://paypa1.com", "https://appIe.com", "http://www.linkdln.com",
        
        # Homograph
        "https://fàcebook.com", "http://paypál.com/login", "https://ámázon.com",
        "http://gòogle.com/secure", "https://netflix-updàte.com",
        
        # IP / Deep Subdomains
        "http://192.168.1.1/login.php", "http://10.10.10.10/verify-account", 
        "http://172.16.0.5/confirm", "http://account.update.secure.login.bankofamerica.com.evil.net", 
        "http://verify.www.paypal.com.account.secure.xyz",
        
        # High Entropy / Random
        "http://login-apple-support.net/qxj9k2z0vmfmwaq8p", "http://secure-update-account.com/token=e82fjwqz8x9cqm",
        "https://amazon-security-update.com/a93jg8q94j284hq98fhq284hf",
        
        # Shorteners
        "http://bit.ly/2kfdA9", "https://tinyurl.com/aB3x9k", "http://t.co/9Ajsd82",
        
        # Basic Suspicious
        "http://verify-your-bank-account.com", "http://paypal-update-user.info",
        "http://account-verify.xyz", "http://facebook-login-verify.com/secure"
    ] * 15
    
    data = []
    for url in legit:
        data.append({'url': url, 'label': 0})
    for url in phish:
        data.append({'url': url, 'label': 1})
        
    df = pd.DataFrame(data)
    df = df.sample(frac=1).reset_index(drop=True)
    df.to_csv(filename, index=False)
    print(f"Dataset saved to {filename}")

if __name__ == "__main__":
    csv_file = 'advanced_phishing_urls.csv'
    
    if not os.path.exists(csv_file):
        generate_synthetic_data(csv_file)
        
    print("Loading dataset...")
    df = pd.read_csv(csv_file)
    
    print("Extracting advanced features...")
    features_list = []
    labels = []
    
    for _, row in df.iterrows():
        try:
            feats = extract_advanced_features(row['url'])
            # Drop the string list feature before ML training
            if 'matched_suspicious_words' in feats:
                del feats['matched_suspicious_words']
            if 'typo_brand' in feats:
                del feats['typo_brand']
            features_list.append(feats)
            labels.append(row['label'])
        except Exception as e:
            pass # Skip malformed row
            
    X = pd.DataFrame(features_list)
    y = pd.Series(labels)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Advanced Random Forest Classifier...")
    # Train model that can handle probability well
    model = RandomForestClassifier(n_estimators=150, max_depth=15, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model trained with accuracy: {accuracy * 100:.2f}%")
    
    print("Saving advanced model to advanced_model.pkl...")
    joblib.dump(model, 'advanced_model.pkl')
    print("Done!")
