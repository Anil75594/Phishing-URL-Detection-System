import re
import math
import tldextract
import Levenshtein
from urllib.parse import urlparse

# List of common popular domains to check against for typosquatting
TOP_DOMAINS = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 
    'paypal', 'netflix', 'linkedin', 'twitter', 'instagram',
    'bankofamerica', 'chase', 'wellsfargo', 'github'
]

# Common URL shorteners
SHORTENERS = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 
    'yfrog.com', 'migre.me', 'ff.im', 'ow.ly', 'ptz.ba'
]

def get_shannon_entropy(string):
    """Calculates the Shannon entropy of a string."""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def check_typosquatting(domain_name):
    """
    Check if the domain is a typosquatted version of top domains.
    Handles repeated characters (e.g., faceboooook -> facebook) and Levenshtein distance.
    Returns (1, matched_brand) if typosquatting detected, else (0, None)
    """
    # Remove consecutive duplicate characters (e.g., faceboooook -> facebok, google -> gogle)
    collapsed_domain = re.sub(r'(.)\1+', r'\1', domain_name.lower())
    
    min_distance = float('inf')
    closest_brand = None
    
    for top_brand in TOP_DOMAINS:
        # Don't flag exact matches (it's the real brand)
        if domain_name.lower() == top_brand:
            return 0, None
            
        # Check against raw domain (e.g., facebok vs facebook -> dist 1)
        dist_raw = Levenshtein.distance(domain_name.lower(), top_brand)
        
        # Check against collapsed domain (e.g., faceboooook -> facebok vs facebook -> facebok -> dist 0)
        collapsed_brand = re.sub(r'(.)\1+', r'\1', top_brand)
        dist_collapsed = Levenshtein.distance(collapsed_domain, collapsed_brand)
        
        # Take the best (lowest) distance
        best_dist = min(dist_raw, dist_collapsed)
        
        if best_dist < min_distance:
            min_distance = best_dist
            closest_brand = top_brand
            
    # Return 1 if it's within 2 edit distance of a major brand
    if 0 <= min_distance <= 2:
        return 1, closest_brand
        
    return 0, None

def extract_advanced_features(url):
    """
    Extracts advanced cybersecurity features from a given URL.
    Returns a dictionary of feature names and numeric values.
    """
    features = {}
    
    # Basic Lexical Features
    features['length'] = len(url)
    features['has_at'] = 1 if '@' in url else 0
    features['has_dash'] = 1 if '-' in url else 0
    features['has_underscore'] = 1 if '_' in url else 0
    features['num_dots'] = url.count('.')
    
    # Parse URL
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
    except Exception:
        domain = ""
        
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"
    
    # IP Address as domain
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
    
    # Suspicious Subdomains (High number of subdomains is suspicious)
    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    features['num_subdomains'] = len(subdomains)
    features['is_suspicious_subdomain'] = 1 if len(subdomains) >= 3 else 0
    
    # URL Shortener detection
    features['is_shortener'] = 1 if registered_domain in SHORTENERS else 0
    
    # Typosquatting
    is_typo, matched_brand = check_typosquatting(ext.domain)
    features['is_typosquatting'] = is_typo
    features['typo_brand'] = matched_brand # Retained for UI

    
    # Entropy (High entropy often indicates randomness used in phishing links)
    features['entropy'] = get_shannon_entropy(url)
    features['high_entropy'] = 1 if features['entropy'] > 4.5 else 0
    
    # Suspicious Keywords in URL
    suspicious_keywords = [
        'login', 'verify', 'account', 'update', 'secure', 'bank', 'confirm',
        'free', 'gift', 'password', 'credential', 'auth', 'signin'
    ]
    matched_words = [word for word in suspicious_keywords if word in url.lower()]
    features['suspicious_words_count'] = len(matched_words)
    features['matched_suspicious_words'] = matched_words # Retained for UI, dropped before model
    
    # Non-ASCII (Homograph)
    features['has_non_ascii'] = 1 if any(ord(char) > 127 for char in url) else 0
    
    # Protocol validation
    features['is_https'] = 1 if url.startswith('https://') else 0
    
    return features

def get_detection_reasons(features):
    """Generates human-readable reasons for flagged features."""
    reasons = []
    
    if features.get('has_ip') == 1:
        reasons.append({"type": "critical", "msg": "IP address used instead of a domain name."})
    if features.get('is_typosquatting') == 1:
        brand = features.get('typo_brand', 'a popular brand')
        reasons.append({"type": "critical", "msg": f"Possible typosquatting detected: domain resembles '{brand}'."})
    if features.get('has_non_ascii') == 1:
        reasons.append({"type": "critical", "msg": "Homograph attack: Non-ASCII/unusual characters detected."})
    if features.get('suspicious_words_count', 0) > 0:
        words = ", ".join(features.get('matched_suspicious_words', []))
        reasons.append({"type": "warning", "msg": f"Suspicious keywords found: {words}"})
    if features.get('is_shortener') == 1:
        reasons.append({"type": "warning", "msg": "URL shortening service used to hide destination."})
    if features.get('is_suspicious_subdomain') == 1:
        reasons.append({"type": "warning", "msg": f"Excessive subdomains ({features.get('num_subdomains')} detected)."})
    if features.get('high_entropy') == 1:
        reasons.append({"type": "warning", "msg": f"High URL randomness (entropy: {features.get('entropy'):.2f})."})
    if features.get('length') > 75:
        reasons.append({"type": "info", "msg": "Unusually long URL length."})
    if features.get('is_https') == 0:
        reasons.append({"type": "info", "msg": "Connection is not secure (HTTP instead of HTTPS)."})
        
    return reasons
