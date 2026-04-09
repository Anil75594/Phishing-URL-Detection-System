from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import os
from features import extract_advanced_features, get_detection_reasons

app = Flask(__name__)

# Load Model
MODEL_PATH = 'advanced_model.pkl'
model = None

def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)

@app.before_request
def initialize():
    if model is None:
        load_model()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model not trained yet. Run train_model.py first.'}), 500
        
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
        
    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400
        
    try:
        # Extract features
        features = extract_advanced_features(url)
        reasons = get_detection_reasons(features)
        
        # Prepare for ML prediction (remove string lists)
        features_for_model = features.copy()
        if 'matched_suspicious_words' in features_for_model:
            del features_for_model['matched_suspicious_words']
        if 'typo_brand' in features_for_model:
            del features_for_model['typo_brand']
            
        df_features = pd.DataFrame([features_for_model])
        
        # Force column order to match model expectations if needed, but DF natively maps
        
        # Predict Probability
        # predict_proba returns [[prob_legit, prob_phish]]
        probabilities = model.predict_proba(df_features)[0]
        phish_prob = round(probabilities[1] * 100, 2)
        
        is_safe = True
        status_text = "Legitimate"
        
        if phish_prob > 60:
            is_safe = False
            status_text = "Phishing Detected"
        elif phish_prob > 35:
            status_text = "Suspicious"
            is_safe = False
            
        return jsonify({
            'url': url,
            'risk_score': phish_prob,
            'is_safe': is_safe,
            'status': status_text,
            'features': features,
            'reasons': reasons
        })
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
