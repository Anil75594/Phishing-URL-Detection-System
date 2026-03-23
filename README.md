# Phishing URL Detection System

An ML-based web application that detects phishing URLs using feature extraction and a trained machine learning model. The system analyzes URLs and classifies them as **Legitimate**, **Suspicious**, or **Phishing**, along with risk scores and insights.

---

## Features

* URL analysis using feature extraction
* Machine Learning-based prediction
* Risk score generation
* Classification: Legitimate / Suspicious / Phishing
* Simple and interactive web interface (Flask)

---

## Tech Stack

* **Backend:** Python, Flask
* **Machine Learning:** Scikit-learn / Pickle model
* **Frontend:** HTML, CSS
* **Dataset:** CSV-based phishing URL dataset

---

## Project Structure

```
Phishing-URL-Detection-System/
│── app.py
│── features.py
│── train_model.py
│── requirements.txt
│── templates/
│   └── index.html
│── static/
│   └── style.css
│── *.pkl (trained models)
│── *.csv (datasets)
```

---

## Installation & Setup

1. Clone the repository:

```
git clone https://github.com/Anil75594/Phishing-URL-Detection-System/
cd Phishing-URL-Detection-System
```

2. Install dependencies:

```
pip install -r requirements.txt
```

3. Run the application:

```
python app.py
```

4. Open in browser:

```
http://127.0.0.1:5000/
```

---

## How It Works

1. User enters a URL
2. System extracts important features
3. ML model predicts phishing probability
4. Output shows:

   * Risk score
   * Classification
   * Security insights

---

## 👨🏻‍💻 Author

**Anil Kumar Sah**
GitHub: https://github.com/Anil75594

---

## If you found this useful, consider giving it a star!
