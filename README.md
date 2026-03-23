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


Output:

<img width="1470" height="706" alt="1" src="https://github.com/user-attachments/assets/42a83c26-fecd-4d3e-8776-482f40ac92bd" />

<img width="1470" height="726" alt="2" src="https://github.com/user-attachments/assets/875ba1aa-8259-4403-8a47-406877661315" />

<img width="1470" height="722" alt="3" src="https://github.com/user-attachments/assets/c26b774b-c1d1-4f14-981a-008bb0615cc2" />

<img width="1470" height="720" alt="4" src="https://github.com/user-attachments/assets/593ed196-9ce6-4c19-b9d3-15cccfc6b705" />

<img width="1465" height="713" alt="5" src="https://github.com/user-attachments/assets/8a2c93c9-365b-4c54-a7de-f6fcc4642f1f" />


