# URL Safety Classifier (Machine Learning Model)

A lightweight and fast URL safety classifier built with Random Forest in Python. This tool predicts whether a URL is malicious or safe using engineered features — no external API dependency required for basic functionality

---

## Features

-Machine Learning Model: Pre-trained Random Forest using scikit-learn

-Feature Extraction: Extracts multiple URL characteristics for prediction

-Fast & Lightweight: Minimal dependencies, instant predictions

-Modular Structure: Easy to integrate into other Python or web apps

-Optional External APIs: Integrate Google Safe Browsing & VirusTotal for extended checks







## Live Demo

https://drdolinksaftycheck.onrender.com/

⚠️ First load may take 30–50 seconds because free Render servers go to sleep when inactive.



## ⚙️ Environment Variables

To run this project, you can (optionally) define the following environment variables in a `.env` file.

> Missing values will disable some features or use defaults.

| Variable Name   | Description                                      | Required | Default         |
|----------------|--------------------------------------------------|----------|-----------------|
| `APIKEY`        | Google API Key — used for extended URL analysis | NO       | `None`          |
| `VT_API_KEY`    | VirusTotal API Key — used for extended URL analysis      | NO     | `None`          |
| `HOST`          | Host for the Flask server                       | NO      | `localhost`       |
| `PORT`          | Port for the Flask server                       | NO     | `5000`          |
| `BACKEND_URL`   | Fully-qualified URL used by frontend to connect | NO       | Auto-generated  |
| `DEBUG`         | Enables Flask debug mode (`True`/`False`)       | NO       | `True`          |

📌 **Tip:**  
If you are deploying on platforms like Render, define these environment variables in their dashboard under **Environment > Environment Variables**.

📁 **Example `.env` file:**
```dotenv
APIKEY=your_google_api_key
VT_API_KEY=your_virustotal_api_key
HOST=0.0.0.0
PORT=5000
DEBUG=False
BACKEND_URL=https://yourbackend.onrender.com
```


