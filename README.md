# Cyber Guard Web Scanner

Cyber Guard Web Scanner is a simple tool built with Streamlit to scan websites for basic HTTP header security issues.

## Features
- Check for presence of key security headers like:
  - X-Frame-Options
  - Content-Security-Policy
  - Strict-Transport-Security
- Identify server and platform information via headers
- User-friendly web interface using Streamlit

## How to Run

1. Clone the repo:
```
git clone https://github.com/rasil44/Cyber-Guard-Web-Scanner.git
cd Cyber-Guard-Web-Scanner
```

2. Install requirements:
```
pip install -r requirements.txt
```

3. Run the app:
```
streamlit run main.py
```

## Demo
You can also deploy and run this on [Replit](https://replit.com/) or [Streamlit Cloud](https://streamlit.io/cloud).