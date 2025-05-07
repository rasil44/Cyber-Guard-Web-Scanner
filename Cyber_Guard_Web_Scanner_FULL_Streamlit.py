import streamlit as st
import requests
from urllib.parse import urlparse

st.set_page_config(page_title="Cyber Guard Web Scanner", layout="wide")
st.title("🛡️ Cyber Guard Web Scanner")
st.markdown("Scan your website for common vulnerabilities like **SQL Injection**, **XSS**, and **more**.")

# Styling
st.markdown("""
    <style>
    .stButton>button {
        background-color: #ff66cc;
        color: white;
        font-weight: bold;
        padding: 10px 20px;
        border-radius: 10px;
        border: none;
    }
    .stButton>button:hover {
        background-color: #e040fb;
        color: black;
    }
    </style>
""", unsafe_allow_html=True)

# URL input
url = st.text_input("🌐 Enter Website URL", placeholder="https://example.com")

# Vulnerability selection
vulns = {
    "SQL Injection": "' OR '1'='1",
    "Cross-Site Scripting (XSS)": "<script>alert('xss')</script>",
    "Directory Traversal": "../../../../etc/passwd",
    "SSL/TLS Check": None,
    "HTTP Methods Check": None,
    "Security Headers": None
}

selected_vulns = st.multiselect("🧪 Select vulnerabilities to test", list(vulns.keys()), default=list(vulns.keys()))

# Function to validate URL
def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc

# Begin scan
if st.button("🚀 Start Scan"):
    if not validate_url(url):
        st.error("❌ Invalid URL. Please enter a valid website address.")
    else:
        st.info(f"🔍 Scanning {url} ...")
        try:
            results = []

            # Test: SSL/TLS
            if "SSL/TLS Check" in selected_vulns:
                if url.startswith("https://"):
                    results.append(("SSL/TLS Check", "✅ Secure: Using HTTPS"))
                else:
                    results.append(("SSL/TLS Check", "❌ Insecure: Not using HTTPS"))

            # Test: HTTP Methods
            if "HTTP Methods Check" in selected_vulns:
                try:
                    res = requests.options(url, timeout=5)
                    allow = res.headers.get("Allow", "")
                    risky = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
                    if risky:
                        results.append(("HTTP Methods Check", f"❌ Risky methods enabled: {', '.join(risky)}"))
                    else:
                        results.append(("HTTP Methods Check", "✅ Safe: No risky HTTP methods"))
                except Exception as e:
                    results.append(("HTTP Methods Check", f"⚠️ Error checking methods: {e}"))

            # Test: Security Headers
            if "Security Headers" in selected_vulns:
                try:
                    res = requests.get(url, timeout=5)
                    headers = res.headers
                    missing = []
                    for header in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
                        if header not in headers:
                            missing.append(header)
                    if missing:
                        results.append(("Security Headers", f"❌ Missing headers: {', '.join(missing)}"))
                    else:
                        results.append(("Security Headers", "✅ All recommended security headers are present"))
                except Exception as e:
                    results.append(("Security Headers", f"⚠️ Error checking headers: {e}"))

            # Test: Injection-based vulnerabilities
            def generic_test(payload, param="test", indicators=[]):
                try:
                    sep = "&" if "?" in url else "/?"
                    full_url = f"{url}{sep}{param}={payload}"
                    r = requests.get(full_url, timeout=5)
                    text = r.text.lower()
                    return any(ind.lower() in text for ind in indicators)
                except:
                    return False

            if "SQL Injection" in selected_vulns:
                indicators = ["sql syntax", "mysql", "syntax error"]
                if generic_test(vulns["SQL Injection"], param="id", indicators=indicators):
                    results.append(("SQL Injection", "❌ Vulnerable to SQL Injection"))
                else:
                    results.append(("SQL Injection", "✅ Not vulnerable to SQL Injection"))

            if "Cross-Site Scripting (XSS)" in selected_vulns:
                if generic_test(vulns["Cross-Site Scripting (XSS)"], param="q", indicators=["<script>alert('xss')"]):
                    results.append(("XSS", "❌ Vulnerable to XSS"))
                else:
                    results.append(("XSS", "✅ Not vulnerable to XSS"))

            if "Directory Traversal" in selected_vulns:
                if generic_test(vulns["Directory Traversal"], param="file", indicators=["root:x:"]):
                    results.append(("Directory Traversal", "❌ Vulnerable to Directory Traversal"))
                else:
                    results.append(("Directory Traversal", "✅ Not vulnerable to Directory Traversal"))

            # Display results
            st.markdown("### 🧾 Scan Results")
            for name, result in results:
                if "✅" in result:
                    st.success(f"{name}: {result}")
                elif "❌" in result:
                    st.error(f"{name}: {result}")
                else:
                    st.warning(f"{name}: {result}")

        except Exception as e:
            st.error(f"🚫 An error occurred during scanning: {e}")