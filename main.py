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

# Vulnerability selection
vulns = {
    "SQL Injection": "' OR '1'='1",
    "Cross-Site Scripting (XSS)": "<script>alert('xss')</script>",
    "Directory Traversal": "../../../../etc/passwd",
    "SSL/TLS Check": None,
    "HTTP Methods Check": None,
    "Security Headers": None
}

# Function to validate URL
def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc

# Tabs for navigation
tab1, tab2 = st.tabs(["🕵️ Vulnerability Scan", "📄 Scan Results"])

with tab1:
    st.header("🛡️ Vulnerability Scan")
    st.write("Select the vulnerabilities you want to test and press the button to start the scan.")
    
    # URL input and vulnerability selection only in the first tab
    url = st.text_input("🌐 Enter Website URL", placeholder="https://example.com")
    selected_vulns = st.multiselect("🧪 Select vulnerabilities to test", list(vulns.keys()), default=list(vulns.keys()))

    # Start Scan button
    start_scan = st.button("🚀 Start Scan")
    
with tab2:
    st.header("📄 Scan Results")
    st.write("The results of your scan will appear here...")

    # Show loading spinner during scan
    if start_scan:
        if not validate_url(url):
            st.error("❌ Invalid URL. Please enter a valid website address.")
        else:
            st.info(f"🔍 Scanning {url} ...")
            
            # Add loading spinner
            with st.spinner("Scanning..."):
                results = []

                # SSL/TLS Check
                if "SSL/TLS Check" in selected_vulns:
                    if url.startswith("https://"):
                        results.append(("SSL/TLS Check", "✅ Secure: Using HTTPS"))
                    else:
                        results.append(("SSL/TLS Check", "❌ Insecure: Not using HTTPS"))

                # HTTP Methods Check
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

                # Security Headers Check
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

                # Display results
                st.markdown("### 🧾 Scan Results")
                for name, result in results:
                    if "✅" in result:
                        st.success(f"{name}: {result}")
                    elif "❌" in result:
                        st.error(f"{name}: {result}")
                    else:
                        st.warning(f"{name}: {result}")

                # Add download button for results
                formatted_results = "\n".join([f"{name}: {result}" for name, result in results])
                st.download_button("Download Results", data=formatted_results, file_name="scan_results.txt")
