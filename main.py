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
    .stTab {
        background-color: #f8e6f9;
        color: #6200ea;
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

# Tabs for navigation
tab1, tab2 = st.tabs(["🕵️ فحص الثغرات", "📄 نتائج الفحص"])

with tab1:
    st.header("🛡️ فحص الثغرات")
    st.write("حدد أنواع الثغرات التي ترغب في فحصها واضغط على الزر لبدء الفحص.")
    
    # URL input and vulnerability selection
    url = st.text_input("🌐 أدخل عنوان الموقع الإلكتروني", placeholder="https://example.com")
    selected_vulns = st.multiselect("🧪 اختر الثغرات للفحص", list(vulns.keys()), default=list(vulns.keys()))
    
    # Start Scan button
    start_scan = st.button("🚀 ابدأ الفحص")
    
with tab2:
    st.header("📄 تقرير النتائج")
    st.write("هنا ستظهر نتائج الفحص...")

    # Show loading spinner during scan
    if start_scan:
        if not validate_url(url):
            st.error("❌ URL غير صالح. يرجى إدخال عنوان موقع صحيح.")
        else:
            st.info(f"🔍 جاري فحص {url} ...")
            
            # Add loading spinner
            with st.spinner("جارٍ الفحص..."):
                results = []

                # SSL/TLS Check
                if "SSL/TLS Check" in selected_vulns:
                    if url.startswith("https://"):
                        results.append(("SSL/TLS Check", "✅ آمن: يستخدم HTTPS"))
                    else:
                        results.append(("SSL/TLS Check", "❌ غير آمن: لا يستخدم HTTPS"))

                # HTTP Methods Check
                if "HTTP Methods Check" in selected_vulns:
                    try:
                        res = requests.options(url, timeout=5)
                        allow = res.headers.get("Allow", "")
                        risky = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
                        if risky:
                            results.append(("HTTP Methods Check", f"❌ طرق خطيرة مفعلة: {', '.join(risky)}"))
                        else:
                            results.append(("HTTP Methods Check", "✅ آمن: لا توجد طرق HTTP خطيرة"))
                    except Exception as e:
                        results.append(("HTTP Methods Check", f"⚠️ خطأ في التحقق: {e}"))

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
                            results.append(("Security Headers", f"❌ رؤوس مفقودة: {', '.join(missing)}"))
                        else:
                            results.append(("Security Headers", "✅ جميع رؤوس الأمان موجودة"))
                    except Exception as e:
                        results.append(("Security Headers", f"⚠️ خطأ في التحقق: {e}"))

                # Display results
                st.markdown("### 🧾 نتائج الفحص")
                for name, result in results:
                    if "✅" in result:
                        st.success(f"{name}: {result}")
                    elif "❌" in result:
                        st.error(f"{name}: {result}")
                    else:
                        st.warning(f"{name}: {result}")

                # Add download button for results
                formatted_results = "\n".join([f"{name}: {result}" for name, result in results])
                st.download_button("تحميل النتائج", data=formatted_results, file_name="scan_results.txt")
