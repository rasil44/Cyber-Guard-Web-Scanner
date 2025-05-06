import streamlit as st
import requests

st.set_page_config(page_title="Cyber Guard Web Scanner", layout="centered")

st.title("🛡️ Cyber Guard Web Scanner")
st.markdown("### Scan your website for common vulnerabilities")

target_url = st.text_input("Enter the URL to scan (e.g., https://example.com)")

if st.button("Start Scan"):
    if not target_url:
        st.warning("Please enter a valid URL.")
    else:
        st.info(f"Scanning {target_url} ...")
        try:
            response = requests.get(target_url)
            headers = response.headers
            server = headers.get('Server', 'Unknown')
            powered_by = headers.get('X-Powered-By', 'Unknown')

            st.success("Scan Completed!")
            st.write("### Server Information:")
            st.write(f"- **Server:** {server}")
            st.write(f"- **X-Powered-By:** {powered_by}")

            st.write("### Security Checks:")
            if "X-Frame-Options" not in headers:
                st.error("❌ X-Frame-Options header is missing!")
            else:
                st.success("✅ X-Frame-Options header is present.")

            if "Content-Security-Policy" not in headers:
                st.error("❌ Content-Security-Policy header is missing!")
            else:
                st.success("✅ Content-Security-Policy header is present.")

            if "Strict-Transport-Security" not in headers:
                st.error("❌ Strict-Transport-Security header is missing!")
            else:
                st.success("✅ Strict-Transport-Security header is present.")

        except Exception as e:
            st.error(f"An error occurred: {e}")