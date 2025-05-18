import streamlit as st
import openai
import re
from datetime import datetime
import base64

# Streamlit page settings
st.set_page_config(page_title="VeriIntel 🧠", layout="wide")
st.sidebar.title("🧭 VeriIntel Tools")
tool = st.sidebar.radio("Select a tool:", ["📡 IP Analyzer", "📧 Email Analyzer", "📊 Dashboard"])

# Optional OpenAI Key
openai_api_key = st.sidebar.text_input("🔑 OpenAI API Key", type="password")

# GPT Analyzer
def analyze_with_gpt(prompt):
    if not openai_api_key:
        return "⚠️ Please provide OpenAI API Key."
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            api_key=openai_api_key,
            messages=[
                {"role": "system", "content": "You are a cybersecurity email threat analyst."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ Error: {str(e)}"

# Basic header field extraction
def parse_email_header(header_text):
    fields = {
        "From": re.search(r"From: (.*)", header_text),
        "To": re.search(r"To: (.*)", header_text),
        "Subject": re.search(r"Subject: (.*)", header_text),
        "SPF": re.search(r"spf=(\w+)", header_text),
        "DKIM": re.search(r"dkim=(\w+)", header_text),
        "DMARC": re.search(r"dmarc=(\w+)", header_text),
        "Received": re.findall(r"Received:.*", header_text)
    }
    return {k: (v.group(1) if v else "Not Found") for k, v in fields.items() if k != "Received"} | {"Received": fields["Received"]}

# Verdict badge
def verdict_badge(text):
    text = text.lower()
    if "phishing" in text:
        return "❌ Verdict: Phishing"
    elif "suspicious" in text:
        return "⚠️ Verdict: Suspicious"
    elif "safe" in text:
        return "✅ Verdict: Safe"
    return "🟡 Verdict: Unclear"

# Downloadable report
def generate_download_link(text, filename="veriintel_report.txt"):
    b64 = base64.b64encode(text.encode()).decode()
    return f'<a href="data:file/txt;base64,{b64}" download="{filename}">📥 Download Report</a>'

# Main App Views
st.title("🔍 VeriIntel - AI-Powered Threat Analysis")

if tool == "📡 IP Analyzer":
    ip_input = st.text_input("Enter IP Address:")
    if st.button("Analyze IP"):
        if ip_input:
            ai_prompt = f"Analyze the IP address: {ip_input}. Check for abuse, threat level, reputation, ASN usage, and known malicious activity."
            result = analyze_with_gpt(ai_prompt)
            st.subheader("🧠 AI Assessment")
            st.write(result)
        else:
            st.warning("Please enter a valid IP address.")

elif tool == "📧 Email Analyzer":
    st.subheader("📧 Email Header Analyzer")

    input_mode = st.radio("Input Method:", ["📤 Upload .eml/.txt", "📝 Paste Header"])
    header_text = ""

    if input_mode == "📤 Upload .eml/.txt":
        file = st.file_uploader("Upload Email Header File", type=["eml", "txt"])
        if file:
            header_text = file.read().decode(errors="ignore")
            st.text_area("📄 Raw Header", header_text, height=300)

    elif input_mode == "📝 Paste Header":
        header_text = st.text_area("📄 Paste Email Header", height=300)

    if st.button("Analyze Header with AI"):
        if header_text.strip():
            st.subheader("🧾 Parsed Header Fields")
            parsed = parse_email_header(header_text)
            for key, value in parsed.items():
                if key == "Received":
                    st.markdown("🛰️ Received Path:")
                    for hop in value:
                        st.code(hop)
                else:
                    st.write(f"🔹 {key}: {value}")

            ai_prompt = f"""
You are a cybersecurity analyst. Analyze the following email header for spoofing, phishing, or malicious behavior. Comment on SPF, DKIM, Received path anomalies, forged addresses, and verdict (Safe, Suspicious, Phishing):

{header_text}
"""
            analysis = analyze_with_gpt(ai_prompt)
            st.subheader("🧠 AI Analysis")
            st.write(analysis)

            verdict = verdict_badge(analysis)
            st.subheader(verdict)

            with st.expander("📥 Export Result"):
                download_link = generate_download_link(f"{header_text}\n\n---\n\nAI Analysis:\n{analysis}", filename="email_analysis_report.txt")
                st.markdown(download_link, unsafe_allow_html=True)
        else:
            st.warning("Please upload or paste an email header.")

elif tool == "📊 Dashboard":
    st.markdown("🚧 Coming Soon: Visual dashboards of submissions, trends, and verdict stats.")

# Footer
st.markdown("---")
st.markdown("Built by VeriIntel · v0.2")
