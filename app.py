import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from database import init_db, verify_login, save_alerts, get_alerts
from detector import train_model, analyze, FEATURES
from reporting import create_pdf_report

st.set_page_config(page_title="CyberShield AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { background: #071426; color: #eaf2ff; }
[data-testid="stSidebar"] { background: #10233d; }
h1, h2, h3 { color: #65c8ff !important; }
div[data-testid="stMetric"] {
  background: #10233d; border: 1px solid #1d4770;
  padding: 16px; border-radius: 12px;
}
.stButton button, .stDownloadButton button {
  background: #087eb5; color: white; border: 0; border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

init_db()
DATA_PATH = Path(__file__).parent / "data" / "network_activity.csv"

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "results" not in st.session_state:
    st.session_state.results = None

def login_screen():
    st.title("🛡️ CyberShield AI")
    st.subheader("Intelligent Cyber Threat Detection & Security Monitoring")
    st.info("Educational demonstration app. Use only sample or authorized datasets.")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        if verify_login(username, password):
            st.session_state.logged_in = True
            st.rerun()
        else:
            st.error("Incorrect username or password.")
    st.caption("Demo login: admin / ChangeMe123! — change this before any real deployment.")

def dashboard():
    st.sidebar.title("🛡️ CyberShield AI")
    page = st.sidebar.radio("Navigation", ["Dashboard", "Analyze Data", "Alert History", "About"])
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.results = None
        st.rerun()

    st.title("Cybersecurity Monitoring Dashboard")
    st.caption("Analyze sample network activity and review potential anomalies.")

    if page == "Dashboard":
        results = st.session_state.results
        if results is None:
            st.info("No analysis yet. Open **Analyze Data** to run the sample dataset or upload a CSV.")
            return
        total = len(results)
        suspicious = int((results["classification"] == "Suspicious").sum())
        normal = total - suspicious
        c1, c2, c3 = st.columns(3)
        c1.metric("Records Analyzed", total)
        c2.metric("Normal", normal)
        c3.metric("Suspicious", suspicious)
        left, right = st.columns(2)
        with left:
            counts = results["classification"].value_counts().reset_index()
            counts.columns = ["Classification", "Count"]
            st.plotly_chart(px.pie(counts, names="Classification", values="Count",
                                   title="Activity Classification", hole=.45), use_container_width=True)
        with right:
            risk = results["risk_level"].value_counts().reset_index()
            risk.columns = ["Risk Level", "Count"]
            st.plotly_chart(px.bar(risk, x="Risk Level", y="Count",
                                   title="Risk Level Summary"), use_container_width=True)
        st.subheader("Latest analysis results")
        st.dataframe(results, use_container_width=True, hide_index=True)
        pdf_data = create_pdf_report(results)
        st.download_button(
            "⬇️ Download PDF Security Report",
            data=pdf_data,
            file_name="cybershield_security_report.pdf",
            mime="application/pdf"
        )

    elif page == "Analyze Data":
        st.subheader("Analyze Network Activity")
        st.write("Upload a CSV with these columns: " + ", ".join(FEATURES))
        st.caption("Optional columns: source and label. The training data is the included sample dataset.")
        uploaded = st.file_uploader("Upload activity CSV", type=["csv"])
        use_sample = st.button("Analyze included sample dataset")
        if use_sample:
            input_df = pd.read_csv(DATA_PATH)
            run_analysis(input_df)
        if uploaded is not None and st.button("Analyze uploaded CSV"):
            try:
                input_df = pd.read_csv(uploaded)
                run_analysis(input_df)
            except Exception as e:
                st.error(f"Could not analyze this file: {e}")

    elif page == "Alert History":
        st.subheader("Saved Suspicious Activity Alerts")
        rows = get_alerts()
        if rows:
            st.dataframe(pd.DataFrame(rows, columns=[
                "Detected At", "Source", "Risk Level", "Anomaly Score", "Reason"
            ]), use_container_width=True, hide_index=True)
        else:
            st.info("No saved alerts yet. Run an analysis first.")

    elif page == "About":
        st.subheader("About this project")
        st.write("""
        CyberShield AI is an educational, defensive project. It uses an
        Isolation Forest machine-learning model to flag records that differ
        from the normal sample activity profile. It is a learning prototype,
        not a production intrusion detection system. Model results can include
        false positives and false negatives.
        """)
        st.write("Required CSV features:")
        st.code(", ".join(FEATURES))

def run_analysis(input_df):
    try:
        training_df = pd.read_csv(DATA_PATH)
        model = train_model(training_df)
        results = analyze(model, input_df)
        if "source" not in results.columns:
            results["source"] = "uploaded-record"
        st.session_state.results = results
        save_alerts(results)
        st.success(f"Analysis complete: {len(results)} records checked.")
        st.rerun()
    except Exception as e:
        st.error(f"Analysis error: {e}")

if not st.session_state.logged_in:
    login_screen()
else:
    dashboard()
