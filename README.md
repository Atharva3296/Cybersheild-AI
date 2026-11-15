# CyberShield AI
**Intelligent Cyber Threat Detection and Security Monitoring System**

An intermediate-level BCA mini project built with Python, Streamlit, Pandas,
Scikit-learn, Plotly, SQLite and ReportLab.

## Features
- Demo admin login
- Dashboard with activity and risk charts
- CSV upload and analysis
- Isolation Forest anomaly detection
- Low / Medium / High risk labels
- SQLite alert history
- PDF security report generation

## Setup (Windows)
1. Install Python 3.10 or newer.
2. Extract the project ZIP.
3. Open Command Prompt in the `CyberShield_AI` folder.
4. Run:

   ```bash
   python -m venv venv
   venv\\Scripts\\activate
   pip install -r requirements.txt
   python generate_sample_data.py
   streamlit run app.py
   ```

5. Open the local address shown by Streamlit in your browser.

## Demo login
- Username: `admin`
- Password: `ChangeMe123!`

This is a classroom demo account. Change it before any real deployment.
Do not use this prototype to protect real systems.

## CSV format
Required numeric columns:
- duration
- src_bytes
- dst_bytes
- failed_logins
- connection_count
- unusual_port_flag

Optional columns:
- source
- label

`unusual_port_flag` should be 0 or 1. The included CSV is synthetic sample data.
The app trains its model on rows labeled `Normal` and analyzes the selected CSV.

## PDF report
A PDF security report can be downloaded directly from the Dashboard after analysis.

## Important limitations
- This is an educational prototype using synthetic data.
- Anomaly detection does not prove an attack occurred.
- False positives and false negatives are possible.
- Only analyze data you own or are authorized to use.
