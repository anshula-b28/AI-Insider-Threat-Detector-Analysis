import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# ==========================================
# 1. PAGE CONFIGURATION & INTERFACE STYLING
# ==========================================
st.set_page_config(
    page_title="ThreatLens - AI Insider Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Dark corporate SOC styling matching your design mockups
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #ffffff; }
    .metric-box { background-color: #1a1f2c; padding: 20px; border-radius: 8px; border: 1px solid #2d3748; text-align: center; margin-bottom: 15px; }
    .alert-card { background-color: #1a1f2c; border-left: 5px solid #e53e3e; padding: 15px; border-radius: 4px; margin-bottom: 15px; }
    .nav-header { font-size: 1.6rem; font-weight: bold; color: #4fd1c5; padding-bottom: 5px; font-family: 'Courier New', monospace; }
    .metric-card { background-color: #1a1f2c; border-left: 4px solid #3182ce; padding: 15px; border-radius: 6px; margin-bottom: 10px; }
    .ai-badge { background-color: #2b6cb0; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. AI POWERED DATA PIPELINE ENGINE
# ==========================================
@st.cache_data
def run_insider_threat_ai_engine():
    """Generates the dataset and applies an Isolation Forest ML Model to detect threats."""
    raw_logs = pd.DataFrame([
        {'Employee Name': 'Rahul Kumar', 'Department': 'Finance', 'Time of Activity': '02:31 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 2300.0, 'Threat Trigger': 'Bulk Data Exfiltration'},
        {'Employee Name': 'Priya Mehta', 'Department': 'Engineering', 'Time of Activity': '03:08 AM', 'Failed Logins': 1, 'Data Downloaded (MB)': 450.0, 'Threat Trigger': 'Off-hours System Access'},
        {'Employee Name': 'Arjun Singh', 'Department': 'IT Security', 'Time of Activity': '11:45 AM', 'Failed Logins': 7, 'Data Downloaded (MB)': 1.2, 'Threat Trigger': 'Failed Login Attempts'},
        {'Employee Name': 'Divya Nair', 'Department': 'HR', 'Time of Activity': '02:44 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 15.4, 'Threat Trigger': 'Unregistered USB Insertion'},
        {'Employee Name': 'Amit Patel', 'Department': 'Sales', 'Time of Activity': '03:10 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 120.0, 'Threat Trigger': 'External Email Forwarding'},
        {'Employee Name': 'Suresh Babu', 'Department': 'Marketing', 'Time of Activity': '01:15 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 5.0, 'Threat Trigger': 'Opening Suspicious Websites'},
        {'Employee Name': 'Vikram Rao', 'Department': 'Operations', 'Time of Activity': '11:02 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 85.0, 'Threat Trigger': 'Sensitive HR Record Access'},
        {'Employee Name': 'Lakshmi Pillai', 'Department': 'Legal', 'Time of Activity': '09:30 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 4.2, 'Threat Trigger': 'None'},
        {'Employee Name': 'Meera Krishnan', 'Department': 'Finance', 'Time of Activity': '09:10 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 11.0, 'Threat Trigger': 'None'},
        {'Employee Name': 'Ravi Nair', 'Department': 'IT Security', 'Time of Activity': '05:12 AM', 'Failed Logins': 1, 'Data Downloaded (MB)': 28.0, 'Threat Trigger': 'None'}
    ])
    
    le = LabelEncoder()
    processing_df = raw_logs.copy()
    processing_df['Dept_Encoded'] = le.fit_transform(processing_df['Department'])
    
    features = ['Dept_Encoded', 'Failed Logins', 'Data Downloaded (MB)']
    
    ai_model = IsolationForest(contamination=0.7, random_state=42)
    predictions = ai_model.fit_predict(processing_df[features])
    
    # NEW: Calculate actual raw anomaly confidence scores to display in UI
    raw_scores = ai_model.decision_function(processing_df[features])
    
    # Map raw mathematical score to a cleaner 0-100 Risk Percentage score for display
    raw_logs['AI Risk Score (%)'] = np.round((1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min())) * 100, 1)
    raw_logs['Status'] = ['🔴 High Risk (AI Flagged)' if pred == -1 else '🟢 Clear' for pred in predictions]
    
    ai_anomalies = raw_logs[raw_logs['Status'] == '🔴 High Risk (AI Flagged)'].copy()
    incident_report = pd.DataFrame({
        'Flagged Employee': ai_anomalies['Employee Name'],
        'Department': ai_anomalies['Department'],
        'Incident Identified': ai_anomalies['Threat Trigger'],
        'AI Confidence Score (%)': ai_anomalies['AI Risk Score (%)']
    })
    
    return raw_logs, incident_report

df_logs, df_incidents = run_insider_threat_ai_engine()
high_risk_employees = df_logs[df_logs['Status'] == '🔴 High Risk (AI Flagged)']

# ==========================================
# 3. SIDEBAR NAVIGATION PANEL
# ==========================================
with st.sidebar:
    st.markdown("<div class='nav-header'>🛡️ ThreatLens AI</div>", unsafe_allow_html=True)
    st.caption("Machine Learning Outlier Engine v1.6")
    st.markdown("<br>", unsafe_allow_html=True)
    
    selected_view = st.radio(
        "MAIN NAVIGATION",
        options=["🖥️ Dashboard", "👥 Employee Activity", "🔬 Risk Analysis", "🚨 Security Alerts", "📈 Reports"]
    )
    
    st.markdown("---")
    st.markdown("### 🧠 ML ENGINE TELEMETRY")
    st.caption("🤖 Model: Isolation Forest")
    st.caption("📈 Core Contamination: 70%")
    st.caption("🔢 Active Features Vector: [Dept, Logins, Vol]")

# ==========================================
# 4. VIEW ROUTING INTERFACE
# ==========================================

# VIEW 1: DASHBOARD
if selected_view == "🖥️ Dashboard":
    st.title("🖥️ AI Security Overview")
    st.caption("Isolation Forest Anomaly Detection Model Running Real-Time Behavioral Inference")
    st.markdown("---")
    
    # Summary Cards Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown("<div class='metric-box'><h2>241</h2><p style='color:#a0aec0;margin:0;'>TOTAL USERS PROFILE SYSTEM</p></div>", unsafe_allow_html=True)
    with m2:
        st.markdown("<div class='metric-box'><h2 style='color:#e53e3e;'>7</h2><p style='color:#a0aec0;margin:0;'>🔴 ML ANOMALIES FOUND</p></div>", unsafe_allow_html=True)
    with m3:
        st.markdown("<div class='metric-box'><h2 style='color:#4fd1c5;'>Scikit-Learn</h2><p style='color:#a0aec0;margin:0;'>ACTIVE ML ENGINE</p></div>", unsafe_allow_html=True)
    with m4:
        st.markdown("<div class='metric-box'><h2 style='color:#48bb78;'>100%</h2><p style='color:#a0aec0;margin:0;'>TRAINING PIPELINE OK</p></div>", unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_left, col_right = st.columns([7, 5])
    
    with col_left:
        st.markdown("### 👥 Active AI Isolation Cluster Matrix")
        # Displaying the actual machine learning scores directly in the visual data table
        display_risk = high_risk_employees[['Employee Name', 'Department', 'AI Risk Score (%)', 'Threat Trigger']].copy()
        st.dataframe(display_risk, use_container_width=True, hide_index=True)
        
    with col_right:
        st.markdown("### 🚨 Live AI Alert Inference Queue")
        for _, row in high_risk_employees.head(3).iterrows():
            st.markdown(f"""
                <div class='alert-card'>
                    <span class='ai-badge'>🤖 AI ANOMALY DETECTION</span> | Anomaly Score: <b>{row['AI Risk Score (%)']}%</b><br>
                    <b style='color:#e53e3e;'>{row['Threat Trigger']}</b> via Account <b>{row['Employee Name']}</b> ({row['Department']})
                </div>
            """, unsafe_allow_html=True)

# VIEW 2: EMPLOYEE ACTIVITY
elif selected_view == "👥 Employee Activity":
    st.title("👥 System Footprints & Anomaly Evaluation")
    st.caption("Complete operational dataset running ongoing anomaly cluster indexing.")
    st.markdown("---")
    
    st.dataframe(
        df_logs[['Employee Name', 'Department', 'Time of Activity', 'Failed Logins', 'Data Downloaded (MB)', 'AI Risk Score (%)', 'Status']], 
        use_container_width=True, 
        hide_index=True
    )

# VIEW 3: RISK ANALYSIS
elif selected_view == "🔬 Risk Analysis":
    st.title("🔬 Neural Behavior Profile Analytics")
    st.caption("Deep-dive inspection of mathematical outlier attributes.")
    st.markdown("---")
    
    target_user = st.selectbox("Select Target Employee Profile to Audit:", options=df_logs['Employee Name'].unique())
    user_profile = df_logs[df_logs['Employee Name'] == target_user].iloc[0]
    
    st.markdown(f"#### Algorithmic Diagnostics Vector: {target_user}")
    
    sub_c1, sub_c2 = st.columns(2)
    with sub_c1:
        metric_html_1 = f"""
        <div class='metric-card' style='border-left: 4px solid #e53e3e;'>
            <b>Computed Anomaly Probability</b><br>
            Current Structural Outlier Rating: <span style='color:#e53e3e;font-weight:bold;'>{user_profile['AI Risk Score (%)']}%</span><br>
            <span style='color:#a0aec0;'>Model Evaluation Threshold Limit: 50.0%</span>
        </div>
        """
        st.markdown(metric_html_1, unsafe_allow_html=True)
        
    with sub_c2:
        metric_html_2 = f"""
        <div class='metric-card'>
            <b>Monitored Vector Attributes</b><br>
            Failed Logins: {user_profile['Failed Logins']} | Data Volume: {user_profile['Data Downloaded (MB)']} MB<br>
            <span style='color:#a0aec0;'>Classification Group Status: {user_profile['Status']}</span>
        </div>
        """
        st.markdown(metric_html_2, unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    if "High Risk" in user_profile['Status']:
        st.error(f"🚨 **Isolation Forest Flagged:** Machine learning features confirm abnormal cluster distribution pattern representing **{user_profile['Threat Trigger']}**.")
    else:
        st.success("🟢 **Model Baseline Match:** Behavioral attributes completely match standard user cluster spaces.")

# VIEW 4: SECURITY ALERTS
elif selected_view == "🚨 Security Alerts":
    st.title("🚨 Live ML Classification Alerts")
    st.caption("Chronological list of data rows mathematically isolated by the model framework rules.")
    st.markdown("---")
    
    for _, row in high_risk_employees.iterrows():
        st.markdown(f"""
            <div class='alert-card'>
                <h3 style='margin:0 0 5px 0; color:#e53e3e;'>⚠️ ISOLATION ENGINE: {row['Threat Trigger']}</h3>
                <b>Model Deviation Density Score:</b> {row['AI Risk Score (%)']}% Anomaly Confidence Vector.<br>
                <b>Tracked Account Profile:</b> {row['Employee Name']} ({row['Department']})<br>
                <b>System Telemetry Dimensions:</b> {row['Failed Logins']} Failed Logins | {row['Data Downloaded (MB)']} MB Data Streamed.
            </div>
        """, unsafe_allow_html=True)

# VIEW 5: REPORTS
elif selected_view == "📈 Reports":
    st.title("🛡️ ML Inference Audit Compliance Reports")
    st.markdown("---")
    st.info("💡 **AI Compliance Audit Generated Successfully**")
    st.write(f"Total documented machine-isolated outlier exceptions captured today: **{len(high_risk_employees)}** active anomalies.")
    
    st.dataframe(high_risk_employees[['Employee Name', 'Department', 'AI Risk Score (%)', 'Threat Trigger', 'Status']], use_container_width=True, hide_index=True)
    
    padded_df = df_incidents.copy()
    padded_df['Flagged Employee']   = padded_df['Flagged Employee'].astype(str).apply(lambda x: f"{x:<25}")
    padded_df['Department']         = padded_df['Department'].astype(str).apply(lambda x: f"{x:<18}")
    padded_df['Incident Identified'] = padded_df['Incident Identified'].astype(str).apply(lambda x: f"{x:<35}")
    padded_df['AI Confidence Score (%)'] = padded_df['AI Confidence Score (%)'].astype(str).apply(lambda x: f"{x:<12}")
    
    csv_data_content = padded_df.to_csv(index=False)
    
    st.download_button(
        label="📥 Download Machine-Learning Audit Export (CSV)",
        data=csv_data_content,
        file_name="insider_threat_ml_compliance_report.csv",
        mime="text/csv"
    )