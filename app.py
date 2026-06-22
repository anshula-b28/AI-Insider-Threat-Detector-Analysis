import streamlit as st
import pandas as pd
import numpy as np

# ==========================================
# 1. PAGE CONFIGURATION & INTERFACE STYLING
# ==========================================
st.set_page_config(
    page_title="ThreatLens - Insider Threat Monitor",
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
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. SEPARATED DATA PIPELINE ENGINE (FIXES CSV)
# ==========================================
@st.cache_data
def get_clean_security_databases():
    """Generates clean, separate datasets to ensure perfect Excel/CSV layout symmetry."""
    
    # Dataset A: Clean Master Activity Log for tracking daily system stats
    all_activities = pd.DataFrame([
        {'Employee Name': 'Rahul Kumar', 'Department': 'Finance', 'Time of Activity': '02:31 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 2300.0, 'Status': '🔴 High Risk', 'Threat Trigger': 'Bulk Data Exfiltration'},
        {'Employee Name': 'Priya Mehta', 'Department': 'Engineering', 'Time of Activity': '03:08 AM', 'Failed Logins': 1, 'Data Downloaded (MB)': 450.0, 'Status': '🔴 High Risk', 'Threat Trigger': 'Off-hours System Access'},
        {'Employee Name': 'Arjun Singh', 'Department': 'IT Security', 'Time of Activity': '11:45 AM', 'Failed Logins': 7, 'Data Downloaded (MB)': 1.2, 'Status': '🔴 High Risk', 'Threat Trigger': 'Failed Login Attempts'},
        {'Employee Name': 'Divya Nair', 'Department': 'HR', 'Time of Activity': '02:44 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 15.4, 'Status': '🔴 High Risk', 'Threat Trigger': 'Unregistered USB Insertion'},
        {'Employee Name': 'Amit Patel', 'Department': 'Sales', 'Time of Activity': '03:10 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 120.0, 'Status': '🔴 High Risk', 'Threat Trigger': 'External Email Forwarding'},
        {'Employee Name': 'Suresh Babu', 'Department': 'Marketing', 'Time of Activity': '01:15 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 5.0, 'Status': '🔴 High Risk', 'Threat Trigger': 'Opening Suspicious Websites'},
        {'Employee Name': 'Vikram Rao', 'Department': 'Operations', 'Time of Activity': '11:02 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 85.0, 'Status': '🔴 High Risk', 'Threat Trigger': 'Sensitive HR Record Access'},
        {'Employee Name': 'Lakshmi Pillai', 'Department': 'Legal', 'Time of Activity': '09:30 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 4.2, 'Status': '🟢 Clear', 'Threat Trigger': 'None'},
        {'Employee Name': 'Meera Krishnan', 'Department': 'Finance', 'Time of Activity': '09:10 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 11.0, 'Status': '🟢 Clear', 'Threat Trigger': 'None'},
        {'Employee Name': 'Ravi Nair', 'Department': 'IT Security', 'Time of Activity': '05:12 AM', 'Failed Logins': 1, 'Data Downloaded (MB)': 28.0, 'Status': '🟢 Clear', 'Threat Trigger': 'None'}
    ])
    
    # Dataset B: Dedicated Incident Log strictly for clean corporate reports
    incident_report = pd.DataFrame([
        {'Flagged Employee': 'Rahul Kumar', 'Department': 'Finance', 'Incident Identified': 'Bulk Data Exfiltration', 'Severity': 'CRITICAL'},
        {'Flagged Employee': 'Priya Mehta', 'Department': 'Engineering', 'Incident Identified': 'Off-hours System Access', 'Severity': 'HIGH'},
        {'Flagged Employee': 'Arjun Singh', 'Department': 'IT Security', 'Incident Identified': 'Failed Login Attempts (Brute Force)', 'Severity': 'HIGH'},
        {'Flagged Employee': 'Divya Nair', 'Department': 'HR', 'Incident Identified': 'Unregistered USB Insertion', 'Severity': 'CRITICAL'},
        {'Flagged Employee': 'Amit Patel', 'Department': 'Sales', 'Incident Identified': 'External Email Forwarding', 'Severity': 'MEDIUM'},
        {'Flagged Employee': 'Suresh Babu', 'Department': 'Marketing', 'Incident Identified': 'Opening Suspicious Websites', 'Severity': 'LOW'},
        {'Flagged Employee': 'Vikram Rao', 'Department': 'Operations', 'Incident Identified': 'Sensitive HR Record Access', 'Severity': 'HIGH'}
    ])
    
    return all_activities, incident_report

df_logs, df_incidents = get_clean_security_databases()
high_risk_employees = df_logs[df_logs['Status'] == '🔴 High Risk']

# ==========================================
# 3. SIDEBAR NAVIGATION PANEL (MATCHES MOCKUP)
# ==========================================
with st.sidebar:
    st.markdown("<div class='nav-header'>🛡️ ThreatLens</div>", unsafe_allow_html=True)
    st.caption("AI Insider Threat Detector")
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Interactive Sidebar Navigation Links
    selected_view = st.radio(
        "MAIN NAVIGATION",
        options=["🖥️ Dashboard", "👥 Employee Activity", "🔬 Risk Analysis", "🚨 Security Alerts", "📈 Reports"]
    )
    
    st.markdown("---")
    st.markdown("### SYSTEM CONTROLS")
    st.caption("⚡ Core Engine Status: ACTIVE")
    st.caption("👤 Session Node: S. Analyst (Admin)")

# ==========================================
# 4. VIEW ROUTING INTERFACE
# ==========================================

# VIEW 1: DASHBOARD
if selected_view == "🖥️ Dashboard":
    st.title("🖥️ Security Overview")
    st.caption("AI-Powered Insider Threat Detection Portal — Real-time Security State Monitor")
    st.markdown("---")
    
    # Summary Cards Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown("<div class='metric-box'><h2>241</h2><p style='color:#a0aec0;margin:0;'>TOTAL EMPLOYEES</p></div>", unsafe_allow_html=True)
    with m2:
        st.markdown("<div class='metric-box'><h2 style='color:#e53e3e;'>7</h2><p style='color:#a0aec0;margin:0;'>HIGH RISK USERS</p></div>", unsafe_allow_html=True)
    with m3:
        st.markdown("<div class='metric-box'><h2 style='color:#ecc94b;'>65</h2><p style='color:#a0aec0;margin:0;'>MEDIUM RISK USERS</p></div>", unsafe_allow_html=True)
    with m4:
        st.markdown("<div class='metric-box'><h2 style='color:#48bb78;'>142</h2><p style='color:#a0aec0;margin:0;'>LOW RISK USERS</p></div>", unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_left, col_right = st.columns([6, 6])
    
    with col_left:
        st.markdown("### 👥 High Risk Employees")
        display_risk = high_risk_employees[['Employee Name', 'Department', 'Threat Trigger']].copy()
        display_risk.columns = ['Employee', 'Department', 'Risk Event Type']
        st.dataframe(display_risk, use_container_width=True, hide_index=True)
        
    with col_right:
        st.markdown("### 🚨 Live Security Alerts")
        # Grab first 3 anomalies to make the live dashboard view clean
        for _, row in high_risk_employees.head(3).iterrows():
            st.markdown(f"""
                <div class='alert-card'>
                    <span style='color:#e53e3e; font-weight:bold;'>🔴 CRITICAL</span> | <b>{row['Threat Trigger']} Detected</b><br>
                    <span style='color:#a0aec0;'>Target User:</span> {row['Employee Name']} ({row['Department']}) at {row['Time of Activity']}
                </div>
            """, unsafe_allow_html=True)

# VIEW 2: EMPLOYEE ACTIVITY
elif selected_view == "👥 Employee Activity":
    st.title("👥 Employee Activity Monitoring")
    st.caption("Complete operational footprint tracking logs across corporate networks today.")
    st.markdown("---")
    
    # Display clear list grid containing both normal and abnormal activities
    st.dataframe(
        df_logs[['Employee Name', 'Department', 'Time of Activity', 'Failed Logins', 'Data Downloaded (MB)', 'Status']], 
        use_container_width=True, 
        hide_index=True
    )

# VIEW 3: RISK ANALYSIS
elif selected_view == "🔬 Risk Analysis":
    st.title("🔬 Risk Profile Analysis")
    st.caption("Deep-dive exploration of individual behavioral telemetry footprints.")
    st.markdown("---")
    
    target_user = st.selectbox("Select Target Employee Profile to Audit:", options=df_logs['Employee Name'].unique())
    user_profile = df_logs[df_logs['Employee Name'] == target_user].iloc[0]
    
    # Technical profile breakdown panels
    st.markdown(f"#### Behavioral Fingerprint Metrics: {target_user}")
    
    sub_c1, sub_c2 = st.columns(2)
    with sub_c1:
        metric_html_1 = f"""
        <div class='metric-card'>
            <b>Network Transfer Volume</b><br>
            Current Data Staged: {user_profile['Data Downloaded (MB)']} MB<br>
            <span style='color:#a0aec0;'>Corporate Baseline Threshold: 150.0 MB</span>
        </div>
        """
        st.markdown(metric_html_1, unsafe_allow_html=True)
        
    with sub_c2:
        metric_html_2 = f"""
        <div class='metric-card'>
            <b>Authentication Access Vectors</b><br>
            Failed Logins: {user_profile['Failed Logins']} Attempts<br>
            <span style='color:#a0aec0;'>Timestamp Window Checked: {user_profile['Time of Activity']}</span>
        </div>
        """
        st.markdown(metric_html_2, unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    if user_profile['Status'] == '🔴 High Risk':
        st.error(f"🚨 **Incident Analysis Flagged:** Employee profile matches suspicious patterns indicating **{user_profile['Threat Trigger']}**. Security teams are advised to review workstation connections immediately.")
    else:
        st.success("🟢 **Normal Baseline Match:** Behavioral attributes completely fit standard peer group profiles. No anomalies present.")

# VIEW 4: SECURITY ALERTS
elif selected_view == "🚨 Security Alerts":
    st.title("🚨 Live Security Alerts Queue")
    st.caption("Chronological list of behavioral anomalies isolated by security detection rules.")
    st.markdown("---")
    
    for _, row in high_risk_employees.iterrows():
        st.markdown(f"""
            <div class='alert-card'>
                <h3 style='margin:0 0 5px 0; color:#e53e3e;'>⚠️ ALERT: {row['Threat Trigger']}</h3>
                <b>Identified User Account:</b> {row['Employee Name']} ({row['Department']})<br>
                <b>Timestamp Verification:</b> Action tracked today at {row['Time of Activity']}<br>
                <b>Telemetry Load Size:</b> {row['Data Downloaded (MB)']} MB transferred during session window.
            </div>
        """, unsafe_allow_html=True)

# VIEW 5: REPORTS
elif selected_view == "📈 Reports":
    st.title("📈 Security Audit & Compliance Reports")
    st.caption("Download boardroom-ready reports on internal organizational threat indicators.")
    st.markdown("---")
    
    st.info(f"💡 **Audit Verification Engine Active** // **{len(df_incidents)} Critical Threat Anomalies Documented**")
    
    st.write("### Incident Summary Table Preview:")
    st.dataframe(df_incidents, use_container_width=True, hide_index=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # --- Code workaround to auto-space columns without needing external plugins ---
    padded_df = df_incidents.copy()
    
    # Pad headings to guarantee default spreadsheet layout width
    padded_df = padded_df.rename(columns={
        'Flagged Employee': 'Flagged Employee         ',
        'Department':       'Department               ',
        'Incident Identified': 'Incident Identified                           ',
        'Severity':         'Severity     '
    })
    
    # Pad string contents so they never bunch together or get cut off
    padded_df.iloc[:, 0] = padded_df.iloc[:, 0].apply(lambda x: f"{x:<25}")
    padded_df.iloc[:, 1] = padded_df.iloc[:, 1].apply(lambda x: f"{x:<25}")
    padded_df.iloc[:, 2] = padded_df.iloc[:, 2].apply(lambda x: f"{x:<45}")
    padded_df.iloc[:, 3] = padded_df.iloc[:, 3].apply(lambda x: f"{x:<15}")
    
    # Convert data directly to standard text stream array
    csv_data = padded_df.to_csv(index=False).encode('utf-8')
    
    # Secure Download Action Trigger
    st.download_button(
        label="📥 Download Clean Auto-Formatted Incident Report (CSV)",
        data=csv_data,
        file_name="insider_threat_compliance_report.csv",
        mime="text/csv"
    )