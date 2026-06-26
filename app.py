import streamlit as st
import pandas as pd
import numpy as np

# ==========================================
# 1. ENTERPRISE SOC CONFIGURATION & THEME
# ==========================================
st.set_page_config(
    page_title="ThreatLens AI — Enterprise SOC Portal",
    page_icon="🛡️",
    layout="wide"
)

# Custom dark-mode CSS injection for premium professional look
st.markdown("""
    <style>
    .main { background-color: #0b0d13; color: #e2e8f0; font-family: 'Inter', sans-serif; }
    .kpi-card { 
        background: linear-gradient(135deg, #161b26 0%, #1a202c 100%); 
        padding: 22px; 
        border-radius: 10px; 
        border: 1px solid #2d3748; 
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        text-align: left;
    }
    .kpi-title { font-size: 0.85rem; font-weight: 600; color: #a0aec0; letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 8px;}
    .kpi-value { font-size: 1.8rem; font-weight: 700; color: #ffffff; line-height: 1.1; }
    .alert-card-pro { 
        background-color: #171e2e; 
        border-left: 4px solid #f56565; 
        padding: 16px; 
        border-radius: 6px; 
        margin-bottom: 12px;
        border-top: 1px solid #2d3748;
        border-right: 1px solid #2d3748;
        border-bottom: 1px solid #2d3748;
    }
    .nav-title { font-size: 1.4rem; font-weight: 700; color: #38bdf8; font-family: monospace; letter-spacing: 1px; }
    .ai-badge-pro { background-color: #0369a1; color: #e0f2fe; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    </style>
""", unsafe_allow_html=True)

# ==========================================
# 2. ADVANCED VECTOR MODEL PIPELINE
# ==========================================
@st.cache_data
def run_insider_threat_ai_engine():
    """Applies a Vector Distance Anomaly Detection Model to track baseline behavioral deviations."""
    raw_logs = pd.DataFrame([
        {'Employee Name': 'James R', 'Department': 'Finance', 'Time of Activity': '02:31 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 2300.0, 'Threat Trigger': 'Bulk Data Exfiltration'},
        {'Employee Name': 'Kayla', 'Department': 'Engineering', 'Time of Activity': '03:08 AM', 'Failed Logins': 1, 'Data Downloaded (MB)': 450.0, 'Threat Trigger': 'Off-hours System Access'},
        {'Employee Name': 'Yumi', 'Department': 'IT Security', 'Time of Activity': '11:45 AM', 'Failed Logins': 7, 'Data Downloaded (MB)': 1.2, 'Threat Trigger': 'Failed Login Attempts'},
        {'Employee Name': 'Ankita', 'Department': 'HR', 'Time of Activity': '02:44 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 15.4, 'Threat Trigger': 'Unregistered USB Insertion'},
        {'Employee Name': 'Lily', 'Department': 'Sales', 'Time of Activity': '03:10 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 120.0, 'Threat Trigger': 'External Email Forwarding'},
        {'Employee Name': 'Jenna', 'Department': 'Marketing', 'Time of Activity': '01:15 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 5.0, 'Threat Trigger': 'Opening Suspicious Websites'},
        {'Employee Name': 'John', 'Department': 'Operations', 'Time of Activity': '11:02 PM', 'Failed Logins': 0, 'Data Downloaded (MB)': 85.0, 'Threat Trigger': 'Sensitive HR Record Access'},
        {'Employee Name': 'Mary', 'Department': 'Legal', 'Time of Activity': '09:30 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 4.2, 'Threat Trigger': 'None'},
        {'Employee Name': 'Kate', 'Department': 'Finance', 'Time of Activity': '09:10 AM', 'Failed Logins': 0, 'Data Downloaded (MB)': 11.0, 'Threat Trigger': 'None'},
        {'Employee Name': 'Reyna', 'Department': 'IT Security', 'Time of Activity': '05:12 AM', 'Failed Logins': 1, 'Data Downloaded (MB)': 28.0, 'Threat Trigger': 'None'}
    ])
    
    logins_vec = raw_logs['Failed Logins'].values
    data_vec = np.log1p(raw_logs['Data Downloaded (MB)'].values)
    
    scores = np.sqrt((logins_vec - 0.2)**2 + (data_vec - 2.5)**2)
    normalized_scores = (scores - scores.min()) / (scores.max() - scores.min())
    
    raw_logs['AI Risk Score (%)'] = np.round(normalized_scores * 100, 1)
    raw_logs['Status'] = ['🔴 High Risk' if s > 35.0 or raw_logs.loc[i, 'Threat Trigger'] != 'None' else '🟢 Clear' for i, s in enumerate(raw_logs['AI Risk Score (%)'])]
    
    ai_anomalies = raw_logs[raw_logs['Status'] == '🔴 High Risk'].copy()
    incident_report = pd.DataFrame({
        'Flagged Employee': ai_anomalies['Employee Name'],
        'Department': ai_anomalies['Department'],
        'Incident Identified': ai_anomalies['Threat Trigger'],
        'AI Confidence Score (%)': ai_anomalies['AI Risk Score (%)']
    })
    
    return raw_logs, incident_report

df_logs, df_incidents = run_insider_threat_ai_engine()
high_risk_employees = df_logs[df_logs['Status'] == '🔴 High Risk']

# ==========================================
# 3. SIDEBAR SYSTEM NAVIGATION
# ==========================================
with st.sidebar:
    st.markdown("<div class='nav-title'>THREATLENS AI</div>", unsafe_allow_html=True)
    st.caption("Enterprise Risk Monitoring Portal")
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    selected_view = st.radio(
        "NAVIGATION CONTROL",
        options=["🖥️ Executive Dashboard", "👥 Employee Footprints", "🔬 Deep Behavioral Risk", "🚨 Core Security Alerts", "📈 Audit & Compliance"]
    )
    
    st.markdown("---")
    st.markdown("### ⚙️ SYSTEM STATE")
    st.caption("Engine: Vector Density Cluster v1.6")
    st.caption("Environment: Live Production Node")
    st.caption("Status: Fully Operational")

# ==========================================
# 4. VIEW INTERFACE IMPLEMENTATION
# ==========================================

# VIEW 1: EXECUTIVE DASHBOARD
if selected_view == "🖥️ Executive Dashboard":
    st.title("🖥️ Security Operations Dashboard")
    st.caption("Real-time telemetry and user behavioral risk modeling overview.")
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Styled KPI Cards Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown("<div class='kpi-card'><div class='kpi-title'>Total Monitored Nodes</div><div class='kpi-value'>241</div></div>", unsafe_allow_html=True)
    with m2:
        st.markdown("<div class='kpi-card'><div class='kpi-title' style='color:#f56565;'>Active AI Anomalies</div><div class='kpi-value' style='color:#f56565;'>7</div></div>", unsafe_allow_html=True)
    with m3:
        st.markdown("<div class='kpi-card'><div class='kpi-title'>Core ML Architecture</div><div class='kpi-value' style='color:#38bdf8;'>Vector Clust</div></div>", unsafe_allow_html=True)
    with m4:
        st.markdown("<div class='kpi-card'><div class='kpi-title'>Pipeline Integrity</div><div class='kpi-value' style='color:#48bb78;'>100%</div></div>", unsafe_allow_html=True)
        
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    layout_left, layout_right = st.columns([7, 5])
    
    with layout_left:
        st.subheader("👥 Dynamic Behavior Metrics Matrix")
        st.caption("Top anomalies flagged by spatial coordinate distribution calculations.")
        display_risk = high_risk_employees[['Employee Name', 'Department', 'AI Risk Score (%)', 'Threat Trigger']].copy()
        st.dataframe(display_risk, use_container_width=True, hide_index=True)
        
    with layout_right:
        st.subheader("🚨 Real-time Inference Stream")
        st.caption("Latest chronological event log deviations.")
        for _, row in high_risk_employees.head(3).iterrows():
            st.markdown(f"""
                <div class='alert-card-pro'>
                    <span class='ai-badge-pro'>Inference Alert</span> &nbsp; Confidence Rating: <b>{row['AI Risk Score (%)']}%</b><br>
                    <span style='font-size:1.05rem;font-weight:600;color:#f56565;'>{row['Threat Trigger']}</span><br>
                    <span style='color:#a0aec0;font-size:0.9rem;'>Subject: User <b>{row['Employee Name']}</b> ({row['Department']})</span>
                </div>
            """, unsafe_allow_html=True)

# VIEW 2: EMPLOYEE FOOTPRINTS
elif selected_view == "👥 Employee Footprints":
    st.title("👥 Employee Activity Logs")
    st.caption("Unified telemetry repository across organizational sectors.")
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Added professional filter option for quick table navigation
    search_query = st.text_input("🔍 Filter logs by employee name or department:", "")
    
    filtered_df = df_logs.copy()
    if search_query:
        filtered_df = filtered_df[
            filtered_df['Employee Name'].str.contains(search_query, case=False) | 
            filtered_df['Department'].str.contains(search_query, case=False)
        ]
        
    st.dataframe(
        filtered_df[['Employee Name', 'Department', 'Time of Activity', 'Failed Logins', 'Data Downloaded (MB)', 'AI Risk Score (%)', 'Status']], 
        use_container_width=True, 
        hide_index=True
    )

# VIEW 3: DEEP BEHAVIORAL RISK
elif selected_view == "🔬 Deep Behavioral Risk":
    st.title("🔬 Advanced Risk Vector Diagnostics")
    st.caption("Deep-dive algorithmic diagnostics mapping individual user coordinates.")
    st.markdown("<br>", unsafe_allow_html=True)
    
    target_user = st.selectbox("Select target account index to audit:", options=df_logs['Employee Name'].unique())
    user_profile = df_logs[df_logs['Employee Name'] == target_user].iloc[0]
    
    st.markdown(f"### Diagnostics Profile: **{target_user}**")
    st.markdown("---")
    
    sub_c1, sub_c2 = st.columns(2)
    with sub_c1:
        st.markdown(f"""
        <div class='kpi-card' style='border-left: 4px solid #f56565;'>
            <div class='kpi-title'>Calculated Risk Amplitude</div>
            <div class='kpi-value' style='color:#f56565;'>{user_profile['AI Risk Score (%)']}%</div>
            <p style='color:#718096;margin:8px 0 0 0;font-size:0.85rem;'>Target Threshold Boundary: 35.0%</p>
        </div>
        """, unsafe_allow_html=True)
        
    with sub_c2:
        st.markdown(f"""
        <div class='kpi-card' style='border-left: 4px solid #38bdf8;'>
            <div class='kpi-title'>Monitored Parameters Matrix</div>
            <div class='kpi-value' style='font-size:1.2rem;color:#ffffff;padding-top:5px;'>
                Failed Logins: <b>{user_profile['Failed Logins']}</b><br>
                Data Payload: <b>{user_profile['Data Downloaded (MB)']} MB</b>
            </div>
            <p style='color:#718096;margin:8px 0 0 0;font-size:0.85rem;'>System Evaluation: {user_profile['Status']}</p>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    if "High Risk" in user_profile['Status']:
        st.error(f"⚠️ **Anomaly Threshold Breached:** User features isolate heavily outside baseline tolerances. Activity matches signatures for **{user_profile['Threat Trigger']}**.")
    else:
        st.success("💪 **Baseline Confirmed:** Account coordinates align perfectly within nominal standard user groups.")

# VIEW 4: CORE SECURITY ALERTS
elif selected_view == "🚨 Core Security Alerts":
    st.title("🚨 Incident Escalation Queue")
    st.caption("Active list of anomalous entities currently flagged for human analyst triage.")
    st.markdown("<br>", unsafe_allow_html=True)
    
    for _, row in high_risk_employees.iterrows():
        st.markdown(f"""
            <div class='alert-card-pro'>
                <h4 style='margin:0 0 6px 0; color:#f56565;'>💥 CRITICAL: {row['Threat Trigger']}</h4>
                <div style='font-size:0.95rem; line-height:1.6;'>
                    <b>Statistical Deviation Score:</b> {row['AI Risk Score (%)']}% Anomaly Weight.<br>
                    <b>Account Identity:</b> {row['Employee Name']} | Department Sector: {row['Department']}<br>
                    <b>Telemetry Dimensions:</b> Failed Logins: {row['Failed Logins']} | Data Volume Streamed: {row['Data Downloaded (MB)']} MB.
                </div>
            </div>
        """, unsafe_allow_html=True)

# VIEW 5: AUDIT & COMPLIANCE
elif selected_view == "📈 Audit & Compliance":
    st.title("🛡️ Compliance Reporting Engine")
    st.caption("Export-ready metrics for internal auditing and technical compliance records.")
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.info("📊 **Verified Compliance Record Assembly Complete**")
    st.write(f"Total isolated threat vectors flagged in current audit run: **{len(high_risk_employees)}** clear behavioral anomalies.")
    
    st.dataframe(high_risk_employees[['Employee Name', 'Department', 'AI Risk Score (%)', 'Threat Trigger', 'Status']], use_container_width=True, hide_index=True)
    
    padded_df = df_incidents.copy()
    padded_df['Flagged Employee']   = padded_df['Flagged Employee'].astype(str).apply(lambda x: f"{x:<25}")
    padded_df['Department']         = padded_df['Department'].astype(str).apply(lambda x: f"{x:<18}")
    padded_df['Incident Identified'] = padded_df['Incident Identified'].astype(str).apply(lambda x: f"{x:<35}")
    padded_df['AI Confidence Score (%)'] = padded_df['AI Confidence Score (%)'].astype(str).apply(lambda x: f"{x:<12}")
    
    csv_data_content = padded_df.to_csv(index=False)
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.download_button(
        label="📥 Export Enterprise Audit Report (CSV)",
        data=csv_data_content,
        file_name="insider_threat_compliance_audit_export.csv",
        mime="text/csv"
    )
