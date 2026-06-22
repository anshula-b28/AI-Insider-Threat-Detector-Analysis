# 🛡️ ThreatLens: Insider Threat Monitoring Dashboard

ThreatLens is a real-time behavioral monitoring and anomaly tracking platform built specifically to identify insider security risks within corporate environments. The system processes employee activity logs to isolate high-risk behavior signatures, manage live incident alerts, and generate boardroom-ready audit compliance reports.

---

## ✨ Key Capabilities

* **Behavioral Detection Engine:** Automates tracking for key corporate risk indicators, including:
  * Off-hours system access (e.g., 2:00 AM database connections)
  * External corporate email forwarding to personal domains
  * Insertion of unregistered or untrusted USB flash drives
  * Unauthorized browsing to high-risk or suspicious websites
  * Bulk data exfiltration volumes exceeding baseline thresholds
  * Repeated failed login brute-force attempts
  * Unauthorized access attempts to sensitive HR or payroll records
* **Interactive Risk Vector Investigator:** Allows security analysts to pull up individual employee footprints to immediately evaluate a user's status (Clear vs. High Risk) against peer group baselines.
* **Live Incident Queue:** Houses chronological priority alerts requiring immediate corporate security evaluation.
* **Structured Compliance Exports:** Generates clean, auto-spaced reporting sheets directly to spreadsheet format with zero visual clutter.

---

## 🎨 User Interface Layout
The application features a sleek, professional Security Operations Center (SOC) dark-mode theme divided into 5 distinct workspaces:
1. **🖥️ Dashboard:** High-level metrics tracking total monitored endpoints, critical alerts, and active high-risk users.
2. **👥 Employee Activity:** A complete grid overview of active network telemetry and data volume counters.
3. **🔬 Risk Analysis:** Profile inspector for drilling down into specific user session details.
4. **🚨 Security Alerts:** A chronological feed detailing *who* triggered *what* threat profile and *at what time*.
5. **📈 Reports:** An auditing station designed to download formatted compliance tables for corporate records.

---

## 🛠️ Technology Stack

* **Language:** Python
* **Interface Framework:** Streamlit
* **Data Processing:** Pandas, NumPy

---

## 🚀 Local Installation & Execution

To set up and run ThreatLens locally on your machine, follow these commands in your terminal window:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_GITHUB_USERNAME/threat-detector.git](https://github.com/YOUR_GITHUB_USERNAME/threat-detector.git)
   cd threat-detector
2. **Install the required libraries:**
   ```bash
   pip install -r requirements.txt
3. **Launch the application local server:**
   ```bash
   streamlit run app.py
