import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px      # NEW
import random

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(
    page_title="CyberGuardian Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------------
# CUSTOM DARK THEME + UI STYLING
# ---------------------------------------------------------
dark_theme_css = """
<style>

/* Global background */
body, .block-container {
    background-color: #0d1117 !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #161b22 !important;
    border-right: 1px solid #30363d;
}

/* Titles */
h1, h2, h3, h4 {
    color: #e6edf3 !important;
    font-weight: 600 !important;
}

/* Text color */
p, div, label {
    color: #c9d1d9 !important;
}

/* Inputs */
input, textarea {
    background-color: #0d1117 !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
}

/* Buttons */
.stButton>button {
    background: linear-gradient(90deg, #1f6feb, #3b82f6);
    color: white !important;
    padding: 10px 18px !important;
    border-radius: 8px !important;
    border: none;
    font-weight: 600;
}

.stButton>button:hover {
    background: linear-gradient(90deg, #3b82f6, #1f6feb);
    transform: scale(1.02);
}

/* Card-style containers */
.card {
    background-color: #161b22;
    padding: 15px 20px;
    border-radius: 10px;
    border: 1px solid #30363d;
    margin-bottom: 15px;
}

/* Recommendation boxes */
.reco-box {
    background-color: #21262d;
    padding: 12px;
    border-radius: 6px;
    margin-bottom: 10px;
    color: #c9d1d9;
    font-size: 15px;
}

/* Dataframe and tables */
.stDataFrame {
    background-color: #0d1117 !important;
}
.dataframe {
    color: #e6edf3 !important;
}

/* Progress bar */
[data-testid="stProgressBar"] > div > div {
    background-color: #238636 !important;
}

</style>
"""
st.markdown(dark_theme_css, unsafe_allow_html=True)

# ---------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------
if "accounts" not in st.session_state:
    st.session_state.accounts = []

if "device" not in st.session_state:
    st.session_state.device = {
        "screen_lock": False,
        "os_updated": False,
        "antivirus": False,
        "public_wifi": True,
    }

# ---------------------------------------------------------
# CORE LOGIC FUNCTIONS
# ---------------------------------------------------------
def check_password_strength(password: str) -> str:
    score = 0
    if len(password) >= 12:
        score += 2
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()_+-=[]{},.<>?/\\|" for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score == 3:
        return "Medium"
        # Strong
    else:
        return "Strong"


def evaluate_device_security(device: dict) -> int:
    penalties = 0
    if not device.get("screen_lock", False):
        penalties += 10
    if not device.get("os_updated", False):
        penalties += 10
    if not device.get("antivirus", False):
        penalties += 5
    if device.get("public_wifi", True):
        penalties += 5
    return penalties


def calculate_score(accounts: list, device: dict) -> int:
    score = 100
    for acc in accounts:
        if acc["password_strength"] == "Weak":
            score -= 10
        elif acc["password_strength"] == "Medium":
            score -= 5
        if not acc["two_fa"]:
            score -= 5

    score -= evaluate_device_security(device)

    return max(0, min(100, score))


def get_recommendations(accounts: list, device: dict, score: int) -> list:
    recs = []

    weak_accounts = [a["name"] for a in accounts if a["password_strength"] == "Weak"]
    no_2fa_accounts = [a["name"] for a in accounts if not a["two_fa"]]

    if weak_accounts:
        recs.append("Change weak passwords for: " + ", ".join(weak_accounts))

    if no_2fa_accounts:
        recs.append("Enable 2FA for: " + ", ".join(no_2fa_accounts))

    if not device["screen_lock"]:
        recs.append("Enable screen lock or biometric protection on your device.")

    if not device["os_updated"]:
        recs.append("Update your operating system to the latest version.")

    if not device["antivirus"]:
        recs.append("Install and regularly update antivirus/antimalware software.")

    if device["public_wifi"]:
        recs.append("Avoid using public Wi-Fi for logins or use a VPN.")

    if score < 40:
        recs.append("Your overall risk is HIGH. Fix the critical issues immediately.")
    elif score < 70:
        recs.append("Your overall risk is MODERATE. Focus on passwords and 2FA.")
    else:
        recs.append("Your overall risk is LOW. Maintain your security posture.")

    return recs


def classify_recommendation(text: str):
    """
    Assign severity and category based on content.
    Returns (severity, color, label)
    """
    text_lower = text.lower()

    # Severity
    if "high" in text_lower or "weak password" in text_lower or "critical" in text_lower:
        severity = "High"
        color = "#f85149"  # red
    elif "moderate" in text_lower or "avoid using public wi-fi" in text_lower or "no 2fa" in text_lower:
        severity = "Medium"
        color = "#d29922"  # orange
    else:
        severity = "Low"
        color = "#3fb950"  # green

    # Category guess
    if "password" in text_lower:
        category = "Account Security"
    elif "2fa" in text_lower:
        category = "Account Security"
    elif "device" in text_lower or "operating system" in text_lower or "antivirus" in text_lower:
        category = "Device Security"
    elif "wi-fi" in text_lower or "vpn" in text_lower:
        category = "Network Risk"
    else:
        category = "General"

    label = f"{severity} • {category}"
    return severity, color, label

# ---------------------------------------------------------
# SIDEBAR - NAVIGATION + SUMMARY
# ---------------------------------------------------------
st.sidebar.title("🛡️ CyberGuardian")

# Quick summary
total_accounts = len(st.session_state.accounts)
weak_count = sum(1 for a in st.session_state.accounts if a["password_strength"] == "Weak")
device_risks = 0
d = st.session_state.device
if not d["screen_lock"]:
    device_risks += 1
if not d["os_updated"]:
    device_risks += 1
if not d["antivirus"]:
    device_risks += 1
if d["public_wifi"]:
    device_risks += 1

current_score = calculate_score(st.session_state.accounts, st.session_state.device)

if current_score >= 70:
    risk_label = "🟢 Low Risk"
elif current_score >= 40:
    risk_label = "🟡 Moderate Risk"
else:
    risk_label = "🔴 High Risk"

st.sidebar.markdown("### 🔍 Security Snapshot")
st.sidebar.markdown(f"- Accounts: **{total_accounts}**")
st.sidebar.markdown(f"- Weak Passwords: **{weak_count}**")
st.sidebar.markdown(f"- Device Issues: **{device_risks}**")
st.sidebar.markdown(f"- Status: **{risk_label}**")

st.sidebar.markdown("---")
page = st.sidebar.radio(     "Navigation",     ["Dashboard", "Accounts", "Device Security", "Future Vision (Labs)"] )

# ---------------------------------------------------------
# GLOBAL HEADER
# ---------------------------------------------------------
st.markdown(
    """
    <div style='padding:10px 16px; background:#020817; border-radius:12px; border:1px solid #30363d; margin-bottom:10px;'>
      <h1 style='margin:0; display:flex; align-items:center; gap:8px; font-size:26px;'>
        <span>🛡️</span> 
        <span>CyberGuardian – Personal Cybersecurity Dashboard</span>
      </h1>
      <p style='margin:4px 0 0; color:#8b949e; font-size:14px;'>
        Analyze your accounts, device settings, and overall cyber hygiene score with clear visual risk indicators.
      </p>
    </div>
    """,
    unsafe_allow_html=True
)

# ---------------------------------------------------------
# ACCOUNTS PAGE - UPGRADED UI/UX
# ---------------------------------------------------------
if page == "Accounts":
    st.subheader("🔐 Accounts Manager")

    st.markdown(
        """
        <div class="card">
            <h3>Add a New Account</h3>
            <p style='color:#8b949e;'>Enter your account details to evaluate password strength and 2FA status.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.container():
        colA, colB = st.columns(2)

        with colA:
            name = st.text_input("Account Name", placeholder="e.g., Gmail, Instagram")
        with colB:
            password = st.text_input("Password", placeholder="Enter password", type="password")

    two_fa = st.checkbox("2FA Enabled?", help="Two-factor authentication greatly improves account security.")

    if st.button("Add Account"):
        if name and password:
            pwd_strength = check_password_strength(password)
            st.session_state.accounts.append({
                "name": name,
                "password_strength": pwd_strength,
                "two_fa": two_fa
            })
            st.success(f"Added {name} ({pwd_strength})")
        else:
            st.warning("Please provide both account name and password.")

    st.markdown("<br>", unsafe_allow_html=True)

    st.subheader("📋 Your Accounts")

    if st.session_state.accounts:
        styled_accounts = []
        for acc in st.session_state.accounts:
            if acc["password_strength"] == "Weak":
                color = "#f85149"
            elif acc["password_strength"] == "Medium":
                color = "#d29922"
            else:
                color = "#3fb950"

            badge = f"<span style='color:white;background-color:{color};padding:4px 10px;border-radius:6px;font-size:12px;'>{acc['password_strength']}</span>"
            styled_accounts.append([
                acc["name"],
                badge,
                "✔️ Yes" if acc["two_fa"] else "❌ No"
            ])

        df = pd.DataFrame(styled_accounts, columns=["Account", "Password Strength", "2FA Enabled"])

        st.write(df.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.info("No accounts added yet. Use the form above to add your first account.")

# ---------------------------------------------------------
# DEVICE SECURITY PAGE - UPGRADED UI/UX
# ---------------------------------------------------------
elif page == "Device Security":
    st.subheader("💻 Device Security Checklist")

    st.markdown(
        """
        <div class="card">
            <h3>Secure Your Devices</h3>
            <p style='color:#8b949e;'>
                Review your primary device settings. These factors directly impact your overall security score.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    device = st.session_state.device

    col1, col2 = st.columns(2)

    with col1:
        device["screen_lock"] = st.checkbox(
            "🔒 Screen Lock / Biometric Enabled",
            device["screen_lock"],
            help="Enabling PIN, pattern, fingerprint or face unlock prevents physical access."
        )

        device["os_updated"] = st.checkbox(
            "🧩 Operating System is Up-to-Date",
            device["os_updated"],
            help="Keep OS and security patches updated."
        )

    with col2:
        device["antivirus"] = st.checkbox(
            "🛡️ Antivirus / Antimalware Installed",
            device["antivirus"],
            help="Real-time protection against malware and ransomware."
        )

        device["public_wifi"] = st.checkbox(
            "📶 I Often Use Public Wi-Fi for Logins",
            device["public_wifi"],
            help="Public Wi-Fi (cafes, malls, open hotspots) increases risk without VPN."
        )

    st.session_state.device = device

    st.markdown("<br>", unsafe_allow_html=True)

    st.subheader("🔍 Device Risk Summary")

    issues = []
    if not device["screen_lock"]:
        issues.append("Screen lock / biometric protection is not enabled.")
    if not device["os_updated"]:
        issues.append("Operating system is not up-to-date.")
    if not device["antivirus"]:
        issues.append("Antivirus / antimalware is not installed or active.")
    if device["public_wifi"]:
        issues.append("You frequently use public Wi-Fi for logins.")

    if issues:
        st.markdown(
            "<div class='reco-box'>Your device has some security gaps:</div>",
            unsafe_allow_html=True
        )
        for issue in issues:
            st.markdown(f"- {issue}")
    else:
        st.markdown(
            "<div class='reco-box'>✅ Your device configuration looks secure.</div>",
            unsafe_allow_html=True
        )

    st.success("Device security preferences saved.")

# ---------------------------------------------------------
# DASHBOARD PAGE - UPGRADED UI + GRAPHICAL ANALYTICS
# ---------------------------------------------------------
else:
    st.subheader("📊 CyberGuardian Overview")

    score = calculate_score(st.session_state.accounts, st.session_state.device)
    recs = get_recommendations(st.session_state.accounts, st.session_state.device, score)

    st.markdown("<br>", unsafe_allow_html=True)

    # SCORE CARD
    st.markdown(
        f"""
        <div class="card" style="text-align:center;">
            <h2 style="color:#58a6ff;">Overall Security Score</h2>
            <h1 style="font-size: 60px; color:#3fb950; font-weight:800;">{score}</h1>
            <p style="color:#8b949e;">Your personal cybersecurity posture score (0–100)</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.progress(score / 100)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    # PASSWORD STRENGTH PIE CHART
    with col1:
        st.subheader("🔐 Password Strength Distribution")

        if st.session_state.accounts:
            counts = {"Weak": 0, "Medium": 0, "Strong": 0}
            for acc in st.session_state.accounts:
                counts[acc["password_strength"]] += 1

            df_pwd = pd.DataFrame(
                {"Strength": list(counts.keys()), "Count": list(counts.values())}
            )

            fig1 = px.pie(
                df_pwd,
                names="Strength",
                values="Count",
                hole=0.3,
            )
            fig1.update_layout(
                margin=dict(l=10, r=10, t=30, b=10),
                height=350,
            )
            st.plotly_chart(fig1, use_container_width=True)
        else:
            st.info("Add accounts to view password strength analytics.")

    # DEVICE SECURITY BAR CHART
        # DEVICE SECURITY BAR CHART
    with col2:
        st.subheader("💻 Device Security Status")

        device = st.session_state.device
        labels = ["Screen Lock", "OS Updated", "Antivirus", "Public Wi-Fi Risk"]
        values = [
            1 if device["screen_lock"] else 0,
            1 if device["os_updated"] else 0,
            1 if device["antivirus"] else 0,
            1 if device["public_wifi"] else 0,
        ]

        df_dev = pd.DataFrame({"Control": labels, "Status": values})

        fig2 = px.bar(
            df_dev,
            x="Control",
            y="Status",
        )
        fig2.update_yaxes(
            tickmode="array",
            tickvals=[0, 1],
            ticktext=["Off / No", "On / Yes"],
        )
        fig2.update_layout(
            margin=dict(l=10, r=10, t=30, b=10),
            height=350,
        )
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # RECOMMENDATIONS WITH SEVERITY
    st.subheader("📝 Personalized Recommendations")
    elif page == "Future Vision (Labs)":
    st.subheader("🔮 Future Vision – Prototype Labs")

    st.markdown(
        """
        <div class="card">
            <h3>Roadmap to a Smarter CyberGuardian</h3>
            <p style='color:#9ca3af; font-size:0.9rem;'>
                This page showcases experimental and planned features such as breach monitoring, 
                ML-based threat prediction, browser extension integration, mobile app vision, and cloud profile analysis.
                Some features are simulated prototypes to demonstrate how the product will evolve.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # ------------------- ROW 1: BREACH + ML THREAT PREDICTION -------------------
    col1, col2 = st.columns(2)

    # Breach API Integration (Simulated)
    with col1:
        st.markdown("### 🧬 Breach API Integration (Prototype)")

        email = st.text_input("Enter email to check for breaches", placeholder="e.g., user@example.com")

        if st.button("Check Breach Status"):
            if email:
                # SIMULATION: In future, this will call a real breach API like HaveIBeenPwned
                st.warning(
                    "⚠ This is a demo. In a production version, this button would query a breach database "
                    "to check if this email appears in known data leaks."
                )
                st.info("For now, we only show the concept and UI flow.")
            else:
                st.error("Please enter an email to check.")

    # ML-Based Threat Prediction (simple rule-based prototype)
    with col2:
        st.markdown("### 🤖 ML-Based Threat Prediction (Concept)")

        st.markdown(
            """
            <p style='color:#9ca3af; font-size:0.9rem;'>
            Here we simulate an ML model by using your current Cyber Score and configuration to assign 
            a <b>Predicted Risk Level</b>.
            In a future version, a real model would learn from behavioral and device data.
            </p>
            """,
            unsafe_allow_html=True
        )

        current_score = calculate_score(st.session_state.accounts, st.session_state.device)
        if current_score >= 75:
            pred_level = "Low"
            msg = "Model prediction: Low chance of near-term compromise."
        elif current_score >= 50:
            pred_level = "Medium"
            msg = "Model prediction: Medium chance of targeted or opportunistic attacks."
        else:
            pred_level = "High"
            msg = "Model prediction: High likelihood of successful attack if no action is taken."

        st.metric("Predicted Threat Level", pred_level)
        st.caption(msg)

    st.markdown("<br>", unsafe_allow_html=True)

    # ------------------- ROW 2: BROWSER EXTENSION + MOBILE APP -------------------
    col3, col4 = st.columns(2)

    with col3:
        st.markdown("### 🌐 Browser Extension – Coming Soon")
        st.markdown(
            """
            <div class="card">
                <p style='color:#9ca3af; font-size:0.9rem;'>
                    Planned browser extension will:
                </p>
                <ul style='color:#e5e7eb; font-size:0.9rem;'>
                    <li>🔐 Detect weak passwords during sign-up / login</li>
                    <li>⚠ Warn on suspicious or phishing URLs</li>
                    <li>🛡 Trigger 2FA reminders in real-time</li>
                </ul>
                <p style='color:#9ca3af; font-size:0.85rem; margin-top:6px;'>
                    This prototype app already defines the backend logic, which the extension can call via APIs later.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col4:
        st.markdown("### 📱 Mobile App – On-the-Go Security")
        st.markdown(
            """
            <div class="card">
                <p style='color:#9ca3af; font-size:0.9rem;'>
                    Future mobile app version will:
                </p>
                <ul style='color:#e5e7eb; font-size:0.9rem;'>
                    <li>📊 Show your Cyber Score and risk level</li>
                    <li>🔔 Send push alerts on high-risk changes</li>
                    <li>📶 Warn you when using unsafe Wi-Fi networks</li>
                </ul>
                <p style='color:#9ca3af; font-size:0.85rem; margin-top:6px;'>
                    Current Streamlit prototype validates the core logic and UI flow before native app development.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ------------------- ROW 3: CLOUD PROFILES -------------------
    st.markdown("### ☁ Cloud Profiles – Future Expansion")

    st.markdown(
        """
        <p style='color:#9ca3af; font-size:0.9rem;'>
            In future versions, CyberGuardian will also analyze the security posture of your cloud services
            such as Google Drive, OneDrive, and cloud email configurations.
        </p>
        """,
        unsafe_allow_html=True
    )

    cloud_services = st.multiselect(
        "Which cloud services do you actively use?",
        ["Google Drive", "OneDrive", "iCloud", "Dropbox", "Gmail", "Outlook", "Other"],
    )

    if cloud_services:
        st.markdown(
            """
            <div class="card">
                <h4>Cloud Security Considerations</h4>
                <p style='color:#9ca3af; font-size:0.9rem;'>
                    Based on your selected services, recommended checks include:
                </p>
                <ul style='color:#e5e7eb; font-size:0.9rem;'>
                    <li>✅ Enabling 2FA / MFA for all cloud accounts</li>
                    <li>🔐 Reviewing file/folder sharing permissions regularly</li>
                    <li>📁 Encrypting highly sensitive documents before upload</li>
                    <li>🧾 Checking activity logs for unusual access or downloads</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.info("Select at least one cloud service to see future cloud security insights.")


    if recs:
        for r in recs:
            severity, color, label = classify_recommendation(r)
            st.markdown(
                f"""
                <div class="reco-box" style="border-left:4px solid {color};">
                    <div style="font-size:13px; color:{color}; font-weight:600; margin-bottom:4px;">
                        {label}
                    </div>
                    <div>{r}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.markdown(
            "<div class='reco-box'>No recommendations at this time. Your setup looks good.</div>",
            unsafe_allow_html=True
        )
