import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import random  # for security tip of the day

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
page = st.sidebar.radio("Navigation", ["Dashboard", "Accounts", "Device Security"])

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
# ---------------------------------------------------------
# ACCOUNTS PAGE - UPGRADED UI/UX + PASSWORD HEALTH + REUSE
# ---------------------------------------------------------
if page == "Accounts":
    st.subheader("🔐 Accounts Manager")

    st.markdown(
        """
        <div class="card">
            <h3>Add a New Account</h3>
            <p style='color:#8b949e;'>Enter your account details to evaluate password strength, reuse, and 2FA status.</p>
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
            # store password internally (not displayed) so we can detect reuse
            st.session_state.accounts.append({
                "name": name,
                "password_strength": pwd_strength,
                "two_fa": two_fa,
                "password": password
            })
            st.success(f"Added {name} ({pwd_strength})")
        else:
            st.warning("Please provide both account name and password.")

    st.markdown("<br>", unsafe_allow_html=True)

    st.subheader("📋 Your Accounts")

    if st.session_state.accounts:
        styled_accounts = []
        passwords = [acc["password"] for acc in st.session_state.accounts]

        for acc in st.session_state.accounts:
            # badge color
            if acc["password_strength"] == "Weak":
                color = "#f85149"
                base_score = 40
            elif acc["password_strength"] == "Medium":
                color = "#d29922"
                base_score = 70
            else:
                color = "#3fb950"
                base_score = 90

            # simple per-account health score
            health_score = base_score
            if acc["two_fa"]:
                health_score += 5
            # if password reused, reduce
            if passwords.count(acc["password"]) > 1:
                health_score -= 15

            health_score = max(0, min(100, health_score))

            badge = f"<span style='color:white;background-color:{color};padding:4px 10px;border-radius:6px;font-size:12px;'>{acc['password_strength']}</span>"

            styled_accounts.append([
                acc["name"],
                badge,
                "✔️ Yes" if acc["two_fa"] else "❌ No",
                f"{health_score}/100"
            ])

        df = pd.DataFrame(styled_accounts, columns=["Account", "Password Strength", "2FA Enabled", "Health Score"])

        st.write(df.to_html(escape=False, index=False), unsafe_allow_html=True)

        # Password reuse detector (simple)
        if len(passwords) != len(set(passwords)):
            st.warning("⚠️ Password reuse detected across accounts. Avoid using the same password on multiple services.")
    else:
        st.info("No accounts added yet. Use the form above to add your first account.")

# ---------------------------------------------------------
# DASHBOARD PAGE - PRO VERSION (SHIELD + TODO + GRAPHS + PROFILE)
# ---------------------------------------------------------
else:
    st.subheader("📊 CyberGuardian Overview")

    score = calculate_score(st.session_state.accounts, st.session_state.device)
    recs = get_recommendations(st.session_state.accounts, st.session_state.device, score)

    # ---------- Security Shield Status ----------
    if score >= 75:
        shield_label = "🟢 Secure"
        shield_desc = "Your overall security posture is good. Maintain your current habits."
    elif score >= 50:
        shield_label = "🟡 Warning"
        shield_desc = "You have some important issues to fix to stay safe."
    else:
        shield_label = "🔴 Risky"
        shield_desc = "Your accounts and devices are at high risk. Immediate action is recommended."

    # ---------- Security Insight of the Day ----------
    tips = [
        "Never reuse the same password across banking, email, and social media.",
        "Always enable 2FA on email and financial accounts first.",
        "Avoid logging into important accounts on public Wi-Fi without a VPN.",
        "Update your operating system and apps monthly to patch vulnerabilities.",
        "Use a password manager to store long, unique passwords safely."
    ]
    daily_tip = random.choice(tips)

    # ---------- Profile & Platform Selection ----------
    platform = st.selectbox(
        "Primary Platform",
        ["Android + Windows", "iPhone + MacOS", "Only Mobile", "Only Laptop/Desktop"],
        help="Used to customize security recommendations in future versions."
    )

    col_profile, col_score = st.columns([1, 2])

    with col_profile:
        st.markdown(
            f"""
            <div class="card">
                <h3>👤 User Profile</h3>
                <p style='color:#8b949e; font-size:14px;'>
                    Security Level: <b>{shield_label}</b><br>
                    Primary Platform: <b>{platform}</b><br>
                    Accounts Tracked: <b>{len(st.session_state.accounts)}</b><br>
                </p>
                <p style='color:#8b949e; font-size:13px; margin-top:8px;'>
                    💡 Tip of the Day:<br> {daily_tip}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_score:
        st.markdown(
            f"""
            <div class="card" style="text-align:center;">
                <h3 style="color:#58a6ff;">Overall Security Score</h3>
                <h1 style="font-size: 60px; color:#3fb950; font-weight:800;">{score}</h1>
                <p style="color:#8b949e;">Score range: 0–100 (higher is safer)</p>
                <p style="margin-top:4px; color:#8b949e;">Status: <b>{shield_label}</b></p>
                <p style="margin-top:4px; color:#8b949e; font-size:13px;">{shield_desc}</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.progress(score / 100)

    st.markdown("<br>", unsafe_allow_html=True)

    # ---------- Charts Row ----------
    col1, col2 = st.columns(2)

    # PASSWORD STRENGTH PIE CHART
    with col1:
        st.subheader("🔐 Password Strength Distribution")

        if st.session_state.accounts:
            counts = {"Weak": 0, "Medium": 0, "Strong": 0}
            for acc in st.session_state.accounts:
                counts[acc["password_strength"]] += 1

            labels = list(counts.keys())
            values = list(counts.values())

            fig1, ax1 = plt.subplots()
            ax1.pie(values, labels=labels, autopct='%1.1f%%')
            ax1.axis('equal')
            st.pyplot(fig1)
        else:
            st.info("Add accounts to view password strength analytics.")

    # DEVICE SECURITY BAR CHART
    with col2:
        st.subheader("💻 Device Security Status")

        device = st.session_state.device
        labels = ["Screen Lock", "OS Updated", "Antivirus", "Public Wi-Fi (Risk)"]
        values = [
            1 if device["screen_lock"] else 0,
            1 if device["os_updated"] else 0,
            1 if device["antivirus"] else 0,
            1 if device["public_wifi"] else 0,
        ]

        fig2, ax2 = plt.subplots()
        ax2.bar(labels, values)
        plt.xticks(rotation=30, ha='right')
        st.pyplot(fig2)

    st.markdown("<br>", unsafe_allow_html=True)

    # ---------- Security To-Do List (Action-Oriented) ----------
    st.subheader("✅ Security To-Do List")

    todo_items = []

    # Build todo list from actual issues
    weak_accounts = [a["name"] for a in st.session_state.accounts if a["password_strength"] == "Weak"]
    no_2fa_accounts = [a["name"] for a in st.session_state.accounts if not a["two_fa"]]

    if weak_accounts:
        todo_items.append(f"Change weak passwords for: {', '.join(weak_accounts)}")
    if no_2fa_accounts:
        todo_items.append(f"Enable 2FA on: {', '.join(no_2fa_accounts)}")

    if not device["screen_lock"]:
        todo_items.append("Enable screen lock / biometric on your primary device.")
    if not device["os_updated"]:
        todo_items.append("Update your operating system to the latest version.")
    if not device["antivirus"]:
        todo_items.append("Install or enable antivirus/antimalware protection.")
    if device["public_wifi"]:
        todo_items.append("Avoid logging into important accounts on public Wi-Fi without VPN.")

    if todo_items:
        for i, item in enumerate(todo_items):
            col_todo, col_btn = st.columns([4, 1])
            with col_todo:
                st.markdown(f"- {item}")
            with col_btn:
                st.button("Mark Done", key=f"todo_{i}")
    else:
        st.markdown(
            "<div class='reco-box'>✅ No urgent tasks. Keep maintaining good security habits.</div>",
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ---------- Login History Risk (Simulated) ----------
    st.subheader("🕵️ Simulated Login Risk Signals")

    st.markdown(
        """
        <div class="card">
            <p style='color:#8b949e; font-size:14px;'>
                In a future version, this section will be powered by real login metadata.<br>
                For now, it demonstrates how unusual login patterns could be flagged:
            </p>
            <ul style='color:#c9d1d9; font-size:14px;'>
                <li>⚠ Login from a new device at 2:30 AM</li>
                <li>⚠ Multiple failed login attempts within 5 minutes</li>
                <li>⚠ Login from a different country than usual</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ---------- Recommendations with Severity ----------
    st.subheader("📝 Personalized Recommendations")

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
