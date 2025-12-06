import streamlit as st
import pandas as pd

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

/* Dataframe formatting */
.dataframe {
    color: #e6edf3 !important;
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
    border-left: 4px solid #3fb950;
    border-radius: 6px;
    margin-bottom: 10px;
    color: #c9d1d9;
    font-size: 15px;
}

/* Table styling */
.stDataFrame {
    background-color: #0d1117 !important;
}

/* Progress bar */
[data-testid="stProgressBar"] > div > div {
    background-color: #238636 !important;
}

</style>
"""

st.markdown(dark_theme_css, unsafe_allow_html=True)

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(
    page_title=" CyberGuardian Dashbord",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------------
# INITIALIZE SESSION STATE
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
# LOGIC FUNCTIONS
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
        recs.append("Enable screen lock or biometric security on your device.")

    if not device["os_updated"]:
        recs.append("Update your operating system to the latest version.")

    if not device["antivirus"]:
        recs.append("Install/Update antivirus software.")

    if device["public_wifi"]:
        recs.append("Avoid using public Wi-Fi or use a VPN.")

    if score < 40:
        recs.append("HIGH RISK: Fix critical issues immediately.")
    elif score < 70:
        recs.append("MODERATE RISK: Improve passwords and enable 2FA.")
    else:
        recs.append("LOW RISK: Maintain your current security practices.")

    return recs


# ---------------------------------------------------------
# SIDEBAR NAVIGATION
# ---------------------------------------------------------
st.sidebar.title("🛡️ CyberGuardian")
page = st.sidebar.radio("Navigation", ["Dashboard", "Accounts", "Device Security"])


# ---------------------------------------------------------

# ---------------------------------------------------------
# ACCOUNTS PAGE - UPGRADED UI/UX
# ---------------------------------------------------------
if page == "Accounts":
    st.title("🔐 Accounts Manager")

    st.markdown(
        """
        <div class="card">
            <h3>Add a New Account</h3>
            <p style='color:#8b949e;'>Enter account details below to evaluate password strength and 2FA status.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ----------------- FORM -----------------
    with st.container():
        colA, colB = st.columns(2)

        with colA:
            name = st.text_input("Account Name", placeholder="e.g., Gmail, Instagram")

        with colB:
            password = st.text_input("Password", placeholder="Enter password", type="password")

    two_fa = st.checkbox("Enable 2FA?", help="Two-factor authentication improves security.")

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
            st.warning("Please fill all fields before adding an account.")

    st.markdown("<br>", unsafe_allow_html=True)

    # ----------------- ACCOUNT LIST -----------------
    st.subheader("📋 Your Accounts")

    if st.session_state.accounts:
        styled_accounts = []
        for acc in st.session_state.accounts:
            # Badge colors
            if acc["password_strength"] == "Weak":
                color = "#f85149"   # red
            elif acc["password_strength"] == "Medium":
                color = "#d29922"   # yellow/orange
            else:
                color = "#3fb950"   # green

            badge = f"<span style='color:white;background-color:{color};padding:4px 10px;border-radius:6px;font-size:12px;'>{acc['password_strength']}</span>"

            styled_accounts.append([
                acc["name"],
                badge,
                "✔️ Yes" if acc["two_fa"] else "❌ No"
            ])

        # Display table with HTML badges
        df = pd.DataFrame(styled_accounts, columns=["Account", "Password Strength", "2FA Enabled"])

        st.write(
            df.to_html(escape=False, index=False),
            unsafe_allow_html=True
        )
    else:
        st.info("No accounts added yet. Add your first account above.")



# ---------------------------------------------------------
# DEVICE SECURITY PAGE - UPGRADED UI/UX
# ---------------------------------------------------------
elif page == "Device Security":
    st.title("💻 Device Security Checklist")

    st.markdown(
        """
        <div class="card">
            <h3>Secure Your Devices</h3>
            <p style='color:#8b949e;'>
                Review the following settings on your primary device (laptop / phone). 
                These factors directly affect your overall cyber risk.
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
            help="PIN, pattern, fingerprint or face unlock should be enabled."
        )

        device["os_updated"] = st.checkbox(
            "🧩 Operating System is Up-to-Date",
            device["os_updated"],
            help="Latest OS and security patches are installed."
        )

    with col2:
        device["antivirus"] = st.checkbox(
            "🛡️ Antivirus / Antimalware Installed",
            device["antivirus"],
            help="Real-time protection is enabled and updated."
        )

        device["public_wifi"] = st.checkbox(
            "📶 I Often Use Public Wi-Fi for Logins",
            device["public_wifi"],
            help="Public Wi-Fi (cafes, malls, open hotspots) increases risk."
        )

    st.session_state.device = device

    st.markdown("<br>", unsafe_allow_html=True)

    # Small summary
    st.subheader("🔍 Device Risk Summary")

    issues = []
    if not device["screen_lock"]:
        issues.append("Screen lock is not enabled.")
    if not device["os_updated"]:
        issues.append("Operating system is not updated.")
    if not device["antivirus"]:
        issues.append("Antivirus is not enabled.")
    if device["public_wifi"]:
        issues.append("Public Wi-Fi is used frequently.")

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
# DASHBOARD PAGE
# ---------------------------------------------------------

     # ---------------------------------------------------------
# DASHBOARD PAGE - UPGRADED UI + GRAPHICAL ANALYTICS
# ---------------------------------------------------------
else:
    st.title("📊 CyberGuardian Dashboard")

    score = calculate_score(st.session_state.accounts, st.session_state.device)
    recs = get_recommendations(st.session_state.accounts, st.session_state.device, score)

    st.markdown("""<br>""", unsafe_allow_html=True)

    # -------------------- SCORE CARD ------------------------
    st.markdown(
        f"""
        <div class="card" style="text-align:center;">
            <h2 style="color:#58a6ff;">Overall Security Score</h2>
            <h1 style="font-size: 60px; color:#3fb950; font-weight:800;">{score}</h1>
            <p>Your personal cybersecurity posture score (0–100)</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.progress(score / 100)

    st.markdown("""<br>""", unsafe_allow_html=True)

    # -------------------- LAYOUT (2 Columns) ------------------------
    col1, col2 = st.columns(2)

    # ---------- PIE CHART: PASSWORD STRENGTH ----------
    with col1:
        st.subheader("🔐 Password Strength Distribution")

        if st.session_state.accounts:
            import matplotlib.pyplot as plt

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

    # ---------- BAR CHART: DEVICE SECURITY ----------
    with col2:
        st.subheader("💻 Device Security Status")

        import matplotlib.pyplot as plt

        device = st.session_state.device
        labels = ["Screen Lock", "OS Updated", "Antivirus", "Public Wi-Fi (Risk)"]
        values = [
            1 if device["screen_lock"] else 0,
            1 if device["os_updated"] else 0,
            1 if device["antivirus"] else 0,
            1 if device["public_wifi"] else 0
        ]

        fig2, ax2 = plt.subplots()
        ax2.bar(labels, values)
        plt.xticks(rotation=30, ha='right')

        st.pyplot(fig2)

    st.markdown("""<br>""", unsafe_allow_html=True)

    # -------------------- RECOMMENDATIONS ------------------------
    st.subheader("📝 Personalized Recommendations")

    for r in recs:
        st.markdown(
            f"""
            <div class="reco-box">
                {r}
            </div>
            """,
            unsafe_allow_html=True
        )
   

