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
    page_title="CyberGuardian Dashboard",
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
# ACCOUNTS PAGE
# ---------------------------------------------------------
if page == "Accounts":
    st.title("🔐 Accounts Manager")

    name = st.text_input("Account Name")
    password = st.text_input("Password", type="password")
    two_fa = st.checkbox("Is 2FA Enabled?")

    if st.button("Add Account"):
        if name and password:
            pwd_strength = check_password_strength(password)

            st.session_state.accounts.append({
                "name": name,
                "password_strength": pwd_strength,
                "two_fa": two_fa
            })

            st.success(f"Added {name} ({pwd_strength})")

    st.subheader("Your Accounts")

    if st.session_state.accounts:
        df = pd.DataFrame(st.session_state.accounts)
        df.columns = ["Account", "Password Strength", "2FA Enabled"]
        st.dataframe(df)
    else:
        st.info("No accounts yet. Add your first account above.")


# ---------------------------------------------------------
# DEVICE SECURITY PAGE
# ---------------------------------------------------------
elif page == "Device Security":
    st.title("💻 Device Security Checklist")

    device = st.session_state.device

    device["screen_lock"] = st.checkbox("Screen Lock / Biometric Enabled", device["screen_lock"])
    device["os_updated"] = st.checkbox("OS Updated", device["os_updated"])
    device["antivirus"] = st.checkbox("Antivirus Installed", device["antivirus"])
    device["public_wifi"] = st.checkbox("Frequently Uses Public Wi-Fi", device["public_wifi"])

    st.session_state.device = device

    st.success("Settings Updated!")


# ---------------------------------------------------------
# DASHBOARD PAGE
# ---------------------------------------------------------
else:
    st.title("📊 CyberGuardian Dashboard")

    score = calculate_score(st.session_state.accounts, st.session_state.device)

    st.subheader(f"Your Security Score: {score}/100")
    st.progress(score / 100)

    st.write("### Recommendations")
    recs = get_recommendations(st.session_state.accounts, st.session_state.device, score)

    for r in recs:
        st.markdown(f"- {r}")

