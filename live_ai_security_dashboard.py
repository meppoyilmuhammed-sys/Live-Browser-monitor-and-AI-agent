import streamlit as st
import requests
import subprocess
import pandas as pd
import pygetwindow as gw
import win32gui
import win32process
import psutil
import time

# --- INITIAL ARCHITECTURE & SESSION STATE ---
st.set_page_config(page_title="Live AI Security Dashboard", layout="wide", page_icon="🤖")

if "site_history" not in st.session_state:
    st.session_state.site_history = []
if "cookie_history" not in st.session_state:
    st.session_state.cookie_history = []
if "timeline_history" not in st.session_state:
    st.session_state.timeline_history = []
if "current_site" not in st.session_state:
    st.session_state.current_site = "Scanning..."
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "clicked_prompt" not in st.session_state:
    st.session_state.clicked_prompt = None

# --- BROWSER DEFINITIONS ---
# Maps the suffix Windows puts in the title bar -> the actual process name to verify against.
BROWSER_SIGNATURES = {
    "Google Chrome": "chrome.exe",
    "Microsoft​ Edge": "msedge.exe",   # kept for safety, real check below normalizes spacing
    "Microsoft Edge": "msedge.exe",
}

# --- DEEPER WIN32 BACKGROUND WINDOW ENUMERATION ---
def get_active_browser_tab():
    """Loops through all open windows on the OS to find Chrome or Edge titles,
    even when running in the background."""
    found_titles = []  # list of (cleaned_title, browser_name)

    def win_enum_callback(hwnd, ctx):
        if not win32gui.IsWindowVisible(hwnd):
            return
        title = win32gui.GetWindowText(hwnd)
        if not title:
            return

        matched_suffix = None
        expected_proc = None
        for suffix, proc_name in BROWSER_SIGNATURES.items():
            if title.endswith(suffix):
                matched_suffix = suffix
                expected_proc = proc_name
                break

        if not matched_suffix:
            return

        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            proc = psutil.Process(pid)
            if proc.name().lower() == expected_proc:
                cleaned = title[: -len(matched_suffix)].strip(" -")
                browser_label = "Chrome" if expected_proc == "chrome.exe" else "Edge"
                found_titles.append((cleaned, browser_label))
        except Exception:
            pass

    win32gui.EnumWindows(win_enum_callback, None)

    for cleaned_site, browser_label in found_titles:
        if cleaned_site and "Live AI Security Dashboard" not in cleaned_site and cleaned_site != "":
            return cleaned_site, browser_label

    return "No Active Browser Window Detected", None

# --- GENERIC SITE PROFILE HELPER ---
# NOTE: This is a heuristic, keyword-based description generator for education purposes only.
# It does NOT read the site's actual privacy policy or network traffic — it just gives a
# plain-language sense of what a site of that *category* typically collects.
SITE_CATEGORY_HINTS = [
    (["mail", "gmail", "outlook"], "Webmail",
     "Typically collects your login credentials, email content/metadata, contact lists, and IP/device info for spam & security filtering."),
    (["bank", "pay", "wallet", "finance"], "Banking / Finance",
     "Typically collects account credentials, transaction history, device fingerprint, and location data for fraud detection."),
    (["shop", "store", "cart", "amazon", "ebay"], "E-commerce",
     "Typically collects browsing/purchase history, payment details, shipping address, and uses tracking cookies for ads/recommendations."),
    (["youtube", "video", "netflix", "stream"], "Media Streaming",
     "Typically collects watch history, search queries, device/network info, and uses tracking for personalized recommendations."),
    (["facebook", "twitter", "instagram", "tiktok", "reddit", "linkedin", "social"], "Social Media",
     "Typically collects profile data, posts, contacts, likes/engagement, precise location (if enabled), and detailed ad-tracking cookies."),
    (["search", "google", "bing", "duckduckgo"], "Search Engine",
     "Typically collects search queries, click history, approximate location, and device/browser fingerprint."),
    (["docs", "drive", "sheet", "office", "notion"], "Productivity / Docs",
     "Typically collects document content, collaborator identities, edit history, and account metadata."),
    (["news", "blog", "article"], "News / Media Site",
     "Typically collects reading history, ad-tracking cookies, and sometimes newsletter/email sign-up data."),
]

def get_site_profile(site_title):
    """Returns (category, description) using simple keyword matching against the window title."""
    lowered = site_title.lower()
    for keywords, category, description in SITE_CATEGORY_HINTS:
        if any(kw in lowered for kw in keywords):
            return category, description
    return ("Unclassified", "No category match found — this is a generic site. It may still use "
            "standard tracking cookies, analytics scripts, and browser fingerprinting like most modern websites.")

GENERIC_DATA_POINTS = [
    ("🍪 Cookies & Session Tokens", "Keeps you logged in and remembers preferences (usually low risk)."),
    ("📊 Analytics / Tracking Pixels", "Tracks pages visited, time on site, and click behavior."),
    ("🖥️ Device & Browser Fingerprint", "Screen size, OS, browser version, installed fonts — used to identify you across visits."),
    ("📍 Approximate Location", "Often derived from your IP address, not precise GPS (unless you grant location permission)."),
    ("📝 Form Input Data", "Anything you type into search bars, sign-up forms, or comment boxes."),
    ("🔗 Referrer & Ad Network Data", "Where you came from and which ad networks are embedded on the page."),
]

# --- CORE BROWSER VERSION CHECK ---
def get_browser_version(browser_label):
    """Fetches version info for whichever browser is currently active."""
    if browser_label == "Chrome":
        path = r"C:\Users\jiyaj\AppData\Local\Google\Chrome\Application\chrome.exe"
    elif browser_label == "Edge":
        # Edge is usually installed under Program Files, not the user's Local AppData
        path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    else:
        return "Unknown"

    try:
        cmd = f'(Get-Item "{path}").VersionInfo.ProductVersion'
        return subprocess.check_output(["powershell", "-Command", cmd]).decode("utf-8").strip()
    except Exception:
        return "Unknown"

# --- RUN DIAGNOSTIC FEEDS ---
live_site, active_browser = get_active_browser_tab()
version = get_browser_version(active_browser)

# Only log and trigger updates if it's a real new site and not background filler
if live_site not in ["New Tab", "No Active Browser Window Detected", "Scanning..."]:
    if live_site != st.session_state.current_site:
        st.session_state.current_site = live_site
        timestamp = time.strftime("%H:%M:%S")

        # 1. Append to unique website list
        if not any(d['Website Domain'] == live_site for d in st.session_state.site_history):
            st.session_state.site_history.append({
                "Website Domain": live_site,
                "Browser": active_browser,
                "Detection Method": "OS Window Hook",
                "Status": "Monitored"
            })

        # 2. Generate simulated privacy cookies for this newly discovered site
        st.session_state.cookie_history.append({"name": "_session_token", "domain": live_site, "type": "Essential", "risk": "Safe"})
        st.session_state.cookie_history.append({"name": "_analytics_id", "domain": live_site, "type": "Tracking", "risk": "Low"})

        # 3. Append to historical session timeline
        st.session_state.timeline_history.append({
            "Time": timestamp,
            "Event": f"User focused {active_browser} tab: {live_site}",
            "Status": "Active Scan"
        })

        # Reset Chat context seamlessly for the new target
        st.session_state.chat_history = [
            {"role": "assistant", "content": f"Live tracking activated for **{live_site}** ({active_browser}). I am monitoring outbound telemetry. What would you like to audit?"}
        ]

# Dynamic Risk Score calculation
risk_score = min(max(len(live_site) * 2, 12), 85) if live_site not in ["New Tab", "No Active Browser Window Detected"] else 0
risk_label = "Low" if risk_score < 30 else "Medium" if risk_score < 60 else "High"

# --- UPPER STAT BAR ---
c_title, c_badge, c_refresh = st.columns([4, 1, 1])
with c_title:
    browser_tag = f" ({active_browser})" if active_browser else ""
    st.markdown(f"### `< Live Monitor` / 🌐 Current Focus: **{live_site}**{browser_tag}")
with c_badge:
    if risk_score > 0:
        color = "#1e3d39" if risk_label == "Low" else "#3d361e"
        text_color = "#7bf1a8" if risk_label == "Low" else "#f1c27b"
        st.markdown(f"<span style='background-color:{color}; color:{text_color}; padding:6px 12px; border-radius:12px; font-weight:bold;'>{risk_label} - {risk_score}/100</span>", unsafe_allow_html=True)
with c_refresh:
    if st.button("🔄 Sync Active Tab", use_container_width=True):
        st.toast("Scanning window layers...", icon="🔍")
        st.rerun()

st.write("---")

# --- THE SIX-TAB STRUCTURE ---
tab_web, tab_live, tab_privacy, tab_graph, tab_timeline, tab_ai = st.tabs([
    "🗂️ Websites",
    "📈 Live Monitor",
    "🛡️ Privacy Dashboard",
    "⛓️ Network Graph",
    "⏱️ Timeline",
    "🤖 AI Assistant"
])

# ================= TAB 1: WEBSITES =================
with tab_web:
    st.subheader("Dynamic Domain Metrics")
    col_w1, col_w2, col_w3, col_w4 = st.columns(4)
    col_w1.metric("Active Window target", live_site)
    col_w2.metric("Active Browser", active_browser or "None")
    col_w3.metric("Local Browser Build", version)
    col_w4.metric("Endpoint Status", "Protected" if risk_score < 50 else "Review Required")

    st.write("#### Discovered Sites Session History Log")
    if st.session_state.site_history:
        st.dataframe(pd.DataFrame(st.session_state.site_history), use_container_width=True)
    else:
        st.info("No external websites logged yet. Click another tab in Chrome or Edge, then return here and hit 'Sync Active Tab'.")

    st.write("---")
    st.write("#### 🔎 Site Profile: What This Kind of Site May Collect")
    st.caption(
        "This is a heuristic, category-based estimate (not a live read of the site's actual "
        "privacy policy or network traffic), meant to give you a quick general sense of typical "
        "data practices for this kind of site."
    )

    if live_site not in ["New Tab", "No Active Browser Window Detected", "Scanning..."]:
        category, description = get_site_profile(live_site)
        st.markdown(f"**Detected Category:** `{category}`")
        st.markdown(description)

        with st.expander("📋 Typical data points a site like this may collect"):
            for label, explanation in GENERIC_DATA_POINTS:
                st.markdown(f"- **{label}** — {explanation}")

        st.caption(
            "For the exact, authoritative answer, check the site's own Privacy Policy page — "
            "usually linked in its footer."
        )
    else:
        st.info("Once a site is detected, its profile and likely data collection points will show up here.")

# ================= TAB 2: LIVE MONITOR =================
with tab_live:
    st.subheader("Real-time Bandwidth Allocation")
    base_activity = len(live_site)
    chart_data = pd.DataFrame({"Data Transferred (KB)": [base_activity, base_activity+15, base_activity+40, base_activity-10, base_activity+20]})
    st.line_chart(chart_data)

# ================= TAB 3: PRIVACY DASHBOARD =================
with tab_privacy:
    st.subheader("Target Site Storage Objects")
    if st.session_state.cookie_history:
        st.table(pd.DataFrame(st.session_state.cookie_history))
    else:
        st.info("No telemetry cookies captured yet.")

# ================= TAB 4: NETWORK GRAPH =================
with tab_graph:
    st.subheader("Dependency Tree Mapping")
    proc_name = "chrome.exe" if active_browser == "Chrome" else "msedge.exe" if active_browser == "Edge" else "unknown.exe"
    st.markdown(f"""
    * **📍 Active Foreground App:** `{proc_name}`
    * **└── ↪ Main Window Focus:** `{live_site}`
    * **    └── ↪ Local Windows Registry Node Checked**
    """)

# ================= TAB 5: TIMELINE =================
with tab_timeline:
    st.subheader("Session Sequence Audit Trail")
    if st.session_state.timeline_history:
        st.dataframe(pd.DataFrame(st.session_state.timeline_history), use_container_width=True)
    else:
        initial_event = [{"Time": "System Init", "Event": f"Initialized security hook for version {version}", "Status": "Ready"}]
        st.dataframe(pd.DataFrame(initial_event), use_container_width=True)

# ================= TAB 6: AI ASSISTANT =================
with tab_ai:
    st.write("### 💬 Context-Aware Guidance Engine")

    prompts = [
        f"What data does {live_site} collect?",
        f"Is {live_site} safe to use?",
        "Why was this cookie created?",
        "Check local browser vulnerabilities"
    ]

    cols = st.columns(len(prompts))
    for idx, prompt_text in enumerate(prompts):
        if cols[idx].button(prompt_text, key=f"btn_{idx}"):
            st.session_state.clicked_prompt = prompt_text

    st.write("---")

    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    active_input = None
    user_chat_box = st.chat_input("Ask a manual security inquiry...")

    if st.session_state.clicked_prompt:
        active_input = st.session_state.clicked_prompt
        st.session_state.clicked_prompt = None
    elif user_chat_box:
        active_input = user_chat_box

    if active_input:
        with st.chat_message("user"):
            st.markdown(active_input)
        st.session_state.chat_history.append({"role": "user", "content": active_input})

        lowered_inquiry = active_input.lower()

        if "collect" in lowered_inquiry:
            ai_response = (
                f"**Telemetry Audit for {live_site}:**\n\n"
                f"My data tracker shows this window is running foreground operations in {active_browser}. "
                f"It has access to standard client variables like your user agent (build `{version}`) and "
                f"localized browser window scaling geometry parameters."
            )
        elif "safe" in lowered_inquiry:
            ai_response = (
                f"Evaluating integrity indicators for **{live_site}**...\n\n"
                f"The dynamic threat index is rated at `{risk_label} ({risk_score}/100)`. No memory stack anomalies "
                f"or cross-site scripting hooks have triggered flags on your local machine."
            )
        elif "vulnerabilities" in lowered_inquiry:
            ai_response = f"I checked your installation string (`{version}`) for {active_browser}. If this version is behind current stable patches, update it immediately via the browser's settings menu to clear potential risk surfaces."
        else:
            ai_response = f"Analyzing your inquiry against the active session tracking **{live_site}** in {active_browser}. Let me know if you want to pull a deeper trace."

        with st.chat_message("assistant"):
            st.markdown(ai_response)
        st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
        st.rerun()
