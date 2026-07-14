LIVE AI SECURITY DASHBOARD
===========================

A Streamlit desktop dashboard that watches which browser tab you're
currently focused on (Chrome or Edge, on Windows) and gives you a live,
educational snapshot of privacy/security-relevant info about it:
detected site category, likely data collection points, a simple risk
score, a session history log, and a small rule-based chat assistant to
ask about it.

This is a LOCAL, PERSONAL MONITORING TOOL. It reads window titles on
your own machine via the Windows API — it does not access network
traffic, cookies, or any other machine's data.


HOW IT WORKS (CODE WALKTHROUGH)
--------------------------------

1. Session State Setup
   Streamlit reruns the whole script on every interaction, so the app
   keeps its memory (site history, cookie log, timeline, chat history,
   current site) in st.session_state so it persists across those reruns.

2. Active Window Detection — get_active_browser_tab()
   Uses win32gui.EnumWindows to loop through every visible window on
   the OS, looking for a title ending in "Google Chrome" or
   "Microsoft Edge". For each match it double-checks the underlying
   process name (chrome.exe / msedge.exe) via psutil so a window that
   merely mentions "Chrome" in its title doesn't get misdetected. It
   returns the cleaned-up tab title plus which browser it came from.

3. Browser Version Check — get_browser_version()
   Runs a PowerShell command to read the installed .exe's file version
   info, so you can see which build of Chrome/Edge is active and get a
   quick "should I update?" signal.

4. Change Detection & Logging
   Every time the detected site differs from the last known one, the
   app timestamps the change and appends to three logs:
     - site_history   -> unique sites seen this session
     - cookie_history  -> simulated example cookies for that domain
     - timeline_history -> a chronological audit trail of tab switches
   It also resets the chat assistant's context to the new site.

5. Risk Score
   A placeholder heuristic (based on title length) just to demonstrate
   a "Low / Medium / High" badge in the UI. Swap this for a real
   scoring model if you want it to mean something more concrete.

6. Site Profile — get_site_profile() + SITE_CATEGORY_HINTS
   A keyword lookup table (mail, bank, shop, social, streaming, etc.)
   that classifies the current site into a rough category and prints a
   plain-English description of what that type of site commonly
   collects. GENERIC_DATA_POINTS lists common categories of data
   (cookies, fingerprinting, location, form inputs, etc.) shown in an
   expander. This is a HEURISTIC based only on the window title — it
   does not read the site's real privacy policy or network traffic.

7. UI Layout — six tabs
   - Websites: metrics, site history table, and the Site Profile panel
   - Live Monitor: a placeholder bandwidth line chart
   - Privacy Dashboard: the simulated cookie table
   - Network Graph: a simple text tree of the "foreground app" chain
   - Timeline: chronological log of tab-focus events
   - AI Assistant: quick-prompt buttons + free-text chat box that
     answers using simple if/else keyword matching (no external LLM
     call) based on the current site, browser, and risk score


REQUIREMENTS
------------
- Windows 10/11 (uses pywin32 / win32gui, so it is Windows-only)
- Python 3.9+
- pip install streamlit pandas pywin32 psutil pygetwindow requests


RUNNING IT
----------
    streamlit run live_ai_security_dashboard.py

Then switch to a Chrome or Edge window and click "Sync Active Tab" (or
just interact with the app) to see it pick up the new tab.


KNOWN LIMITATIONS
------------------
- Detects the FOREGROUND Chrome/Edge window by title text only; it
  cannot see the actual URL, only whatever text is in the tab title.
- The Edge install path used for the version check is
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" —
  adjust get_browser_version() if your install lives elsewhere.
- Risk score, cookie data, and site category are simplified/simulated
  for demonstration; they are not derived from real telemetry.
- The AI Assistant tab uses basic keyword matching, not a real LLM.


POSSIBLE NEXT STEPS
--------------------
- Pull the actual URL via the browser's accessibility/automation API
  instead of parsing the window title.
- Replace the rule-based chat with a real LLM call for richer answers.
- Persist history to a local file/database across app restarts.
- Add macOS/Linux support (would require replacing the win32 calls).


LICENSE
-------
None - A part of MCA Cyber programme by Amrita University 
