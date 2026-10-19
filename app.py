
import streamlit as st

# Import the functions from our log analyzer.
from log_parser import (
    read_log_file,
    count_failed_logins,
    total_failed_logins,
    find_suspicious_ips,
)

# Set the title of the application.
st.title("🔐 Smart Security Monitor")

# Explain what the application does.
st.write(
    "Analyze web server logs and identify suspicious login activity."
)

