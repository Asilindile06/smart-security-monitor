
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

# Analyze the logs when the button is clicked.
if st.button("Analyze Logs"):
    try:
        logs = read_log_file("sample.log")

        # Count failed login attempts for each IP address.
        failed_logins = count_failed_logins(logs)

        # Calculate the total number of failed attempts.
        total_failed = total_failed_logins(failed_logins)

        # Identify IP addresses with 3 or more failed attempts.
        suspicious_ips = find_suspicious_ips(
            failed_logins, threshold=3
        )

        # Display the analysis results.
        st.metric("Log Entries Analyzed", len(logs))
        st.metric("Failed Login Attempts", total_failed)
        st.metric("Suspicious IP Addresses", len(suspicious_ips))

        st.subheader("Suspicious IP Addresses")

        if suspicious_ips:
            for ip_address in suspicious_ips:
                attempts = failed_logins[ip_address]
                st.warning(
                    f"{ip_address}: {attempts} failed login attempts"
                )
        else:
            st.success("No suspicious IP addresses detected.")

    except FileNotFoundError:
        st.error("sample.log was not found. Check that it exists.")