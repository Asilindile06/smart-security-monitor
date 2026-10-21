
import streamlit as st
import json

# Import the functions from our log analyzer.
from log_parser import (
    read_log_file,
    count_failed_logins,
    total_failed_logins,
    find_suspicious_ips,
    count_status_codes,
)

# Set the title of the application.
st.title("🔐 Smart Security Monitor")

# Explain what the application does.
st.write(
    "Analyze web server logs and identify suspicious login activity."
)

# Let the user choose the failed login threshold.
threshold = st.slider(
    "Failed login threshold",
    min_value=1,
    max_value=20,
    value=3,
    help="Flag an IP address when its failed login count reaches this number."
)

# Analyze the logs when the button is clicked.
if st.button("Analyze Logs"):
    try:
        # Read the log file.
        logs = read_log_file("sample.log")

        # Count failed login attempts for each IP address.
        failed_logins = count_failed_logins(logs)

        # Calculate the total number of failed attempts.
        total_failed = total_failed_logins(failed_logins)

        # Count the different HTTP status codes.
        status_codes = count_status_codes(logs)

        # Identify suspicious IP addresses using the selected threshold.
        suspicious_ips = find_suspicious_ips(
            failed_logins,
            threshold=threshold
        )

        # Display the main security metrics.
        st.subheader("Security Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric("Log Entries Analyzed", len(logs))
        col2.metric("Failed Login Attempts", total_failed)
        col3.metric("Suspicious IP Addresses", len(suspicious_ips))

        # Display failed login attempts by IP address.
        st.subheader("Failed Login Activity")

        if failed_logins:
            st.bar_chart(failed_logins)
        else:
            st.info("No failed login attempts found.")

        # Display HTTP status code counts.
        st.subheader("HTTP Status Code Breakdown")

        if status_codes:
            st.bar_chart(status_codes)
        else:
            st.info("No HTTP status codes found.")

        # Display suspicious IP addresses.
        st.subheader("Suspicious IP Addresses")

        if suspicious_ips:
            for ip_address in suspicious_ips:
                attempts = failed_logins[ip_address]

                # Show the IP address and its failed login count.
                st.warning(
                    f"Suspicious IP Address: {ip_address}"
                )

                # Explain why the alert was triggered.
                st.write(
                    f"This IP address recorded {attempts} failed login "
                    f"attempts. The configured threshold is {threshold}."
                )

                # Explain what the pattern could mean.
                st.caption(
                    "Repeated failed logins may indicate a brute-force "
                    "attempt. This alert is a warning, not proof of an attack."
                )
        else:
            st.success("No suspicious IP addresses detected.")

        # Prepare the security report for download.
        report = {
            "total_log_entries": len(logs),
            "total_failed_logins": total_failed,
            "threshold": threshold,
            "status_codes": status_codes,
            "suspicious_ips": {
                ip_address: failed_logins[ip_address]
                for ip_address in suspicious_ips
            },
        }

        # Convert the report into formatted JSON.
        report_json = json.dumps(report, indent=4)

        # Allow the user to download the report.
        st.download_button(
            label="Download Security Report (JSON)",
            data=report_json,
            file_name="security_report.json",
            mime="application/json",
        )

    except FileNotFoundError:
        st.error(
            "sample.log was not found. Check that it exists."
        )

