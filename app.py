
import streamlit as st
import json

# Import the functions from our log analyzer.
from log_parser import (
    parse_log_line,
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

# Allow users to upload their own log files.
uploaded_file = st.file_uploader(
    "Upload a web server log file",
    type=["log", "txt"],
    help="Upload a text file containing web server log entries."
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
        # Read the uploaded file or use the sample log.
        if uploaded_file is not None:
            file_content = uploaded_file.getvalue().decode("utf-8")
            log_lines = file_content.splitlines()
            source_name = uploaded_file.name
        else:
            with open("sample.log", "r", encoding="utf-8") as file:
                log_lines = file.readlines()
            source_name = "sample.log"

        # Parse valid log entries and ignore invalid lines.
        logs = []

        for line in log_lines:
            line = line.strip()

            if line:
                try:
                    log = parse_log_line(line)

                    if log is not None:
                        logs.append(log)

                except (ValueError, IndexError):
                    # Ignore malformed log entries.
                    continue

        # Stop if no valid entries were found.
        if not logs:
            st.error(
                "No valid log entries were found in the selected file."
            )
            st.stop()

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

        # Show which file was analyzed.
        st.success(f"Successfully analyzed: {source_name}")

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

                st.warning(
                    f"Suspicious IP Address: {ip_address}"
                )

                st.write(
                    f"This IP address recorded {attempts} failed login "
                    f"attempts. The configured threshold is {threshold}."
                )

                st.caption(
                    "Repeated failed logins may indicate a brute-force "
                    "attempt. This alert is a warning, not proof of an attack."
                )
        else:
            st.success("No suspicious IP addresses detected.")

        # Prepare the security report for download.
        report = {
            "source_file": source_name,
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
            "sample.log was not found. Upload a log file to continue."
        )

    except UnicodeDecodeError:
        st.error(
            "The uploaded file could not be decoded as UTF-8 text."
        )
