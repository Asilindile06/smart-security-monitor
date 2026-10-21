
import streamlit as st
import json
import pandas as pd

from log_parser import (
    parse_log_line,
    count_failed_logins,
    total_failed_logins,
    find_suspicious_ips,
    count_status_codes,
)

# Set up the application page.
st.title("🔐 Smart Security Monitor")
st.write("Analyze web server logs and identify suspicious login activity.")

# Allow the user to upload a log file.
uploaded_file = st.file_uploader(
    "Upload a web server log file",
    type=["log", "txt"],
    help="Upload a text file containing web server log entries."
)

# Let the user choose how many failed logins trigger an alert.
threshold = st.slider(
    "Failed login threshold",
    min_value=1,
    max_value=20,
    value=3,
    help="Flag an IP address when its failed login count reaches this number."
)

if st.button("Analyze Logs"):
    try:
        # Read the uploaded file or use the sample log file.
        if uploaded_file is not None:
            file_content = uploaded_file.getvalue().decode("utf-8")
            log_lines = file_content.splitlines()
            source_name = uploaded_file.name
        else:
            with open("sample.log", "r", encoding="utf-8") as file:
                log_lines = file.readlines()
            source_name = "sample.log"

        # Parse valid log entries.
        logs = []

        for line in log_lines:
            line = line.strip()

            if line:
                try:
                    log = parse_log_line(line)

                    if log is not None:
                        logs.append(log)

                except (ValueError, IndexError):
                    continue

        # Stop if the selected file contains no valid entries.
        if not logs:
            st.error("No valid log entries were found in the selected file.")
            st.stop()

        # Calculate the overall security results.
        failed_logins = count_failed_logins(logs)
        total_failed = total_failed_logins(failed_logins)
        status_codes = count_status_codes(logs)
        suspicious_ips = find_suspicious_ips(
            failed_logins,
            threshold=threshold
        )

        st.success(f"Successfully analyzed: {source_name}")

        # Display the main dashboard metrics.
        st.subheader("Security Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric("Log Entries Analyzed", len(logs))
        col2.metric("Failed Login Attempts", total_failed)
        col3.metric("Suspicious IP Addresses", len(suspicious_ips))

        # Display failed login activity.
        st.subheader("Failed Login Activity")

        if failed_logins:
            st.bar_chart(failed_logins)
        else:
            st.info("No failed login attempts found.")

        # Display HTTP status code totals.
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

                st.warning(f"Suspicious IP Address: {ip_address}")

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

        # NEW FEATURE: Allow the user to filter the log entries.
        st.subheader("🔎 Investigate Log Entries")

        # Build filter options from the logs that were actually analyzed.
        available_statuses = sorted(
            {log["status"] for log in logs}
        )
        available_paths = sorted(
            {log["path"] for log in logs}
        )
        available_ips = sorted(
            {log["ip"] for log in logs}
        )

        # Let the user select a status code, path and IP address.
        selected_status = st.selectbox(
            "Filter by HTTP status code",
            ["All"] + available_statuses
        )

        selected_path = st.selectbox(
            "Filter by request path",
            ["All"] + available_paths
        )

        selected_ip = st.selectbox(
            "Filter by IP address",
            ["All"] + available_ips
        )

        # Start with all log entries, then apply the chosen filters.
        filtered_logs = []

        for log in logs:
            matches_status = (
                selected_status == "All"
                or log["status"] == selected_status
            )

            matches_path = (
                selected_path == "All"
                or log["path"] == selected_path
            )

            matches_ip = (
                selected_ip == "All"
                or log["ip"] == selected_ip
            )

            # Include the entry only when it matches every selected filter.
            if matches_status and matches_path and matches_ip:
                filtered_logs.append(log)

        # Show the results of the investigation.
        st.write(f"Matching log entries: {len(filtered_logs)}")

        if filtered_logs:
            st.dataframe(filtered_logs, use_container_width=True)

            if filtered_logs:
                st.dataframe(filtered_logs, use_container_width=True)

            # Convert the filtered log entries into a CSV file.
            filtered_logs_df = pd.DataFrame(filtered_logs)
            csv_data = filtered_logs_df.to_csv(index=False).encode("utf-8")

            # Allow the user to download the filtered entries.
            st.download_button(
                label="Download Filtered Logs as CSV",
                data=csv_data,
                file_name="filtered_log_entries.csv",
                mime="text/csv",
            )

        else:
            st.info("No log entries match the selected filters.")

            

        # Prepare the JSON security report.
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

        report_json = json.dumps(report, indent=4)

        # Let the user download the report.
        st.download_button(
            label="Download Security Report (JSON)",
            data=report_json,
            file_name="security_report.json",
            mime="application/json",
        )

    except FileNotFoundError:
        st.error("sample.log was not found. Upload a log file to continue.")

    except UnicodeDecodeError:
        st.error("The uploaded file could not be decoded as UTF-8 text.")
