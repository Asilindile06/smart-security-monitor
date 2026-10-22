# 🔐 Smart Security Monitor

A Python-based cybersecurity project that analyzes web server logs to identify suspicious login activity and help investigate potential security threats.

## 📌 Project Overview

Smart Security Monitor is a web-based log analysis tool built with Python and Streamlit. It processes web server log entries, identifies repeated failed login attempts, flags potentially suspicious IP addresses, and provides downloadable reports.

The goal of this project is to demonstrate how log analysis can help security teams monitor activity and investigate possible brute-force login attempts.

## ✨ Features

- **Web Server Log Analysis:** Analyze log entries from a sample log file or upload a custom `.log` or `.txt` file.
- **Failed Login Detection:** Identify and count unsuccessful login attempts.
- **Suspicious IP Detection:** Flag IP addresses that reach a configurable failed-login threshold.
- **Security Dashboard:** Display total log entries, failed login attempts, and suspicious IP addresses.
- **HTTP Status Code Analysis:** View a breakdown of HTTP response status codes.
- **Investigation Filters:** Filter log entries by HTTP status code, request path, and IP address.
- **CSV Export:** Download filtered log entries for further investigation.
- **JSON Security Reports:** Download a structured report containing analysis results and suspicious IP activity.

## 🛠️ Technologies Used

- Python
- Streamlit
- Pandas
- JSON
- Git and GitHub

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Asilindile06/smart-security-monitor.git
```

### 2. Navigate to the project directory

```bash
cd smart-security-monitor
```

### 3. Create a virtual environment

```bash
python3 -m venv venv
```

### 4. Activate the virtual environment

On Ubuntu or WSL:

```bash
source venv/bin/activate
```

### 5. Install the dependencies

```bash
pip install streamlit pandas
```

### 6. Run the application

```bash
streamlit run app.py
```

Streamlit will provide a local URL that you can open in your browser to use the application.

## 🚀 How to Use

1. Launch the application.
2. Upload a web server log file, or use the default `sample.log` file.
3. Adjust the failed-login threshold using the slider.
4. Click **Analyze Logs**.
5. Review the security overview, failed login activity, HTTP status codes, and suspicious IP alerts.
6. Use the investigation filters to narrow down log entries.
7. Download filtered entries as a CSV file or download the complete security summary as a JSON report.

## 📊 Understanding the Results

The application presents several indicators to help investigate web server activity:

- **Log Entries Analyzed:** The number of valid log entries processed.
- **Failed Login Attempts:** The total number of unsuccessful login attempts detected.
- **Suspicious IP Addresses:** The number of IP addresses that meet the configured failed-login threshold.
- **HTTP Status Code Breakdown:** The distribution of response status codes found in the analyzed logs.

Repeated failed logins can indicate suspicious activity, including a possible brute-force attempt. However, an alert alone does not prove that an attack has occurred.

## 📁 Project Structure

```text
smart-security-monitor/
├── app.py
├── log_parser.py
├── main.py
├── sample.log
├── tests/
│   └── test_log_parser.py
├── README.md
└── .gitignore
```

*This structure reflects the main project files; additional files may be present in the repository.*

## 🧪 Testing

The project includes unit tests for log parsing and analysis functions.

To run the tests from the project directory, activate the virtual environment and execute:

```bash
python -m unittest discover -s tests
```

## 🔒 Security and Limitations

- The tool analyzes the log data provided to it; it does not automatically monitor live network traffic.
- Suspicious IP alerts are indicators for further investigation, not definitive proof of malicious activity.
- Results depend on the quality and format of the supplied log entries.
- Avoid uploading logs containing sensitive personal information or confidential production data to environments that are not approved to handle them.

## 🎯 Project Goals

This project demonstrates practical skills in:

- Python programming and data processing
- Log parsing and security event analysis
- Identifying patterns in failed login activity
- Building interactive dashboards with Streamlit
- Exporting structured data in CSV and JSON formats
- Writing unit tests and using Git for version control

## 👩🏽‍💻 Author

**Asilindile06**

GitHub: [@Asilindile06](https://github.com/Asilindile06)

---

*Smart Security Monitor — turning web server logs into actionable security insights.*
