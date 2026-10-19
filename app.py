
import streamlit as st

# Import the functions from our log analyzer.
from log_parser import (
    read_log_file,
    count_failed_logins,
    total_failed_logins,
    find_suspicious_ips,
)
