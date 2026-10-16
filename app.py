import streamlit as st

# Set the title of the application.
st.title("🔐 Cybersecurity Log Analyzer")

# Short description of the project.
st.write(
    "Analyze web server logs and identify suspicious login activity."
)

# Create a button for analyzing the logs.
if st.button("Analyze Logs"):
    st.success("Log analysis started!")