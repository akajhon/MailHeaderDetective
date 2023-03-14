import re
import email
import extract_msg
import argparse
import requests
import streamlit as st
import pandas as pd
import textwrap
from streamlit_option_menu import option_menu

st.set_page_config(
    page_title="M.H.D",
    page_icon="📧",
    layout="wide")

def extract_headers(msg_file):
    if msg_file.name.endswith(".msg"):
        # Open the .msg file and extract the metadata
        msg = extract_msg.Message(msg_file)
        metadata = msg.header
    elif msg_file.name.endswith(".eml"):
        # Parse the .eml file and extract the metadata
        msg = email.message_from_bytes(msg_file.read())
        metadata = msg


    # Store the metadata in a list of dictionaries, combining values of duplicate keys
    metadata_list = []
    received_values = []
    if len(metadata) > 2:
        metadata = metadata.items()
    for key, value in metadata:
        if key.lower() == "received":
            received_values.append(value)
        else:
            value_wrapped = textwrap.fill(str(value), width=80)
            metadata_list.append({"key": key, "value": value_wrapped})
    if received_values:
        metadata_list.append({"key": "received", "value": received_values})
    
    return metadata_list, dict(metadata)
    # Open the .msg file and extract the metadata
    msg = extract_msg.Message(msg_file)
    metadata = msg.header

    # Store the metadata in a list of dictionaries, combining values of duplicate keys
    metadata_list = []
    received_values = []
    for key, value in metadata.items():
        if key == "received":
            received_values.append(value)
        else:
            value_wrapped = textwrap.fill(str(value), width=80)
            metadata_list.append({"key": key, "value": value_wrapped})
    if received_values:
        metadata_list.append({"key": "received", "value": received_values})
    
    return metadata_list, metadata

def display_metadata(metadata_list):
    #st.set_page_config(page_title="My App", page_icon=":guardsman:", layout="wide")
    st.write("Metadata")
    df = pd.DataFrame(metadata_list)
    #st.dataframe(df,3000)
    st.table(df)


def display_informations(metadata): 
    # Search for IP addresses in the metadata
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ip_addresses = []
    for key, value in metadata.items():
        ip_addresses += re.findall(ip_pattern, str(value))

    # Search for email addresses in the metadata
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    email_addresses = []
    for key, value in metadata.items():
        email_addresses += re.findall(email_pattern, str(value))

    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    urls_found = []
    for key, value in metadata.items():
        urls_found += re.findall(url_pattern, str(value))

    st.write("IP Addresses")
    st.table(ip_addresses)

    st.write("Email Addresses")
    st.table(email_addresses)

    st.write("URLs Found")
    st.table(urls_found)

if __name__ == '__main__':
    # Navigation Menu *
    selected = option_menu(
        menu_title=None,  # required
        options=["File Upload", "Header Analysis", "Content Report"],  # required
        icons=["file-arrow-up", "card-list", "info-circle"],  # optional
        menu_icon="cast",  # optional
        default_index=0,  # optional
        orientation="horizontal",
        styles={
            "container": {"padding": "0!important"},
            "nav-link": {"font-size": "12px", "text-align": "center", "margin":"0px", "--hover-color": "#eee"},
        }
    )

    if selected == "File Upload":
        st.title("Mail Header Detective")
        if "msg_file" not in st.session_state:
            st.session_state["msg_file"] = ""
        msg_file = st.file_uploader("Upload your .msg or .eml here:", type=["msg", "eml"])
        st.session_state["msg_file"] = msg_file
        #with st.spinner("Extracting metadata from .msg file..."):
    if selected == "Header Analysis":
        msg_file = st.session_state["msg_file"]
        with st.spinner("Extracting metadata from .msg file..."):
            metadata_list, metadata = extract_headers(msg_file)
            display_metadata(metadata_list)
    if selected == "Content Report":
        msg_file = st.session_state["msg_file"]
        metadata_list, metadata = extract_headers(msg_file)
        display_informations(metadata)
