import streamlit as st

def login():
    st.sidebar.subheader("🔐 Login")

    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authenticated = True
        else:
            st.sidebar.error("Invalid credentials")

def check_auth():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    return st.session_state.authenticated