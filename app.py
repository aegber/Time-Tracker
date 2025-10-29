
import streamlit as st
import jwt
import datetime
import hashlib

# Simulated database
users_db = {}
utilization_db = {}

SECRET_KEY = "your_secret_key"

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username):
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        return None

def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in users_db and users_db[username] == hash_password(password):
            st.session_state["token"] = create_token(username)
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials")

def signup():
    st.subheader("Signup")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    if st.button("Signup"):
        if username in users_db:
            st.error("Username already exists")
        else:
            users_db[username] = hash_password(password)
            st.success("User created successfully")

def utilization_entry(username):
    st.subheader("Enter Weekly Utilization")
    week = st.date_input("Week Start Date")
    project_entries = {}
    for i in range(3):
        project = st.text_input(f"Project {i+1} Name", key=f"proj_{i}")
        percent = st.slider(f"{project} % Time", 0, 100, 0, key=f"perc_{i}")
        if project:
            project_entries[project] = percent
    if st.button("Submit Utilization"):
        utilization_db.setdefault(username, []).append({"week": week, "projects": project_entries})
        st.success("Utilization submitted")

def dashboard():
    st.subheader("Dashboard")
    for user, entries in utilization_db.items():
        st.write(f"### {user}")
        for entry in entries:
            total = sum(entry["projects"].values())
            status = "Underloaded" if total < 80 else "Overloaded" if total > 100 else "Balanced"
            st.write(f"Week: {entry['week']}, Total: {total}%, Status: {status}")
            st.write(entry["projects"])

# Main app
st.title("User Utilization Tracker")

if "token" not in st.session_state:
    option = st.radio("Choose Action", ["Login", "Signup"])
    if option == "Login":
        login()
    else:
        signup()
else:
    username = verify_token(st.session_state["token"])
    if username:
        st.sidebar.write(f"Logged in as {username}")
        page = st.sidebar.selectbox("Navigate", ["Enter Utilization", "Dashboard"])
        if page == "Enter Utilization":
            utilization_entry(username)
        else:
            dashboard()
    else:
        st.error("Session expired. Please login again.")
        del st.session_state["token"]
