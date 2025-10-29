
import streamlit as st
import jwt
import datetime
import hashlib

# Secret key for JWT
SECRET_KEY = "mysecret"

# Initialize session state
if "users" not in st.session_state:
    st.session_state["users"] = {}
if "utilization" not in st.session_state:
    st.session_state["utilization"] = []
if "token" not in st.session_state:
    st.session_state["token"] = None

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

def signup():
    st.subheader("Sign Up")
    username = st.text_input("Username", key="signup_user")
    password = st.text_input("Password", type="password", key="signup_pass")
    if st.button("Create Account"):
        if username in st.session_state["users"]:
            st.error("Username already exists.")
        else:
            st.session_state["users"][username] = hash_password(password)
            st.success("Account created successfully.")

def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")
    if st.button("Login"):
        hashed = hash_password(password)
        if st.session_state["users"].get(username) == hashed:
            st.session_state["token"] = create_token(username)
            st.success("Logged in successfully.")
        else:
            st.error("Invalid credentials.")

def utilization_form(username):
    st.subheader("Enter Weekly Utilization")
    week = st.date_input("Week of")
    projects = st.text_area("Enter projects and % (e.g., Project A 20%, Project B 30%)")
    if st.button("Submit Utilization"):
        st.session_state["utilization"].append({
            "username": username,
            "week": str(week),
            "projects": projects
        })
        st.success("Utilization submitted.")

def dashboard():
    st.subheader("Dashboard")
    user_filter = st.selectbox("Filter by User", ["All"] + list(st.session_state["users"].keys()))
    week_filter = st.text_input("Filter by Week (YYYY-MM-DD)")

    for entry in st.session_state["utilization"]:
        if (user_filter == "All" or entry["username"] == user_filter) and (week_filter == "" or entry["week"] == week_filter):
            st.write(f"**{entry['username']}** - Week: {entry['week']}")
            st.write(entry["projects"])

# Main app
st.title("User Utilization Tracker")

if st.session_state["token"]:
    user = verify_token(st.session_state["token"])
    if user:
        st.sidebar.write(f"Logged in as: {user}")
        if st.sidebar.button("Logout"):
            st.session_state["token"] = None
        utilization_form(user)
        dashboard()
    else:
        st.session_state["token"] = None
        st.error("Session expired. Please log in again.")
else:
    auth_choice = st.radio("Choose Action", ["Login", "Sign Up"])
    if auth_choice == "Login":
        login()
    else:
        signup()
