import streamlit as st
import pandas as pd
from datetime import datetime
from google.cloud import firestore
import bcrypt # A library to securely hash passwords
import smtplib
from email.message import EmailMessage
import random
import string
import time

# --- App Configuration ---
st.set_page_config(
    page_title="SmartWallet",
    page_icon="💰",
    layout="wide",
)

# Initialize session state variables for authentication
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'reset_password_stage' not in st.session_state:
    st.session_state.reset_password_stage = 0

# --- Firestore Connection ---
@st.cache_resource(ttl=3600)
def init_firestore_connection():
    """Initializes and caches the Firestore connection."""
    try:
        # Use Streamlit's secrets to authenticate with Firestore
        # The service account key should be in a file named .streamlit/secrets.toml
        return firestore.Client.from_service_account_info(st.secrets["firestore"])
    except Exception as e:
        st.error(f"Error authenticating with Firestore: {e}. Please ensure your secrets are configured correctly.")
        st.stop()

db = init_firestore_connection()
transactions_collection = db.collection("transactions")
users_collection = db.collection("users")

# --- Password and Email Functions ---
def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed_password):
    """Checks a password against its hashed version."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_verification_code():
    """Generates a random 6-digit alphanumeric verification code."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def send_verification_email(receiver_email, code):
    """Sends a verification email to the user."""
    sender_email = st.secrets["email"]["sender_email"]
    sender_password = st.secrets["email"]["sender_password"]
    
    msg = EmailMessage()
    msg.set_content(f"Your SmartWallet password reset code is: {code}")
    msg["Subject"] = "SmartWallet Password Reset"
    msg["From"] = sender_email
    msg["To"] = receiver_email
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send email. Please check your email credentials in `secrets.toml`. Error: {e}")
        return False

# --- Data Handling Functions ---
def load_user_data():
    """
    Loads transaction data for the logged-in user from the Firestore collection.
    """
    if st.session_state.username:
        query = transactions_collection.where("username", "==", st.session_state.username).stream()
        data = [doc.to_dict() for doc in query]
        
        df = pd.DataFrame(data)
        if not df.empty:
            df['date'] = pd.to_datetime(df['date'])
    else:
        df = pd.DataFrame()
    return df

def save_transaction(date, trans_type, amount, description):
    """Saves a new transaction to the Firestore collection for the logged-in user."""
    doc_ref = transactions_collection.document()
    doc = {
        "username": st.session_state.username,
        "date": date.isoformat(),
        "type": trans_type,
        "amount": float(amount),
        "description": description
    }
    doc_ref.set(doc)

# --- UI Forms ---
def login_form():
    """Displays the login/signup form."""
    with st.sidebar.form("login_form", clear_on_submit=False):
        st.header("Login or Sign Up")
        username_input = st.text_input("Username")
        password_input = st.text_input("Password", type="password")
        signup_email = st.text_input("Email (for new users and password resets)")
        
        login_submitted = st.form_submit_button("Login")
        
        # New "Forgot Password" button
        if st.form_submit_button("Forgot Password?"):
            st.session_state.reset_password_stage = 1
            st.rerun()

        if login_submitted:
            if not username_input or not password_input:
                st.error("Please enter both a username and a password.")
            else:
                user_doc = users_collection.document(username_input).get()
                
                if user_doc.exists:
                    # Existing user, check password
                    user_data = user_doc.to_dict()
                    if check_password(password_input, user_data["hashed_password"]):
                        st.session_state.logged_in = True
                        st.session_state.username = username_input
                        st.sidebar.success(f"Logged in as: **{st.session_state.username}**")
                        st.rerun()
                    else:
                        st.error("Incorrect username or password.")
                elif signup_email:
                    # New user, create account
                    hashed_pw = hash_password(password_input)
                    users_collection.document(username_input).set({
                        "hashed_password": hashed_pw,
                        "email": signup_email
                    })
                    st.session_state.logged_in = True
                    st.session_state.username = username_input
                    st.sidebar.success(f"Account created and logged in as: **{st.session_state.username}**")
                    st.rerun()
                else:
                    st.error("User not found. Please provide an email to create a new account.")

def forgot_password_form():
    """Manages the forgot password flow."""
    with st.sidebar.form("forgot_password_form", clear_on_submit=False):
        st.header("Password Reset")
        
        # Stage 1: Get email and send code
        if st.session_state.reset_password_stage == 1:
            email_input = st.text_input("Enter your email address")
            submitted = st.form_submit_button("Send Verification Code")
            if submitted:
                # Find the user by their email address
                query = users_collection.where("email", "==", email_input).stream()
                user_docs = list(query)
                if not user_docs:
                    st.error("Email not found. Please check the address.")
                else:
                    user_doc = user_docs[0]
                    
                    code = generate_verification_code()
                    if send_verification_email(email_input, code):
                        # Store the code in the user's Firestore document
                        user_doc.reference.update({
                            "verification_code": code
                        })
                        st.session_state.reset_password_stage = 2
                        st.success("Verification code sent to your email!")
                        st.rerun()

        # Stage 2: Enter code and new password
        elif st.session_state.reset_password_stage == 2:
            code_input = st.text_input("Enter verification code")
            new_password = st.text_input("Enter new password", type="password")
            submitted = st.form_submit_button("Reset Password")
            if submitted:
                # Find the user by their verification code
                query = users_collection.where("verification_code", "==", code_input).stream()
                user_docs = list(query)
                if not user_docs:
                    st.error("Invalid verification code.")
                else:
                    user_doc = user_docs[0]
                    user_data = user_doc.to_dict()
                    
                    hashed_pw = hash_password(new_password)
                    user_doc.reference.update({
                        "hashed_password": hashed_pw,
                        "verification_code": firestore.DELETE_FIELD
                    })
                    st.session_state.reset_password_stage = 0
                    st.success("Password has been reset successfully! You can now log in.")
                    st.rerun()

def logout():
    """Logs out the current user."""
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.reset_password_stage = 0
    st.rerun()

# --- Main Application Logic ---
def main():
    if not st.session_state.logged_in and st.session_state.reset_password_stage == 0:
        login_form()
    elif not st.session_state.logged_in and st.session_state.reset_password_stage > 0:
        forgot_password_form()
    else:
        st.title("SmartWallet: Your Personal Pocket Money Tracker")

        # Add a logout button
        st.sidebar.button("Logout", on_click=logout)
        
        # The main content is only shown when the user is logged in
        st.sidebar.success(f"Logged in as: **{st.session_state.username}**")

        # Load data for the logged-in user
        transactions_df = load_user_data()

        # --- Sidebar for Adding Transactions ---
        st.sidebar.header("Add a New Transaction")
        with st.sidebar.form("add_transaction_form", clear_on_submit=True):
            transaction_type = st.selectbox("Type", ["Credit (Income)", "Debit (Expense)"])
            amount = st.number_input("Amount", min_value=0.01, format="%.2f")
            description = st.text_input("Source/Description")
            transaction_date = st.date_input("Date", datetime.now())
            submitted = st.form_submit_button("Add Transaction")

            if submitted:
                if amount > 0 and description:
                    save_transaction(transaction_date, transaction_type.split(" ")[0], amount, description)
                    st.sidebar.success("Transaction added successfully!")
                    st.rerun()
                else:
                    st.sidebar.error("Please fill in both Amount and Description.")

        # --- Main Page Display ---
        st.header(f"Dashboard for {st.session_state.username}")

        # Display current balance
        credits = transactions_df[transactions_df['type'] == 'Credit']['amount'].sum() if not transactions_df.empty else 0
        debits = transactions_df[transactions_df['type'] == 'Debit']['amount'].sum() if not transactions_df.empty else 0
        balance = credits - debits
        st.metric(label="Current Balance", value=f"₹{balance:,.2f}")

        # Display transaction history
        st.header("Transaction History")
        if not transactions_df.empty:
            display_df = transactions_df[['date', 'type', 'amount', 'description']].copy()
            display_df = display_df.sort_values(by="date", ascending=False)
            st.dataframe(display_df, use_container_width=True)
        else:
            st.info("No transactions recorded yet. Add one from the sidebar to get started!")

        # Visualize trends
        st.header("Financial Trends")
        if not transactions_df.empty:
            viz_df = transactions_df.copy()
            viz_df.set_index('date', inplace=True)
            monthly_summary = viz_df.groupby('type').resample('MS')['amount'].sum().unstack(level=0, fill_value=0)

            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Income vs. Expense Over Time")
                st.line_chart(monthly_summary)
            with col2:
                st.subheader("Transaction Breakdown")
                transaction_counts = viz_df.reset_index()['type'].value_counts()
                st.bar_chart(transaction_counts)
        else:
            st.info("No transaction data to visualize.")

if __name__ == "__main__":
    main()
