# SmartWallet: A Secure Personal Finance Tracker  

SmartWallet is a modern, secure, and user-friendly web application for personal finance management.  
Built with **Streamlit**, it allows users to securely track income and expenses, visualize financial trends, and manage money with ease.  

---

## 🚀 Live Demo  
👉 [Try SmartWallet](https://smartwallet.streamlit.app/)  

---

## ✨ Key Features  
- **Secure User Authentication** – Create accounts with unique credentials, with passwords securely hashed using **bcrypt**.  
- **Password Reset via Email** – Includes "Forgot Password" flow with verification code sent via email.  
- **Persistent Data Storage** – Transactions and credentials stored in **Firebase Firestore (NoSQL)** for permanent access.  
- **Interactive Dashboard** – Current balance display with detailed transaction history.  
- **Financial Trends Visualization** – Dynamic line and bar charts powered by **pandas**.  

---

## 💻 Tech Stack  
- **Frontend**: Streamlit  
- **Backend & Database**: Firebase Firestore (NoSQL)  
- **Authentication & Security**: bcrypt, smtplib  
- **Data Handling**: pandas  
- **Deployment**: Streamlit Cloud  

---

## 🛠️ How to Run Locally  

```bash
# Clone the repository
git clone https://github.com/MahathiChinta/SmartWallet-App.git
cd SmartWallet-App

# Install dependencies
pip install -r requirements.txt

# .streamlit/secrets.toml

[firestore]
type = "service_account"
project_id = "your-project-id"
private_key_id = "your-private-key-id"
private_key = """...""" 
client_email = "..."

[email]
sender_email = "your-email@gmail.com"
sender_password = "your-16-digit-app-password"

# Run the app
streamlit run smart_wallet.py


