import sqlite3
import streamlit as st
import pandas as pd
import os
from PIL import Image
import folium
import streamlit.components.v1 as components
from cryptography.fernet import Fernet

# Generate and load encryption key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    st.success("Encryption key generated and saved successfully!")

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        st.error("Error: secret.key file not found. Please generate the key using 'generate_key()'.")
        return None

# Encrypt password
def encrypt_password(password):
    key = load_key()
    if key:
        cipher = Fernet(key)
        encrypted_password = cipher.encrypt(password.encode()).decode()
        return encrypted_password
    else:
        return None

# Decrypt password
def decrypt_password(encrypted_password):
    try:
        key = load_key()
        if key is None:
            raise ValueError("No key found for decryption.")
        
        cipher = Fernet(key)
        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
        return decrypted_password
    except Exception as e:
        st.error(f"Error during decryption: {str(e)}")
        return None

# Create SQLite database and user table if they don't exist
def create_database():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT)''')
    conn.commit()
    conn.close()

# Add user to database (for registration)
def add_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Check if the username already exists
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        st.error(f"Username '{username}' already exists. Please choose a different username.")
    else:
        encrypted_password = encrypt_password(password)
        if encrypted_password:  # Only proceed if encryption is successful
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
            conn.commit()
            st.success(f"User '{username}' added successfully!")
        else:
            st.error("Failed to encrypt the password. User not added.")

    conn.close()

# Authenticate user
def authenticate_user(username, password):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()  # Fetch one matching user
        conn.close()

        if user:
            encrypted_password = user[1]  # Get the encrypted password from the database
            decrypted_password = decrypt_password(encrypted_password)

            if decrypted_password is None:
                st.error("Decryption failed. Please try again.")
                return False

            if decrypted_password == password:
                return True
            else:
                st.error("Invalid password, please try again.")
                return False
        else:
            st.error("User not found, please sign up.")
            return False
    except Exception as e:
        st.error(f"Error during authentication: {str(e)}")
        return False

# Function to check privacy of sensitive data (CSV content)
def check_data_privacy(data):
    sensitive_columns = ['name', 'email', 'address', 'phone', 'biometric', 'location']
    found_sensitive = [col for col in data.columns if any(sens in col.lower() for sens in sensitive_columns)]
    
    if found_sensitive:
        st.warning(f"Warning: Sensitive information found in the following columns: {', '.join(found_sensitive)}")
    else:
        st.success("No sensitive information found. Your data seems compliant!")
    
    sensitive_patterns = {
        'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        'credit_card': r'(\d{4}[ -]?){3}\d{4}',  # More accurate credit card format
        'biometric': r'\d{5,15}',  # Assuming biometric data is a numeric ID
        'location': r'\d{1,3}\.\d{5,6},\s*\d{1,3}\.\d{5,6}'  # Lat/Lon with more precision
    }

    for col in data.columns:
        col_data = data[col].astype(str)
        for pattern_name, pattern in sensitive_patterns.items():
            if col_data.str.contains(pattern, regex=True).any():
                st.warning(f"Warning: {pattern_name} pattern found in column '{col}'")

# Function to generate a privacy report
def generate_privacy_report(data):
    report = "Privacy Check Report\n"
    report += "====================\n\n"
    
    sensitive_columns = ['name', 'email', 'address', 'phone', 'biometric', 'location']
    found_sensitive = [col for col in data.columns if any(sens in col.lower() for sens in sensitive_columns)]
    
    if found_sensitive:
        report += f"Warning: Sensitive information found in the following columns: {', '.join(found_sensitive)}\n"
    else:
        report += "No sensitive information found based on column names.\n"
    
    sensitive_patterns = {
        'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        'credit_card': r'(\d{4}[ -]?){3}\d{4}',
        'biometric': r'\d{5,15}',
        'location': r'\d{1,3}\.\d{5,6},\s*\d{1,3}\.\d{5,6}'
    }
    
    for col in data.columns:
        col_data = data[col].astype(str)
        for pattern_name, pattern in sensitive_patterns.items():
            if col_data.str.contains(pattern, regex=True).any():
                report += f"Warning: {pattern_name} pattern found in column '{col}'\n"
    
    return report

# Function to display interactive map with sensitive zones
def display_map():
    sensitive_zone = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "geometry": {
                    "type": "Polygon",
                    "coordinates": [
                        [
                            [-73.935242, 40.730610],
                            [-73.985242, 40.730610],
                            [-73.985242, 40.780610],
                            [-73.935242, 40.780610]
                        ]
                    ]
                },
                "properties": {
                    "name": "Sensitive Zone"
                }
            }
        ]
    }

    # Create folium map centered on the given latitude and longitude
    map_center = [40.730610, -73.935242]  # Example coordinates (New York City)
    m = folium.Map(location=map_center, zoom_start=13)
    
    # Add polygon to map
    folium.GeoJson(sensitive_zone).add_to(m)
    
    # Display map in Streamlit app
    st.write("### Sensitive Zone Map")
    
    # Convert folium map to HTML and display it
    map_html = m._repr_html_()  # Convert folium map to HTML
    components.html(map_html, height=500)  # Display the map in Streamlit using HTML

# Main function for the app
def main():
    st.title("Data Privacy Compliance App")
    st.write("Welcome to the Data Privacy Compliance App!")
    st.write("This app helps you check if your data complies with privacy regulations.")
    
    # Help Section
    st.sidebar.write("### Help")
    st.sidebar.write("Use this app to scan files for sensitive data and generate privacy compliance reports.")
    
    # Authentication Section
    choice = st.sidebar.selectbox("Login / Sign Up", ["Login", "Sign Up"])
    
    if choice == "Login":
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        
        if st.sidebar.button("Log In"):
            if authenticate_user(username, password):
                st.sidebar.success(f"Welcome {username}!")
                file_uploader()
            else:
                st.sidebar.error("Invalid credentials, please try again.")
    
    elif choice == "Sign Up":
        username = st.sidebar.text_input("Create Username")
        password = st.sidebar.text_input("Create Password", type="password")
        
        if st.sidebar.button("Sign Up"):
            add_user(username, password)
            st.sidebar.success("User added successfully! You can now log in.")

# File upload function
def file_uploader():
    uploaded_file = st.file_uploader("Upload a file", type=["csv", "txt", "png", "jpg", "jpeg"])
    
    if uploaded_file is not None:
        file_extension = os.path.splitext(uploaded_file.name)[1]
        
        if file_extension == '.csv':
            data = pd.read_csv(uploaded_file)
            st.write("### File Preview")
            st.dataframe(data.head())  # Show preview of the uploaded file
            check_data_privacy(data)  # Check for privacy issues in the CSV
            st.text(generate_privacy_report(data))  # Generate a privacy report
        elif file_extension in ['.png', '.jpg', '.jpeg']:
            image = Image.open(uploaded_file)
            st.image(image, caption='Uploaded Image.', use_column_width=True)
            st.write("Image uploaded successfully!")
        else:
            st.error("Unsupported file type! Only CSV, TXT, and image files are supported.")
        
        display_map()  # Display sensitive zone map

if __name__ == "__main__":
    create_database()
    main()
