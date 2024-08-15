import vrchatapi
from vrchatapi.api import authentication_api
from vrchatapi.exceptions import UnauthorizedException
from vrchatapi.models.two_factor_auth_code import TwoFactorAuthCode
from vrchatapi.models.two_factor_email_code import TwoFactorEmailCode
from dotenv import load_dotenv
import os
import requests
from base64 import b64encode
import pickle

# Load environment variables from a .env file
load_dotenv()

# Step 1: Create a requests session
session = requests.Session()

# Step 2: Attempt to load cookies from the saved file
cookie_file = 'cookies.pkl'
cookies_loaded = False

if os.path.exists(cookie_file):
    with open(cookie_file, 'rb') as file:
        session.cookies.update(pickle.load(file))
    cookies_loaded = True
    print("Cookies loaded successfully.")

# Step 3: Check if the loaded cookies are still valid
login_url = 'https://api.vrchat.com/api/1/auth/user'
response = session.get(login_url)

if response.status_code == 200:
    print("Cookie is valid. Logged in using the saved cookie.")
else:
    print("Saved cookie is invalid or expired. Performing normal login.")

    # Prepare the Authorization header
    username = os.getenv("USER_NAME")
    password = os.getenv("PASSWORD")
    auth_str = b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_str}',
        'User-Agent': 'MyVRChatApp/1.0 (contact@example.com)'
    }

    # Attempt to log in using the provided URL
    response = session.get(login_url, headers=headers)

    # Debugging - Log the response content to understand what's happening
    print("Login Response Status Code:", response.status_code)
    print("Login Response Content:", response.text)

    # Handle the login response and 2FA if required
    if response.status_code == 200:
        # Check if 2FA is required
        if "requiresTwoFactorAuth" in response.json():
            print("2FA required, handling it next.")
            
            # Check the response content for clues on the type of 2FA required
            if "totp" in response.json()["requiresTwoFactorAuth"]:
                totp_code = input("Enter your TOTP 2FA Code: ")
                totp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/totp/verify'
                totp_response = session.post(totp_url, json={'code': totp_code}, headers=headers)
                print("TOTP 2FA Submission Response Status Code:", totp_response.status_code)
                print("TOTP 2FA Submission Response Content:", totp_response.text)
            elif "otp" in response.json()["requiresTwoFactorAuth"]:
                otp_code = input("Enter your OTP 2FA Code: ")
                otp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/otp/verify'
                otp_response = session.post(otp_url, json={'code': otp_code}, headers=headers)
                print("OTP 2FA Submission Response Status Code:", otp_response.status_code)
                print("OTP 2FA Submission Response Content:", otp_response.text)
            
            # Retry logging in after 2FA
            response = session.get(login_url, headers=headers)
            print("Post-2FA Login Response Status Code:", response.status_code)
            print("Post-2FA Login Response Content:", response.text)
            
            if response.status_code == 200 and "requiresTwoFactorAuth" not in response.json():
                print("2FA successful, logged in!")
            else:
                print("Failed to log in after 2FA or still requires 2FA.")
        else:
            print("Logged in successfully without needing 2FA.")
    else:
        print("Login failed or encountered an error.")

# Step 4: Save the new or refreshed cookies

if response.status_code == 200:
    current_user_info = session.get('https://api.vrchat.com/api/1/auth/user')
    print(current_user_info.status_code)
    if current_user_info.status_code == 200:
        current_user_data = current_user_info.json()
        print("Logged in as:", current_user_data.get('displayName'))

        # Save the session's cookies to a file
        with open(cookie_file, 'wb') as file:
            pickle.dump(session.cookies, file)
            print("Auth cookie saved successfully!")
    else:
        print("Failed to retrieve current user information.")
