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
import json
import pandas as pd
import time
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
            elif "otp" in response.json()["requiresTwoFactorAuth"]:
                otp_code = input("Enter your OTP 2FA Code: ")
                otp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/otp/verify'
                otp_response = session.post(otp_url, json={'code': otp_code}, headers=headers)
                print("OTP 2FA Submission Response Status Code:", otp_response.status_code)
            
            # Retry logging in after 2FA
            response = session.get(login_url, headers=headers)
            print("Post-2FA Login Response Status Code:", response.status_code)
            
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
    current_user_info = session.get('https://api.vrchat.com/api/1/auth/user', headers=headers)
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

header_no_auth = {
    'User-Agent': 'MyVRChatApp/1.0 (contact@example.com)'
}


while True:
    for i in range(3):
        params = {
            'offset': i,  # Page number to start from
            'n': 100,  # Number of entries per page
            'offline': False
        }

        friends_url = 'https://api.vrchat.com/api/1/auth/user/friends'
        response = session.get(friends_url, headers=header_no_auth, params = params)

        # Check and print the response
        if response.status_code == 200:
            print("Successfully retrieved friends list!")
            friends_data = response.json()

            print(json.dumps(friends_data, indent=4))
            extracted_data = []
            for user in friends_data:
                if user.get("platform") != 'web':
                    user_info = {
                        "displayName": user.get("displayName"),
                        "status": user.get("status"),
                        "id": user.get("id")
                    }
                    extracted_data.append(user_info)
            sorted_data = sorted(extracted_data, key=lambda x: x['status'])
            max_display_name_length = max(len(item['displayName']) for item in sorted_data)
            max_status_length = max(len(item['status']) for item in sorted_data)

        # Print each item with aligned fields
        #for item in sorted_data:
            #print(f"{item['displayName']:<{max_display_name_length}}  {item['status']:<{max_status_length}}")


        else:
            print(f"Request failed with status code: {response.status_code}")



        if not os.path.exists('user_data.csv'):
            headers = ["displayName", "id", "Orange", "Green", "Blue"]
            df = pd.DataFrame(columns=headers)
            df.to_csv('user_data.csv', index=False)

        df_existing = pd.read_csv('user_data.csv')

        print(df_existing)
        for user in extracted_data:
            user_id = user.get('id')
            if user_id in df_existing['id'].values:
                index = df_existing.index[df_existing['id'] == user_id].tolist()[0]
                if user['status'] == 'ask me':
                    df_existing.at[index, 'Orange'] += 1
                if user['status'] == 'active':
                    df_existing.at[index, 'Green'] += 1
                if user['status'] == 'join me':
                    df_existing.at[index, 'Blue'] += 1
            else:

                df_existing.loc[len(df_existing)] = {
                    'displayName': user.get('displayName'),
                    'id': user_id,
                    'Orange': 1 if user['status'] == 'ask me' else 0,
                    'Green': 1 if user['status'] == 'active' else 0,
                    'Blue': 1 if user['status'] == 'join me' else 0
                }


        df_existing.to_csv('user_data.csv', index=False)
        time.sleep(61)

