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


def load_environment_variables():
    load_dotenv()

def create_session():
    return requests.Session()

def load_cookies(session, cookie_file = 'cookies.pkl'):
    if os.path.exists(cookie_file):
        with open(cookie_file, 'rb') as file:
            session.cookies.update(pickle.load(file))
        cookies_loaded = True
        print("Cookies loaded successfully.")
        return True
    print("Cookie failed to load")
    return False

def is_cookie_valid(session):
    login_url = 'https://api.vrchat.com/api/1/auth/user'
    response = session.get(login_url)
    return response.status_code == 200


def handle_login(session):
    # Prepare the Authorization header
    username = os.getenv("USER_NAME")
    password = os.getenv("PASSWORD")
    auth_str = b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_str}',
        'User-Agent': 'MyVRChatApp/1.0 (contact@example.com)'
    }

    # Attempt to log in using the provided URL
    login_url = 'https://api.vrchat.com/api/1/auth/user'
    response = session.get(login_url, headers=headers)

    if response.status_code == 200 and "requiresTwoFactorAuth" in response.json():
        handle_2fa(session, response.json()["requiresTwoFactorAuth"], headers)
        response = session.get(login_url, headers=headers)
    if response.status_code == 200:
        print("Logged in successfully.")
        return True
    else:
        print("Login failed.")
        return False


def handle_2fa(session, auth_info, headers):
    if "totp" in auth_info:
        totp_code = input("Enter your TOTP 2FA Code: ")
        totp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/totp/verify'
        session.post(totp_url, json={'code': totp_code}, headers=headers)
    elif "otp" in auth_info:
        otp_code = input("Enter your OTP 2FA Code: ")
        otp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/otp/verify'
        session.post(otp_url, json={'code': otp_code}, headers=headers)

def save_cookies(session, cookie_file = 'cookies.pkl'):
    with open(cookie_file,'wb') as file:
        pickle.dump(session.cookies,file)
        print("Cookies saved, yum")

def get_friends_data(session,offset):
    params = {'offset': offset, 'n':100, 'offline': False}
    friends_url = 'https://api.vrchat.com/api/1/auth/user/friends'
    header_no_auth = {
        'User-Agent': 'MyVRChatApp/1.0 (contact@example.com)'
    }
    response = session.get(friends_url, headers=header_no_auth, params=params)
    if response.status_code == 200:

        return response.json()
    else:
        print(f"Request failed with status code: {response.status_code}")
        return None

def process_friends_data(friends_data):
    extracted_data = []
    for user in friends_data:
        if user.get("platform") != 'web':
            user_info = {
                "displayName": user.get("displayName"),
                "status": user.get("status"),
                "id": user.get("id")
            }
            extracted_data.append(user_info)
    return extracted_data

def update_user_data_csv(extracted_data,csv_file = 'user_data.csv'):
    if not os.path.exists(csv_file):
        headers = ["displayName", "id", "Orange", "Green", "Blue"]
        df = pd.DataFrame(columns=headers)
        df.to_csv(csv_file, index=False)
    df_existing = pd.read_csv(csv_file)

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

    df_existing.to_csv(csv_file, index=False)


def main():
    load_environment_variables()
    session = create_session()

    cookie_file = 'cookies.pkl'
    if not load_cookies(session, cookie_file) or not is_cookie_valid(session):
        if not handle_login(session):
            return

    save_cookies(session, cookie_file)

    while True:
        for i in range(3):
            friends_data = get_friends_data(session, i)
            if friends_data:

                extracted_data = process_friends_data(friends_data)

                update_user_data_csv(extracted_data)
        time.sleep(61)



if __name__ == "__main__":
    main()