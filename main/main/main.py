# Standard library imports
import os
import pickle
import json
import time
import threading
from base64 import b64encode

# Third-party library imports
import requests
import pandas as pd
from dotenv import load_dotenv

# VRChat API imports
import vrchatapi
from vrchatapi.api import authentication_api
from vrchatapi.exceptions import UnauthorizedException
from vrchatapi.models.two_factor_auth_code import TwoFactorAuthCode
from vrchatapi.models.two_factor_email_code import TwoFactorEmailCode

# Tkinter imports
import tkinter as tk
from tkinter import ttk, filedialog

# Loads username+pass from .env file
def load_environment_variables():
    load_dotenv()

# creates the initial session
def create_session():
    return requests.Session()

#attempts to load in existing auth cookie if it exists
def load_cookies(session, cookie_file = 'cookies.pkl'):
    if os.path.exists(cookie_file):
        with open(cookie_file, 'rb') as file:
            session.cookies.update(pickle.load(file))
        cookies_loaded = True
        print("Cookies loaded successfully.")
        return True
    print("Cookie failed to load")
    return False

#Checks if current cookie is valid or not
def is_cookie_valid(session):
    login_url = 'https://api.vrchat.com/api/1/auth/user'
    response = session.get(login_url)
    return response.status_code == 200

# If current cookie is not valid this will be called and will invoke 2fa loggin process
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

# handles 2fa login
def handle_2fa(session, auth_info, headers):
    if "totp" in auth_info:
        totp_code = input("Enter your TOTP 2FA Code: ")
        totp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/totp/verify'
        session.post(totp_url, json={'code': totp_code}, headers=headers)
    elif "otp" in auth_info:
        otp_code = input("Enter your OTP 2FA Code: ")
        otp_url = 'https://api.vrchat.com/api/1/auth/twofactorauth/otp/verify'
        session.post(otp_url, json={'code': otp_code}, headers=headers)

# updates the new auth cookie
def save_cookies(session, cookie_file = 'cookies.pkl'):
    with open(cookie_file,'wb') as file:
        pickle.dump(session.cookies,file)
        print("Cookies saved, yum")

# gets raw friend data from the VRC API
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

# processes the raw data into a more useable format, removes players loggin in through hte website
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

# Updates the CSV file/will generate one if it doesnt already exist
def update_user_data_csv(extracted_data,csv_file = 'user_data.csv'):
    headers = ["displayName", "id"]
    if not os.path.exists(csv_file):
        df = pd.DataFrame(columns=headers)
        df.to_csv(csv_file, index=False)
    df_existing = pd.read_csv(csv_file)

    
    for user in extracted_data:
        new_rows = []
        user_id = user.get('id')
        status_map = {
            'join me': 'Blue',
            'active': 'Green',
            'ask me': 'Orange',
            'busy' : 'Red'
        }

        status = status_map.get(user.get('status'), user.get('status'))
        if status not in df_existing.columns:
            df_existing[status] = 0

        if user_id in df_existing['id'].values:
            index = df_existing.index[df_existing['id'] == user_id].tolist()[0]
            df_existing.at[index, status] += 1
        else:
            new_row = {header: 0 for header in df_existing.columns}
            new_row['displayName'] = user.get('displayName')
            new_row['id'] = user_id

            new_row[status] = 1
            new_rows.append(pd.DataFrame([new_row]))
            df_existing = pd.concat([df_existing] + new_rows, ignore_index=True)

    df_existing.fillna(0, inplace=True)
    for col in df_existing.columns:
        if df_existing[col].dtype != 'object':  # Check if the column is not of object type (which includes strings)
            df_existing[col] = df_existing[col].astype(int)
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
        for i in range(1):
            friends_data = get_friends_data(session, i)
            if friends_data:

                extracted_data = process_friends_data(friends_data)

        update_user_data_csv(extracted_data)        
        time.sleep(61)


class GUIWINDOW(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("USER DATA DISPLAY")
        self.geometry("600x400")
        self.tree = ttk.Treeview(self)
        self.tree.pack(expand=True,fill = "both")
        self.load_CSV_data()
        self.column_dict = {col: True  for col in list(self.df.columns)}
    def clear_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

    def on_header_click(self, col):
        self.column_dict[col] = not self.column_dict[col]
        if(self.column_dict[col]):
            df_sorted = self.df.sort_values(by=col,ascending=False)
        else:
            df_sorted = self.df.sort_values(by=col,ascending=True)

        self.clear_tree()

        for row in df_sorted.itertuples(index=False):
            self.tree.insert("", "end", values=row)
            
    def load_CSV_data(self, csv_file='user_data.csv'):
        # Read the CSV file into a DataFrame
        self.df = pd.read_csv(csv_file)


        self.clear_tree()

        # Define the columns and headings
        self.tree["columns"] = list(self.df.columns)
        self.tree["show"] = "headings"

        for col in self.tree["columns"]:
            # Bind the header click to the sorting function
            self.tree.heading(col, text=col, command=lambda _col=col: self.on_header_click(_col))

        # Insert the data into the Treeview
        for row in self.df.itertuples(index=False):
            self.tree.insert("", "end", values=row)








if __name__ == "__main__":
    #app = GUIWINDOW()
    #app.mainloop()
    main()