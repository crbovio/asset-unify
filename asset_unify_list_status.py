#!/usr/bin/env python3

import os
import json
import xml.etree.ElementTree as ET
import sys
import requests
import logging
import keyring
import json
import argparse
import time
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from urllib.parse import quote

# Load config
with open("config.json") as f:
    config = json.load(f)

GOOGLE_KEYCHAIN_SERVICE = config["GOOGLE_KEYCHAIN_SERVICE"]
GOOGLE_KEYCHAIN_USER = config["GOOGLE_KEYCHAIN_USER"]
SPREADSHEET_ID = config["SPREADSHEET_ID"]
SHEET_NAME = config["SHEET_NAME"]
SCOPES = config["SCOPES"]
JAMF_URL = config["JAMF_URL"]
JAMF_KEYCHAIN_SERVICE = config["JAMF_KEYCHAIN_SERVICE"]
PRELOAD_NAME_EA_ID = 52
JAMF_LDAP_SERVER_ID = config["JAMF_LDAP_SERVER_ID"]
STATIC_GROUP_ID = config["STATIC_GROUP_ID"]


def load_google_credentials():
    raw_json = keyring.get_password(GOOGLE_KEYCHAIN_SERVICE, GOOGLE_KEYCHAIN_USER)
    creds = json.loads(raw_json)
    return service_account.Credentials.from_service_account_info(creds, scopes=SCOPES)

def get_sheet_mapping(credentials):
    service = build("sheets", "v4", credentials=credentials)
    range_name = f"{SHEET_NAME}!A1:Z"
    values = service.spreadsheets().values().get(spreadsheetId=SPREADSHEET_ID, range=range_name).execute().get("values", [])

    if not values:
        return {}

    header = values[0]
    rows = values[1:]

    col_serial = header.index("Serial Number")
    col_name = header.index("Computer Name")
    col_user = header.index("User ID") if "User ID" in header else None

    mapping = {}
    for row in rows:
        if len(row) <= max(col_serial, col_name):
            continue
        serial = row[col_serial].strip()
        desired_name = row[col_name].strip()
        username = row[col_user].strip() if col_user is not None and len(row) > col_user else ""
        if serial:
            mapping[serial] = {"name": desired_name, "username": username}
    return mapping

def get_jamf_token():
    client_id = keyring.get_password(JAMF_KEYCHAIN_SERVICE, "client_id")
    client_secret = keyring.get_password(JAMF_KEYCHAIN_SERVICE, "client_secret")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    response = requests.post(f"{JAMF_URL}/api/oauth/token", headers=headers, data=data)
    response.raise_for_status()
    tok = response.json()
    return tok["access_token"], time.time() + tok["expires_in"] - 60

def get_all_computers(token):
    headers = {"Authorization": f"Bearer {token}"}
    computers = {}
    page = 0
    
    while True:
        url = f"{JAMF_URL}/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION&section=EXTENSION_ATTRIBUTES&section=GROUP_MEMBERSHIPS&page={page}&page-size=100"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            break
        results = resp.json().get("results", [])
        for comp in results:
            serial = comp.get("hardware", {}).get("serialNumber", "")
            name = comp.get("general", {}).get("name", "")
            username = comp.get("userAndLocation", {}).get("username", "") or ""
            realname = comp.get("userAndLocation", {}).get("realname", "") or ""
            email = comp.get("userAndLocation", {}).get("email", "") or ""
            ea_name = None
            
            for ea in comp.get("general", {}).get("extensionAttributes", []):
                if ea.get("name") == "Local Computer Name":
                    values = ea.get("values", [])
                    if values:
                        ea_name = values[0]
                    break
            
            static_group = ""
            for group in comp.get("groupMemberships", []):
                if group.get("groupId") == f"{STATIC_GROUP_ID}":
                    static_group = "true"
                    break
                
            
            if serial:
                computers[serial] = {
                    "name": name,
                    "username": username,
                    "realName": realname,
                    "email": email,
                    "ea_reported": ea_name,
                    "static_group": static_group
                }
        if len(results) < 100:
            break
        page += 1
    return computers

def get_all_preloads(token):
    headers = {"Authorization": f"Bearer {token}"}
    preloads = {}
    page = 0
    while True:
        url = f"{JAMF_URL}/api/v2/inventory-preload/records?page={page}&page-size=100"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            break
        results = resp.json().get("results", [])
        for comp in results:
            serial = comp.get("serialNumber", "")
            username = comp.get("username", "") or ""
            realname = comp.get("fullName", "") or ""
            email = comp.get("emailAddress", "") or ""
            ea_name = ""
            
            for ea in comp.get("extensionAttributes", []):
                if ea.get("name") == "Preload Computer Name":
                    ea_name = ea.get("value", "")
                    break
            
            static_group = ""
            for group in comp.get("groupMemberships", []):
                if group.get("groupId") == f"{STATIC_GROUP_ID}":
                    static_group = "true"
                    break

            if serial:
                preloads[serial] = {
                    "serial": serial,
                    "username": username,
                    "realname": realname,
                    "email": email,
                    "ea_reported": ea_name,
                    "static_group": static_group
                }
        if len(results) < 100:
            break
        page += 1
    return preloads

def ldap_lookup(token, username):
    try:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
        url = f"{JAMF_URL}/JSSResource/ldapservers/id/{JAMF_LDAP_SERVER_ID}/user/{username}"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 404:
            print("❌ LDAP user not found.")
            return None
        if resp.status_code != 200:
            print(f"❌ LDAP error: {resp.text}")
            return None
        root = ET.fromstring(resp.text)
        for user in root.findall("ldap_user"):
            uid = user.findtext("uid") or ""
            ldap_username = user.findtext("username") or ""
            if uid == username or ldap_username == username:
                full_name = user.findtext("realname") or user.findtext("real_name") or ""
                email = user.findtext("email_address") or ""
                return {
                    "username": ldap_username,
                    "full_name": full_name,
                    "email": email
                }
        print("❌ LDAP user structure found but no match.")
        return None
    except Exception as e:
        print(f"❌ LDAP exception: {e}")
        return None    
    
#def compare_google_jamf_inventory(serial, entry, comp):
#   google_name = entry.get("name", "").strip()
#   comp_name = comp.get("name", "").strip()
#   
#   if google_name != comp_name:
#       print(f"⚠️ Name mismatch for {serial}:")
#       print(f"    Jamf name:    {comp_name}")
#       print(f"    Google Sheet name:    {google_name}")
#       return True
#   return False
#       
#def compare_google_jamf_preload(serial, entry, plcomp):
#   google_name = entry.get("name", "").strip()
#   preload_name = plcomp.get("ea_reported", "").strip()
#   
#   if google_name != preload_name:
#       print(f"⚠️ Name mismatch for {serial}:")
#       print(f"    Preload name: {preload_name}")
#       print(f"    Google Sheet name:    {google_name}")
#       return True
#   return False
        
def main():
    creds = load_google_credentials()
    sheet = get_sheet_mapping(creds)
    token, _ = get_jamf_token()
    jamf_computers = get_all_computers(token)
    preload_computers = get_all_preloads(token)
    total_static_group = 0
    printed_inventory_header = False
    printed_preload_header = False
    
    for serial, entry in sheet.items():
        google_name = entry.get("name", "").strip()
        username = entry.get("username", "").strip()
        
        if serial in jamf_computers:
            comp = jamf_computers[serial]
            comp_name = comp.get("name", "").strip()
                
            if google_name != comp_name:
                if not printed_inventory_header:
                    print("\nJAMF INVENTORY MISMATCHES:")
                    printed_inventory_header = True
                    print(f"🔄 Rename needed: {serial} | '{comp_name}' → '{google_name}'") 
            
        if serial in preload_computers:
            plcomp = preload_computers[serial]
            preload_name = plcomp.get("ea_reported", "").strip()
            
            if google_name != preload_name:
                if not printed_preload_header:
                    print("\nJAMF PRELOAD MISMATCHES:")
                    printed_preload_header = True
                    print(f"🔄 Rename needed: {serial} | '{preload_name}' → '{google_name}'") 
    
#   for serial, entry in sheet.items():
#       username = entry.get("username", "").strip()
##       ldap_info = ldap_lookup(token, username) if username else None
#       
#       if serial in preload_computers:
#           compare_google_jamf_preload(serial, entry, preload_computers[serial])
        
#       if serial in jamf_computers:
#           comp = jamf_computers[serial]
#           print(f"Serial number in Google Sheet: {serial}")
#           print(f"Assigned name in Google Sheet: {entry['name']}")
#           print(f"Assigned username in Google Sheet: {entry['username']}")
#           print("Computer in Jamf inventory? Yes")
#           print(f"  Computer name in Jamf: {comp.get('name', '')}")
#           print(f"  Computer name reported by Mac: {comp.get('ea_reported', '')}")
#           if ldap_info:
#               print(f"  User name: {username}")
#               print(f"  Real name: {ldap_info['full_name']}")
#               print(f"  Email Address: {ldap_info['email']}")
#           else:
#               print(f"  LDAP lookup failed or returned nothing.")
#           if str(comp.get('static_group', '')).lower() == "true":
#               print("In renamer static group")
#               total_static_group += 1
#       elif serial in preload_computers:
#           plcomp = preload_computers[serial]
#           print(f"Serial number in Google Sheet: {serial}")
#           print(f"Assigned name in Google Sheet: {entry['name']}")
#           print(f"Assigned username in Google Sheet: {entry['username']}")
#           print("Computer in Jamf preload? Yes")
#           print(f"  Computer to be named in Jamf: {plcomp['ea_reported']}")
#           print(f"  In renamer static group: {plcomp['static_group']}")
#           if ldap_info:
#               print(f"  User name: {username}")
#               print(f"  Real name: {ldap_info['full_name']}")
#               print(f"  Email Address: {ldap_info['email']}")
#       else:
#           print(f" Computer not found: {serial}")
#           
#       print("-" * 50)
#   print (f" Total in renamer group: {total_static_group}")

if __name__ == "__main__":
    main()
    