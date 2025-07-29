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

#----------------------------------------------
# JAMF COMPUTER COLLECTION START
#----------------------------------------------

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
            mac_id = comp.get("id", "")
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
                    "mac_id": mac_id,
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
            mac_id = comp.get("id", "")
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
                    "mac_id": mac_id,
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

#----------------------------------------------
# JAMF COMPUTER COLLECTION END
#----------------------------------------------

#----------------------------------------------
# USER FUNCTIONS START
#----------------------------------------------
def get_static_group_xml(group_id, token):
    url = f"{JAMF_URL}/JSSResource/computergroups/id/{group_id}"
    headers = {
        "Accept": "application/xml",
        "Authorization": f"Bearer {token}"  # You can also use basic auth if needed
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        print(f"❌ Error getting static group: {response.status_code}")
        print(response.text)
        return None
    
def remove_computer_from_group_xml(xml_data, comp_id):
    root = ET.fromstring(xml_data)
    computers = root.find("computers")
    removed = False
    
    for computer in list(computers):  # Copy to avoid modifying while iterating
        cid = computer.find("id")
        if cid is not None and cid.text == str(comp_id):
            computers.remove(computer)
            removed = True
            
    return ET.tostring(root, encoding="utf-8"), removed

def put_static_group_xml(group_id, token, updated_xml):
    url = f"{JAMF_URL}/JSSResource/computergroups/id/{group_id}"
    headers = {
        "Content-Type": "application/xml",
        "Accept": "application/xml",
        "Authorization": f"Bearer {token}"
    }
    response = requests.put(url, headers=headers, data=updated_xml)
    if response.status_code == 201:
        print(f"✅ Successfully updated group {group_id}")
    else:
        print(f"❌ Failed to update group: {response.status_code}")
        print(response.text)
        
def remove_from_static_group(token, group_id, comp_id):
    xml_data = get_static_group_xml(group_id, token)
    if not xml_data:
        return
    
    updated_xml, removed = remove_computer_from_group_xml(xml_data, comp_id)
    if not removed:
        print(f"ℹ️ Computer {comp_id} not found in group {group_id}")
        return
    
    put_static_group_xml(group_id, token, updated_xml)
    
    
def add_computer_to_group_xml(xml_data, comp_id):
    root = ET.fromstring(xml_data)
    computers = root.find("computers")
    
    if computers is None:
        # Create <computers> node if it doesn't exist
        computers = ET.SubElement(root, "computers")
        
    found = False
    for c in computers.findall("computer"):
        id_elem = c.find("id")
        if id_elem is not None and id_elem.text == str(comp_id):
            found = True
            break
        
    if not found:
        new_comp = ET.SubElement(computers, "computer")
        ET.SubElement(new_comp, "id").text = str(comp_id)
        added = True
    else:
        added = False
        
    return ET.tostring(root, encoding="utf-8"), added

def add_to_static_group(token, group_id, comp_id):
    xml_data = get_static_group_xml(group_id, token)
    if not xml_data:
        return
    
    updated_xml, added = add_computer_to_group_xml(xml_data, comp_id)
    if not added:
        print(f"ℹ️ Computer {comp_id} is already in group {group_id}")
        return
    
    put_static_group_xml(group_id, token, updated_xml)

#----------------------------------------------
# STATIC GROUP FUNCTIONS END
#----------------------------------------------

#----------------------------------------------
# USER FUNCTIONS START
#----------------------------------------------

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


def assign_user_to_inventory(token, comp_id, username, full_name, email):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{JAMF_URL}/v1/computers-inventory-detail/{comp_id}"
    payload = {
        "userAndLocation": {
            "username": username,
            "realname": full_name,
            "email": email
        }
    }

    resp = requests.patch(url, headers=headers, json=payload)
    return resp.status_code in (200, 204)

def clear_user_from_inventory(token, comp_id):
    url = f"{JAMF_URL}/api/v1/computers-inventory-detail/{comp_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    payload = {
        "userAndLocation": {
            "username": "",
            "realname": "",
            "email": ""
        }
    }
    
    response = requests.patch(url, headers=headers, json=payload)

    try:
        json_response = response.json()
    except Exception:
        json_response = response.text
        
    if response.status_code == 200:
        return True, json_response
    else:
        print(f"❌ Failed to clear user from inventory ID {comp_id}. Status: {response.status_code}")
        print(f"Response: {json_response}")
        return False, json_response


#----------------------------------------------
# USER FUNCTIONS END
#----------------------------------------------

#----------------------------------------------
# COMPUTER RENAME START
#----------------------------------------------
def inventory_rename(token, comp_id, new_comp_name):
    url = f"{JAMF_URL}/api/v1/computers-inventory-detail/{comp_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
                "general": {
                    "name": new_comp_name
                }
            }

    resp = requests.patch(url, headers=headers, json=payload)
    return resp.status_code in (200, 204)

#----------------------------------------------
# COMPUTER RENAME END
#----------------------------------------------

#----------------------------------------------
# PRELOAD UPDATE START
#----------------------------------------------

def create_preload(token, serial, pl_name, username, full_name, email, asset):
    url = f"{JAMF_URL}/api/v2/inventory-preload/records"
    payload = {
        "device-type": "Computer",
        "serialNumber": serial,
            "username": username,
            "fullName": full_name,
        "emailAddress": email,
            "assetTag": asset
        }

    headers = {
        "accept": "application/json",
        "content-type": "application/json"    
    }
    response = requests.post(url, json=payload, headers=headers)

    print(response.text)
    

#----------------------------------------------
# PRELOAD UPDATE END
#----------------------------------------------

# def preload_update(token, pl_id, pl_ea, pl_username, pl_realname, pl_email):


# // COMPUTER RENAME FUNCTIONS

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Run without prompts")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    creds = load_google_credentials()
    sheet = get_sheet_mapping(creds)
    token, _ = get_jamf_token()
    jamf_computers = get_all_computers(token)
    preload_computers = get_all_preloads(token)
    total_static_group = 0
    printed_inventory_header = False
    printed_preload_header = False
    
    inventory_user_updated = 0
    inventory_name_updated = 0
    
    for serial, entry in sheet.items():
        google_name = entry.get("name", "").strip()
        username = entry.get("username", "").strip()
        
        if serial in jamf_computers:
            comp = jamf_computers[serial]
            comp_name = comp.get("name", "").strip()
            comp_id = comp.get("mac_id", "").strip()
            static_group = comp.get("static_group", "").strip()
            local_name_ea = comp.get("ea_reported", "")
            comp_user = comp.get("username", "")

            
            if google_name != comp_name:
                print(f"🔄 Inventory Rename needed: {comp_id}: {serial} | '{comp_name}' → '{google_name}'")

                # Rename Mac to Google name. Add computer to static group.
                if args.verbose or not args.force:
                    if args.force or input("Update computer name? (Y/N): ").strip().lower() == "y":
                        if inventory_rename(token, comp_id, google_name):
                            print(f" {serial}: {comp_name} changed to {google_name}")
                            add_to_static_group(token, int(STATIC_GROUP_ID), int(comp_id))
                            inventory_name_updated += 1


            # If Jamf Inventory Name matches Google Sheets Name and is already in the Aseet Unify static group,
            # but the extension attribute hasn't reported the updated name, inform that we're just awaiting awaiting 
            # the computer to run an inventory update to reflect that the name has stuck. No action needed.

            if google_name == comp_name and google_name != local_name_ea and static_group:
                print(f"⚠️ Name correct. {comp_id}:{serial}| {comp_name} Awaiting Inventory Update")
                
            # If Jamf Inventory Name matches Google Sheets Name and the reported name extension attribute also matches,
            # the name has officially stuck and the computer will be removed from the static group.    

            if local_name_ea == google_name and static_group:
                print(f"✅ Name correct and inventory updated. {comp_id}:{serial}| {comp_name} Removing from Static Group.")
                
                # Remove from Static Group
                remove_from_static_group(token, int(STATIC_GROUP_ID), int(comp_id))
                
            if username != comp_user:
                ldap_info = ldap_lookup(token, username) if username else None
                ldap_full_name = ldap_info['full_name'] if username else None
                ldap_email = ldap_info['email'] if username else None

                # If Jamf assigned username doesn't match the Google assigned username, assign to Google username
                if username and comp_user:
                    print(f"❌ User mismatch. {comp_id}:{serial}| {comp_name} Should be assigned to {username}:{ldap_full_name}. Replacing user {comp_user} with {username}")
                    if args.verbose or not args.force:
                        if args.force or input("Replace user (Y/N): ").strip().lower() == "y":
                           if assign_user_from_inventory(token, comp_id, username, ldap_full_name, ldap_email):
                            print(f"Replacing {comp_user} from {serial}:{comp_name} with {username}:{ldap_full_name}")
                            inventory_user_updated += 1

                # If there's no Google assigned username, clear username in Jamf
                elif comp_user != "":
                    print(f"❌ {comp_id}:{serial}| {comp_name} should have no user assigned. Removing {comp_user}.")
                    if args.verbose or not args.force:
                        print (f"🧼 Purging user {comp_user} from {serial}:{comp_name}")
                        if args.force or input("Purge user (Y/N): ").strip().lower() == "y":
                           if clear_user_from_inventory(token, comp_id):
                            print(f"Clearing {comp_user} from {serial}:{comp_name}")
                            inventory_user_updated += 1
            
        if serial in preload_computers:
            plcomp = preload_computers[serial]
            preload_name = plcomp.get("ea_reported", "").strip()
            preload_id = plcomp.get("mac_id", "").strip()
            
            mismatch_messages = []
            
            if google_name != preload_name:
                print(f"🔄 Preload Rename needed: {preload_id}: {serial} | '{preload_name}' → '{google_name}'")
    
    print(f"Jamf Inventory Name Updates: {inventory_name_updated}")  
    print(f"Jamf User Updates: {inventory_user_updated}")
                
                
if __name__ == "__main__":
	main()