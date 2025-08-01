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

def verbose_log(serial, name, username, asset, label="▶"):
    print(f"{label} SERIAL: {serial}")
    print(f"   ↪ Name      : {name}")
    print(f"   ↪ Username  : {username}")
    print(f"   ↪ Asset Tag : {asset}")

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
    col_asset = header.index("Asset Tag") if "Asset Tag" in header else None

    mapping = {}
    for row in rows:
        required_indices = [col_serial, col_name]
        if col_asset is not None:
            required_indices.append(col_asset)
        if col_user is not None:
            required_indices.append(col_user)
            
        # 👇 Pad short rows with empty strings
        row += [""] * (max(required_indices) + 1 - len(row))
        
        serial = row[col_serial].strip().upper()
        if serial == "EXIT":
            continue
        desired_name = row[col_name].strip()
        username = row[col_user].strip() if col_user is not None else ""
        asset = row[col_asset].strip() if col_asset is not None else ""
        
        if serial:
            mapping[serial] = {"name": desired_name, "username": username, "asset": asset}
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
            asset = comp.get("general", {}).get("assetTag", "")
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
                    "asset": asset,
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
            asset = comp.get("assetTag", "") or ""
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
                    "asset": asset,
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

# --------------- JAMF LDAP + INVENTORY OPS -----------
    
def ldap_lookup(token, username):
    url = f"{JAMF_URL}/JSSResource/ldapservers/id/{JAMF_LDAP_SERVER_ID}/user/{username}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
    resp = requests.get(url, headers=headers)
    
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        print(f"❌ LDAP error: {resp.status_code} - {resp.text}")
        return None
    
    try:
        root = ET.fromstring(resp.text)
        for user in root.findall("ldap_user"):
            return {
                "username": user.findtext("username") or "",
                "full_name": user.findtext("realname") or user.findtext("real_name") or "",
                "email": user.findtext("email_address") or ""
            }
    except Exception as e:
        print(f"❌ LDAP parse error: {e}")
        return None
    
def inventory_rename(token, comp_id, new_name):
    url = f"{JAMF_URL}/api/v1/computers-inventory-detail/{comp_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = { "general": { "name": new_name } }
    resp = requests.patch(url, headers=headers, json=payload)
    return resp.status_code in (200, 204)

def assign_user_from_inventory(token, comp_id, username, full_name, email):
    url = f"{JAMF_URL}/api/v1/computers-inventory-detail/{comp_id}"
    headers = {"Authorization": f"Bearer {token}"}
    payload = { "userAndLocation": { "username": username, "realname": full_name, "email": email } }
    resp = requests.patch(url, headers=headers, json=payload)
    return resp.status_code in (200, 204)

def clear_user_from_inventory(token, comp_id):
    url = f"{JAMF_URL}/api/v1/computers-inventory-detail/{comp_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = { "userAndLocation": { "username": "", "realname": "", "email": "" } }
    resp = requests.patch(url, headers=headers, json=payload)
    return resp.status_code in (200, 204)

# --------------- PRELOAD OPS -------------------------

def preload_update(token, preload_id, serial, name, username, full_name, email, asset):
    url = f"{JAMF_URL}/api/v2/inventory-preload/records/{preload_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "deviceType": "Computer",
        "serialNumber": serial,
        "username": username,
        "fullName": full_name,
        "emailAddress": email,
        "assetTag": asset,
        "extensionAttributes": [{"name": "Preload Computer Name", "value": name}]
    }

    resp = requests.put(url, headers=headers, json=payload)
    return resp.status_code in (200, 201)

def create_preload(token, serial, name, username, full_name, email, asset):
    url = f"{JAMF_URL}/api/v2/inventory-preload/records"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "deviceType": "Computer",
        "serialNumber": serial,
        "username": username,
        "fullName": full_name,
        "emailAddress": email,
        "assetTag": asset,
        "extensionAttributes": [{"name": "Preload Computer Name", "value": name}]
    }
    resp = requests.post(url, headers=headers, json=payload)
    return resp.status_code == 201

def delete_preload(token, preload_id):
    url = f"{JAMF_URL}/api/v2/inventory-preload/records/{preload_id}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    resp = requests.delete(url, headers=headers)
    return resp.status_code == 201

# --------------- STATIC GROUP OPS --------------------

def get_static_group_xml(group_id, token):
    url = f"{JAMF_URL}/JSSResource/computergroups/id/{group_id}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
    resp = requests.get(url, headers=headers)
    return resp.text if resp.status_code == 200 else None

def modify_group_xml(xml_data, comp_id, action="add"):
    root = ET.fromstring(xml_data)
    computers = root.find("computers") or ET.SubElement(root, "computers")
    exists = any(c.find("id").text == str(comp_id) for c in computers.findall("computer"))
    
    if action == "add" and not exists:
        new_c = ET.SubElement(computers, "computer")
        ET.SubElement(new_c, "id").text = str(comp_id)
        return ET.tostring(root, encoding="utf-8"), True
    elif action == "remove" and exists:
        for c in list(computers):
            if c.find("id").text == str(comp_id):
                computers.remove(c)
        return ET.tostring(root, encoding="utf-8"), True
    return xml_data.encode("utf-8"), False

def update_static_group(group_id, token, comp_id, action):
    xml_data = get_static_group_xml(group_id, token)
    if not xml_data:
        print(f"❌ Could not fetch XML for group {group_id}")
        return
    
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        print(f"❌ Failed to parse XML for group {group_id}: {e}")
        return
    
    # Jamf returns <computer_group> as root
    group = root if root.tag == "computer_group" else root.find("computer_group")
    if group is None:
        print(f"❌ Could not find a valid <computer_group> in group {group_id}")
        return
    
    computers = group.find("computers")
    if computers is None:
        if action == "add":
            computers = ET.SubElement(group, "computers")
        else:
            print(f"⚠️ No <computers> section found in group {group_id}")
            return
        
    changed = False
    
    if action == "add":
        already_present = any(
            c.find("id") is not None and c.find("id").text == str(comp_id)
            for c in computers.findall("computer")
        )
        if not already_present:
            computer = ET.SubElement(computers, "computer")
            ET.SubElement(computer, "id").text = str(comp_id)
            changed = True
            
    elif action == "remove":
        for c in list(computers.findall("computer")):
            cid = c.find("id")
            if cid is not None and cid.text == str(comp_id):
                computers.remove(c)
                changed = True
                
    else:
        print(f"❌ Unknown action: {action}")
        return
    
    if changed:
        updated_xml = ET.tostring(root, encoding="utf-8")
        url = f"{JAMF_URL}/JSSResource/computergroups/id/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/xml"
        }
        resp = requests.put(url, headers=headers, data=updated_xml)
        status = "added to" if action == "add" else "removed from"
        if resp.status_code in (200, 201):
            print(f"✅ {comp_id} {status} group {group_id}")
        else:
            print(f"❌ Failed to update group {group_id}: {resp.status_code}")
    else:
        print(f"ℹ️ {comp_id} already correct in group {group_id}")
        
# --------------- MAIN LOGIC --------------------------
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Run without prompts")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    args = parser.parse_args()
    
    creds = load_google_credentials()
    sheet = get_sheet_mapping(creds)
    token, _ = get_jamf_token()
    jamf_computers = get_all_computers(token)
    preload_computers = get_all_preloads(token)
    
    print(f"Processing {len(sheet)} rows from Google Sheet")
    
    updates = {
        "inventory_name_updated": 0,
        "inventory_user_updated": 0,
        "preload_record_updated": 0,
        "preload_record_created": 0
    }
    
    for serial, entry in sheet.items():
        google_name = entry["name"]
        username = entry["username"]
        asset = entry["asset"]
        
        comp = jamf_computers.get(serial)
        preload = preload_computers.get(serial)
        
        # Inventory rename logic
        if comp:
            comp_id = comp["mac_id"]
            current_name = comp["name"]
            if google_name != current_name:
                verbose_log(serial, google_name, username, asset)
                print(f"   🔄 Rename: '{current_name}' → '{google_name}'")
                if args.dry_run:
                    continue
                if args.force or input("Rename? (Y/N): ").lower() == "y":
                    if inventory_rename(token, comp_id, google_name):
                        updates["inventory_name_updated"] += 1
                        update_static_group(STATIC_GROUP_ID, token, comp_id, "add")
                        
                        # Static group cleanup
            if comp["ea_reported"] == google_name and comp["static_group"]:
                if args.dry_run:
                    print(f"Dry-run: Remove {serial} from static group")
                else:
                    update_static_group(STATIC_GROUP_ID, token, comp_id, "remove")
                    
                    # User assignment
            if username != comp["username"]:
                ldap = ldap_lookup(token, username) if username else None
                if not username and comp["username"]:
                    verbose_log(serial, google_name, username, asset)
                    print(f"   🧼 Clearing user: '{comp['username']}' → ''")
                    if not args.dry_run and (args.force or input("Clear user? (Y/N): ").lower() == "y"):
                        if clear_user_from_inventory(token, comp_id):
                            updates["inventory_user_updated"] += 1
                elif username:
                    verbose_log(serial, google_name, username, asset)
                    print(f"   🔄 Assign user: '{comp['username']}' → '{username}' {ldap['full_name']}")
                    if not args.dry_run and ldap and (args.force or input("Assign user? (Y/N): ").lower() == "y"):
                            if assign_user_from_inventory(token, comp_id, username, ldap["full_name"], ldap["email"]):
                                updates["inventory_user_updated"] += 1
                            
        # Preload update logic
        if preload:
            changed = (
                google_name != preload["ea_reported"] or
                username != preload["username"] or
                asset != preload["asset"]
            )
            if changed:
                ldap = ldap_lookup(token, username) if username else None
                verbose_log(serial, google_name, username, asset)
                if args.dry_run:
                    print("   ✏️  Preload update:")
                    if google_name != preload["ea_reported"]:
                        print(f"     - Name: '{preload['ea_reported']}' → '{google_name}'")
                    if username != preload["username"]:
                        print(f"     - Username: '{preload['username']}' → '{username}'")
                    if asset != preload["asset"]:
                        print(f"     - Asset Tag: '{preload['asset']}' → '{asset}'")
                elif args.force or input(f"Update preload for {serial}? (Y/N): ").lower() == "y":
                    if preload_update(token, preload["mac_id"], serial, google_name, username,
                                      ldap["full_name"] if ldap else "", ldap["email"] if ldap else "", asset):
                        print("✅ Preload update succeeded.")
                        updates["preload_record_updated"] += 1
        else:
            ldap = ldap_lookup(token, username) if username else None
            verbose_log(serial, google_name, username, asset)
            if args.dry_run:
                verbose_log(serial, google_name, username, asset)
                print("   ➕ Creating preload record (did not exist previously)")
            elif args.force or input(f"Create preload for {serial}? (Y/N): ").lower() == "y":
                if create_preload(token, serial, google_name, username,
                                  ldap["full_name"] if ldap else "", ldap["email"] if ldap else "", asset):
                    print("✅ Preload creation succeeded.")
                    updates["preload_record_created"] += 1
                
    print("\nSummary:")
    for k, v in updates.items():
        print(f"{k.replace('_', ' ').title()}: {v}")
        
if __name__ == "__main__":
    main()
    