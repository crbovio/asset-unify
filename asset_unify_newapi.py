#!/usr/bin/env python3

import os
import json
import sys
import requests
import logging
import keyring
import argparse
import time
from google.oauth2 import service_account
from googleapiclient.discovery import build
from xml.etree import ElementTree as ET

# ------------------------------
# CONFIGURATION
# ------------------------------
with open("config.json") as f:
    config = json.load(f)

GOOGLE_KEYCHAIN_SERVICE = config["GOOGLE_KEYCHAIN_SERVICE"]
GOOGLE_KEYCHAIN_USER = config["GOOGLE_KEYCHAIN_USER"]
SPREADSHEET_ID = config["SPREADSHEET_ID"]
SHEET_NAME = config["SHEET_NAME"]
SCOPES = config["SCOPES"]

JAMF_URL = config["JAMF_URL"]
JAMF_KEYCHAIN_SERVICE = config["JAMF_KEYCHAIN_SERVICE"]
STATIC_GROUP_ID = config["STATIC_GROUP_ID"]
REPORTED_NAME_EA_ID = 51
PRELOAD_NAME_EA_NAME = "Preload Computer Name"
JAMF_LDAP_SERVER_ID = config["JAMF_LDAP_SERVER_ID"]
LOG_FILE = config["LOG_FILE"]

# ------------------------------
# LOGGING
# ------------------------------
logger = logging.getLogger("asset_unify")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# ------------------------------
# GOOGLE SHEETS
# ------------------------------
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

# ------------------------------
# JAMF AUTH
# ------------------------------
def get_jamf_token():
    client_id = keyring.get_password(JAMF_KEYCHAIN_SERVICE, "client_id")
    client_secret = keyring.get_password(JAMF_KEYCHAIN_SERVICE, "client_secret")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    response = requests.post(f"{JAMF_URL}/api/oauth/token", headers=headers, data=data)
    response.raise_for_status()
    tok = response.json()
    return tok["access_token"], time.time() + tok["expires_in"] - 60

# ------------------------------
# JAMF DATA
# ------------------------------
def get_all_computers(token):
    headers = {"Authorization": f"Bearer {token}"}
    computers = {}
    page = 0
    while True:
        url = f"{JAMF_URL}/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION&section=EXTENSION_ATTRIBUTES&page={page}&page-size=100"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            break
        results = resp.json().get("results", [])
        for comp in results:
            serial = comp.get("hardware", {}).get("serialNumber", "")
            comp_id = comp.get("id", "")
            name = comp.get("general", {}).get("name", "")
            username = comp.get("userAndLocation", {}).get("username", "") or ""
            realname = comp.get("userAndLocation", {}).get("realName", "") or ""
            email = comp.get("userAndLocation", {}).get("emailAddress", "") or ""
            ea_dict = {}
            for ea in comp.get("extensionAttributes", []):
                def_id = str(ea.get("definitionId", ""))
                val_list = ea.get("values")
                if isinstance(val_list, list) and val_list:
                    ea_dict[def_id] = val_list[0]
                else:
                    ea_dict[def_id] = ""
            ea_reported = ea_dict.get(str(REPORTED_NAME_EA_ID), "")
            if serial:
                computers[serial] = {
                    "id": comp_id,
                    "name": name,
                    "username": username,
                    "realName": realname,
                    "email": email,
                    "ea_reported": ea_reported
                }
        if len(results) < 100:
            break
        page += 1
    return computers

def update_name(token, comp_id, new_name):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    data = {"name": new_name}
    url = f"{JAMF_URL}/api/v1/computers-inventory/{comp_id}"
    resp = requests.patch(url, headers=headers, json=data)
    return resp.status_code in (200, 204)

def update_user(token, comp_id, username, full_name, email):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    data = {
        "userAndLocation": {
            "username": username,
            "realName": full_name,
            "emailAddress": email
        }
    }
    url = f"{JAMF_URL}/api/v1/computers-inventory/{comp_id}"
    resp = requests.patch(url, headers=headers, json=data)
    return resp.status_code in (200, 204)

# ------------------------------
# STATIC GROUP
# ------------------------------
def get_static_group_members(token):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{JAMF_URL}/api/v1/static-groups/computers/{STATIC_GROUP_ID}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return set()
    return set(str(c["id"]) for c in resp.json().get("computers", []))

def update_static_group(token, ids):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{JAMF_URL}/api/v1/static-groups/computers/{STATIC_GROUP_ID}"
    data = {"computerIds": list(map(int, ids))}
    resp = requests.put(url, headers=headers, json=data)
    return resp.status_code in (200, 204)

# ------------------------------
# PRELOAD
# ------------------------------
def get_preload(token, serial):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{JAMF_URL}/api/v2/inventory-preload/records/{serial}"
    resp = requests.get(url, headers=headers)
    return resp.json() if resp.status_code == 200 else None

def create_or_update_preload(token, serial, name, ldap_info=None):
    existing = get_preload(token, serial)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "serialNumber": serial,
        "deviceType": "Computer",
        "extensionAttributes": [{"name": PRELOAD_NAME_EA_NAME, "value": name}]
    }
    if ldap_info:
        payload.update({
            "username": ldap_info["username"],
            "fullName": ldap_info["full_name"],
            "emailAddress": ldap_info["email"]
        })
        
    if existing:
        changed = False
        for field in ("username", "fullName", "emailAddress"):
            if payload.get(field, "") != existing.get(field, ""):
                changed = True
        for ea in payload["extensionAttributes"]:
            if not any(ea["name"] == e.get("name") and ea["value"] == e.get("value") for e in existing.get("extensionAttributes", [])):
                changed = True
        if changed:
            url = f"{JAMF_URL}/api/v2/inventory-preload/records/{serial}"
            resp = requests.put(url, headers=headers, json=payload)
            return resp.status_code in (200, 201)
    else:
        url = f"{JAMF_URL}/api/v2/inventory-preload/records"
        resp = requests.post(url, headers=headers, json=payload)
        return resp.status_code in (200, 201)
    return False

# ------------------------------
# LDAP LOOKUP (Classic API)
# ------------------------------
def ldap_lookup(token, username):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
    url = f"{JAMF_URL}/JSSResource/ldapservers/id/{JAMF_LDAP_SERVER_ID}/user/{username}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return None
    root = ET.fromstring(resp.text)
    for user in root.findall("ldap_user"):
        uid = user.findtext("uid") or ""
        ldap_username = user.findtext("username") or ""
        if uid == username or ldap_username == username:
            return {
                "username": ldap_username,
                "full_name": user.findtext("realname") or user.findtext("real_name") or "",
                "email": user.findtext("email_address") or ""
            }
    return None

# ------------------------------
# MAIN
# ------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    creds = load_google_credentials()
    sheet = get_sheet_mapping(creds)
    token, expiry = get_jamf_token()
    jamf_computers = get_all_computers(token)
    static_group = get_static_group_members(token)

    unchanged = not_found = renamed = user_updated = preload_created = 0
    keep_ids = set()

    for serial, entry in sheet.items():
        if time.time() >= expiry:
            token, expiry = get_jamf_token()

        name = entry["name"]
        username = entry.get("username", "").strip()
        comp = jamf_computers.get(serial)

        if not comp:
            ldap = ldap_lookup(token, username) if username else None
            if create_or_update_preload(token, serial, name, ldap):
                preload_created += 1
                if args.verbose:
                    print(f"➕ Preload created for {serial}")
            continue

        comp_id = str(comp["id"])

        # Rename if needed
        if comp["name"] != name:
            if args.force or input(f"Rename {serial}? (Y/N): ").lower() == "y":
                if update_name(token, comp_id, name):
                    renamed += 1
                    if args.verbose: print(f"✏️ Renamed {serial} to {name}")
        elif comp["ea_reported"] == name and comp_id in static_group:
            if args.verbose:
                print(f"✅ EA matches name, removing {serial} from group")
        else:
            if args.verbose:
                print(f"⏳ EA mismatch or awaiting update for {serial}")
            keep_ids.add(int(comp_id))

        # User assignment/removal
        if username:
            if (comp["username"] or "").lower() != username.lower():
                ldap = ldap_lookup(token, username)
                if ldap:
                    if args.force or input(f"Assign user to {serial}? (Y/N): ").lower() == "y":
                        if update_user(token, comp_id, ldap["username"], ldap["full_name"], ldap["email"]):
                            user_updated += 1
                            if args.verbose: print(f"👤 Assigned user {ldap['username']} to {serial}")
        else:
            if comp["username"]:
                if args.force or input(f"Clear user from {serial}? (Y/N): ").lower() == "y":
                    if update_user(token, comp_id, "", "", ""):
                        user_updated += 1
                        if args.verbose: print(f"🧹 Cleared user from {serial}")

        if comp_id in static_group:
            keep_ids.add(int(comp_id))
        else:
            unchanged += 1
            if args.verbose:
                print(f"✔️ No changes needed for {serial}")

    # Update static group
    if keep_ids != {int(x) for x in static_group}:
        print("🧼 Updating static group...")
        if update_static_group(token, keep_ids):
            print("✅ Static group updated.")
        else:
            print("❌ Failed to update static group.")

    # Summary
    print("\n📊 Summary:")
    print(f"  Unchanged Macs in Jamf: {unchanged}")
    print(f"  Not found in Jamf: {len(sheet) - len(jamf_computers)}")
    print(f"  Macs with name changes: {renamed}")
    print(f"  Macs with user changes: {user_updated}")
    print(f"  Preload records created: {preload_created}")

if __name__ == "__main__":
    main()
    