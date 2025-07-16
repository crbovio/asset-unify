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
with open("config.json") as f:
	config = json.load(f)

# CONFIG

GOOGLE_KEYCHAIN_SERVICE = config["GOOGLE_KEYCHAIN_SERVICE"]
GOOGLE_KEYCHAIN_USER = config["GOOGLE_KEYCHAIN_USER"]
SPREADSHEET_ID = config["SPREADSHEET_ID"]
SHEET_NAME = config["SHEET_NAME"]
SCOPES = config["SCOPES"]

JAMF_URL = config["JAMF_URL"]
JAMF_KEYCHAIN_SERVICE = config["JAMF_KEYCHAIN_SERVICE"]
STATIC_GROUP_ID = config["STATIC_GROUP_ID"]
REPORTED_NAME_EXTENSION_ATTRIBUTE_NAME = config["REPORTED_NAME_EXTENSION_ATTRIBUTE_NAME"]
PRELOAD_NAME_EXTENSION_ATTRIBUTE_NAME = config["PRELOAD_NAME_EXTENSION_ATTRIBUTE_NAME"]
JAMF_LDAP_SERVER_ID = config["JAMF_LDAP_SERVER_ID"]

# LOGGING

LOG_FILE = config["LOG_FILE"]
logger = logging.getLogger("asset_unify")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# GOOGLE SHEETS AUTH

def load_google_credentials():
	try:
		raw_json = keyring.get_password(GOOGLE_KEYCHAIN_SERVICE, GOOGLE_KEYCHAIN_USER)
		if not raw_json:
			raise Exception("Google service account JSON not found in Keychain.")
		credentials_info = json.loads(raw_json)
		return service_account.Credentials.from_service_account_info(credentials_info, scopes=SCOPES)
	except Exception as e:
		print(f"❌ Google credentials error: {e}")
		sys.exit(1)
		
# SHEET DATA
		
def get_sheet_mapping(credentials):
	try:
		service = build("sheets", "v4", credentials=credentials)
		range_name = f"{SHEET_NAME}!A1:Z"
		result = service.spreadsheets().values().get(spreadsheetId=SPREADSHEET_ID, range=range_name).execute()
		values = result.get("values", [])
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
				mapping[serial] = {
					"name": desired_name,
					"username": username
				}
		return mapping
	except Exception as e:
		print(f"❌ Failed to load Google Sheet data: {e}")
		sys.exit(1)
		
# JAMF TOKEN
		
def get_jamf_token():
	client_id = keyring.get_password(JAMF_KEYCHAIN_SERVICE, "client_id")
	client_secret = keyring.get_password(JAMF_KEYCHAIN_SERVICE, "client_secret")
	if not client_id or not client_secret:
		print("❌ Jamf API credentials not found in Keychain.")
		sys.exit(1)
	headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
	data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
	response = requests.post(f"{JAMF_URL}/api/oauth/token", headers=headers, data=data)
	response.raise_for_status()
	token_data = response.json()
	return token_data["access_token"], time.time() + token_data["expires_in"] - 60

# JAMF FUNCTIONS

def get_all_computers(token):
	headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
	url = f"{JAMF_URL}/JSSResource/computers/subset/basic"
	response = requests.get(url, headers=headers)
	root = ET.fromstring(response.text)
	computers = {}
	for comp in root.findall("computer"):
		comp_id = comp.findtext("id")
		name = comp.findtext("name")
		serial = comp.findtext("serial_number") or comp.findtext("serialNumber")
		if serial and comp_id and name:
			computers[serial.strip()] = {"id": comp_id.strip(), "name": name.strip()}
	return computers

def get_computer_xml(token, comp_id):
	headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
	url = f"{JAMF_URL}/JSSResource/computers/id/{comp_id}"
	response = requests.get(url, headers=headers)
	return response.text if response.status_code == 200 else None

def update_computer_name(token, comp_id, computer_xml, new_name):
	try:
		root = ET.fromstring(computer_xml)
		general = root.find("general")
		if general is not None:
			name_elem = general.find("name")
			if name_elem is not None:
				old_name = name_elem.text
				if old_name == new_name:
					print(f"⚠️ Already named: {new_name}")
					return False
				print(f"🛠️ Changing name from '{old_name}' to '{new_name}'")
				name_elem.text = new_name
				updated_xml = ET.tostring(root, encoding="utf-8")
				headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
				url = f"{JAMF_URL}/JSSResource/computers/id/{comp_id}"
				resp = requests.put(url, headers=headers, data=updated_xml)
				if resp.status_code not in (200, 201):
					print(f"❌ PUT failed: {resp.status_code} | {resp.text}")
					return False
				return True
	except Exception as e:
		print(f"❌ Exception: {e}")
		return False

def assign_user_to_computer(token, comp_id, username, full_name, email):
	try:
		headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
		root = ET.Element("computer")
		location = ET.SubElement(root, "location")
		ET.SubElement(location, "username").text = username
		ET.SubElement(location, "real_name").text = full_name
		ET.SubElement(location, "email_address").text = email
		payload = ET.tostring(root, encoding="utf-8")
		url = f"{JAMF_URL}/JSSResource/computers/id/{comp_id}"
		resp = requests.put(url, headers=headers, data=payload)
		return resp.status_code in (200, 201)
	except Exception:
		return False
	
def purge_user_from_computer(token, comp_id):
	return assign_user_to_computer(token, comp_id, "", "", "")

def get_existing_username(computer_xml):
	try:
		root = ET.fromstring(computer_xml)
		location = root.find("location")
		return location.findtext("username") if location is not None else ""
	except:
		return ""
	
def get_extension_attribute_value(computer_xml, attr_name):
	try:
		root = ET.fromstring(computer_xml)
		ea_list = root.find("extension_attributes")
		for ea in ea_list.findall("extension_attribute"):
			if ea.findtext("name") == attr_name:
				return ea.findtext("value") or ""
	except:
		return ""
	return ""

# LDAP

def ldap_lookup(token, username):
	try:
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
				full_name = user.findtext("realname") or user.findtext("real_name") or ""
				email = user.findtext("email_address") or ""
				return {
					"username": ldap_username,
					"full_name": full_name,
					"email": email
				}
		return None
	except:
		return None
	
# STATIC GROUP
	
def get_static_group_members(token, group_id):
	headers = {"Authorization": f"Bearer {token}", "Accept": "application/xml"}
	url = f"{JAMF_URL}/JSSResource/computergroups/id/{group_id}"
	response = requests.get(url, headers=headers)
	root = ET.fromstring(response.text)
	return {comp.findtext("id") for comp in root.findall(".//computer")}, response.text

def rebuild_group_xml(original_xml, keep_ids):
	try:
		root = ET.fromstring(original_xml)
		comps = root.find("computers")
		if comps is not None:
			comps.clear()
			for cid in sorted(keep_ids):
				comp_elem = ET.SubElement(comps, "computer")
				id_elem = ET.SubElement(comp_elem, "id")
				id_elem.text = str(cid)
			return ET.tostring(root, encoding="utf-8")
	except:
		pass
	return None

def update_static_group(token, group_id, new_xml):
	headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/xml"}
	url = f"{JAMF_URL}/JSSResource/computergroups/id/{group_id}"
	response = requests.put(url, headers=headers, data=new_xml)
	return response.status_code in (200, 201)

# MAIN

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--force", action="store_true", help="Run without prompts")
	parser.add_argument("--verbose", action="store_true", help="Verbose output")
	args = parser.parse_args()
	
	creds = load_google_credentials()
	mapping = get_sheet_mapping(creds)
	token, expiry = get_jamf_token()
	computers = get_all_computers(token)
	group_members, group_xml = get_static_group_members(token, STATIC_GROUP_ID)
	
	keep_ids = set()
	unchanged, not_found, renamed, user_updated = 0, 0, 0, 0
	
	for serial, data in mapping.items():
		if time.time() >= expiry:
			token, expiry = get_jamf_token()
			
		info = computers.get(serial)
		if not info:
			not_found += 1
			if args.verbose:
				print(f"❌ Not found in Jamf: {serial}")
			continue
		
		comp_id = info["id"]
		current_name = info["name"]
		desired_name = data["name"]
		username = data.get("username", "").strip()
		needs_xml = False
		xml = None
		
		# Rename check
		if current_name != desired_name:
			if args.verbose or not args.force:
				print(f"🔄 Rename needed: {serial} | '{current_name}' → '{desired_name}'")
			if args.force or input("Rename? (Y/N): ").strip().lower() == "y":
				xml = get_computer_xml(token, comp_id)
				if xml and update_computer_name(token, comp_id, xml, desired_name):
					renamed += 1
					keep_ids.add(comp_id)
					
		elif comp_id in group_members:
			if not xml:
				xml = get_computer_xml(token, comp_id)
			local_name = get_extension_attribute_value(xml, REPORTED_NAME_EXTENSION_ATTRIBUTE_NAME)
			if local_name == desired_name:
				if args.verbose or not args.force:
					print(f"✅ EA match: {serial} | '{local_name}' — removing from group")
			else:
				if args.verbose:
					print(f"⏳ Waiting on EA: {serial} | '{local_name}' ≠ '{desired_name}'")
				keep_ids.add(comp_id)
				continue
		else:
			if args.verbose:
				print(f"✅ Unchanged: {serial}")
			unchanged += 1
			
		# User assignment or removal
		if not xml:
			xml = get_computer_xml(token, comp_id)
		current_user = get_existing_username(xml)
		
		if username:
			if current_user.lower() == username.lower():
				continue
			ldap = ldap_lookup(token, username)
			if ldap:
				if args.verbose or not args.force:
					print(f"👤 Found LDAP for {serial}: {ldap}")
				if args.force or input("Assign user? (Y/N): ").strip().lower() == "y":
					if assign_user_to_computer(token, comp_id, ldap["username"], ldap["full_name"], ldap["email"]):
						user_updated += 1
			else:
				if args.verbose:
					print(f"⚠️ No LDAP match for {username}")
		else:
			if current_user:
				if args.verbose or not args.force:
					print(f"🧼 Purging user {current_user} from {serial}:{current_name}")
				if args.force or input("Purge user (Y/N): ").strip().lower() == "y":
					if purge_user_from_computer(token, comp_id):
						user_updated += 1
						
		if comp_id in group_members:
			keep_ids.add(comp_id)
			
	# Final group update
	if keep_ids != group_members:
		print("🧼 Updating group membership...")
		new_xml = rebuild_group_xml(group_xml, keep_ids)
		if update_static_group(token, STATIC_GROUP_ID, new_xml):
			print("✅ Static group updated.")
		else:
			print("❌ Failed to update static group.")
			
	# Summary
	print("\n📊 Summary:")
	print(f"  Unchanged Macs in Jamf: {unchanged}")
	print(f"  Not found in Jamf: {not_found}")
	print(f"  Macs with name changes in Jamf: {renamed}")
	print(f"  Macs with user changes in Jamf: {user_updated}")
	
if __name__ == "__main__":
	main()