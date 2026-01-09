# asset-unify - Automate computer naming and user assignments using Jamf Pro API and Google Sheets API

asset-unify is an automated sync service that keeps Jamf Pro inventory and preload records aligned using Google Sheets as the source of truth.

It is designed to run independently and on a schedule, although it can also be run attended, allowing for approval of changes and to have dry-runs as well.

The functions of this service are as follows:
- Inventory computer renaming
- Inventory user assignment and clearing, using LDAP validation
- Preload record creation and updates
- Static group and extension attribute management for enforcement in Jamf

# Features

## Current, Active Inventory
- Rename computers to match Google Sheet
- Assign users (username, full name, e-mail) only if there is an identical LDAP match
- Clear user entries when:
  - User on Google Sheet is blank
  - LDAP lookup fails
- Add asset tag information
- Add computers to static group to scope policy run in enforcing updated computer name.
- Removes computers from static group once reported computer name matches Google Sheet name.

## Preload Records
- Creates or updates preload record for every single computer in inventory sheet
- Sets computer name as extension attribute to be used in name enforcement at enrollment
- Update user, name, email, asset tag information in preload record
- Clear preload user information when LDAP lookup fails or if user field is empty

# Safety Controls

## Standard Run
  - runs interactively, prompting to approve changes
## Force Run
  - run non-interactively
## Verbose
  - standard run + verbose logging
## Dry Run
  - only prints, does not make any changes

# Google Sheet Requirements
The spreadsheet should contain the following headers:
Serial Number - required
  - Device serial numer is the key. If the text "EXIT" is in this box, the row will be skipped.
Computer Name - required
  - This is what you want to name the computer
User ID - optional
  - LDAP name, must be a perfect match.
  - Empty or non-perfect matches will clear the user info in Jamf
Asset Tag - optional
  - Asset tag value

# Jamf Requirements
## Static Group
  - Create a static group and name it asset-unify-group. Set ID of this Static Group in config.json.
## Smart Groups
  - "Newly Enrolled"
    ### "Last Enrollment: Less Than X Days Ago" : 14
  - "Newly Enrolled, preload EA not reported"
    ### "Last Enrollment: Less Than X Days Ago" : 14
    ### AND ( "Preload Computer Name Reported" IS "Unknown"
    ### OR "Preload Computer Name Reported" IS "not reported" )
## Extension attributes - available in support files
  - "Preload Computer Name". This is a value set in the script. Set ID of this Extension Attribute in config.json. 
  - "Local Computer Name". This is a script that reports on the computer's name.
  - "Preload Computer Name Reported". This is a script that checks if the computer has picked up on the changed name.
## Scripts
  - Upload script "Rename Mac from Local Computer", found in support files.
## Configuration Profiles
  - Profiles are "EA_Computer Name" and "EA_Computer Name2" and set the key localName to the result of the "Preload Computer Name" Extension attribute. Set the preference domain to edu.ea.massart and:
    <key>localName</key>
    <string>$EXTENSIONATTRIBUTE_##</string>
where ## is the ID number of "Preload Computer Name", which you also set in config.json. For instance, it could be $EXTENSIONATTRIBUTE_52

These configuration profiles are identical except you should scope "EA_Computer Name" to Smart Group "Newly Enrolled" and exclude Smart Group "Newly Enrolled, preload EA not reported".

Scope "EA_Computer Name2" to the Smart Group "Newly Enrolled, preload EA not reported".
## Policies
  ## New computer deployment - run as part of initial computer deployment workflow
    - "Set Computer Name from EA". Set for custom event of "computerEA". Set to ongoing.
    - Add script "Rename Mac from Local Computer Extension Attribute"
    - Add Maintenance "Update Inventory"
    - Scope to all computers

  ## Subsequent renames, automated by script
    - "Sync Computer Name to Jamf Name"
    - Recurring checkin, once per computer
    - Maintenance - "Update Inventory" + "Reset Computer Names"
    - Scoped to asset-unify-group
    
