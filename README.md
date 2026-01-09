# asset-unify - Automate computer naming and user assignments using Jamf Pro API and Google Sheets API

asset-unify is an automated sync service that keeps Jamf Pro inventory and preload records aligned using Google Sheets as the source of truth.

It is designed to run independently and on a schedule, although it can also be run attended, allowing for approval of changes and to have dry-runs as well.

The functions of this service are as follows:
- Inventory computer renaming
- Inventory user assignment and clearing, using LDAP validation
- Preload record creation and updates
- Static group and extension attribute management for enforcement in Jamf

# Features

# Current, Active Inventory
- Rename computers to match Google Sheet
- Assign users (username, full name, e-mail) only if there is an identical LDAP match
- Clear user entries when:
  - User on Google Sheet is blank
  - LDAP lookup fails
- Add asset tag information
- Add computers to static group to scope policy run in enforcing updated computer name.
- Removes computers from static group once reported computer name matches Google Sheet name.

# Preload Records
- Creates or updates preload record for every single computer in inventory sheet
- Sets computer name as extension attribute to be used in name enforcement at enrollment
- Update user, name, email, asset tag information in preload record
- Clear preload user information when LDAP lookup fails or if user field is empty

# Safety Controls

# Standard Run
  - runs interactively, prompting to approve changes
# Force Run
  - run non-interactively
# Verbose
  - standard run + verbose logging
# Dry Run
  - only prints, does not make any changes

