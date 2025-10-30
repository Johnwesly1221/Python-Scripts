# ✅ Full Combined Script: Mirror, Termination, Server-Decomm
# Written by Johnwesly — Final Operator-Safe Version
# mode selection with partial/fuzzy matching and detailed comments. - Production Ready_2_every thing is ready for demo.

# [1] Imports and Setup
import requests
import urllib3
import getpass
import json
import difflib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
mgmt_server = "https://192.168.10.110/web_api"
sid = None

def login():
    global sid
    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ").strip()
    payload = {"user": username, "password": password}
    headers = {"Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/login", json=payload, headers=headers, verify=False, timeout=30)
    response.raise_for_status()
    sid = response.json()["sid"]
    print("[+] Logged in successfully.")

def logout():
    headers = {"X-chkp-sid": sid}
    requests.post(f"{mgmt_server}/logout", headers=headers, verify=False)
    print("[*] Logout successful.")

def object_exists(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    object_types = [
        ("host", "show-host"),
        ("network", "show-network"),
        ("service", "show-service"),
        ("service-tcp", "show-service-tcp"),
        ("service-udp", "show-service-udp"),
        ("group", "show-group"),
        ("user", "show-user"),
        ("access-role", "show-access-role")
    ]
    for obj_type, endpoint in object_types:
        payload = {"name": object_name}
        response = requests.post(f"{mgmt_server}/{endpoint}", json=payload, headers=headers, verify=False)
        if response.status_code == 200:
            print(f"[✓] Object '{object_name}' is available as type '{obj_type}'.")
            return True
    print(f"[!] Object '{object_name}' is not available in any known type.")
    return False

def get_where_used(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": object_name, "indirect": True}
    response = requests.post(f"{mgmt_server}/where-used", json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

def get_rule_details(rule_uid, layer):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"uid": rule_uid, "layer": layer, "details-level": "full"}
    response = requests.post(f"{mgmt_server}/show-access-rule", json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    return None

def update_rule_comment(rule_uid, layer, comment_text):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rule_data = get_rule_details(rule_uid, layer)
    if not rule_data:
        print(f"[!] Failed to fetch rule {rule_uid} for comment update.")
        return
    existing_comment = rule_data.get("comments", "")
    new_comment = f"{existing_comment}\n{comment_text}" if existing_comment else comment_text
    payload = {"uid": rule_uid, "layer": layer, "comments": new_comment.strip()}
    response = requests.post(f"{mgmt_server}/set-access-rule", json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"[✓] Comment updated for rule '{rule_data.get('name', rule_uid)}'")
    else:
        print(f"[!] Failed to update comment: {response.text}")

def discard():
    headers = {"X-chkp-sid": sid, "content-type": "application/json"}
    response = requests.post(f"{mgmt_server}/discard", headers=headers, json={}, verify=False)
    if response.status_code == 200:
        print("[!] Changes discarded successfully.")
    else:
        print(f"[!] Discard failed with status {response.status_code}: {response.text or response.reason}")

def publish(object_name):
    # ✅ Skip usage check if object was renamed
    if object_name.startswith("NEGSDELETE-"):
        confirm = input("[?] Do you want to publish changes? (yes/no): ").strip().lower()
        if confirm != "yes":
            discard()
            return
    else:
        # ✅ Only check usage for original object
        usage_check = get_where_used(object_name)
        still_used = usage_check["used-directly"].get("access-control-rules", [])

        if still_used:
            print(f"[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
            for ref in still_used:
                rule_uid = ref["rule"]["uid"]
                layer = ref["layer"]["name"]
                rule_data = get_rule_details(rule_uid, layer)
                rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
                rule_number = rule_data.get("rule-number", "N/A")
                print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}, Rule No: {rule_number}")
        else:
            print(f"[✓] Object '{object_name}' is no longer used in any access rules.")

        confirm = input("[?] Do you want to publish changes? (yes/no): ").strip().lower()
        if confirm != "yes":
            discard()
            return

    # ✅ Proceed to publish
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/publish", headers=headers, json={}, verify=False)
    if response.status_code == 200:
        print("[+] Changes published.")
    else:
        print(f"[!] Failed to publish changes: {response.text}")
def mirror_mode():
    target_object = input("Enter the New user object (host/network/user): ").strip()
    if not object_exists(target_object):
        print(f"[!] Object '{target_object}' is not available. Kindly create it first.")
        return

    usage_data = get_where_used(target_object)
    existing_rules = usage_data["used-directly"].get("access-control-rules", [])

    if existing_rules:
        print(f"[!] Object '{target_object}' is already used in {len(existing_rules)} rule(s).")
        print("[*] Object is already available in the following rules:")
        for ref in existing_rules:
            rule_uid = ref["rule"]["uid"]
            layer = ref["layer"]["name"]
            rule_data = get_rule_details(rule_uid, layer)
            rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
            rule_number = rule_data.get("rule-number", "N/A")
            print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}, Rule No: {rule_number}")
        return

    reference_object = input("Enter the Existing user object to find rules: ").strip()
    if not object_exists(reference_object):
        print(f"[!] Reference object '{reference_object}' not found.")
        return

    usage_data = get_where_used(reference_object)
    rules = usage_data["used-directly"].get("access-control-rules", [])
    if not rules:
        print(f"[!] No rules found using '{reference_object}'.")
        return

    print(f"[+] Rules using '{reference_object}':")
    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

    confirm = input(f"[?] Do you want to add '{target_object}' to these rules? (yes/no): ").strip().lower()
    if confirm == "yes":
        add_object_to_rules(target_object, reference_object, usage_data)
        publish(target_object)
    else:
        print("[!] Addition aborted by user.")

def add_object_to_rules(new_object, reference_object, usage_data):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rules = usage_data["used-directly"].get("access-control-rules", [])
    print(f"[+] Found {len(rules)} rules using '{reference_object}'.")

    user_comment = input("[?] Enter comment to add to each mirrored rule: ").strip()
    list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]
    single_fields = ["action", "track"]

    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        if not rule_data:
            print(f"[!] Failed to fetch rule {rule_uid}")
            continue

        rule_name = rule_data.get("name", "Unnamed Rule")
        print(f"\n[→] Rule UID: {rule_uid}, Rule Name: {rule_name}")
        updated_fields = []

        for field in rule_data:
            field_value = rule_data[field]
            if field in list_fields and isinstance(field_value, list):
                if any(obj.get("name", "").lower() == reference_object.lower() for obj in field_value):
                    update_payload = {"uid": rule_uid, "layer": layer, field: {"add": [new_object]}}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Added '{new_object}' to field '{field}'")
                        updated_fields.append(field)
                    else:
                        print(f"[!] Failed to add to field '{field}': {update_resp.text}")
            elif field in single_fields and isinstance(field_value, dict):
                if field_value.get("name", "").lower() == reference_object.lower():
                    update_payload = {"uid": rule_uid, "layer": layer, field: new_object}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Set '{new_object}' in field '{field}'")
                        updated_fields.append(field)
                    else:
                        print(f"[!] Failed to set field '{field}': {update_resp.text}")

        if updated_fields:
            update_rule_comment(rule_uid, layer, user_comment)
        else:
            print(f"[!] Reference object not found in editable fields for rule {rule_uid}")
def rename_object(original_name, new_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    object_types = [
        ("host", "set-host"),
        ("network", "set-network"),
        ("service", "set-service"),
        ("service-tcp", "set-service-tcp"),
        ("service-udp", "set-service-udp"),
        ("group", "set-group"),
        ("user", "set-user"),
        ("access-role", "set-access-role")
    ]
    for obj_type, endpoint in object_types:
        payload = {"name": original_name}
        check = requests.post(f"{mgmt_server}/show-{obj_type}", json=payload, headers=headers, verify=False)
        if check.status_code == 200:
            rename_payload = {"name": original_name, "new-name": new_name}
            response = requests.post(f"{mgmt_server}/{endpoint}", json=rename_payload, headers=headers, verify=False)
            if response.status_code == 200:
                print(f"[✓] Renamed '{original_name}' to '{new_name}'")
                return new_name
            else:
                print(f"[!] Rename failed: {response.text}")
                return original_name
    print(f"[!] Object '{original_name}' not found for renaming.")
    return original_name

def remove_object_from_rules(object_name, usage_data):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rules = usage_data["used-directly"].get("access-control-rules", [])
    print(f"[+] Found {len(rules)} access control rules using object '{object_name}'.")

    if not rules:
        #print("[!] No rules found. Exiting.")
        return False

    print("[*] Rules using object before removal:")
    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        get_payload = {"uid": rule_uid, "layer": layer, "details-level": "full"}
        get_resp = requests.post(f"{mgmt_server}/show-access-rule", json=get_payload, headers=headers, verify=False)
        if get_resp.status_code == 200:
            rule_data = get_resp.json()
            rule_name = rule_data.get("name", "Unnamed Rule")
            print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")
        else:
            print(f"    - Rule UID: {rule_uid} [Name fetch failed]")

    confirm = input(f"[?] Object '{object_name}' found in rules. Do you want to proceed with removal? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[!] Removal aborted by user.")
        return False

    user_comment = input("[?] Enter comment to add to each rule after removal: ").strip()
    any_updated = False
    list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]
    single_fields = ["action", "track"]

    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        get_payload = {"uid": rule_uid, "layer": layer, "details-level": "full"}
        get_resp = requests.post(f"{mgmt_server}/show-access-rule", json=get_payload, headers=headers, verify=False)
        if get_resp.status_code != 200:
            print(f"\n[→] Rule UID: {rule_uid}")
            print(f"[!] Failed to fetch rule details: {get_resp.text}")
            continue

        rule_data = get_resp.json()
        rule_name = rule_data.get("name", "Unnamed Rule")
        rule_number = rule_data.get("rule-number", "N/A")
        print(f"\n[→] Rule UID: {rule_uid}, Rule Name: {rule_name}, Rule No: {rule_number} " )

        removed_fields = []

        for field in rule_data:
            field_value = rule_data[field]
            if field in list_fields and isinstance(field_value, list):
                if any(obj.get("name", "").lower() == object_name.lower() for obj in field_value):
                    update_payload = {"uid": rule_uid, "layer": layer, field: {"remove": [object_name]}}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Removed '{object_name}' from {field}")
                        removed_fields.append(field)
                        any_updated = True
                    else:
                        print(f"[!] Failed to update {field}: {update_resp.text}")
            elif isinstance(field_value, dict):
                if field_value.get("name", "").lower() == object_name.lower():
                    update_payload = {"uid": rule_uid, "layer": layer, field: None}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Removed '{object_name}' from field '{field}'")
                        removed_fields.append(field)
                        any_updated = True
                    else:
                        print(f"[!] Failed to remove from field '{field}': {update_resp.text}")

        if removed_fields:
            update_rule_comment(rule_uid, layer, user_comment)
        else:
            print(f"[!] Object not found in editable fields for rule {rule_uid}")

    return any_updated
def get_group_members(group_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": group_name}
    response = requests.post(f"{mgmt_server}/show-group", json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get("members", [])
    return []

def find_groups_containing_object(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    found_groups = []
    payload = {"limit": 500}
    response = requests.post(f"{mgmt_server}/show-groups", json=payload, headers=headers, verify=False)
    if response.status_code != 200:
        print(f"[!] Failed to fetch groups: {response.text}")
        return []
    groups = response.json().get("objects", [])
    for group in groups:
        group_name = group.get("name")
        members = get_group_members(group_name)
        if any(obj.get("name", "").lower() == object_name.lower() for obj in members):
            found_groups.append(group_name)
    return found_groups

def find_parent_groups(group_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    parent_groups = []
    payload = {"limit": 500}
    response = requests.post(f"{mgmt_server}/show-groups", json=payload, headers=headers, verify=False)
    if response.status_code != 200:
        print(f"[!] Failed to fetch groups for parent lookup: {response.text}")
        return []
    groups = response.json().get("objects", [])
    for group in groups:
        members = get_group_members(group.get("name"))
        if any(m.get("name", "").lower() == group_name.lower() for m in members):
            parent_groups.append(group.get("name"))
    return parent_groups

def handle_group_reference(object_name, group_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    members = get_group_members(group_name)
    other_members = [m["name"] for m in members if m["name"].lower() != object_name.lower()]
    print(f"[→] Group '{group_name}' contains {len(members)} member(s).")

    if other_members:
        print(f"[✓] Group '{group_name}' includes other members besides '{object_name}'.")
    else:
        print(f"[!] '{object_name}' is the only member in the group.")

    parent_groups = find_parent_groups(group_name)
    if parent_groups:
        print(f"\n[→] Group '{group_name}' is also part of {len(parent_groups)} parent group(s): {parent_groups}")
    else:
        print(f"[✓] Group '{group_name}' is not part of any parent group.")

    group_usage = get_where_used(group_name)
    rules = group_usage["used-directly"].get("access-control-rules", [])
    print(f"\n[→] Group '{group_name}' is used in {len(rules)} access rule(s):")
    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

    confirm = input(f"[?] Do you want to remove '{object_name}' from group '{group_name}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print(f"[!] Skipped removal from group '{group_name}'")
        return

    # Remove host from group
    payload = {
        "name": group_name,
        "members": {
            "remove": [object_name]
        }
    }
    response = requests.post(f"{mgmt_server}/set-group", headers=headers, json=payload, verify=False)
    if response.status_code == 200:
        print(f"[✓] Removed '{object_name}' from group '{group_name}'")
    else:
        print(f"[!] Failed to remove from group '{group_name}': {response.text}")
        return

    # Re-check group membership
    updated_members = get_group_members(group_name)
    if updated_members:
        return  # Group still has members — no further action

    # Remove group from parent groups
    for parent in parent_groups:
        print(f"[→] Removing empty group '{group_name}' from parent group '{parent}'")
        remove_payload = {
            "name": parent,
            "members": {
                "remove": [group_name]
            }
        }
        remove_resp = requests.post(f"{mgmt_server}/set-group", headers=headers, json=remove_payload, verify=False)
        if remove_resp.status_code == 200:
            print(f"[✓] Removed group '{group_name}' from parent group '{parent}'")
        else:
            print(f"[!] Failed to remove from parent group '{parent}': {remove_resp.text}")

    # Remove group from access rules
    group_usage = get_where_used(group_name)
    rule_refs = group_usage["used-directly"].get("access-control-rules", [])
    if not rule_refs:
        return

    print(f"\n[→] Removing empty group '{group_name}' from {len(rule_refs)} access rule(s):")
    comment_text = input("[?] Enter comment to add to each rule after group removal: ").strip()
    for ref in rule_refs:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

        list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]
        single_fields = ["action", "track"]

        removed_fields = []
        for field in rule_data:
            field_value = rule_data[field]
            if field in list_fields and isinstance(field_value, list):
                if any(obj.get("name", "").lower() == group_name.lower() for obj in field_value):
                    update_payload = {"uid": rule_uid, "layer": layer, field: {"remove": [group_name]}}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Removed group '{group_name}' from field '{field}'")
                        removed_fields.append(field)
                    else:
                        print(f"[!] Failed to remove from field '{field}': {update_resp.text}")
            elif isinstance(field_value, dict):
                if field_value.get("name", "").lower() == group_name.lower():
                    update_payload = {"uid": rule_uid, "layer": layer, field: None}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Removed group '{group_name}' from field '{field}'")
                        removed_fields.append(field)
                    else:
                        print(f"[!] Failed to remove from field '{field}': {update_resp.text}")

        if removed_fields:
            update_rule_comment(rule_uid, layer, comment_text)



if __name__ == "__main__":
    try:
        valid_modes = {"termination": "termination", "mirror": "mirror", "server-decomm": "server-decomm"}

        def resolve_mode(user_input):
            user_input = user_input.strip().lower()
            matches = [mode for mode in valid_modes if mode.startswith(user_input)]
            if len(matches) == 1:
                return valid_modes[matches[0]]
            elif len(matches) > 1:
                print(f"[!] Ambiguous input. Matches: {matches}")
                return None
            # Then try fuzzy match
            fuzzy = difflib.get_close_matches(user_input, valid_modes.keys(), n=1, cutoff=0.6)
            if fuzzy:
                print(f"[~] Interpreting '{user_input}' as '{fuzzy[0]}'")
                return valid_modes[fuzzy[0]]
            print("[!] Invalid mode. Try typing a full or partial match like 'ter', 'mir', or 'ser'.")
            return None

        mode = None
        while not mode:
            raw_input = input("Select mode (Termination/Mirror/Server-Decomm): ")
            mode = resolve_mode(raw_input)
        print(f"[✓] Mode selected: {mode.capitalize()}")

        login()

        if mode == "termination":
            object_name = input("Enter the object name (host/network/user): ").strip()
            usage = get_where_used(object_name)
            if remove_object_from_rules(object_name, usage):
                usage_check = get_where_used(object_name)
                still_used = usage_check["used-directly"].get("access-control-rules", [])
                if still_used:
                    print(f"[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
                    for ref in still_used:
                        rule_uid = ref["rule"]["uid"]
                        layer = ref["layer"]["name"]
                        rule_data = get_rule_details(rule_uid, layer)
                        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
                        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")
                else:
                    print(f"\n[✓] Object '{object_name}' is no longer used in any access rules.")
                renamed_object = f"NEGSDELETE-{object_name}"
                object_name = rename_object(object_name, renamed_object)
                publish(object_name)

        elif mode == "mirror":
            mirror_mode()

        elif mode == "server-decomm":
            object_name = input("Enter the server object name to decommission: ").strip()
            object_type = object_exists(object_name)
            if not object_type:
                print(f"[!] Object '{object_name}' not found. Exiting.")
                exit()

            usage = get_where_used(object_name)
            rule_count = len(usage["used-directly"].get("access-control-rules", []))
            #print(f"[✓] Object '{object_name}' is available as type '{object_type}'.")
            #print(f"[+] Found {rule_count} access control rules using object '{object_name}'")

            group_names = find_groups_containing_object(object_name)
            if group_names:
                print(f"[+] Object '{object_name}' is part of {len(group_names)} group(s): {group_names}")
                for group_name in group_names:
                    handle_group_reference(object_name, group_name)
            else:
                print(f"[!] Object '{object_name}' is not part of any group.")

            rule_removed = remove_object_from_rules(object_name, usage)
            if not rule_removed and not group_names:
                print("[!] No rules found. Exiting.")
                exit()

            publish(object_name)

        else:
            print("[!] Invalid mode selected.")

    except Exception as e:
        print(f"[!] Error: {e}")
        discard()
    finally:
        logout()
