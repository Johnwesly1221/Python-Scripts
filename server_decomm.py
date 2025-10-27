import requests
import urllib3
import getpass
import json

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
        ("group", "show-group")
    ]
    for obj_type, endpoint in object_types:
        payload = {"name": object_name}
        response = requests.post(f"{mgmt_server}/{endpoint}", json=payload, headers=headers, verify=False)
        if response.status_code == 200:
            return obj_type  # ✅ Return type only
    return None


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

    # Get all groups
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

    # Get all groups
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

    # 🔍 Get group members
    members = get_group_members(group_name)
    other_members = [m["name"] for m in members if m["name"].lower() != object_name.lower()]
    print(f"[→] Group '{group_name}' contains {len(members)} member(s).")

    if other_members:
        print(f"[✓] Group '{group_name}' includes other members besides '{object_name}'.")
    else:
        print(f"[!] '{object_name}' is the only member in the group.")

    # 🔍 Show parent group names first (no rule dump)
    parent_groups = find_parent_groups(group_name)
    if parent_groups:
        print(f"\n[→] Group '{group_name}' is also part of {len(parent_groups)} parent group(s): {parent_groups}")
    else:
        print(f"[✓] Group '{group_name}' is not part of any parent group.")

    # 🔍 Then show where the group is used
    group_usage = get_where_used(group_name)
    rules = group_usage["used-directly"].get("access-control-rules", [])

    print(f"\n[→] Group '{group_name}' is used in {len(rules)} access rule(s):")
    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

    # 🧹 Ask engineer whether to remove object from group
    confirm = input(f"[?] Do you want to remove '{object_name}' from group '{group_name}'? (yes/no): ").strip().lower()
    if confirm == "yes":
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
    else:
        print(f"[!] Skipped removal from group '{group_name}'")


def remove_object_from_rules(object_name, usage_data):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rules = usage_data["used-directly"].get("access-control-rules", [])
    print(f"[+] Found {len(rules)} access control rules using object '{object_name}'.")

    if not rules:
        print("[!] No rules found. Exiting.")
        return False

    print("[*] Rules using object before removal:")
    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

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
        rule_data = get_rule_details(rule_uid, layer)
        if not rule_data:
            print(f"[!] Failed to fetch rule {rule_uid}")
            continue

        rule_name = rule_data.get("name", "Unnamed Rule")
        print(f"\n[→] Rule UID: {rule_uid}, Rule Name: {rule_name}")
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

def discard():
    headers = {"X-chkp-sid": sid, "content-type": "application/json"}
    response = requests.post(f"{mgmt_server}/discard", headers=headers, json={}, verify=False)
    if response.status_code == 200:
        print("[!] Changes discarded successfully.")
    else:
        print(f"[!] Discard failed with status {response.status_code}: {response.text or response.reason}")
def publish(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
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
        print(f"[✓] Object '{object_name}' is no longer used in any access rules.")

    confirm = input("[?] Do you want to publish changes? (yes/no): ").strip().lower()
    if confirm == "yes":
        response = requests.post(f"{mgmt_server}/publish", headers=headers, json={}, verify=False)
        if response.status_code == 200:
            print("[+] Changes published.")
        else:
            print(f"[!] Failed to publish changes: {response.text}")
    else:
        discard()
if __name__ == "__main__":
    try:
        login()
        print()

        object_name = input("Enter the server object name to decommission: ").strip()
        print()

        object_type = object_exists(object_name)
        if not object_type:
            print(f"[!] Object '{object_name}' not found. Exiting.")
            exit()

        usage = get_where_used(object_name)
        rule_count = len(usage["used-directly"].get("access-control-rules", []))

        print(f"[✓] Object '{object_name}' is available as type '{object_type}'.")
        print(f"[+] Found {rule_count} access control rules using object '{object_name}'")
        print()

        # 🔍 Check group membership using reverse lookup
        group_names = find_groups_containing_object(object_name)
        if group_names:
            print(f"[+] Object '{object_name}' is part of {len(group_names)} group(s): {group_names}")
            print()
            for group_name in group_names:
                handle_group_reference(object_name, group_name)
                print()

                # 🚪 Early exit if user skips removal and no rules exist
                if rule_count == 0:
                    print("[!] No rules found. Exiting.")
                    exit()
        else:
            print(f"[!] Object '{object_name}' is not part of any group.")
            print()

        # 🧹 Then handle direct rule references
        rule_removed = remove_object_from_rules(object_name, usage)
        print()

        # 🚪 Early exit if no changes were made
        if not rule_removed and not group_names:
            print("[!] No rules found. Exiting.")
            exit()

        # 📤 Publish if any changes were made
        publish(object_name)

    except Exception as e:
        print(f"[!] Error: {e}")
        discard()
    finally:
        logout()