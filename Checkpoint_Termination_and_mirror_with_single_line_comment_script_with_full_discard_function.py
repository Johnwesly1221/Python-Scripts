# Checkpoint Mirror & Termination Full Script with Single Line Comment Addition long with Publish/Discard
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

    payload = {
        "uid": rule_uid,
        "layer": layer,
        "comments": new_comment.strip()
    }
    response = requests.post(f"{mgmt_server}/set-access-rule", json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"[✓] Comment updated for rule '{rule_data.get('name', rule_uid)}'")
    else:
        print(f"[!] Failed to update comment: {response.text}")

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

            # Handle list-type fields
            if field in list_fields and isinstance(field_value, list):
                if any(obj.get("name", "").lower() == reference_object.lower() for obj in field_value):
                    update_payload = {
                        "uid": rule_uid,
                        "layer": layer,
                        field: {
                            "add": [new_object]
                        }
                    }
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Added '{new_object}' to field '{field}'")
                        updated_fields.append(field)
                    else:
                        print(f"[!] Failed to add to field '{field}': {update_resp.text}")

            # Handle single-object fields
            elif field in single_fields and isinstance(field_value, dict):
                if field_value.get("name", "").lower() == reference_object.lower():
                    update_payload = {
                        "uid": rule_uid,
                        "layer": layer,
                        field: new_object
                    }
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
            print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")
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
        print(f"\n[→] Rule UID: {rule_uid}, Rule Name: {rule_name}")

        removed_fields = []

        for field in rule_data:
            field_value = rule_data[field]

            # Handle list-type fields using 'remove' syntax
            if field in list_fields and isinstance(field_value, list):
                if any(obj.get("name", "").lower() == object_name.lower() for obj in field_value):
                    update_payload = {
                        "uid": rule_uid,
                        "layer": layer,
                        field: {
                            "remove": [object_name]
                        }
                    }
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Removed '{object_name}' from {field}")
                        #update_rule_comment(rule_uid, layer, user_comment)
                        removed_fields.append(field)
                        any_updated = True
                    else:
                        print(f"[!] Failed to update {field} in rule {rule_uid}: {update_resp.text}")

            # Handle single-object fields
            elif isinstance(field_value, dict):
                if field_value.get("name", "").lower() == object_name.lower():
                    update_payload = {"uid": rule_uid, "layer": layer, field: None}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"[✓] Removed '{object_name}' from field '{field}'")
                        removed_fields.append(field)
                        any_updated = True
                    else:
                        print(f"[!] Failed to remove '{object_name}' from field '{field}': {update_resp.text}")
        if removed_fields:
            update_rule_comment(rule_uid, layer, user_comment)
        else:
            print(f"[!] Object '{object_name}' not found directly in any editable rule field")

    return any_updated

def discard():
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/discard", headers=headers, verify=False)
    if response.status_code == 200:
        print("[✓] Changes discarded Successfully.")
    else:
        print(f"[!] Discard failed with status {response.status_code}: {response.text or response.reason}")

def publish(object_name):
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
    if confirm != "yes":
        discard()
        return

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/publish", headers=headers, json={}, verify=False)
    if response.status_code == 200:
        print("[+] Changes published.")
    else:
        print(f"[!] Failed to publish changes: {response.text}")
def logout():
    headers = {"X-chkp-sid": sid}
    requests.post(f"{mgmt_server}/logout", headers=headers, verify=False)

if __name__ == "__main__":
    try:
        mode = input("Select mode (Termination/Mirror): ").strip().lower()
        login()
        if mode == "termination":
            object_name = input("Enter the object name (host/network/user): ").strip()
            usage = get_where_used(object_name)
            if remove_object_from_rules(object_name, usage):
                publish(object_name)
        elif mode == "mirror":
            mirror_mode()
        else:
            print("[!] Invalid mode selected.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        logout()
        print("[*] Logout Successfull.")