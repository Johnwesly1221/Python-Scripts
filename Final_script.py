import requests
import urllib3
import getpass

# Disable SSL warnings (only for testing; use proper certs in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
mgmt_server = "https://192.168.10.110/web_api"
sid = None  # Session ID

# --- Login using username and password ---
def login():
    global sid
    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ").strip()
    payload = {"user": username, "password": password}
    headers = {"Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/login", json=payload, headers=headers, verify=False)
    response.raise_for_status()
    sid = response.json()["sid"]
    print("[+] Logged in successfully.")

# --- Where Used ---
def get_where_used(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": object_name, "indirect": False}
    response = requests.post(f"{mgmt_server}/where-used", json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

# --- Remove Object from Rules ---
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

        # Fetch rule name
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

    any_updated = False
    valid_types = {"host", "network", "group", "user", "group-with-exclusion"}

    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]

        # Get current rule with full details
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

        for field in ["source", "destination"]:
            current_list = rule_data.get(field, [])
            if any(obj.get("type") in valid_types and obj.get("name", "").lower() == object_name.lower() for obj in current_list):
                new_list = [obj["uid"] for obj in current_list if not (obj.get("type") in valid_types and obj.get("name", "").lower() == object_name.lower())]
                update_payload = {
                    "uid": rule_uid,
                    "layer": layer,
                    field: new_list
                }
                update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                if update_resp.status_code == 200:
                    print(f"[✓] Removed '{object_name}' from {field}")
                    removed_fields.append(field)
                    any_updated = True
                else:
                    print(f"[!] Failed to update {field} in rule {rule_uid}: {update_resp.text}")

        if not removed_fields:
            print(f"[!] Object '{object_name}' not found in source or destination")

    return any_updated

# --- Discard Changes ---
def discard():
    headers = {"X-chkp-sid": sid}
    response = requests.post(f"{mgmt_server}/discard", headers=headers, verify=False)
    if response.status_code == 200:
        print("[!] Changes discarded.")
    else:
        print(f"[!] Failed to discard changes: {response.text}")

# --- Publish Changes ---
def publish(object_name):
    usage_check = get_where_used(object_name)
    still_used = usage_check["used-directly"].get("access-control-rules", [])

    if still_used:
        print(f"[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
        print("[*] Still used in the following rules:")
        for ref in still_used:
            print(f"    - Rule UID: {ref['rule']['uid']}")
    else:
        print(f"[✓] Object '{object_name}' is no longer used in any access rules.")

    confirm = input("[?] Do you want to publish changes? (yes/no): ").strip().lower()
    if confirm != "yes":
        discard()
        return

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/publish", headers=headers, json={}, verify=False)
    response.raise_for_status()
    print("[+] Changes published.")

# --- Logout Session ---
def logout():
    headers = {"X-chkp-sid": sid}
    requests.post(f"{mgmt_server}/logout", headers=headers, verify=False)

# --- Main Execution ---
if __name__ == "__main__":
    try:
        object_name = input("Enter the object name (host/network/user): ").strip()
        login()
        usage = get_where_used(object_name)
        if remove_object_from_rules(object_name, usage):
            publish(object_name)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        logout()
print("[*] Logout Successfull.")
