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
def get_where_used(host_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": host_name, "indirect": False}
    response = requests.post(f"{mgmt_server}/where-used", json=payload, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

# --- Remove Host from Rules ---
def remove_host_from_rules(host_name, usage_data):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rules = usage_data["used-directly"].get("access-control-rules", [])
    print(f"[+] Found {len(rules)} access control rules using host '{host_name}'.")

    if not rules:
        print("[!] No rules found. Exiting.")
        return False

    print("[*] Rules using host before removal:")
    for ref in rules:
        print(f"    - Rule UID: {ref['rule']['uid']} in layer: {ref['layer']['name']}")

    confirm = input(f"[?] Host '{host_name}' found in rules. Do you want to proceed with removal? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[!] Removal aborted by user.")
        return False

    any_updated = False

    for ref in rules:
        layer = ref["layer"]["name"]
        rule_uid = ref["rule"]["uid"]

        # Get current rule
        get_payload = {"uid": rule_uid, "layer": layer}
        get_resp = requests.post(f"{mgmt_server}/show-access-rule", json=get_payload, headers=headers, verify=False)
        if get_resp.status_code != 200:
            print(f"[!] Failed to fetch rule {rule_uid}: {get_resp.text}")
            continue

        rule_data = get_resp.json()
        print(f"[i] Rule {rule_uid} fields: {list(rule_data.keys())}")

        for field in ["source", "destination"]:
            value = rule_data.get(field)
            if value:
                print(f"[→] {field}: {value}")

        updated = False

        for field in ["source", "destination"]:
            current_list = rule_data.get(field, [])
            if any(obj.get("type") == "host" and obj.get("name") == host_name for obj in current_list):
                new_list = [obj["uid"] for obj in current_list if not (obj.get("type") == "host" and obj.get("name") == host_name)]
                update_payload = {
                    "uid": rule_uid,
                    "layer": layer,
                    field: new_list
                }
                update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                if update_resp.status_code == 200:
                    print(f"[-] Removed host '{host_name}' from {field} in rule {rule_uid}.")
                    updated = True
                    any_updated = True
                else:
                    print(f"[!] Failed to update {field} in rule {rule_uid}: {update_resp.text}")

        if not updated:
            print(f"[!] Host '{host_name}' not found in rule {rule_uid} source/destination.")

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
def publish(host_name):
    usage_check = get_where_used(host_name)
    still_used = usage_check["used-directly"].get("access-control-rules", [])

    if still_used:
        print(f"[!] Host '{host_name}' is still used in {len(still_used)} rule(s).")
        print("[*] Host still used in the following rules:")
        for ref in still_used:
            print(f"    - Rule UID: {ref['rule']['uid']} in layer: {ref['layer']['name']}")
    else:
        print(f"[✓] Host '{host_name}' is no longer used in any access rules.")

    confirm = input("[?] Do you want to publish changes? (yes/no): ").strip().lower()
    if confirm != "yes":
        discard()
        return

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/publish", headers=headers, json={}, verify=False)
    response.raise_for_status()
    print("[+] Changes published.")

# --- Main Execution ---
if __name__ == "__main__":
    try:
        host_name = input("Enter the Host name: ").strip()
        login()
        usage = get_where_used(host_name)
        if remove_host_from_rules(host_name, usage):
            publish(host_name)
    except Exception as e:
        print(f"[!] Error: {e}")
