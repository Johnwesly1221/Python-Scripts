# Full Combined Script: Mirror, Termination, Server-Decomm
# Written by Johnwesly — Final Operator-Safe Version 
# Mode TAB completion added / Every detail output added to engineer better understand.
# Comment Updated as requested 
# Functionalities - Termination, Mirror, Server-Decomm, auto add comment, NEGSDELETE-for termination, discard, publish, logout.
import requests
import urllib3
import getpass
import json
import readline
import difflib
from datetime import datetime

def log_session(username, mode, ticket_id):
    log_entry = f"{datetime.now().strftime('%Y-%m-%d')}, {username}, {mode}, {ticket_id}\n"
    with open("session_log.txt", "a") as log_file:
        log_file.write(log_entry)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
mgmt_server = "https://192.168.10.110/web_api"
sid = None
username = None


def login():
    global sid, username
    while True:
        username = input("Enter your username: ").strip()
        password = getpass.getpass("Enter your password: ").strip()
        payload = {"user": username, "password": password}
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(f"{mgmt_server}/login", json=payload, headers=headers, verify=False, timeout=30)
            response.raise_for_status()
            sid = response.json()["sid"]
            print("[+] Logged in successfully.")
            break
        except requests.exceptions.HTTPError as e:
            print("[!] Wrong username or password. Please try again.")
        except Exception as e:
            print(f"[!] Login failed: {e}")


def logout():
    global sid
    if not sid:
        return
    headers = {"X-chkp-sid": sid}
    requests.post(f"{mgmt_server}/logout", headers=headers, verify=False)
    print("[*] Logout successful.")
    sid = None

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

# Cache for rule-number mapping per layer
_layer_rule_map = {}

def get_rule_number_map(layer):
    if layer in _layer_rule_map:
        return _layer_rule_map[layer]

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": layer, "details-level": "standard"}
    response = requests.post(f"{mgmt_server}/show-access-rulebase", json=payload, headers=headers, verify=False)

    rule_map = {}
    if response.status_code == 200:
        rulebase = response.json().get("rulebase", [])
        for rule in rulebase:
            uid = rule.get("uid")
            number = rule.get("rule-number")
            if uid and number:
                rule_map[uid] = number
    _layer_rule_map[layer] = rule_map
    return rule_map


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
    global sid
    if not sid:
        return
    headers = {"X-chkp-sid": sid, "content-type": "application/json"}
    response = requests.post(f"{mgmt_server}/discard", headers=headers, json={}, verify=False)
    if response.status_code == 200:
        print("[!] Changes discarded successfully.")
    else:
        print(f"[!] Discard failed with status {response.status_code}: {response.text or response.reason}")

def publish(object_name=None, skip_usage_check=False):
    """
    Publish changes to the management server.
    - object_name: optional, used for usage check
    - skip_usage_check: if True, bypasses where-used check (for batch mode)
    """

    # ✅ Skip usage check in batch mode
    if not skip_usage_check and object_name and not object_name.startswith("NEGSDELETE-"):
        try:
            usage_check = get_where_used(object_name)
            still_used = usage_check["used-directly"].get("access-control-rules", [])

            if still_used:
                print(f"\n[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
                for ref in still_used:
                    rule_uid = ref["rule"]["uid"]
                    layer = ref["layer"]["name"]
                    rule_data = get_rule_details(rule_uid, layer)
                    rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
                    rule_number_map = get_rule_number_map(layer)
                    rule_number = rule_number_map.get(rule_uid, "N/A")
                    print(f"    - Rule No: {rule_number}, UID: {rule_uid}, Name: {rule_name}")
            else:
                print(f"[✓] Object '{object_name}' is no longer used in any access rules.")
        except Exception as e:
            print(f"[!] Skipping usage check due to error: {e}")

    confirm = input("\n[?] Do you want to publish changes? (yes/no): ").strip().lower()
    if confirm != "yes":
        discard()
        return

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/publish", headers=headers, json={}, verify=False)
    if response.status_code == 200:
        print("[+] Changes published.")
    else:
        print(f"[!] Failed to publish changes: {response.text}")


'''
def publish(object_name):
    # ✅ Skip usage check if object was renamed
    if object_name.startswith("NEGSDELETE-"):
        confirm = input("\n[?] Do you want to publish changes? (yes/no): ").strip().lower()
        if confirm != "yes":
            discard()
            return
    else:
        # ✅ Only check usage for original object
        usage_check = get_where_used(object_name)
        still_used = usage_check["used-directly"].get("access-control-rules", [])

        if still_used:
            print(f"\n[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
            for ref in still_used:
                rule_uid = ref["rule"]["uid"]
                layer = ref["layer"]["name"]
                rule_data = get_rule_details(rule_uid, layer)
                rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
                rule_number = rule_data.get("rule-number", "N/A")
                print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")
        else:
            print(f"[✓] Object '{object_name}' is no longer used in any access rules.")

        confirm = input("\n[?] Do you want to publish changes? (yes/no): ").strip().lower()
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
'''
def mirror_mode():
    target_object = input("\nEnter the New user object (host/network/user): ").strip()
    if not object_exists(target_object):
        print(f"[!] Object '{target_object}' is not available. Kindly create it first.")
        return

    usage_data = get_where_used(target_object)
    existing_rules = usage_data["used-directly"].get("access-control-rules", [])

    if existing_rules:
        print(f"\n[!] Object '{target_object}' is already used in {len(existing_rules)} rule(s).")
        print("[*] Object is already available in the following rules:")
        for ref in existing_rules:
            rule_uid = ref["rule"]["uid"]
            layer = ref["layer"]["name"]
            rule_data = get_rule_details(rule_uid, layer)
            rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
            rule_number = rule_data.get("rule-number", "N/A")
            print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}, Rule No: {rule_number}")
        return

    reference_object = input("\nEnter the Existing user object to find rules: ").strip()
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

def mirror_diff_add():
    hosts_a = input("\nEnter reference objects (host-A, comma separated): ").strip().split(",")
    hosts_b = input("Enter new objects to mirror (host-B, comma separated): ").strip().split(",")
    hosts_a = [h.strip() for h in hosts_a if h.strip()]
    hosts_b = [h.strip() for h in hosts_b if h.strip()]

    if not hosts_a or not hosts_b:
        print("[!] No valid objects entered.")
        return

    # Ticket once for the whole batch
    today_str = datetime.now().strftime("%Y%m%d")
    short_user = username[:4].lower()
    ticket = input("[?] Enter ticket number (e.g., TKT234764290): ").strip()
    mode_symbol = "(+)"
    final_comment = f"{today_str} {short_user} {ticket}{mode_symbol}jks"

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]

    summary = {}

    # Step 1: Discovery phase
    rules_to_update = []
    for host_a in hosts_a:
        print(f"\n[✓] Processing reference object: {host_a}")
        if not object_exists(host_a):
            print(f"[!] Reference object '{host_a}' not found.")
            continue

        usage_a = get_where_used(host_a)
        rules_a = usage_a["used-directly"].get("access-control-rules", [])
        print(f"[→] '{host_a}' is used in {len(rules_a)} rule(s):")

        summary[host_a] = {"updated": 0, "skipped": 0}

        for ref in rules_a:
            rule_uid = ref["rule"]["uid"]
            layer = ref["layer"]["name"]
            rule_data = get_rule_details(rule_uid, layer)
            rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
            print(f"    rule uid: {rule_uid}, rule name: {rule_name}")
            rules_to_update.append((host_a, rule_uid, layer, rule_name))

    # Step 2: Confirmation
    confirm = input(f"\n[?] Do you want to add {hosts_b} to these rules? (yes/no): ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("[!] Operation aborted.")
        return

    # Step 3: Update phase
    for host_a, rule_uid, layer, rule_name in rules_to_update:
        rule_data = get_rule_details(rule_uid, layer)
        updated_fields = []
        skipped_fields = []

        for field in list_fields:
            field_value = rule_data.get(field, [])
            if isinstance(field_value, list):
                if any(obj.get("name", "").lower() == host_a.lower() for obj in field_value):
                    existing_names = {obj.get("name", "").lower() for obj in field_value}
                    to_add = [b for b in hosts_b if b.lower() not in existing_names]

                    if to_add:
                        update_payload = {"uid": rule_uid, "layer": layer, field: {"add": to_add}}
                        update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                        if update_resp.status_code == 200:
                            print(f"[✓] Rule {rule_name}: Added {to_add} to {field}")
                            updated_fields.append(field)
                            summary[host_a]["updated"] += 1
                        else:
                            print(f"[!] Failed to update field '{field}': {update_resp.text}")
                    else:
                        print(f"[→] Rule {rule_name}: Already contains {hosts_b} in {field} — skipped")
                        skipped_fields.append(field)
                        summary[host_a]["skipped"] += 1

        # ✅ Only update comment once per rule
        if updated_fields or skipped_fields:
            update_rule_comment(rule_uid, layer, final_comment)
            print(f"[✓] Comment updated for rule '{rule_name}' with ticket {ticket}")

    # Step 4: Summary phase
    print("\n[✓] Summary of updates:")
    for ref_obj, stats in summary.items():
        print(f"    {ref_obj} → {stats['updated']} rules updated, {stats['skipped']} skips logged")

    # Step 5: Publish phase
    confirm = input("\n[?] Do you want to publish all changes now? (yes/no): ").strip().lower()
    if confirm in ["y", "yes"]:
        publish(skip_usage_check=True)
    else:
        discard()
    confirm = input ("\n Do you want to logout? (Yes/no): ").strip().lower()
    if confirm in ["y", "yes"]:
        logout()
    else:
        return mirror_diff_add()


'''
def mirror_diff_add():
    host_a = input("\nEnter reference object (host-A): ").strip()
    host_b = input("Enter new object to mirror (host-B): ").strip()
    if not object_exists(host_a) or not object_exists(host_b):
        print("[!] One or both objects not found.")
        return

    usage_a = get_where_used(host_a)
    usage_b = get_where_used(host_b)

    rules_a = usage_a["used-directly"].get("access-control-rules", [])
    rules_b = usage_b["used-directly"].get("access-control-rules", [])

    print(f"\n[→] '{host_a}' is used in {len(rules_a)} rule(s):")
    for ref in rules_a:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        rule_number = rule_data.get("rule-number", "N/A")
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

    print(f"\n[→] '{host_b}' is used in {len(rules_b)} rule(s):")
    for ref in rules_b:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        rule_number = rule_data.get("rule-number", "N/A")
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")


    rule_uids_b = {ref["rule"]["uid"] for ref in rules_b}
    rules_to_update = []

    print(f"\n[✓] Comparing rules for '{host_a}' and '{host_b}'...")

    for ref in rules_a:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        if rule_uid not in rule_uids_b:
            rule_data = get_rule_details(rule_uid, layer)
            rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
            rule_number = rule_data.get("rule-number", "N/A")
            print(f"    - Missing in Rule UID: {rule_uid}, Rule Name: {rule_name}")
            rules_to_update.append((rule_uid, layer, rule_number, rule_name))


    if not rules_to_update:
        print("[✓] No rules need updating. Host-B already present in all Host-A rules.")
        return

    confirm = input(f"\n[?] Do you want to add '{host_b}' to these {len(rules_to_update)} rules? (yes/no): ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("[!] Operation aborted.")
        return

    # Comment setup
    today_str = datetime.now().strftime("%Y%m%d")
    short_user = username[:4].lower()
    ticket = input("[?] Enter ticket number (e.g., TKT234764290): ").strip()
    mode_symbol = "(+)"
    final_comment = f"{today_str} {short_user} {ticket}{mode_symbol}jks"

    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]
    single_fields = ["action", "track"]

    for rule_uid, layer, rule_number, rule_name in rules_to_update:
        rule_data = get_rule_details(rule_uid, layer)
        updated_fields = []

        for field in rule_data:
            field_value = rule_data[field]
            if field in list_fields and isinstance(field_value, list):
                if any(obj.get("name", "").lower() == host_a.lower() for obj in field_value):
                    update_payload = {"uid": rule_uid, "layer": layer, field: {"add": [host_b]}}
                    update_resp = requests.post(f"{mgmt_server}/set-access-rule", json=update_payload, headers=headers, verify=False)
                    if update_resp.status_code == 200:
                        print(f"\n[->] Rule UID: {rule_uid} Rule Name: {rule_name}")
                        print(f"[✓] Added '{host_b}' to field '{field}'")
                        updated_fields.append(field)
                    else:
                        print(f"[!] Failed to update field '{field}': {update_resp.text}")

        if updated_fields:
            update_rule_comment(rule_uid, layer, final_comment)

    # Show updated rules for host-B
    usage_b_post = get_where_used(host_b)
    rules_b_post = usage_b_post["used-directly"].get("access-control-rules", [])
    print(f"\n[✓] '{host_b}' is now used in {len(rules_b_post)} rule(s):")
    for ref in rules_b_post:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        rule_number = rule_data.get("rule-number", "N/A")
        print(f"    - Rule UID: {rule_uid}, Rule Name: {rule_name}")

    confirm = input("\n[?] Do you want to publish changes? (yes/no): ").strip().lower()
    if confirm in ["y", "yes"]:
        print("[DEBUG] Calling publish() now...")
        import builtins
        original_input = input
        def patched_input(prompt=""):
            if "publish" in prompt.lower():
                print(f"{prompt}yes")
                return "yes"
            return original_input(prompt)
        builtins.input = patched_input
        publish(host_b)
        builtins.input = original_input
    else:
        discard()
'''
def add_object_to_rules(new_object, reference_object, usage_data):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rules = usage_data["used-directly"].get("access-control-rules", [])
    print(f"[+] Found {len(rules)} rules using '{reference_object}'.")

    #user_comment = input("[?] Enter comment to add to each mirrored rule: ").strip()
    today_str = datetime.now().strftime("%Y%m%d")
    short_user = username[:4].lower()
    ticket = input("[?] Enter ticket number (e.g., TKT234764290): ").strip()
    mode_symbol = {"termination": "(-)", "mirror": "(+)", "server-decomm": "(-)"}.get(mode, "(?)")
    log_session(username, mode, ticket)
    final_comment = f"{today_str} {short_user} {ticket}{mode_symbol}jks"
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
            update_rule_comment(rule_uid, layer, final_comment)
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
    print(f"\n[+] Found {len(rules)} access control rules using object '{object_name}'.")

    if not rules:
        #print("[!] No rules found. Exiting.")
        return False

    # Enrich rules with rule-number
    enriched_rules = []
    for ref in rules:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_map = get_rule_number_map(layer)
        rule_number = rule_map.get(rule_uid, "N/A")
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        enriched_rules.append((rule_number, rule_uid, rule_name, layer))

        # Sort by rule-number (if numeric)
    enriched_rules.sort(key=lambda x: int(x[0]) if str(x[0]).isdigit() else 9999)

    print("[*] Rules using object before removal (ordered):")
    for rule_number, rule_uid, rule_name, layer in enriched_rules:
        print(f"    - Rule No: {rule_number}, Rule UID: {rule_uid}, Rule Name: {rule_name}")


    confirm = input(f"[?] Object '{object_name}' found in rules. Do you want to proceed with removal? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[!] Removal aborted by user.")
        return False

    #user_comment = input("[?] Enter comment to add to each rule after removal: ").strip()
    

    today_str = datetime.now().strftime("%Y%m%d")
    short_user = username[:4].lower()
    ticket = input("[?] Enter ticket number (e.g., TKT234764290): ").strip()
    mode_symbol = {"termination": "(-)", "mirror": "(+)", "server-decomm": "(-)"}.get(mode, "(?)")
    log_session(username, mode, ticket)
    final_comment = f"{today_str} {short_user} {ticket}{mode_symbol}jks"

    any_updated = False
    list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]
    single_fields = ["action", "track"]
    
    for rule_number, rule_uid, rule_name, layer in enriched_rules:
    #for ref in rules:
        #rule_uid = ref["rule"]["uid"]
        #layer = ref["layer"]["name"]
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
            update_rule_comment(rule_uid, layer, final_comment)
        else:
            print(f"[!] Object not found in editable fields for rule {rule_uid}")

    return any_updated
'''
def get_group_members(group_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": group_name}
    response = requests.post(f"{mgmt_server}/show-group", json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get("members", [])
    return []

from concurrent.futures import ThreadPoolExecutor, as_completed

def threaded_group_scan(object_name, group_list, max_threads=10):
    found_groups = []

    def check_group(group_name):
        members = get_group_members(group_name)
        if any(obj.get("name", "").lower() == object_name.lower() for obj in members):
            return group_name
        return None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_group = {executor.submit(check_group, g): g for g in group_list}
        for future in as_completed(future_to_group):
            result = future.result()
            if result:
                found_groups.append(result)

    return found_groups

def get_total_group_count():
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"limit": 1}
    response = requests.post(f"{mgmt_server}/show-groups", json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get("total", 0)
    return 0

def find_groups_containing_object(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": object_name, "indirect": True}
    response = requests.post(f"{mgmt_server}/where-used", json=payload, headers=headers, verify=False)

    group_names = set()
    if response.status_code == 200:
        data = response.json()
        direct_groups = data.get("used-directly", {}).get("groups", [])
        indirect_groups = data.get("used-indirectly", {}).get("groups", [])
        for ref in direct_groups + indirect_groups:
            if "name" in ref:
                group_names.add(ref["name"])

    if group_names:
        return list(group_names)

    # Fallback scan
    print("[DEBUG] No groups found via where-used. Falling back to full group scan...")

    total_group_count = get_total_group_count()
    if total_group_count > 10000:
        max_groups_to_scan = 3000
        max_threads = 5
        use_threading = True
    elif total_group_count > 1000:
        max_groups_to_scan = 1000
        max_threads = 10
        use_threading = True
    else:
        max_groups_to_scan = 100
        max_threads = 1
        use_threading = False

    all_groups = []
    offset = 0
    batch_size = 500

    while True:
        payload = {"limit": batch_size, "offset": offset}
        resp = requests.post(f"{mgmt_server}/show-groups", json=payload, headers=headers, verify=False)
        if resp.status_code != 200:
            print(f"[!] Failed to fetch groups: {resp.text}")
            break

        groups = resp.json().get("objects", [])
        if not groups:
            break

        for group in groups:
            group_name = group.get("name")
            if group_name:
                all_groups.append(group_name)

        offset += batch_size
        if len(all_groups) >= max_groups_to_scan:
            print(f"[!] Scan limit of {max_groups_to_scan} reached. Stopping early.")
            break

    if use_threading:
        found_groups = threaded_group_scan(object_name, all_groups[:max_groups_to_scan], max_threads=max_threads)
    else:
        found_groups = []
        for group_name in all_groups[:max_groups_to_scan]:
            members = get_group_members(group_name)
            if any(obj.get("name", "").lower() == object_name.lower() for obj in members):
                found_groups.append(group_name)

    print(f"[DEBUG] Found groups via fallback scan: {found_groups}")
    return found_groups

def find_parent_groups(group_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    parent_groups = []
    offset = 0
    batch_size = 500

    while True:
        payload = {"limit": batch_size, "offset": offset}
        response = requests.post(f"{mgmt_server}/show-groups", json=payload, headers=headers, verify=False)
        if response.status_code != 200:
            print(f"[!] Failed to fetch groups for parent lookup: {response.text}")
            break

        groups = response.json().get("objects", [])
        if not groups:
            break

        for group in groups:
            members = get_group_members(group.get("name"))
            if any(m.get("name", "").lower() == group_name.lower() for m in members):
                parent_groups.append(group.get("name"))

        offset += batch_size

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
    # Rename host after removal
    #new_name = f"NEGSDELETE-{object_name}"
    #object_name = rename_object(object_name, new_name)


    # Re-check group membership
    updated_members = get_group_members(group_name)
    if updated_members:
        return  # Group still has members — no further action
    
    # Rename group if now empty
    #new_group_name = f"NEGSDELETE-{group_name}"
    #group_name = rename_object(group_name, new_group_name)


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
    """
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
        """
    group_usage = get_where_used(group_name)
    rule_refs = group_usage["used-directly"].get("access-control-rules", [])
    if not rule_refs:
        return

# Enrich rule refs with rule number and name
    enriched_rules = []
    for ref in rule_refs:
        rule_uid = ref["rule"]["uid"]
        layer = ref["layer"]["name"]
        rule_map = get_rule_number_map(layer)
        rule_number = rule_map.get(rule_uid, "N/A")
        rule_data = get_rule_details(rule_uid, layer)
        rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
        enriched_rules.append((rule_number, rule_uid, rule_name, layer))

# Sort by rule number
    enriched_rules.sort(key=lambda x: int(x[0]) if str(x[0]).isdigit() else 9999)

    print(f"\n[→] Removing empty group '{group_name}' from {len(enriched_rules)} access rule(s):")
    #comment_text = input("[?] Enter comment to add to each rule after group removal: ").strip()
    today_str = datetime.now().strftime("%Y%m%d")
    short_user = username[:4].lower()
    ticket = input("[?] Enter ticket number (e.g., TKT234764290): ").strip()
    mode_symbol = {"termination": "(-)", "mirror": "(+)", "server-decomm": "(-)"}.get(mode, "(?)")
    final_comment = f"{today_str} {short_user} {ticket} {mode_symbol} (jk-scr)"
    list_fields = ["source", "destination", "service", "vpn", "content", "time", "install-on"]
    single_fields = ["action", "track"]

    for rule_number, rule_uid, rule_name, layer in enriched_rules:
        print(f"    - Rule No: {rule_number}, Rule UID: {rule_uid}, Rule Name: {rule_name}")
        rule_data = get_rule_details(rule_uid, layer)
        if not rule_data:
            print(f"[!] Failed to fetch rule details for UID: {rule_uid}")
            continue

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
        update_rule_comment(rule_uid, layer, final_comment)

def run_server_decomm():
    while True:
        object_name = input("\nEnter the server object name to decommission: ").strip()
        if object_exists(object_name):
            break
        print(f"[!] Object '{object_name}' not found. Please try again.")

    groups = find_groups_containing_object(object_name)
    if not groups:
        print(f"[✓] Object '{object_name}' is not part of any group. Proceeding to rule cleanup...")
        usage_data = get_where_used(object_name)
        updated = remove_object_from_rules(object_name, usage_data)
        if updated:
            publish(object_name)
        else:
            print(f"[!] No rule updates were made for '{object_name}'.")
        return

    print(f"[+] Object '{object_name}' is part of {len(groups)} group(s): {groups}")
    for group_name in groups:
        handle_group_reference(object_name, group_name)

    groups = find_groups_containing_object(object_name)
    print(f"[DEBUG] Raw group lookup result for '{object_name}': {groups}")

    usage = get_where_used(object_name)
    rule_removed = remove_object_from_rules(object_name, usage)
    if not rule_removed and not groups:
        print("[!] No rules found. Exiting.")
        #return publish(object_name), logout()
    #publish(object_name)
#new Added of host rename
    usage_check = get_where_used(object_name)
    still_used = usage_check["used-directly"].get("access-control-rules", [])

    if still_used:
        print(f"\n[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
        for ref in still_used:
            rule_uid = ref["rule"]["uid"]
            layer = ref["layer"]["name"]
            rule_map = get_rule_number_map(layer)
            rule_number = rule_map.get(rule_uid, "N/A")
            rule_data = get_rule_details(rule_uid, layer)
            rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
            print(f"    - Rule No: {rule_number}, Rule UID: {rule_uid}, Rule Name: {rule_name}")
    else:
        print(f"\n[✓] Object '{object_name}' is no longer used in any access rules.")
        renamed_object = f"NEGSDELETE-{object_name}"
        object_name = rename_object(object_name, renamed_object)
    publish(object_name)
'''

if __name__ == "__main__":
    try:
        try:
            valid_modes = {"termination": "termination", "mirror": "mirror", "rules_mirror": "mirror_diff_add"}

            def completer(text, state):
                options = [mode for mode in valid_modes if mode.startswith(text.lower())]
                return options[state] if state < len(options) else None

            readline.set_completer(completer)
            readline.parse_and_bind("tab: complete")

            def resolve_mode(user_input):
                user_input = user_input.strip().lower()
                matches = [mode for mode in valid_modes if mode.startswith(user_input)]
                if len(matches) == 1:
                    return valid_modes[matches[0]]
                elif len(matches) > 1:
                    print(f"[!] Ambiguous input. Matches: {matches}")
                    return None
                fuzzy = difflib.get_close_matches(user_input, valid_modes.keys(), n=1, cutoff=0.6)
                if fuzzy:
                    print(f"[~] Interpreting '{user_input}' as '{fuzzy[0]}'")
                    return valid_modes[fuzzy[0]]
                print("[!] Invalid mode. Try typing a full or partial match like 'ter', 'mir', or 'mir_dif'.")
                return None

            mode = None
            while not mode:
                raw_input = input("Select mode (Termination/Mirror/mirror_diff_add): ")
                mode = resolve_mode(raw_input)

            print(f"[✓] Mode selected: {mode.capitalize()}")
            login()

            if mode == "termination":
                object_name = input("\nEnter the object name (host/network/user): ").strip()
                if not object_exists(object_name):
                    print(f"[!] Object '{object_name}' is not available. Kindly create it first.")
                    exit()
                usage = get_where_used(object_name)
                if remove_object_from_rules(object_name, usage):
                    usage_check = get_where_used(object_name)
                    still_used = usage_check["used-directly"].get("access-control-rules", [])

                    if still_used:
                        #print(f"\n[!] Object '{object_name}' is still used in {len(still_used)} rule(s).")
                        enriched_post = []
                        for ref in still_used:
                            rule_uid = ref["rule"]["uid"]
                            layer = ref["layer"]["name"]
                            rule_map = get_rule_number_map(layer)
                            rule_number = rule_map.get(rule_uid, "N/A")
                            rule_data = get_rule_details(rule_uid, layer)
                            rule_name = rule_data.get("name", "Unnamed Rule") if rule_data else "Unknown"
                            enriched_post.append((rule_number, rule_uid, rule_name, layer))

                        enriched_post.sort(key=lambda x: int(x[0]) if str(x[0]).isdigit() else 9999)

                        #print("[*] Remaining rules using object (ordered):")
                        #for rule_number, rule_uid, rule_name, _ in enriched_post:
                            #print(f"    - Rule No: {rule_number}, Rule UID: {rule_uid}, Rule Name: {rule_name}")
                        #confirm = input("\n[?] Do you want to publish changes? (yes/no): ").strip().lower()
                        #if confirm in ["y", "yes"]:
                        publish(object_name)
                        #else:
                            #discard()
                    else:
                        print(f"\n[✓] Object '{object_name}' is no longer used in any access rules.")
                        renamed_object = f"NEGSDELETE-{object_name}"
                        object_name = rename_object(object_name, renamed_object)
                        publish(object_name)

            elif mode == "mirror":
                mirror_mode()
            elif mode == "mirror_diff_add":
                #host_a = input("\nEnter reference object (host-A): ").strip()
                #host_b = input("Enter new object to mirror (host-B): ").strip()
                #mirror_diff_add(host_a, host_b)
                mirror_diff_add()
            

            #elif mode == "server-decomm":
                #run_server_decomm()

            else:
                print("[!] Invalid mode selected.")
        except Exception as e:
            print(f"[!] Error: {e}")
            discard()
        except KeyboardInterrupt:
            print("\nKeyboard Interruppted by User (CTRL+C)")
            discard()
    finally:
        logout()

