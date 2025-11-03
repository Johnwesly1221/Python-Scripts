import requests
import urllib3
import json
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mgmt_server = "https://192.168.10.110/web_api"
sid = None

def load_credentials():
    try:
        with open("credentials.json", "r") as f:
            creds = json.load(f)
            return creds["username"], creds["password"]
    except Exception as e:
        print(f"[!] Failed to load credentials: {e}")
        exit(1)

def login():
    global sid
    username, password = load_credentials()
    payload = {"user": username, "password": password}
    headers = {"Content-Type": "application/json"}
    response = requests.post(f"{mgmt_server}/login", json=payload, headers=headers, verify=False, timeout=30)
    response.raise_for_status()
    sid = response.json()["sid"]
    print(f"[+] Logged in as  '{username}'")

def logout():
    global sid
    if not sid:
        return
    headers = {"X-chkp-sid": sid}
    try:
        requests.post(f"{mgmt_server}/logout", headers=headers, verify=False, timeout=30)
        print("[*] Logout Successful.")
    except Exception:
        print("[*] Logout attempt failed or session already closed.")
    sid = None

def object_exists(object_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    object_types = [
        ("host", "show-host"),
        ("network", "show-network"),
        ("group", "show-group"),
        ("access-role", "show-access-role"),
        ("service", "show-service"),
        ("service-tcp", "show-service-tcp"),
        ("service-udp", "show-service-udp")
    ]
    for obj_type, endpoint in object_types:
        payload = {"name": object_name}
        try:
            response = requests.post(f"{mgmt_server}/{endpoint}", json=payload, headers=headers, verify=False, timeout=30)
        except Exception:
            continue
        if response.status_code == 200:
            return True
    return False

def get_services_by_port(port):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    matched_services = set()

    for endpoint in ["show-services-tcp", "show-services-udp"]:
        offset = 0
        limit = 100
        while True:
            payload = {"limit": limit, "offset": offset}
            response = requests.post(f"{mgmt_server}/{endpoint}", json=payload, headers=headers, verify=False, timeout=30)
            if response.status_code != 200:
                break
            services = response.json().get("objects", [])
            for svc in services:
                svc_port = svc.get("port", "")
                if str(svc_port) == str(port):
                    matched_services.add(svc.get("name"))
            if len(services) < limit:
                break
            offset += limit

    return matched_services

def get_where_used_safe(object_name):
    if not object_name or object_name.lower() == "any":
        return set()
    if not object_exists(object_name):
        # silently treat missing object as no usage
        return set()
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": object_name, "indirect": True}
    try:
        response = requests.post(f"{mgmt_server}/where-used", json=payload, headers=headers, verify=False, timeout=30)
    except Exception:
        return set()
    if response.status_code != 200:
        return set()
    data = response.json()
    return {ref["rule"]["uid"] for ref in data.get("used-directly", {}).get("access-control-rules", [])}

def get_all_rule_uids(layer_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    all_uids = set()
    offset = 0
    limit = 100

    while True:
        payload = {
            "name": layer_name,
            "limit": limit,
            "offset": offset,
            "details-level": "standard"
        }
        response = requests.post(f"{mgmt_server}/show-access-rulebase", headers=headers, json=payload, verify=False, timeout=30)
        if response.status_code != 200:
            break
        rules = response.json().get("rulebase", [])
        for rule in rules:
            uid = rule.get("uid")
            if uid:
                all_uids.add(uid)
        if len(rules) < limit:
            break
        offset += limit

    return all_uids

def get_rule_details(rule_uid, layer_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"uid": rule_uid, "layer": layer_name, "details-level": "full"}
    try:
        response = requests.post(f"{mgmt_server}/show-access-rule", json=payload, headers=headers, verify=False, timeout=30)
    except Exception:
        return None
    return response.json() if response.status_code == 200 else None

def get_rule_number_map(layer_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    rule_map = {}
    offset = 0
    limit = 100

    while True:
        payload = {
            "name": layer_name,
            "limit": limit,
            "offset": offset,
            "details-level": "standard"
        }
        response = requests.post(f"{mgmt_server}/show-access-rulebase", headers=headers, json=payload, verify=False, timeout=30)
        if response.status_code != 200:
            break
        rules = response.json().get("rulebase", [])
        for rule in rules:
            uid = rule.get("uid")
            if uid:
                rule_map[uid] = rule.get("rule-number", "N/A")
        if len(rules) < limit:
            break
        offset += limit

    return rule_map

def search_rules_by_object(layer_name, source=None, destination=None, services=None):
    source = source.strip() if source else "Any"
    destination = destination.strip() if destination else "Any"
    services = [s.strip() for s in services.split(",")] if services else ["Any"]

    rule_sets = []

    # Source
    rule_sets.append(get_where_used_safe(source) if source != "Any" else get_all_rule_uids(layer_name))

    # Destination
    rule_sets.append(get_where_used_safe(destination) if destination != "Any" else get_all_rule_uids(layer_name))

    # Services
    if services != ["Any"]:
        svc_rules = set()
        for svc in services:
            if svc.isdigit():
                matched_names = get_services_by_port(svc)
                for name in matched_names:
                    svc_rules.update(get_where_used_safe(name))
            else:
                svc_rules.update(get_where_used_safe(svc))
        rule_sets.append(svc_rules)
    else:
        rule_sets.append(get_all_rule_uids(layer_name))

    # if any of the sets is empty, intersection will be empty
    if not rule_sets:
        return set()

    matched_rules = set.intersection(*rule_sets)

    return matched_rules

def get_layers():
    """
    Try to discover layers automatically.
    1) Preferred: show-access-layers
    2) Fallback: attempt to infer layer names from show-access-rulebase listing
    Returns list of layer names (may be empty).
    """
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    layers = []
    offset = 0
    limit = 100

    # First attempt: show-access-layers
    while True:
        payload = {"limit": limit, "offset": offset}
        try:
            response = requests.post(f"{mgmt_server}/show-access-layers", json=payload, headers=headers, verify=False, timeout=30)
        except Exception:
            response = None
        if response and response.status_code == 200:
            data = response.json()
            for l in data.get("layers", []):
                name = l.get("name")
                if name and name not in layers:
                    layers.append(name)
            if len(data.get("layers", [])) < limit:
                break
            offset += limit
        else:
            break

    # If nothing discovered, fallback to scanning show-access-rulebase for layer names
    if not layers:
        offset = 0
        while True:
            payload = {"limit": limit, "offset": offset}
            try:
                response = requests.post(f"{mgmt_server}/show-access-rulebase", json=payload, headers=headers, verify=False, timeout=30)
            except Exception:
                response = None
            if not response or response.status_code != 200:
                break
            data = response.json()
            # Some servers return top-level "rulebase" with entries that include layer info
            for entry in data.get("rulebase", []):
                # try common keys that might contain a layer name
                layer_name = entry.get("layer") or entry.get("name") or entry.get("layer-name")
                if layer_name and layer_name not in layers:
                    layers.append(layer_name)
            if len(data.get("rulebase", [])) < limit:
                break
            offset += limit

    return layers

if __name__ == "__main__":
    try:
        login()

        # Automatically discover layers after login; no interactive prompts
        layers = get_layers()

        # If discovery failed (empty list), fall back to a sensible single default layer name
        # Adjust default_layer to match your environment if needed
        if not layers:
            default_layer = "Network"
            layers = [default_layer]

        # Read search criteria once
        print("\nEnter rule search criteria (leave blank for 'Any'):")
        source_input = input("Source object: ")
        destination_input = input("Destination object: ")
        service_input = input("Comma-separated services (e.g., 3389,9100): ")

        for layer_name in layers:
            try:
                matched = search_rules_by_object(layer_name, source_input, destination_input, service_input)
                if not matched:
                    print(f"\n[✓] Layer: {layer_name} - Total Rules Found: 0")
                    continue

                rule_number_map = get_rule_number_map(layer_name)
                print(f"\n[✓] Layer: {layer_name} - Total Rules Found: {len(matched)}")
                sorted_uids = sorted(
    matched,
    key=lambda uid: rule_number_map.get(uid, float('inf'))  # fallback if rule number missing
)

                for rule_uid in sorted_uids:
                    rule_data = get_rule_details(rule_uid, layer_name)
                    if rule_data:
                        rule_name = rule_data.get("name", "Unnamed Rule")
                        rule_num = rule_number_map.get(rule_uid, "N/A")
                        print(f"\n[✓] Rule matched in layer {layer_name}:")
                        print(f"    Rule UID   : {rule_uid}")
                        print(f"    Rule Name  : {rule_name}")
                        print(f"    Rule No    : {rule_num}")
            except Exception as e:
                print(f"[!] Error searching layer {layer_name}: {e}")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        logout()
