# Checkpoint Rule Search by Object Script 
import requests
import urllib3
import getpass

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
    print("[*] Logout Successful.")

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
        response = requests.post(f"{mgmt_server}/{endpoint}", json=payload, headers=headers, verify=False)
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
            response = requests.post(f"{mgmt_server}/{endpoint}", json=payload, headers=headers, verify=False)
            if response.status_code != 200:
                break
            services = response.json().get("objects", [])
            for svc in services:
                svc_port = svc.get("port", "")
                if str(svc_port) == str(port):
                    matched_services.add(svc["name"])
            if len(services) < limit:
                break
            offset += limit

    return matched_services

def get_where_used_safe(object_name):
    if not object_name or object_name.lower() == "any":
        return set()
    if not object_exists(object_name):
        print(f"[!] Object '{object_name}' not found or unsupported.")
        return set()
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"name": object_name, "indirect": True}
    response = requests.post(f"{mgmt_server}/where-used", json=payload, headers=headers, verify=False)
    if response.status_code != 200:
        print(f"[!] Failed to fetch usage for '{object_name}': {response.text}")
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
        response = requests.post(f"{mgmt_server}/show-access-rulebase", headers=headers, json=payload, verify=False)
        if response.status_code != 200:
            break
        rules = response.json().get("rulebase", [])
        for rule in rules:
            all_uids.add(rule["uid"])
        if len(rules) < limit:
            break
        offset += limit

    return all_uids

def get_rule_details(rule_uid, layer_name):
    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
    payload = {"uid": rule_uid, "layer": layer_name, "details-level": "full"}
    response = requests.post(f"{mgmt_server}/show-access-rule", json=payload, headers=headers, verify=False)
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
        response = requests.post(f"{mgmt_server}/show-access-rulebase", headers=headers, json=payload, verify=False)
        if response.status_code != 200:
            break
        rules = response.json().get("rulebase", [])
        for rule in rules:
            rule_map[rule["uid"]] = rule.get("rule-number", "N/A")
        if len(rules) < limit:
            break
        offset += limit

    return rule_map

def search_rules_by_object(layer_name, source=None, destination=None, services=None):
    print(f"\n[✓] Domain name: Standalone")

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

    matched_rules = set.intersection(*rule_sets)

    if not matched_rules:
        print("\n[✓] Total Rules Found: 0")
        return

    rule_number_map = get_rule_number_map(layer_name)

    print(f"\n[✓] Total Rules Found: {len(matched_rules)}")
    for rule_uid in matched_rules:
        rule_data = get_rule_details(rule_uid, layer_name)
        if rule_data:
            rule_name = rule_data.get("name", "Unnamed Rule")
            rule_num = rule_number_map.get(rule_uid, "N/A")
            print(f"\n[✓] Rule matched:")
            print(f"    Rule UID   : {rule_uid}")
            print(f"    Rule Name  : {rule_name}")
            print(f"    Rule No    : {rule_num}")

if __name__ == "__main__":
    try:
        login()
        layer_name = "Network"  # Replace with your actual layer name

        print("\nEnter rule search criteria (leave blank for 'Any'):")
        source_input = input("Source object: ")
        destination_input = input("Destination object: ")
        service_input = input("Comma-separated services (e.g., 3389,9100): ")

        search_rules_by_object(layer_name, source_input, destination_input, service_input)

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        logout()
