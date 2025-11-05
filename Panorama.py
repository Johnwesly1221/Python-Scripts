import requests
import xml.etree.ElementTree as ET
import getpass

# Hardcoded Panorama IPs
PANORAMA_LIST = ['192.168.10.62', '192.168.10.63']

# Disable warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

def get_api_key(panorama_ip, username, password):
    url = f"https://{panorama_ip}/api/?type=keygen&user={username}&password={password}"
    response = requests.get(url, verify=False)
    root = ET.fromstring(response.text)
    return root.find('.//key').text if root.find('.//key') is not None else None

def find_where_used(panorama_ip, api_key, object_name):
    url = f"https://{panorama_ip}/api/?type=op&cmd=<show><object><where-used><name>{object_name}</name></where-used></object></show>&key={api_key}"
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        print(f"Failed to query where-used for {object_name} on {panorama_ip}")
        return None
    return response.text

def extract_rule_xpaths(xml_text):
    rule_xpaths = []
    try:
        root = ET.fromstring(xml_text)
        for entry in root.findall(".//result/entry/object/entry/used/entry"):
            obj_type = entry.find("type").text
            xpath = entry.find("xpath").text
            if obj_type == "security-rule" and xpath:
                if "/source/" in xpath:
                    field = "source"
                elif "/destination/" in xpath:
                    field = "destination"
                elif "/service/" in xpath:
                    field = "service"
                elif "/application/" in xpath:
                    field = "application"
                elif "/source-user/" in xpath:
                    field = "source-user"
                else:
                    field = "unknown"
                rule_xpaths.append((xpath, field))
    except ET.ParseError:
        print("❌ Failed to parse XML response.")
    return rule_xpaths


def remove_object_from_rules(panorama_ip, api_key, object_name, rule_xpath_list):
    for xpath in rule_xpath_list:
        print(f"Removing from rule: {xpath}")
        url = f"https://{panorama_ip}/api/?type=config&action=delete&xpath={xpath}&key={api_key}"
        requests.get(url, verify=False)

def commit_changes(panorama_ip, api_key):
    url = f"https://{panorama_ip}/api/?type=commit&cmd=<commit><shared-policy><device-and-network-policy/></shared-policy></commit>&key={api_key}"
    response = requests.get(url, verify=False)
    print("Commit initiated:", response.text)

def main():
    username = input("Enter your Panorama username: ")
    password = getpass.getpass("Enter your password: ")

    # Step 1: Authenticate to all Panorama instances
    active_sessions = {}
    for pano_ip in PANORAMA_LIST:
        print(f"\n🔐 Attempting login to Panorama: {pano_ip}")
        api_key = get_api_key(pano_ip, username, password)
        if api_key:
            print(f"✅ Login successful for {pano_ip}")
            active_sessions[pano_ip] = api_key
        else:
            print(f"❌ Login failed for {pano_ip}")

    # Step 2: Check if any logins succeeded
    if not active_sessions:
        print("\n🚫 No Panorama logins succeeded. Exiting.")
        return

    # Step 3: Prompt for object name
    object_name = input("\nEnter the AD username or object name to remove: ")

    # Step 4: Search and cleanup
    for pano_ip, api_key in active_sessions.items():
        print(f"\n🔍 Searching for object in Panorama: {pano_ip}")
        xml_response = find_where_used(pano_ip, api_key, object_name)
        if object_name not in xml_response:
            print(f"✅ Object not found in {pano_ip}")
            continue

        print(f"⚠️ Object '{object_name}' found in {pano_ip}")
        print("Raw response:\n", xml_response)

        confirm = input("Do you want to remove this object from all rules? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("❎ Skipping this Panorama.")
            continue

        # TODO: Parse XML and extract rule_xpaths
        rule_xpaths = []  # Replace with parsed paths

        remove_object_from_rules(pano_ip, api_key, object_name, rule_xpaths)

        post_check = find_where_used(pano_ip, api_key, object_name)
        if object_name in post_check:
            print("⚠️ Object still found after removal attempt.")
        else:
            print("✅ Object successfully removed from all rules.")
        rule_xpaths = extract_rule_xpaths(xml_response)
        if not rule_xpaths:
            print("✅ Object found, but no security rules reference it.")
            continue

        print(f"🔗 Found {len(rule_xpaths)} rule references:")
        for xpath, field in rule_xpaths:
            print(f" - {xpath} [field: {field}]")

        final_commit = input("Do you want to commit changes to Panorama? (yes/no): ").strip().lower()
        if final_commit == 'yes':
            commit_changes(pano_ip, api_key)
        else:
            print("🚫 Discarding changes (no commit).")

if __name__ == "__main__":
    main()
