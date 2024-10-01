import xml.etree.ElementTree as ET
import os
import hashlib
import pandas as pd
from tkinter import Tk, filedialog
import glob
import sys

# Banner
banner = '''
 ,---.    .--.     .---. ,---.  .-. .-.,---.     .---.   .---. .-. .-.   .---. 
 | .-'   / /\\ \\   ( .-._)| .-'  |  \\| || .-'    ( .-._) ( .-._)| | | |  ( .-._)
 | `-.  / /__\\ \\ (_) \\   | `-.  |   | || `-.   (_) \\   (_) \\   | | | | (_) \\   
 | .-'  |  __  | _  \\ \\  | .-'  | |\\  || .-'   _  \\ \\  _  \\ \\  | | | | _  \\ \\  
 |  `--.| |  |)|( `-'  ) |  `--.| | |)||  `--.( `-'  )( `-'  ) | `-')|( `-'  ) 
 /( __.'|_|  (_) `----'  /( __.'/(  (_)/( __.' `----'  `----'  `---(_) `----'  
(__)                    (__)   (__)   (__)                                     

Author: SpongyYeti
'''

print(banner)

# Parsing command-line arguments
sort_option = None
if '-s' in sys.argv:
    sort_index = sys.argv.index('-s') + 1
    if sort_index < len(sys.argv):
        sort_option = sys.argv[sort_index]

def hash_file(file_path):
    """Generate a SHA-256 hash of the file content."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def list_vulnerabilities(files):
    """List all unique vulnerabilities from the provided .nessus files."""
    vulnerabilities = {}
    severity_levels = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low"}
    
    for nessus_file in files:
        if not os.path.exists(nessus_file):
            print(f"File not found: {nessus_file}")
            continue

        tree = ET.parse(nessus_file)
        root = tree.getroot()

        # Loop through each report item (vulnerability) in the host
        for report_item in root.findall('.//ReportItem'):
            plugin_name = report_item.attrib.get('pluginName')
            severity = report_item.attrib.get('severity')

            # Include only critical, high, medium, and low severity vulnerabilities
            if severity in severity_levels:
                if plugin_name not in vulnerabilities:
                    vulnerabilities[plugin_name] = severity_levels[severity]

    # Sorting based on the sort_option
    if sort_option == 'vuln':
        vulnerabilities = dict(sorted(vulnerabilities.items(), key=lambda x: list(severity_levels.values()).index(x[1])))
    elif sort_option == 'default':
        vulnerabilities = dict(sorted(vulnerabilities.items()))

    return vulnerabilities

def ensure_excel_extension(file_path):
    """Ensure the file path ends with .xlsx extension."""
    if not file_path.lower().endswith('.xlsx'):
        file_path += '.xlsx'
    return file_path

def extract_vulnerabilities_by_plugin(files, plugin_names):
    """Extract vulnerabilities by plugin names, consolidating IPs and Ports."""
    extracted_data = []
    severity_levels = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low"}

    for plugin_name in plugin_names:
        ip_list = []
        port_list = []
        for nessus_file in files:
            tree = ET.parse(nessus_file)
            root = tree.getroot()

            for report_host in root.findall('.//ReportHost'):
                host_ip = report_host.attrib.get('name')

                for report_item in report_host.findall('.//ReportItem'):
                    if report_item.attrib.get('pluginName') == plugin_name:
                        port = report_item.attrib.get('port')
                        severity = report_item.attrib.get('severity')
                        severity_str = severity_levels.get(severity, "Unknown")
                        ip_list.append(host_ip)
                        port_list.append(port)

        if ip_list and port_list:
            extracted_data.append({
                "Plugin Name": plugin_name,
                "Severity": severity_str,
                "IP Count": len(set(ip_list)),  # Number of unique IP addresses
                "IP Addresses": ', '.join(set(ip_list)),
                "Ports": ', '.join(set(port_list))
            })

    return extracted_data

def merge_vulnerabilities(extracted_data):
    """Merge vulnerabilities by consolidating IP addresses and ports for each plugin."""
    merged_data = {}
    for data in extracted_data:
        plugin_name = data["Plugin Name"]
        if plugin_name not in merged_data:
            merged_data[plugin_name] = {
                "Severity": data["Severity"],
                "IP Addresses": set(data["IP Addresses"].split(', ')),
                "Ports": set(data["Ports"].split(', ')),
                "IP Count": data["IP Count"]
            }
        else:
            merged_data[plugin_name]["IP Addresses"].update(data["IP Addresses"].split(', '))
            merged_data[plugin_name]["Ports"].update(data["Ports"].split(', '))
            merged_data[plugin_name]["IP Count"] = len(merged_data[plugin_name]["IP Addresses"])

    # Convert sets to comma-separated strings
    for plugin_name, data in merged_data.items():
        data["IP Addresses"] = ', '.join(data["IP Addresses"])
        data["Ports"] = ', '.join(data["Ports"])
    
    return [dict({"Plugin Name": k, **v}) for k, v in merged_data.items()]

def choose_nessus_files():
    """Prompt the user to choose `.nessus` files manually or automatically."""
    while True:
        print("Choose an option to select `.nessus` files:")
        print("1. Automatically select all `.nessus` files from the current directory")
        print("2. Manually select `.nessus` files")
        print("**. Back")
        print("exit. Exit the script")

        choice = input("Enter your choice (1, 2, **, or exit): ").strip().lower()

        if choice == "1":
            # Automatically find all .nessus files in the current directory
            files = glob.glob(os.path.join(os.getcwd(), '*.nessus'))
            print(f"Automatically selected files: {files}")
            return files
        elif choice == "2":
            root = Tk()
            root.withdraw()  # Hide the root window
            file_paths = filedialog.askopenfilenames(title="Select .nessus files", filetypes=[("Nessus Files", "*.nessus")])
            files = list(file_paths)
            print(f"Manually selected files: {files}")
            return files
        elif choice == "**":
            return None
        elif choice == "exit":
            print("Exiting the script.")
            exit()
        else:
            print("Invalid choice. Please select 1, 2, **, or exit.")

def select_vulnerabilities(vulnerabilities):
    """Allow the user to manually select vulnerabilities by plugin name."""
    if not vulnerabilities:
        print("No vulnerabilities to select from.")
        return []

    selected_plugin_names = []
    sorted_vulnerabilities = sorted(vulnerabilities.items(), key=lambda x: list(vulnerabilities.keys()).index(x[0]))

    print("Select vulnerabilities by entering the corresponding numbers (e.g., 1,3-5):")
    for i, (plugin_name, severity) in enumerate(sorted_vulnerabilities):
        print(f"{i + 1}. {plugin_name} (Severity: {severity})")

    print("Enter 'all' to select all vulnerabilities.")
    print("Enter 'exit' to exit the script.")
    selection = input("Your selection: ").strip().lower()

    selected_indices = parse_selection(selection, len(vulnerabilities))
    if not selected_indices:
        print("No valid selection made.")
        return []

    for i in selected_indices:
        selected_plugin_names.append(sorted_vulnerabilities[i][0])

    return selected_plugin_names

def parse_selection(selection, total_items):
    """Parse user selection for individual numbers, ranges, and special keywords."""
    if selection.lower() == 'exit':
        exit()

    if selection.lower() == 'all':
        return list(range(total_items))

    selected_indices = set()
    parts = selection.split(',')

    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                start = int(start.strip()) - 1
                end = int(end.strip()) - 1
                if 0 <= start < total_items and 0 <= end < total_items:
                    selected_indices.update(range(start, end + 1))
            except ValueError:
                print(f"Invalid range format: {part}")
        else:
            try:
                index = int(part) - 1
                if 0 <= index < total_items:
                    selected_indices.add(index)
            except ValueError:
                print(f"Invalid number format: {part}")

    return sorted(selected_indices)

def search_vulnerabilities(vulnerabilities):
    """Search for a specific vulnerability by name."""
    search_term = input("Enter the name or part of the name of the vulnerability to search: ").strip().lower()
    matched_vulnerabilities = {name: severity for name, severity in vulnerabilities.items() if search_term in name.lower()}

    if matched_vulnerabilities:
        print("\nMatched Vulnerabilities:")
        for plugin_name, severity in matched_vulnerabilities.items():
            print(f"{plugin_name} (Severity: {severity})")
    else:
        print("No vulnerabilities matched your search.")

def export_to_excel(extracted_data):
    """Export the extracted vulnerabilities to an Excel file."""
    if not extracted_data:
        print("No data to export.")
        return

    file_path = input("Enter the Excel file path for export (or press Enter to use 'output.xlsx'): ").strip()
    if not file_path:
        file_path = 'output.xlsx'

    file_path = ensure_excel_extension(file_path)

    df = pd.DataFrame(extracted_data)
    df.to_excel(file_path, index=False)
    print(f"Data exported to {file_path} successfully.")

def main():
    while True:
        files = choose_nessus_files()
        if not files:
            return

        print("\nListing unique vulnerabilities from the selected files...\n")
        vulnerabilities = list_vulnerabilities(files)

        while True:
            print("\nOptions:")
            print("1. Search for vulnerabilities")
            print("2. Select vulnerabilities manually")
            print("**. Back")
            print("3. Exit")

            option = input("Choose an option (1, 2, **, or 3): ").strip()

            if option == "1":
                search_vulnerabilities(vulnerabilities)
            elif option == "2":
                selected_vulnerabilities = select_vulnerabilities(vulnerabilities)
                if selected_vulnerabilities:
                    extracted_data = extract_vulnerabilities_by_plugin(files, selected_vulnerabilities)

                    print("Do you want to merge vulnerabilities? (yes/no)")
                    merge_choice = input().strip().lower()
                    if merge_choice == 'yes':
                        merged_data = merge_vulnerabilities(extracted_data)
                        export_to_excel(merged_data)
                    else:
                        export_to_excel(extracted_data)
            elif option == "**":
                break  # Break out of the current loop and go back to file selection
            elif option == "3":
                print("Exiting the script.")
                exit()
            else:
                print("Invalid option. Please choose 1, 2, **, or 3.")

if __name__ == "__main__":
    main()
