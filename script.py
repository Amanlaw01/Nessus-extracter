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

def extract_selected_vulnerabilities(files, selected_plugin_names, output_file):
    """Extract selected vulnerabilities from the provided .nessus files."""
    try:
        seen = set()
        extracted_data = []
        severity_levels = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low"}

        for nessus_file in files:
            tree = ET.parse(nessus_file)
            root = tree.getroot()

            print(f"Processing file: {nessus_file}\n")

            for report_host in root.findall('.//ReportHost'):
                host_ip = report_host.attrib.get('name')

                for report_item in report_host.findall('.//ReportItem'):
                    plugin_name = report_item.attrib.get('pluginName')
                    port = report_item.attrib.get('port')
                    severity = report_item.attrib.get('severity')

                    if plugin_name in selected_plugin_names and (host_ip, port, plugin_name) not in seen:
                        seen.add((host_ip, port, plugin_name))
                        severity_str = severity_levels.get(severity, "Unknown")

                        extracted_data.append({
                            "Host IP": host_ip,
                            "Port": port,
                            "Plugin Name": plugin_name,
                            "Severity": severity_str
                        })

        if extracted_data:
            df = pd.DataFrame(extracted_data)
            if not output_file.lower().endswith('.xlsx'):
                output_file += '.xlsx'
            df.to_excel(output_file, index=False)
            print(f"Data successfully saved to {output_file}")
        else:
            print("No selected vulnerabilities found.")
            with open(output_file.replace('.xlsx', '_not_found.txt'), 'w') as f:
                f.write("No vulnerabilities matching the selected plugin names were found in the provided .nessus files.")

    except ET.ParseError as e:
        print(f"Failed to parse a .nessus file: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

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

def merge_vulnerabilities(files, selected_plugin_names):
    """Merge selected vulnerabilities into one entry with IP and Port details."""
    seen = set()
    merged_data = []
    severity_levels = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low"}

    for nessus_file in files:
        tree = ET.parse(nessus_file)
        root = tree.getroot()

        for report_host in root.findall('.//ReportHost'):
            host_ip = report_host.attrib.get('name')

            for report_item in report_host.findall('.//ReportItem'):
                plugin_name = report_item.attrib.get('pluginName')
                port = report_item.attrib.get('port')
                severity = report_item.attrib.get('severity')

                if plugin_name in selected_plugin_names:
                    if (host_ip, port) not in seen:
                        seen.add((host_ip, port))
                        merged_data.append({
                            "Host IP": host_ip,
                            "Port": port,
                            "Plugin Name": plugin_name,
                            "Severity": severity_levels.get(severity, "Unknown")
                        })
                    else:
                        # Append the plugin name and severity for existing IP and Port
                        for data in merged_data:
                            if data["Host IP"] == host_ip and data["Port"] == port:
                                data["Plugin Name"] += f"\n{plugin_name}"
                                data["Severity"] += f", {severity_levels.get(severity, 'Unknown')}"
                                break

    if merged_data:
        df = pd.DataFrame(merged_data)
        return df
    else:
        print("No data found for the selected vulnerabilities.")
        return None

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

# Example usage
if __name__ == "__main__":
    while True:
        nessus_files = choose_nessus_files()
        if not nessus_files:
            print("No .nessus files selected or user chose to go back.")
            continue
        
        # List all unique vulnerabilities (plugin names) and allow user to select
        vulnerabilities = list_vulnerabilities(nessus_files)

        if vulnerabilities:
            print("\nSelect vulnerabilities to extract or merge:")
            for i, (plugin_name, severity) in enumerate(vulnerabilities.items(), 1):
                print(f"{i}. {plugin_name} [{severity}]")
            print("Enter the numbers (comma-separated or range) of the vulnerabilities you want to select,")
            print("or type 'all' to select all vulnerabilities, '**' to go back, 'exit' to quit.")

            selection = input("Your selection: ").strip().lower()
            selected_indices = parse_selection(selection, len(vulnerabilities))
            
            if not selected_indices:
                print("Invalid selection. Please try again.")
                continue
            
            selected_plugins = [list(vulnerabilities.keys())[i] for i in selected_indices]

            print("\nChoose an action:")
            print("1. Extract the selected vulnerabilities into a new .xlsx file")
            print("2. Merge selected vulnerabilities by IP and port into a new .xlsx file")
            print("**. Back")
            print("exit. Exit the script")

            action_choice = input("Enter your choice (1, 2, **, or exit): ").strip().lower()

            if action_choice == "1":
                output_file = input("Enter the output file path (including .xlsx): ").strip()
                extract_selected_vulnerabilities(nessus_files, selected_plugins, output_file)
            elif action_choice == "2":
                output_file = input("Enter the output file path (including .xlsx): ").strip()
                merged_df = merge_vulnerabilities(nessus_files, selected_plugins)
                if merged_df is not None:
                    merged_df.to_excel(output_file, index=False)
                    print(f"Merged data saved to {output_file}")
            elif action_choice == "**":
                continue
            elif action_choice == "exit":
                print("Exiting the script.")
                exit()
            else:
                print("Invalid choice. Please select 1, 2, **, or exit.")
        else:
            print("No vulnerabilities found in the selected files.")
