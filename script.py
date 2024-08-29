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
                            "Severity": severity_str,
                            "Source File": os.path.basename(nessus_file)  # Add the source file column
                        })

        if extracted_data:
            df = pd.DataFrame(extracted_data)
            output_file = ensure_excel_extension(output_file)
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
                            "Severity": severity_levels.get(severity, "Unknown"),
                            "Source File": os.path.basename(nessus_file)  # Add the source file column
                        })
                    else:
                        # Append the plugin name and severity for existing IP and Port
                        for data in merged_data:
                            if data["Host IP"] == host_ip and data["Port"] == port:
                                data["Plugin Name"] += f"\n{plugin_name}"
                                data["Severity"] += f", {severity_levels.get(severity, 'Unknown')}"
                                data["Source File"] += f", {os.path.basename(nessus_file)}"  # Append the source file name
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
                print(f"Invalid selection format: {part}")

    return list(selected_indices)

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

def main():
    while True:
        nessus_files = choose_nessus_files()
        if not nessus_files:
            continue

        vulnerabilities = list_vulnerabilities(nessus_files)
        if not vulnerabilities:
            print("No vulnerabilities found.")
            continue

        selected_plugin_names = select_vulnerabilities(vulnerabilities)

        merge_option = input("Do you want to merge any vulnerabilities into one entry with multiple plugin names (yes/no)? ").strip().lower()
        if merge_option == "yes":
            merged_df = merge_vulnerabilities(nessus_files, selected_plugin_names)
            if merged_df is not None:
                output_file = input("Enter the output Excel file name (without extension): ")
                output_file = ensure_excel_extension(output_file)
                merged_output_file = output_file.replace('.xlsx', '_merged.xlsx')
                merged_df.to_excel(merged_output_file, index=False)
                print(f"Merged data successfully saved to {merged_output_file}")
        else:
            output_file = input("Enter the output Excel file name (without extension): ")
            output_file = ensure_excel_extension(output_file)
            extract_selected_vulnerabilities(nessus_files, selected_plugin_names, output_file)

        next_step = input("Do you want to process another set of files (yes/no)? ").strip().lower()
        if next_step != "yes":
            print("Exiting the script.")
            break

if __name__ == "__main__":
    main()
