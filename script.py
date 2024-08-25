import xml.etree.ElementTree as ET
import os
import hashlib
import pandas as pd
from tkinter import Tk, filedialog

def hash_file(file_path):
    """Generate a SHA-256 hash of the file content."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def list_vulnerabilities(files):
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
                vulnerabilities[plugin_name] = severity_levels[severity]

    # Return a sorted list of unique plugin names without repetition
    return sorted(vulnerabilities.keys())

def extract_selected_vulnerabilities(files, selected_plugin_names, output_file):
    try:
        seen = set()
        extracted_data = []
        severity_levels = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low"}

        # Loop through each unique .nessus file
        for nessus_file in files:
            tree = ET.parse(nessus_file)
            root = tree.getroot()

            print(f"Processing file: {nessus_file}\n")

            # Loop through each host in the report
            for report_host in root.findall('.//ReportHost'):
                host_ip = report_host.attrib.get('name')

                # Loop through each report item (vulnerability) in the host
                for report_item in report_host.findall('.//ReportItem'):
                    plugin_name = report_item.attrib.get('pluginName')
                    port = report_item.attrib.get('port')
                    severity = report_item.attrib.get('severity')

                    if plugin_name in selected_plugin_names and (host_ip, port, plugin_name) not in seen:
                        seen.add((host_ip, port, plugin_name))
                        severity_str = severity_levels.get(severity, "Unknown")

                        # Store the extracted data in the list
                        extracted_data.append({
                            "Host IP": host_ip,
                            "Port": port,
                            "Plugin Name": plugin_name,
                            "Severity": severity_str
                        })

        if extracted_data:
            # Convert the list of dictionaries to a pandas DataFrame
            df = pd.DataFrame(extracted_data)
            
            # Save the DataFrame to an Excel file
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
    print("Choose an option to select `.nessus` files:")
    print("1. Automatically select all `.nessus` files from the current directory")
    print("2. Manually select `.nessus` files")

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        return [f for f in os.listdir('.') if f.endswith('.nessus')]
    elif choice == "2":
        root = Tk()
        root.withdraw()  # Hide the root window
        file_paths = filedialog.askopenfilenames(title="Select .nessus files", filetypes=[("Nessus Files", "*.nessus")])
        return list(file_paths)
    else:
        print("Invalid choice. Please select 1 or 2.")
        return choose_nessus_files()

# Example usage
if __name__ == "__main__":
    nessus_files = choose_nessus_files()
    
    if not nessus_files:
        print("No .nessus files selected.")
    else:
        # List all unique vulnerabilities (plugin names) with specific severities
        vulnerabilities = list_vulnerabilities(nessus_files)

        if vulnerabilities:
            print("\nAvailable Vulnerabilities (Plugin Names):")
            for i, v in enumerate(vulnerabilities, 1):
                print(f"{i}. {v}")

            # Prompt the user to select plugin names
            selected_indices = input("\nEnter the numbers of the plugin names you want to extract, separated by commas (e.g., 1, 3, 5): ")
            selected_indices = [int(i.strip()) for i in selected_indices.split(',') if i.strip().isdigit()]
            selected_plugin_names = [vulnerabilities[i-1] for i in selected_indices if 0 < i <= len(vulnerabilities)]

            if selected_plugin_names:
                output_file = input("\nEnter the output Excel file path (e.g., 'vulnerabilities_report.xlsx'): ")
                extract_selected_vulnerabilities(nessus_files, selected_plugin_names, output_file)
            else:
                print("No valid selections made.")
        else:
            print("No vulnerabilities with the specified severity levels found in the provided .nessus files.")
