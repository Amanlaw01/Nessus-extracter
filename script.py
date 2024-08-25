import xml.etree.ElementTree as ET
import os
import hashlib
import pandas as pd

def hash_file(file_path):
    """Generate a SHA-256 hash of the file content."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def extract_details_by_keyword(files, keyword, output_file):
    try:
        # Set to keep track of seen (IP, port, plugin_name) combinations across all files
        seen = set()
        matches_found = False

        # List to store extracted data
        extracted_data = []

        # Process unique files
        processed_hashes = set()
        unique_files = []

        for nessus_file in files:
            if not os.path.exists(nessus_file):
                print(f"File not found: {nessus_file}")
                continue

            # Hash the file to check for duplicates
            file_hash = hash_file(nessus_file)
            if file_hash not in processed_hashes:
                processed_hashes.add(file_hash)
                unique_files.append(nessus_file)
            else:
                print(f"Duplicate file removed: {nessus_file}")

        # Loop through each unique .nessus file
        for nessus_file in unique_files:
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

                    # Create a tuple to check for duplicates
                    identifier = (host_ip, port, plugin_name)

                    # Check if the plugin name contains the keyword and is not a duplicate
                    if keyword.lower() in plugin_name.lower() and identifier not in seen:
                        matches_found = True
                        seen.add(identifier)  # Add to seen set

                        # Store the extracted data in the list
                        extracted_data.append({
                            "Host IP": host_ip,
                            "Port": port,
                            "Plugin Name": plugin_name
                        })

        if matches_found:
            # Convert the list of dictionaries to a pandas DataFrame
            df = pd.DataFrame(extracted_data)
            
            # Save the DataFrame to an Excel file
            df.to_excel(output_file, index=False)
            print(f"Data successfully saved to {output_file}")
        else:
            print(f"No matches found for the keyword: '{keyword}'")
            with open(output_file.replace('.xlsx', '_not_found.txt'), 'w') as f:
                f.write(f"Vulnerability '{keyword}' does not exist in any of the provided .nessus files.")

    except ET.ParseError as e:
        print(f"Failed to parse a .nessus file: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
if __name__ == "__main__":
    # Automatically find all .nessus files in the current directory
    nessus_files = [f for f in os.listdir('.') if f.endswith('.nessus')]
    
    if not nessus_files:
        print("No .nessus files found in the current directory.")
    else:
        keyword = input("Enter the keyword to search (e.g., 'TLS'): ")
        output_file = input("Enter the output Excel file path (e.g., 'output.xlsx'): ")

        extract_details_by_keyword(nessus_files, keyword, output_file)
