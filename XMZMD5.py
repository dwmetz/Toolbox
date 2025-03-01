import os
import yara
import hashlib

def compile_yara_rules():
    """
    Compile YARA rules for MZ, PDF, and ZIP headers.
    
    Returns:
        yara.Rules: Compiled YARA rules.
    """
    rules = """
rule mz_header {
    meta:
        description = "Matches files with MZ header (Windows Executables)"
    strings:
        $mz = {4D 5A}  // MZ header in hex
    condition:
        $mz at 0  // Match if MZ header is at the start of the file
}

rule pdf_header {
    meta:
        description = "Matches files with PDF header"
    strings:
        $pdf = {25 50 44 46}  // PDF header in hex (%PDF)
    condition:
        $pdf at 0  // Match if PDF header is at the start of the file
}

rule zip_header {
    meta:
        description = "Matches files with ZIP header"
    strings:
        $zip = {50 4B 03 04}  // ZIP header in hex
    condition:
        $zip at 0  // Match if ZIP header is at the start of the file
}
"""
    return yara.compile(source=rules)

def calculate_md5(file_path):
    """
    Calculate the MD5 hash of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: MD5 hash of the file, or None if an error occurs.
    """
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"[ERROR] Unable to calculate MD5 for {file_path}: {e}")
        return None

def scan_directory(directory, rules, output_file):
    """
    Scan a directory for files that do not match YARA rules and calculate their MD5 hashes.

    Args:
        directory (str): Path to the directory to scan.
        rules (yara.Rules): Compiled YARA rules.
        output_file (str): File to save MD5 hashes of unmatched files.
    """
    hash_count = 0  # Counter for total number of hashes written

    try:
        with open(output_file, 'w') as out:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Check if the file matches any YARA rule
                        matches = rules.match(file_path)
                        if not matches:  # Only process files that do not match any rule
                            md5_hash = calculate_md5(file_path)
                            if md5_hash:
                                print(md5_hash)  # Print hash to console
                                out.write(md5_hash + '\n')  # Write only hash to output file
                                hash_count += 1
                    except yara.Error as ye:
                        print(f"[WARNING] YARA error scanning {file_path}: {ye}")
                    except Exception as e:
                        print(f"[ERROR] Unexpected error scanning {file_path}: {e}")
        
        # Report total number of hashes written and location of the output file
        print(f"\nScan completed.")
        print(f"Total number of hashes written: {hash_count}")
        print(f"Output file location: {os.path.abspath(output_file)}")

    except Exception as e:
        print(f"[ERROR] Failed to write to output file {output_file}: {e}")

if __name__ == "__main__":
    # Prompt user for directory to scan
    directory_to_scan = input("Enter directory to scan: ").strip()
    
    # Compile YARA rules
    try:
        yara_rules = compile_yara_rules()
    except Exception as e:
        print(f"[ERROR] Failed to compile YARA rules: {e}")
        exit(1)

    # Output filename for unmatched files' MD5 hashes
    output_filename = "XMZMD5.txt"

    # Check if the output file already exists and prompt user for action
    if os.path.exists(output_filename):
        overwrite_prompt = input(f"[WARNING] The file '{output_filename}' already exists. Do you want to overwrite it? (yes/no): ").strip().lower()
        
        if overwrite_prompt not in ['yes', 'y']:
            print("[INFO] Operation canceled by user.")
            exit(0)

    # Scan the directory
    if os.path.isdir(directory_to_scan):
        scan_directory(directory_to_scan, yara_rules, output_filename)
    else:
        print(f"[ERROR] The provided path is not a valid directory: {directory_to_scan}")
