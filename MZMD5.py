import os
import yara
import hashlib
import sys

def compile_yara_rules():
    """
    Compile YARA rules for detecting MZ headers.
    
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
"""
    return yara.compile(source=rules)

def calculate_md5(file_path):
    """
    Calculate the MD5 hash of a file.
    
    Args:
        file_path (str): Path to the file.
    
    Returns:
        str: MD5 hash in hexadecimal format.
    """
    md5_hash = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
        return md5_hash.hexdigest()
    except Exception as e:
        return None

def scan_and_hash_files(directory, rules, output_file):
    """
    Scan files in a directory using YARA rules, calculate MD5 hashes for matches,
    and write results to an output file.
    
    Args:
        directory (str): Path to the directory to scan.
        rules (yara.Rules): Compiled YARA rules.
        output_file (str): Path to the output file where results will be saved.
    
    Returns:
        int: Total number of hashes written to the output file.
    """
    hash_count = 0
    with open(output_file, "w") as out_file:
        # Walk through the directory and its subdirectories
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    # Match YARA rules against the file
                    matches = rules.match(file_path)
                    if any(match.rule == "mz_header" for match in matches):
                        # Calculate MD5 hash if the file matches the MZ header rule
                        md5_hash = calculate_md5(file_path)
                        if md5_hash:
                            out_file.write(f"{md5_hash}\n")
                            # Print hash value and flush output immediately
                            print(md5_hash, flush=True)
                            hash_count += 1
                except Exception as e:
                    pass  # Suppress error messages
    
    return hash_count

if __name__ == "__main__":
    # Prompt user for directory to scan
    directory_to_scan = input("Enter the directory you want to scan: ").strip()
    
    # Verify that the directory exists
    if not os.path.isdir(directory_to_scan):
        print("Error: The specified directory does not exist.")
        exit(1)
    
    # Set output file path to MZMD5.txt in the current working directory
    output_file_path = "MZMD5.txt"
    
    # Check if the output file already exists
    if os.path.exists(output_file_path):
        overwrite = input(f"The file '{output_file_path}' already exists. Overwrite? (y/n): ").strip().lower()
        if overwrite != 'y':
            print("Operation canceled.")
            exit(0)
    
    # Compile YARA rules
    yara_rules = compile_yara_rules()
    
    # Scan directory, calculate MD5 hashes, and write results to an output file
    total_hashes = scan_and_hash_files(directory_to_scan, yara_rules, output_file_path)
    
    # Report total number of hashes written and location of the output file
    print(f"\nScan completed.")
    print(f"Total number of hashes written: {total_hashes}")
    print(f"Output file location: {os.path.abspath(output_file_path)}")
