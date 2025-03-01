import os
import yara
import time


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
    try:
        return yara.compile(source=rules)
    except yara.SyntaxError as e:
        print(f"Error compiling YARA rules: {e}")
        raise


def display_table(counts):
    """
    Display the counts in a simple table format.
    
    Args:
        counts (dict): Dictionary containing counts for each file type.
    """
    # Clear console before displaying new table
    os.system('cls' if os.name == 'nt' else 'clear')  # Clears terminal for Windows ('cls') or Linux/Mac ('clear')
    
    # Print updated table
    print("\n+----------------------+---------+")
    print("| File Type           | Count   |")
    print("+----------------------+---------+")
    print(f"| Total Files         | {counts['total_files']:<7} |")
    print(f"| MZ Header Files     | {counts['mz_header']:<7} |")
    print(f"| PDF Header Files    | {counts['pdf_header']:<7} |")
    print(f"| ZIP Header Files    | {counts['zip_header']:<7} |")
    print(f"| Neither Header Files| {counts['neither_header']:<7} |")
    print("+----------------------+---------+")


def scan_and_count_files(directory, rules, use_table_display):
    """
    Scan files in a directory using YARA rules and count matches by header type.
    
    Args:
        directory (str): Path to the directory to scan.
        rules (yara.Rules): Compiled YARA rules.
        use_table_display (bool): Whether to use table display for live updates.
    
    Returns:
        dict: A dictionary with counts for total files, MZ headers, PDF headers, ZIP headers, and neither headers.
    """
    counts = {
        "total_files": 0,
        "mz_header": 0,
        "pdf_header": 0,
        "zip_header": 0,
        "neither_header": 0
    }

    # Walk through the directory and its subdirectories
    for root, _, files in os.walk(directory):
        for file in files:
            counts["total_files"] += 1
            file_path = os.path.join(root, file)
            
            try:
                # Open file in binary mode for YARA matching
                with open(file_path, "rb") as f:
                    data = f.read()
                
                # Match YARA rules against file content
                matches = rules.match(data=data)

                # Process matches
                if matches:
                    matched_rules = {match.rule for match in matches}
                    if "mz_header" in matched_rules:
                        counts["mz_header"] += 1
                    if "pdf_header" in matched_rules:
                        counts["pdf_header"] += 1
                    if "zip_header" in matched_rules:
                        counts["zip_header"] += 1
                else:
                    counts["neither_header"] += 1

            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
                # Decrement total_files if an error occurs
                counts["total_files"] -= 1
            
            # Display updated output after processing each file
            if use_table_display:
                display_table(counts)
            else:
                print(f"Scanned: {file_path}")
                print(f"Current Counts: {counts}")
            
            time.sleep(0.1)  # Optional: Add a small delay for smoother updates
    
    return counts


if __name__ == "__main__":
    # Prompt user for directory to scan
    directory_to_scan = input("Enter directory to scan: ").strip()
    
    # Check if the directory exists
    if not os.path.isdir(directory_to_scan):
        print(f"Error: The directory '{directory_to_scan}' does not exist. Please enter a valid directory.")
        exit(1)
    
    # Prompt user for display format preference
    display_choice = input("Choose output format - (1) Detailed, (2) Table Display: ").strip()
    
    # Determine whether to use table display or original output format
    use_table_display = display_choice == "2"
    
    # Compile YARA rules
    yara_rules = compile_yara_rules()
    
    # Scan directory and count matches
    results = scan_and_count_files(directory_to_scan, yara_rules, use_table_display)
    
    # Final results display after completion
    print("\nFinal Results:")
    
    if use_table_display:
        display_table(results)
        
        # Handle case where no results were found
        if results["total_files"] == 0:
            print("No files were scanned. Please check your directory.")
            
    else:
        print(f"Total files scanned: {results['total_files']}")
        print(f"Files with MZ header: {results['mz_header']}")
        print(f"Files with PDF header: {results['pdf_header']}")
        print(f"Files with ZIP header: {results['zip_header']}")
        print(f"Files with neither MZ, PDF, nor ZIP header: {results['neither_header']}")
