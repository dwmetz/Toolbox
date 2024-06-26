import os
import subprocess

# Directory where you want to start the search
start_dir = os.getcwd()

# Password for 7-Zip extraction
password = "infected"

# Function to extract a .7z file
def extract_7z(file_path, output_dir):
    cmd = ["7zz", "e", "-o" + output_dir, "-p" + password, file_path]
    subprocess.run(cmd, check=True)

# Recursively search for .7z files and extract them
for root, dirs, files in os.walk(start_dir):
    for file in files:
        if file.endswith(".7z"):
            file_path = os.path.join(root, file)
            output_dir = os.path.dirname(file_path)
            try:
                extract_7z(file_path, output_dir)
                print(f"Extracted {file}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to extract {file}: {e}")

print("Extraction complete.")
