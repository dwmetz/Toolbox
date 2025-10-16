#!/usr/bin/env python3

import os
import re
import argparse
import subprocess
import shutil

# Check if yara CLI is available for validation
YARA_CLI_AVAILABLE = shutil.which("yara") is not None

MAX_SIZE = 1_000_000  # 1 MB per chunk
REPLICATE_IMPORTS = True
OUTPUT_SUBDIR = "output"  # new output folder name


def is_rule_start(line: str) -> bool:
    """Return True if the line marks the start of a new YARA rule."""
    return bool(re.match(r'^[ \t]*(?:private|global)?\s*rule\s+\w+', line))


def validate_yara_syntax(file_path: str) -> bool:
    """
    Validate that a YARA file has correct syntax using the YARA CLI.

    Args:
        file_path: Path to the YARA file to validate

    Returns:
        True if valid, False otherwise
    """
    if not YARA_CLI_AVAILABLE:
        return True  # Skip validation if YARA CLI not available

    try:
        # Use yarac to compile the rules (faster and validates syntax)
        # The -w flag disables warnings, we only care about errors
        result = subprocess.run(
            ["yarac", file_path, "/dev/null"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return True
        else:
            # Extract first error line for cleaner output
            error_lines = result.stderr.strip().split('\n')
            first_error = error_lines[0] if error_lines else "Unknown error"
            print(f"  ⚠️  Syntax error in {os.path.basename(file_path)}: {first_error}")
            return False

    except subprocess.TimeoutExpired:
        print(f"  ⚠️  Validation timeout for {os.path.basename(file_path)}")
        return False
    except Exception as e:
        print(f"  ⚠️  Validation error in {os.path.basename(file_path)}: {e}")
        return False


def split_yara_file(file_path: str, validate: bool = False):
    """
    Split a YARA rules file into smaller chunks.

    Args:
        file_path: Path to the YARA rules file to split
        validate: Whether to validate output files with YARA compiler
    """
    # --- Normalize and verify path ---
    file_path = os.path.expanduser(file_path)  # expand ~
    file_path = os.path.abspath(file_path)  # absolute path

    if not os.path.isfile(file_path):
        print(f"❌ File not found: {file_path}")
        return

    # Validate file extension
    if not file_path.lower().endswith(('.yar', '.yara')):
        print(f"⚠️  Warning: Expected .yar or .yara file extension")

    # --- Read file ---
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return

    if not lines:
        print(f"❌ File is empty")
        return

    preamble_lines = []
    rules = []
    current_rule = []
    inter_rule_lines = []  # Lines between rules (comments, whitespace)
    inside_rule = False
    brace_depth = 0
    found_first_rule = False

    for line in lines:
        if is_rule_start(line):
            if current_rule:
                # Save the previous rule
                rules.append("".join(current_rule))
                current_rule = []
                brace_depth = 0

            # Attach any inter-rule content to this new rule
            if inter_rule_lines:
                current_rule.extend(inter_rule_lines)
                inter_rule_lines = []

            inside_rule = True
            found_first_rule = True
            current_rule.append(line)
        elif inside_rule:
            current_rule.append(line)
            # Track brace depth to handle nested braces correctly
            for char in line:
                if char == '{':
                    brace_depth += 1
                elif char == '}':
                    brace_depth -= 1
                    if brace_depth == 0:
                        # Found the closing brace of the rule
                        rules.append("".join(current_rule))
                        current_rule = []
                        inside_rule = False
                        break
        else:
            # Line is not part of a rule
            if not found_first_rule:
                # Before first rule: add to preamble
                preamble_lines.append(line)
            else:
                # Between rules: save to attach to next rule
                inter_rule_lines.append(line)

    # Handle incomplete rule at end of file
    if current_rule:
        if brace_depth == 0:
            rules.append("".join(current_rule))
        else:
            print(f"⚠️  Warning: Incomplete rule detected at end of file (unclosed braces)")
    
    preamble = "".join(preamble_lines)
    imports = "\n".join(l for l in preamble_lines if l.strip().startswith("import "))
    
    # --- Create output directory beside input file ---
    input_dir = os.path.dirname(file_path)
    output_dir = os.path.join(input_dir, OUTPUT_SUBDIR)
    os.makedirs(output_dir, exist_ok=True)
    
    # --- Build chunks ---
    chunks = []
    chunk_rule_counts = []
    current_chunk = preamble
    current_size = len(current_chunk.encode("utf-8"))
    rules_in_chunk = []
    
    for rule in rules:
        rule_size = len(rule.encode("utf-8")) + 2
        if current_size + rule_size > MAX_SIZE and current_chunk.strip():
            chunks.append(current_chunk.strip() + "\n")
            chunk_rule_counts.append(len(rules_in_chunk))
            current_chunk = (imports + "\n\n" if REPLICATE_IMPORTS and imports else "") + rule
            current_size = len(current_chunk.encode("utf-8"))
            rules_in_chunk = [rule]
        else:
            current_chunk += "\n\n" + rule
            current_size += rule_size
            rules_in_chunk.append(rule)
    
    if current_chunk.strip():
        chunks.append(current_chunk.strip() + "\n")
        chunk_rule_counts.append(len(rules_in_chunk))
    
    # --- Write results into output folder ---
    base, ext = os.path.splitext(os.path.basename(file_path))
    total = len(chunks)

    print(f"\n📂 Output directory: {output_dir}\n")

    # Track statistics
    total_rules = sum(chunk_rule_counts)
    total_bytes = 0
    output_files = []

    for i, chunk in enumerate(chunks, 1):
        out_path = os.path.join(output_dir, f"{base}-{i}of{total}{ext}")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(chunk)
        size_bytes = len(chunk.encode("utf-8"))
        total_bytes += size_bytes
        rules_count = chunk_rule_counts[i-1]
        output_files.append(out_path)
        print(f"Created {out_path} ({size_bytes:,} bytes, {rules_count} rules)")

    # --- Validate output files ---
    if validate and YARA_CLI_AVAILABLE:
        print(f"\n🔍 Validating output files with yarac...")
        validation_failed = 0
        for out_path in output_files:
            if not validate_yara_syntax(out_path):
                validation_failed += 1

        if validation_failed == 0:
            print(f"  ✅ All {total} files validated successfully")
        else:
            print(f"  ⚠️  {validation_failed} file(s) failed validation")
    elif validate and not YARA_CLI_AVAILABLE:
        print(f"\n⚠️  Validation requested but YARA is not installed")
        print(f"   Install with: brew install yara")

    # --- Print summary statistics ---
    print(f"\n{'='*60}")
    print(f"✅ Split complete!")
    print(f"{'='*60}")
    print(f"  Total rules:          {total_rules}")
    print(f"  Output files:         {total}")
    print(f"  Total size:           {total_bytes:,} bytes ({total_bytes/1024/1024:.2f} MB)")
    print(f"  Avg rules per file:   {total_rules/total:.1f}")
    print(f"  Avg size per file:    {total_bytes/total:,.0f} bytes")
    print(f"{'='*60}")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Split large YARA rules files into smaller chunks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s yara-rules-core.yar              # Split without validation
  %(prog)s yara-rules-core.yar -v           # Split with validation
  %(prog)s ~/rules/malware.yar --validate   # Split with validation (long form)
        """
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to the YARA rules file to split"
    )
    parser.add_argument(
        "-v", "--validate",
        action="store_true",
        help="Validate output files with YARA compiler (requires yarac)"
    )

    args = parser.parse_args()

    # If no file provided via CLI, prompt interactively
    if args.file:
        file_path = args.file
    else:
        file_path = input("Enter path to your .yar file (e.g., ~/Desktop/CoreBreaker/yara-rules-core.yar): ").strip('"')

    split_yara_file(file_path, validate=args.validate)


if __name__ == "__main__":
    main()