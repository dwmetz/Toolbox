#!/usr/bin/env python3

# # Takes the input of strings.txt, prompts for author and rule metadata, and create output in propperly formatted YARA rule
# # Defaults to 'all of'.  Also watch your special characters.  It's not perfect but it can get the process started.

# # Sets up the YARA rule metadata. You can hardcode author.
def get_user_input():
    rule_name = input("Enter the rule name: ")
    author = input("Enter the author: ")
    description = input("Enter the description: ")
    hash_value = input("Enter the hash value: ")
    return rule_name, author, description, hash_value

# Create the YARA rule with tabs and formatting
def create_yara_rule(rule_name, author, description, hash_value, strings_file):
    yara_rule = f'''rule {rule_name} {{
    meta:
    \tauthor = "{author}"
    \tdescription = "{description}"
    \thash = "{hash_value}"

    strings:
    '''
    with open(strings_file, 'r') as file:
        for id, line in enumerate(file, start=1):
            yara_rule += f'\t$s{id} = "{line.strip()}"\n\t'
    yara_rule += '\n'
    yara_rule += '\tcondition:\n'
    yara_rule += '\t\tany of them\n}\n'

    return yara_rule

def main():
    rule_name, author, description, hash_value = get_user_input()
    strings_file = 'strings.txt'  # Path to your strings file

    yara_rule = create_yara_rule(rule_name, author, description, hash_value, strings_file)
    print("Generated YARA rule:")
    print(yara_rule)
    
# Save the YARA rule to a .yar file
    yar_filename = f'{rule_name}.yar'
    with open(yar_filename, 'w') as yar_file:
        yar_file.write(yara_rule)

    print(f"YARA rule saved to {yar_filename}")

if __name__ == "__main__":
    main()






