# Define the directory containing YARA rules
$ruleDirectory = 'C:\Tools\yara\RL_rules'
# Output file where combined rules will be saved
$outputFile = 'C:\Tools\yara\combined_rule.yara'
# Initialize an empty string to store combined rules
$combinedRules = ''
# Get all .yara files in the directory
$yaraFiles = Get-ChildItem -Path $ruleDirectory -Filter *.yara | Where-Object { !$_.PSIsContainer }
# Loop through each YARA file and append its content to $combinedRules
foreach ($file in $yaraFiles) {
    $ruleContent = Get-Content -Path $file.FullName -Raw
    $combinedRules += $ruleContent + "`n"  # Add newline after each rule
}
# Write the combined rules to the output file
$combinedRules | Set-Content -Path $outputFile -Force
