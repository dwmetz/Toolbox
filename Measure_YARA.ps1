<#
YARA Benchmarking PowerShell Script

Script will accept the input of 
- 1 for *one rule*,
- a for *all* rules,
- c for *combined* rule

example:  measure_yara.ps1 1
#>
param (
    [Parameter(Position=0)]
    [ValidateSet('1', 'a', 'c')]
    [string]$Option
)
## Variables - This is the only area you should need to modify.
$1_rule = 'C:\Tools\yara\wcry.yara'                     # point to a single YARA rule.
$rule_dir = 'C:\Tools\yara\RL_rules'                    # Adjust to your YARA rules directory$EpochTime = Get-Date -UFormat "%s"
$c_rule = 'C:\Tools\yara\combined_rule.yara'            # combine all the rules from a directory into one with Combine_YARA.ps1
## 'make no changes after here'.
$time = Get-Date
$error_log = "C:\Tools\yara\logs\log-$EpochTime.log"    # Error log, unique log per timestamp started
$scan_dir = 'C:\'                                       # Adjust to the directory you want to scan
## Time and stopwatch initialization
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
## Switch statements to execute based on parameter
switch ($Option) {
    '1' {
        Write-Host ''
        Write-Host -Fore Green "Starting YARA scan at $time"   
        Write-Host "Scanning $scan_dir with a single YARA rule."
        Write-Host ''
        Write-Host -Fore Cyan "YARA Matches:"
        Write-Host ''
        & 'C:\Tools\Yara\yara64.exe' -r $1_rule $scan_dir 2>> $error_log
        }
    'a' {
        Write-host ''
        Write-Host -Fore Green "Starting YARA scan at $time"
        $yaraFiles = Get-ChildItem -Path $rule_dir -Filter *.yara | Where-Object { !$_.PSIsContainer }
        $fileCount = $yaraFiles.Count
        Write-Host "Scanning $scan_dir with $fileCount rules in $rule_dir"
        Write-Host ''
        Write-Host -Fore Cyan "YARA Matches:"
        Write-Host ''
        foreach ($ruleFile in $yaraFiles) {
            & 'C:\Tools\Yara\yara64.exe' -r $ruleFile.FullName $scan_dir 2>> $error_log
        }}
    'c' {
        Write-Host ''
        Write-Host -Fore Green "Starting YARA scan at $time"   
        Write-Host "Scanning $scan_dir with a combination YARA rule (278 rules collapsed into 1)."
        Write-Host ''
        Write-Host -Fore Cyan "YARA Matches:"
        Write-Host ''
        & 'C:\Tools\Yara\yara64.exe' -r $c_rule $scan_dir 2>> $error_log
        }    
    Default {
        Write-Host ''
        Write-Host -Fore Red "Invalid option. Please use -1 or -all." 
        Write-Host ''
        exit 1
        }
}
## Stop stopwatch and calculate time elapsed
$StopWatch.Stop()
$null = $stopwatch.Elapsed
$Minutes = $StopWatch.Elapsed.Minutes
$Seconds = $StopWatch.Elapsed.Seconds
## Output completion message and skipped file count
Write-Host ''
Write-Host -Fore Green "*** YARA Completed in $Minutes minutes and $Seconds seconds. ***"
$count = (Get-Content $error_log | Measure-Object -Line).Lines
Write-Host "Files skipped (temp or log files): $count"
## Count unique skipped files
$lines = Get-Content -Path $error_log
$uniqueLines = $lines | Sort-Object | Get-Unique
$uniqueLineCount = $uniqueLines.Count
Write-Host "Number of unique files skipped: $uniqueLineCount"
Write-Host -Fore Yellow "See $error_log for details."
Write-Host ''
## Report on drive space
$driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
if ($driveInfo) {
    $totalSizeGB = [math]::Round($driveInfo.Size / 1GB, 2)
    $freeSpaceGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)
    $used = $totalSizeGB - $freeSpaceGB
    Write-Host "Total size of C: drive: $totalSizeGB GB"
    Write-Host "Free space on C: drive: $freeSpaceGB GB"
    Write-Host "Used space on C: drive: $used GB"
} else {
    Write-Host "Unable to retrieve information for C: drive."
}
Write-Host ''