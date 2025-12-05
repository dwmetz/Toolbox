<div align="center">
 <img style="padding:0;vertical-align:bottom;" height="150" width="220" src="images/toolbox.png"/>
 <p>
  <h2>
   ToolBox
  </h2>
  <h5>

  <div align="center">   
</h5>
<h4>
Miscellaneous PowerShell and Python scripts related to YARA and Malware Analysis.
</h4>

<h5>Note: MANY of these tools or improved equivalents are available in 
 
 [MalChela, the Rust based YARA & Malware Analysis Toolkit](https://github.com/dwmetz/MalChela)

 ** = Not in MalChela
</h5>
<p>
<div align="left">

| Program                   | Function |
|---------------------------|----------|
| ** cloudtrail_timeline.py | Parses AWS CloudTrail JSON logs and outputs CSV format for Timeline Explorer |
| Combine_YARA.ps1          | Takes a directory of YARA rules and converts them into one combined rule |
| ** core-breaker.py        | Breaks the large yara-rules-core files into smaller .yar files for tool ingestion |
| ** EtTu.py                | Caesar cipher brute force decoder (Murdle :) |
| Extract_Samples.py        | Recursively traverses directory and extracts all password protected malware samples |
| ** mac_triage_timeline.sh | Processes Mac-Triage ZIP files and generates timeline for Timeline Explorer |
| ** Measure_YARA.ps1       | Benchmarking script for calculating YARA executions |
| MZcount.py                | Recursively traverses a directory and produces a count of file types (MZ, PDF, ZIP, Other) identified by YARA |
| MZMD5.py                  | Recursively traverses a directory and produces a hash set of all files with a MZ header identified by YARA |
| ** rename_malware.py      | Scans files with Windows Defender and renames them based on detected threat name and SHA-256 hash |
| Strings_to_YARA.py        | Takes the input of strings.txt, prompts for metadata, and produces formatted YARA rule |
| tshark_to_csv.py          | Takes the input of a pcap file, runs tshark against it (must be in PATH), converts timestamps, and zips |
| ** uac_timeline.sh        | Processes UAC tar.gz files and generates timeline for Timeline Explorer (Linux/macOS) |
| XMZMD5.py                 | Recursively traverses a directory and produces a hash set of all files without a MZ, PDF or ZIP header identified by YARA |







