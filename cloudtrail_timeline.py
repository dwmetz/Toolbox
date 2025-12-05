#!/usr/bin/env python3
"""
CloudTrail to CSV Converter
Parses AWS CloudTrail JSON logs and outputs CSV format for Timeline Explorer
Author: Doug Metz
"""

import json
import csv
import sys
import argparse
from pathlib import Path
from datetime import datetime

def extract_username(user_identity):
    """Extract the most relevant username from userIdentity object"""
    if not user_identity:
        return "Unknown"
    
    # Try to get the most specific identifier
    if user_identity.get('type') == 'IAMUser':
        return user_identity.get('userName', 'Unknown')
    elif user_identity.get('type') == 'AssumedRole':
        # Get the role name from the session context
        session_context = user_identity.get('sessionContext', {})
        session_issuer = session_context.get('sessionIssuer', {})
        return session_issuer.get('userName', user_identity.get('principalId', 'Unknown'))
    elif user_identity.get('type') == 'Root':
        return 'ROOT'
    elif user_identity.get('type') == 'AWSService':
        return user_identity.get('invokedBy', 'AWSService')
    else:
        return user_identity.get('principalId', user_identity.get('type', 'Unknown'))

def get_error_info(record):
    """Extract error information if present"""
    error_code = record.get('errorCode', '')
    error_message = record.get('errorMessage', '')
    
    if error_code:
        return f"{error_code}: {error_message}"
    return "Success"

def get_details(record):
    """Extract relevant details from request/response"""
    details = []
    
    # Add recipient account
    if record.get('recipientAccountId'):
        details.append(f"Account: {record['recipientAccountId']}")
    
    # Add key request parameters
    req_params = record.get('requestParameters')
    if req_params:
        # Extract instance IDs
        if 'instancesSet' in req_params:
            instances = req_params['instancesSet'].get('items', [])
            instance_ids = [i.get('instanceId') for i in instances if i.get('instanceId')]
            if instance_ids:
                details.append(f"Instances: {', '.join(instance_ids)}")
        
        # Extract bucket names
        if 'bucketName' in req_params:
            details.append(f"Bucket: {req_params['bucketName']}")
        
        # Extract key names for S3
        if 'key' in req_params:
            details.append(f"Key: {req_params['key']}")
    
    # Add key response elements
    resp_elements = record.get('responseElements')
    if resp_elements and isinstance(resp_elements, dict):
        # For identity operations
        if 'userId' in resp_elements:
            details.append(f"UserID: {resp_elements['userId']}")
    
    # Add resource info if available
    resources = record.get('resources', [])
    if resources:
        resource_names = [r.get('ARN', '') for r in resources if r.get('ARN')]
        if resource_names:
            details.append(f"Resources: {', '.join(resource_names[:3])}")  # Limit to first 3
    
    return ' | '.join(details) if details else ''

def parse_cloudtrail_record(record):
    """Parse a single CloudTrail record into CSV row data"""
    user_identity = record.get('userIdentity', {})
    
    return {
        'Timestamp': record.get('eventTime', ''),
        'Event': record.get('eventName', ''),
        'EventSource': record.get('eventSource', ''),
        'User': extract_username(user_identity),
        'UserType': user_identity.get('type', ''),
        'SourceIP': record.get('sourceIPAddress', ''),
        'UserAgent': record.get('userAgent', ''),
        'Region': record.get('awsRegion', ''),
        'Result': get_error_info(record),
        'EventType': record.get('eventType', ''),
        'Details': get_details(record),
        'EventID': record.get('eventID', ''),
        'RequestID': record.get('requestID', '')
    }

def process_cloudtrail_file(input_file):
    """Process a CloudTrail JSON file and return parsed records"""
    records = []
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            # Handle both single record and Records array format
            if 'Records' in data:
                cloudtrail_records = data['Records']
            elif isinstance(data, list):
                cloudtrail_records = data
            else:
                cloudtrail_records = [data]
            
            for record in cloudtrail_records:
                parsed = parse_cloudtrail_record(record)
                records.append(parsed)
                
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from {input_file}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Error processing {input_file}: {e}", file=sys.stderr)
    
    return records

def write_csv(records, output_file):
    """Write parsed records to CSV file"""
    if not records:
        print("No records to write", file=sys.stderr)
        return
    
    fieldnames = ['Timestamp', 'Event', 'EventSource', 'User', 'UserType', 
                  'SourceIP', 'UserAgent', 'Region', 'Result', 'EventType',
                  'Details', 'EventID', 'RequestID']
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    
    print(f"[+] Wrote {len(records)} records to {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Convert AWS CloudTrail JSON logs to CSV for Timeline Explorer',
        epilog='Example: python cloudtrail_to_csv.py cloudtrail.json -o timeline.csv'
    )
    parser.add_argument('input', help='Input CloudTrail JSON file or directory')
    parser.add_argument('-o', '--output', default='cloudtrail_timeline.csv',
                       help='Output CSV file (default: cloudtrail_timeline.csv)')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively process all JSON files in directory')
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    all_records = []
    
    # Process single file or directory
    if input_path.is_file():
        print(f"[*] Processing {input_path}")
        all_records = process_cloudtrail_file(input_path)
    elif input_path.is_dir():
        pattern = '**/*.json' if args.recursive else '*.json'
        json_files = list(input_path.glob(pattern))
        
        if not json_files:
            print(f"No JSON files found in {input_path}", file=sys.stderr)
            return 1
        
        print(f"[*] Found {len(json_files)} JSON file(s)")
        for json_file in json_files:
            print(f"[*] Processing {json_file}")
            records = process_cloudtrail_file(json_file)
            all_records.extend(records)
    else:
        print(f"Error: {input_path} not found", file=sys.stderr)
        return 1
    
    if all_records:
        # Sort by timestamp
        all_records.sort(key=lambda x: x['Timestamp'])
        write_csv(all_records, args.output)
        print(f"[+] Success! Open {args.output} in Timeline Explorer")
    else:
        print("No records found to process", file=sys.stderr)
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
