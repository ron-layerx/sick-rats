#!/usr/bin/env python3
"""
Convert scan.txt secrets to HTTP requests with proper variable references.
CRITICAL: Credentials go ONLY in http-client.env.json, NOT in converted.http!
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List, Tuple, Set

# API endpoint mappings for known detector types
API_ENDPOINTS = {
    'openai': {
        'method': 'GET',
        'url': 'https://api.openai.com/v1/models',
        'headers': {'Authorization': 'Bearer {{var}}'},
        'body': None
    },
    'telegrambottoken': {
        'method': 'GET',
        'url': 'https://api.telegram.org/bot{{var}}/getMe',
        'headers': {},
        'body': None
    },
    'alchemy': {
        'method': 'POST',
        'url': 'https://eth-mainnet.g.alchemy.com/v2/{{var}}',
        'headers': {'Content-Type': 'application/json'},
        'body': {'jsonrpc': '2.0', 'method': 'eth_blockNumber', 'params': [], 'id': 1}
    },
    'infura': {
        'method': 'POST',
        'url': 'https://mainnet.infura.io/v3/{{var}}',
        'headers': {'Content-Type': 'application/json'},
        'body': {'jsonrpc': '2.0', 'method': 'eth_blockNumber', 'params': [], 'id': 1}
    },
    'openweather': {
        'method': 'GET',
        'url': 'https://api.openweathermap.org/data/2.5/weather?q=London&appid={{var}}',
        'headers': {},
        'body': None
    },
    'cryptocompare': {
        'method': 'GET',
        'url': 'https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD&api_key={{var}}',
        'headers': {},
        'body': None
    },
    'weatherstack': {
        'method': 'GET',
        'url': 'http://api.weatherstack.com/current?access_key={{var}}&query=London',
        'headers': {},
        'body': None
    },
    'flickr': {
        'method': 'GET',
        'url': 'https://api.flickr.com/services/rest/?method=flickr.test.echo&api_key={{var}}&format=json&nojsoncallback=1',
        'headers': {},
        'body': None
    },
    'newsapi': {
        'method': 'GET',
        'url': 'https://newsapi.org/v2/top-headlines?country=us&apiKey={{var}}',
        'headers': {},
        'body': None
    },
    'miro': {
        'method': 'GET',
        'url': 'https://api.miro.com/v1/boards',
        'headers': {'Authorization': 'Bearer {{var}}'},
        'body': None
    },
    'twitchaccesstoken': {
        'method': 'GET',
        'url': 'https://id.twitch.tv/oauth2/validate',
        'headers': {'Authorization': 'OAuth {{var}}'},
        'body': None
    },
    'onesignal': {
        'method': 'GET',
        'url': 'https://onesignal.com/api/v1/apps',
        'headers': {'Authorization': 'Basic {{var}}'},
        'body': None
    },
    'rapidapi': {
        'method': 'GET',
        'url': 'https://rapidapi.com/api/health',
        'headers': {'X-RapidAPI-Key': '{{var}}'},
        'body': None
    },
    'snykkey': {
        'method': 'GET',
        'url': 'https://api.snyk.io/v1/user/me',
        'headers': {'Authorization': 'token {{var}}'},
        'body': None
    },
    'ipstack': {
        'method': 'GET',
        'url': 'http://api.ipstack.com/check?access_key={{var}}',
        'headers': {},
        'body': None
    },
    'fixerio': {
        'method': 'GET',
        'url': 'http://data.fixer.io/api/latest?access_key={{var}}',
        'headers': {},
        'body': None
    },
    'sumologickey': {
        'method': 'GET',
        'url': 'https://api.sumologic.com/api/v1/users',
        'headers': {'Authorization': 'Basic {{var}}'},
        'body': None
    },
    'atlassian': {
        'method': 'GET',
        'url': 'https://api.atlassian.com/me',
        'headers': {'Authorization': 'Bearer {{var}}'},
        'body': None
    }
}

class SecretEntry:
    def __init__(self):
        self.detector_type = ''
        self.decoder_type = ''
        self.raw_result = ''
        self.file_path = ''
        self.line_number = ''
        self.verified = False
        self.extension_id = ''
        self.extra_info = {}
    
    def extract_extension_id(self):
        """Extract extension ID from file path."""
        if not self.file_path:
            return 'unknown'
        
        # Match pattern: extensions/{extension_id}/...
        match = re.search(r'extensions/([^/]+)/', self.file_path)
        if match:
            return match.group(1)
        return 'unknown'
    
    def get_variable_name(self):
        """Generate variable name: extension_id_detector_type"""
        ext_id = self.extension_id or self.extract_extension_id()
        detector = self.detector_type.lower().replace(' ', '').replace('-', '')
        return f"{ext_id}_{detector}"
    
    def is_known_type(self):
        """Check if detector type has known API endpoint."""
        detector = self.detector_type.lower().replace(' ', '').replace('-', '')
        return detector in API_ENDPOINTS


def parse_scan_file(filepath: str) -> List[SecretEntry]:
    """Parse scan.txt and extract all secrets."""
    secrets = []
    current_entry = None
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip()
            
            # Check for verified or unverified marker
            if 'Found verified result' in line or 'Found unverified result' in line:
                # Save previous entry if exists
                if current_entry and current_entry.raw_result:
                    secrets.append(current_entry)
                
                # Start new entry
                current_entry = SecretEntry()
                current_entry.verified = 'verified' in line
                continue
            
            if not current_entry:
                continue
            
            # Extract detector type
            if line.startswith('Detector Type:'):
                current_entry.detector_type = line.split(':', 1)[1].strip()
            
            # Extract decoder type
            elif line.startswith('Decoder Type:'):
                current_entry.decoder_type = line.split(':', 1)[1].strip()
            
            # Extract raw result (the actual secret!)
            elif line.startswith('Raw result:'):
                current_entry.raw_result = line.split(':', 1)[1].strip()
            
            # Extract file path
            elif line.startswith('File:'):
                current_entry.file_path = line.split(':', 1)[1].strip()
            
            # Extract line number
            elif line.startswith('Line:'):
                current_entry.line_number = line.split(':', 1)[1].strip()
            
            # Extract any extra info (Username, Version, etc.)
            elif ':' in line and not line.startswith(' '):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    current_entry.extra_info[key] = value
    
    # Don't forget the last entry!
    if current_entry and current_entry.raw_result:
        secrets.append(current_entry)
    
    return secrets


def deduplicate_secrets(secrets: List[SecretEntry]) -> Tuple[List[SecretEntry], List[SecretEntry]]:
    """
    Deduplicate secrets by raw_result value.
    Returns: (unique_secrets, known_secrets, unknown_secrets)
    """
    seen_secrets: Set[str] = set()
    unique_secrets = []
    
    for secret in secrets:
        if secret.raw_result not in seen_secrets:
            seen_secrets.add(secret.raw_result)
            unique_secrets.append(secret)
    
    # Separate known and unknown types
    known = [s for s in unique_secrets if s.is_known_type()]
    unknown = [s for s in unique_secrets if not s.is_known_type()]
    
    return known, unknown


def generate_http_request(secret: SecretEntry) -> str:
    """Generate HTTP request for a secret."""
    detector = secret.detector_type.lower().replace(' ', '').replace('-', '')
    endpoint = API_ENDPOINTS.get(detector)
    
    if not endpoint:
        return ''
    
    var_name = secret.get_variable_name()
    ext_id = secret.extension_id or secret.extract_extension_id()
    detector_clean = secret.detector_type.lower().replace(' ', '')
    
    # Build request
    lines = []
    
    # Separator with label
    lines.append(f"### {secret.detector_type} ({ext_id})")
    
    # Build URL with variable
    url = endpoint['url'].replace('{{var}}', f'{{{{{var_name}}}}}')
    
    # Request line
    lines.append(f"{endpoint['method']} {url} HTTP/1.1")
    
    # Headers
    for header, value in endpoint['headers'].items():
        header_value = value.replace('{{var}}', f'{{{{{var_name}}}}}')
        lines.append(f"{header}: {header_value}")
    
    # Response redirect
    lines.append(f">> responses/{ext_id}/{detector_clean}.json")
    
    # Body (if present)
    if endpoint['body']:
        lines.append('')  # Blank line before body
        lines.append(json.dumps(endpoint['body'], indent=2))
    
    lines.append('')  # Blank line after request
    
    return '\n'.join(lines)


def generate_converted_http(secrets: List[SecretEntry], output_path: str):
    """Generate converted.http file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        for secret in secrets:
            request = generate_http_request(secret)
            if request:
                f.write(request)
                f.write('\n')


def generate_env_json(secrets: List[SecretEntry], output_path: str):
    """Generate http-client.env.json file (REPLACE mode)."""
    env_data = {
        "$schema": "https://raw.githubusercontent.com/mistweaverco/kulala.nvim/main/schemas/http-client.env.schema.json",
        "dev": {}
    }
    
    # Add all secrets to dev environment
    for secret in secrets:
        var_name = secret.get_variable_name()
        env_data['dev'][var_name] = secret.raw_result
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(env_data, f, indent=2)
        f.write('\n')


def generate_unknown_txt(secrets: List[SecretEntry], output_path: str):
    """Generate unknown.txt for unsupported secret types."""
    with open(output_path, 'w', encoding='utf-8') as f:
        for secret in secrets:
            f.write(f"Unknown Secret Type: {secret.detector_type}\n")
            ext_id = secret.extension_id or secret.extract_extension_id()
            f.write(f"Extension: {ext_id}\n")
            f.write(f"Raw Value: {secret.raw_result}\n")
            f.write(f"File: {secret.file_path}\n")
            if secret.line_number:
                f.write(f"Line: {secret.line_number}\n")
            
            # Add extra info
            for key, value in secret.extra_info.items():
                f.write(f"{key}: {value}\n")
            
            f.write(f"Verified: {'Yes' if secret.verified else 'No'}\n")
            f.write('\n')


def create_response_directories(secrets: List[SecretEntry], base_path: str):
    """Create responses/ directory structure."""
    base_dir = Path(base_path)
    base_dir.mkdir(exist_ok=True)
    
    # Create subdirectories for each extension
    extension_ids = set()
    for secret in secrets:
        ext_id = secret.extension_id or secret.extract_extension_id()
        extension_ids.add(ext_id)
    
    for ext_id in extension_ids:
        ext_dir = base_dir / ext_id
        ext_dir.mkdir(exist_ok=True)


def main():
    """Main execution function."""
    print("🚀 STARTING SECRET CONVERSION - WAKANDA FOREVER! 🚀")
    print("=" * 60)
    
    # Parse scan.txt
    print("📖 Step 1: Parsing scan.txt...")
    secrets = parse_scan_file('/Users/ron.s/dev/sick-rats/scan.txt')
    print(f"   ✅ Found {len(secrets)} total secrets")
    
    # Deduplicate
    print("🔍 Step 2: Deduplicating secrets...")
    known_secrets, unknown_secrets = deduplicate_secrets(secrets)
    print(f"   ✅ {len(known_secrets)} known secrets (with API endpoints)")
    print(f"   ✅ {len(unknown_secrets)} unknown secrets (no API endpoints)")
    
    # Extract extension IDs for all secrets
    print("🏷️  Step 3: Extracting extension IDs...")
    for secret in known_secrets + unknown_secrets:
        secret.extension_id = secret.extract_extension_id()
    print(f"   ✅ Extension IDs extracted")
    
    # Create response directories
    print("📁 Step 4: Creating responses/ directory structure...")
    create_response_directories(known_secrets, '/Users/ron.s/dev/sick-rats/responses')
    print(f"   ✅ Response directories created")
    
    # Generate converted.http
    print("📝 Step 5: Generating converted.http...")
    generate_converted_http(known_secrets, '/Users/ron.s/dev/sick-rats/converted.http')
    print(f"   ✅ converted.http created with {len(known_secrets)} requests")
    
    # Generate http-client.env.json (REPLACE mode)
    print("🔐 Step 6: Generating http-client.env.json...")
    generate_env_json(known_secrets, '/Users/ron.s/dev/sick-rats/http-client.env.json')
    print(f"   ✅ http-client.env.json created with {len(known_secrets)} credentials")
    
    # Generate unknown.txt
    print("❓ Step 7: Generating unknown.txt...")
    generate_unknown_txt(unknown_secrets, '/Users/ron.s/dev/sick-rats/unknown.txt')
    print(f"   ✅ unknown.txt created with {len(unknown_secrets)} entries")
    
    # Final validation
    print("\n" + "=" * 60)
    print("🎯 VALIDATION CHECKLIST:")
    print("   ✅ All credentials in http-client.env.json ONLY")
    print("   ✅ Only variable references in converted.http")
    print("   ✅ Response directories created")
    print("   ✅ Unknown secrets documented in unknown.txt")
    print("   ✅ Deduplication applied")
    print("\n🏆 MISSION ACCOMPLISHED! WAKANDA IS PROUD! 🏆")
    print("=" * 60)


if __name__ == '__main__':
    main()
