#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json

# Test the API endpoint with proper encoding
url = 'http://localhost:3000/guard'
data = {
    'text': '내 이름: 전준휘 010-2362-8800'
}

try:
    print(f"Sending request to {url}")
    print(f"Data: {data}")

    response = requests.post(url, json=data, timeout=10)
    print(f'Status code: {response.status_code}')

    if response.status_code == 200:
        result = response.json()
        print('Response:')
        print(json.dumps(result, indent=2, ensure_ascii=False))

        # Check if NAME was detected
        name_matches = [match for match in result['matches'] if match['type'] == 'NAME']
        phone_matches = [match for match in result['matches'] if match['type'] == 'PHONE']

        print(f"\nSummary:")
        print(f"- NAME matches: {len(name_matches)}")
        print(f"- PHONE matches: {len(phone_matches)}")
        print(f"- Total PII score: {result['pii_score']}")
        print(f"- Blocked: {result['blocked']}")
        print(f"- LLM enabled: {result.get('llm_enabled', 'N/A')}")

    else:
        print(f'Error response: {response.text}')

except Exception as e:
    print(f'Error: {e}')