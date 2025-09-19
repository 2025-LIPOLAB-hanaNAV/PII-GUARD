#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append('pii-guard')

from pii_guard.detector import PIIDetector
import re

# Test the name detection patterns
text = "내 이름: 전준휘 010-2362-8800"
print(f"Original text: {text}")
print(f"Text bytes: {text.encode('utf-8')}")

# Test regex patterns
patterns = [
    r'(?:이름은?|성명은?|성함은?|이름이)\s*([김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구원태선설마길연방명기반왕금옥육인맹제갈선우남궁독고황보제][가-힣]{1,2})',
    r'(?:이름|성명|성함)[:：]\s*([김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구원태선설마길연방명기반왕금옥육인맹제갈선우남궁독고황보제][가-힣]{1,2})',
    r'([김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구원태선설마길연방명기반왕금옥육인맹제갈선우남궁독고황보제][가-힣]{1,2})(?:님|씨|선생|군|양|학생|고객|손님)',
]

print("\nTesting individual patterns:")
for i, pattern in enumerate(patterns):
    print(f"Pattern {i+1}: {pattern}")
    matches = list(re.finditer(pattern, text))
    print(f"Matches: {matches}")
    for match in matches:
        print(f"  Match: {match.group()}")
        if match.groups():
            print(f"  Group 1: {match.group(1)}")

# Test detector
print("\nTesting detector:")
detector = PIIDetector(use_llm=False)  # Disable LLM for faster testing
matches = detector.detect_pii(text)
print(f"Detected matches: {len(matches)}")
for match in matches:
    print(f"  {match.type}: '{match.value}' at {match.span} (confidence: {match.confidence}, source: {match.source})")