#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append('pii-guard')

from pii_guard.guard import guard_answer
from pii_guard.detector import PIIDetector

# Test the guard function directly
text = "내 이름: 전준휘 010-2362-8800"
print(f"Testing text: {text}")

# Create detector
detector = PIIDetector(use_llm=True)
print(f"Detector created - LLM enabled: {detector.use_llm}")

# Test guard function
try:
    result = guard_answer(text, detector)
    print("\nGuard result:")
    print(f"- Answer: {result['answer']}")
    print(f"- PII Score: {result['pii_score']}")
    print(f"- Blocked: {result['blocked']}")
    print(f"- Matches: {len(result['matches'])}")

    for match in result['matches']:
        print(f"  {match['type']}: '{match['value']}' at {match['span']} (confidence: {match['confidence']}, source: {match['source']})")

    print(f"- Prompt Injection: {result['prompt_injection']}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()