# pii_guard/detector.py
import re
import math
import yaml
from pathlib import Path
from typing import List, Dict, Tuple, Any


class PIIMatch:
    def __init__(self, type: str, value: str, start: int, end: int):
        self.type = type
        self.value = value
        self.start = start
        self.end = end
        self.span = (start, end)

    def to_dict(self):
        return {
            "type": self.type,
            "value": self.value,
            "span": self.span
        }


class PIIDetector:
    def __init__(self, whitelist_path: str = None):
        """PII 탐지기 초기화"""
        self.weights = {
            'RRN': 1.0,
            'CARD': 0.9,
            'ACCOUNT': 0.8,
            'PHONE': 0.6,
            'EMAIL': 0.5
        }

        # 정규식 패턴 정의
        self.patterns = {
            'PHONE': [
                # 휴대폰: 01X-XXXX-XXXX 또는 01XXXXXXXXX
                r'01[016789]-?\d{3,4}-?\d{4}',
                # 유선전화: 0XX-XXX(X)-XXXX 또는 0XXXXXXXXX
                r'0\d{1,2}-\d{3,4}-\d{4}'
            ],
            'EMAIL': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            'CARD': [
                # 13-19자리 숫자 (공백, 하이픈 포함 가능)
                r'\b[\d\s-]{13,25}\b'
            ],
            'RRN': [
                # YYMMDD-XXXXXXX
                r'\b\d{6}-[1-4]\d{6}\b'
            ],
            'ACCOUNT': [
                # 계좌 키워드 근처 10-20자리 숫자/하이픈
                r'(?:계좌|계좌번호|account|계좌\s*번호)[\s:]*([0-9-]{10,20})',
                # 단독 계좌 형태 (XXX-XX-XXXXXX)
                r'\b\d{3}-\d{2,3}-\d{6,8}\b'
            ]
        }

        # 화이트리스트 로드
        self.whitelist = self._load_whitelist(whitelist_path)

    def _load_whitelist(self, whitelist_path: str = None) -> Dict[str, List[str]]:
        """화이트리스트 YAML 파일 로드"""
        if whitelist_path is None:
            # 기본 경로: 현재 파일과 같은 디렉토리의 ../whitelist.yml
            current_dir = Path(__file__).parent
            whitelist_path = current_dir.parent / 'whitelist.yml'

        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                whitelist = yaml.safe_load(f)
                return {
                    'phones': whitelist.get('phones', []),
                    'emails': whitelist.get('emails', []),
                    'accounts': whitelist.get('accounts', [])
                }
        except Exception:
            # 화이트리스트 로드 실패시 기본값
            return {'phones': [], 'emails': [], 'accounts': []}

    def _validate_luhn(self, card_number: str) -> bool:
        """Luhn 알고리즘으로 신용카드 번호 검증"""
        # 숫자만 추출
        digits = re.sub(r'\D', '', card_number)
        if len(digits) < 13 or len(digits) > 19:
            return False

        # Luhn 체크
        total = 0
        reverse_digits = digits[::-1]

        for i, char in enumerate(reverse_digits):
            digit = int(char)
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit = digit // 10 + digit % 10
            total += digit

        return total % 10 == 0

    def _validate_rrn(self, rrn: str) -> bool:
        """주민등록번호 검증"""
        if '-' not in rrn or len(rrn) != 14:
            return False

        digits = re.sub(r'-', '', rrn)
        if len(digits) != 13:
            return False

        # 생년월일 검증
        year = int(digits[:2])
        month = int(digits[2:4])
        day = int(digits[4:6])

        if month < 1 or month > 12 or day < 1 or day > 31:
            return False

        # 성별 코드 검증 (7번째 자리)
        gender_code = int(digits[6])
        if gender_code not in [1, 2, 3, 4]:
            return False

        # 체크섬 검증
        multipliers = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
        total = sum(int(digits[i]) * multipliers[i] for i in range(12))
        check_digit = (11 - (total % 11)) % 10

        return check_digit == int(digits[12])

    def _is_whitelisted(self, pii_type: str, value: str) -> bool:
        """화이트리스트 체크"""
        if pii_type == 'PHONE':
            return value in self.whitelist['phones']
        elif pii_type == 'EMAIL':
            return value in self.whitelist['emails']
        elif pii_type == 'ACCOUNT':
            return value in self.whitelist['accounts']
        return False

    def detect_pii(self, text: str) -> List[PIIMatch]:
        """텍스트에서 PII 탐지"""
        matches = []

        # PHONE 탐지
        for pattern in self.patterns['PHONE']:
            for match in re.finditer(pattern, text):
                value = match.group()
                if not self._is_whitelisted('PHONE', value):
                    matches.append(PIIMatch('PHONE', value, match.start(), match.end()))

        # EMAIL 탐지
        for pattern in self.patterns['EMAIL']:
            for match in re.finditer(pattern, text):
                value = match.group()
                if not self._is_whitelisted('EMAIL', value):
                    matches.append(PIIMatch('EMAIL', value, match.start(), match.end()))

        # CARD 탐지 (Luhn 검증)
        for pattern in self.patterns['CARD']:
            for match in re.finditer(pattern, text):
                value = match.group().strip()
                if self._validate_luhn(value):
                    matches.append(PIIMatch('CARD', value, match.start(), match.end()))

        # RRN 탐지 (주민등록번호 검증)
        for pattern in self.patterns['RRN']:
            for match in re.finditer(pattern, text):
                value = match.group()
                if self._validate_rrn(value):
                    matches.append(PIIMatch('RRN', value, match.start(), match.end()))

        # ACCOUNT 탐지
        for pattern in self.patterns['ACCOUNT']:
            for match in re.finditer(pattern, text):
                if '계좌' in pattern:
                    # 계좌 키워드가 있는 패턴의 경우 그룹 1 사용
                    if match.groups():
                        value = match.group(1).strip()
                        start = match.start(1)
                        end = match.end(1)
                    else:
                        continue
                else:
                    # 단독 계좌 형태
                    value = match.group().strip()
                    start = match.start()
                    end = match.end()

                # 길이 10 이상만 유효
                digits_only = re.sub(r'\D', '', value)
                if len(digits_only) >= 10 and not self._is_whitelisted('ACCOUNT', value):
                    matches.append(PIIMatch('ACCOUNT', value, start, end))

        # 중복 제거 (같은 위치의 매치)
        unique_matches = []
        seen_spans = set()
        for match in matches:
            if match.span not in seen_spans:
                unique_matches.append(match)
                seen_spans.add(match.span)

        return unique_matches

    def calculate_risk_score(self, matches: List[PIIMatch]) -> int:
        """위험도 점수 계산"""
        # 타입별 개수 계산
        type_counts = {}
        for match in matches:
            type_counts[match.type] = type_counts.get(match.type, 0) + 1

        # 가중치 적용한 위험도 계산
        risk_value = 0
        for pii_type, count in type_counts.items():
            weight = self.weights.get(pii_type, 0.2)
            risk_value += weight * count

        # 점수 변환: min(100, round(100*(1 - exp(-R/3))))
        if risk_value == 0:
            return 0

        score = min(100, round(100 * (1 - math.exp(-risk_value / 3))))
        return score

    def mask_pii(self, text: str, matches: List[PIIMatch]) -> str:
        """PII 마스킹 (뒤에서부터 치환하여 인덱스 어긋남 방지)"""
        # 끝 위치 기준으로 역순 정렬
        sorted_matches = sorted(matches, key=lambda x: x.start, reverse=True)

        masked_text = text
        for match in sorted_matches:
            token = f"<{match.type}>"
            masked_text = masked_text[:match.start] + token + masked_text[match.end:]

        return masked_text