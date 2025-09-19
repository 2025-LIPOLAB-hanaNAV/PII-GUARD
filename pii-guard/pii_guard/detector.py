# pii_guard/detector.py
import re
import math
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional

logger = logging.getLogger(__name__)


class PIIMatch:
    def __init__(self, type: str, value: str, start: int, end: int, confidence: float = 1.0, source: str = "regex"):
        self.type = type
        self.value = value
        self.start = start
        self.end = end
        self.span = (start, end)
        self.confidence = confidence  # 0.0-1.0 신뢰도
        self.source = source  # "regex" 또는 "llm"

    def to_dict(self):
        return {
            "type": self.type,
            "value": self.value,
            "span": self.span,
            "confidence": self.confidence,
            "source": self.source
        }


class PIIDetector:
    def __init__(self, whitelist_path: str = None, use_llm: bool = True, ollama_url: str = "http://localhost:11434"):
        """PII 탐지기 초기화"""
        self.use_llm = use_llm
        self.weights = {
            'RRN': 1.0,           # 주민등록번호
            'CARD': 0.9,          # 신용카드번호
            'ACCOUNT': 0.8,       # 계좌번호
            'NAME': 0.7,          # 개인 이름 (새로 추가)
            'PHONE': 0.6,         # 전화번호
            'EMAIL': 0.5,         # 이메일
            'ADDRESS': 0.6,       # 주소 (새로 추가)
            'ID_NUMBER': 0.4,     # 기타 식별번호 (새로 추가)
        }

        # LLM 클라이언트 초기화
        self.llm_client = None
        self.llm_detector = None
        if self.use_llm:
            try:
                logger.info(f"Initializing LLM detector with URL: {ollama_url}")
                from .llm_client import OllamaClient, LLMPIIDetector
                self.llm_client = OllamaClient(base_url=ollama_url)
                logger.info("OllamaClient created successfully")
                self.llm_detector = LLMPIIDetector(self.llm_client)
                logger.info("LLM PII detector initialized successfully")

                # 연결 테스트
                try:
                    test_result = self.llm_detector.detect_prompt_injection_sync("테스트")
                    logger.info(f"LLM connection test successful: {test_result}")
                except Exception as test_e:
                    logger.error(f"LLM connection test failed: {test_e}")
                    self.use_llm = False

            except Exception as e:
                logger.error(f"Failed to initialize LLM detector: {e}")
                import traceback
                logger.error(f"Full traceback: {traceback.format_exc()}")
                self.use_llm = False

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
            ],
            'NAME': [
                # 한국 이름 패턴 - 이름 맥락에서만 탐지
                r'(?:이름은?|성명은?|성함은?|이름이)\s*([김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구원태선설마길연방명기반왕금옥육인맹제갈선우남궁독고황보제][가-힣]{1,2})',
                r'(?:이름|성명|성함)[:：]\s*([김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구원태선설마길연방명기반왕금옥육인맹제갈선우남궁독고황보제][가-힣]{1,2})',
                r'([김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구원태선설마길연방명기반왕금옥육인맹제갈선우남궁독고황보제][가-힣]{1,2})(?:님|씨|선생|군|양|학생|고객|손님)',
                # 영어 이름 패턴 (First Last)
                r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'
            ],
            'ADDRESS': [
                # 한국 주소 패턴
                r'(?:서울|부산|대구|인천|광주|대전|울산|경기|강원|충북|충남|전북|전남|경북|경남|제주)[시도군구]?\s*[가-힣\s\d-]+(?:동|로|가|길|번지|호)',
                # 우편번호 패턴
                r'\b\d{5}\b'
            ],
            'ID_NUMBER': [
                # 사번, 학번 등 (숫자+문자 조합)
                r'(?:사번|학번|직번|회원번호|고객번호)[\s:]*[A-Z0-9-]{4,15}',
                # 기타 ID 형태
                r'\b[A-Z]{2,4}\d{4,8}\b'
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
        """하이브리드 PII 탐지 (RegEx + LLM)"""
        all_matches = []

        # 1단계: RegEx 기반 탐지 (빠른 스크리닝)
        regex_matches = self._detect_pii_regex(text)
        all_matches.extend(regex_matches)

        # 2단계: LLM 기반 탐지 (정밀 분석)
        if self.use_llm and self.llm_detector:
            try:
                llm_matches = self._detect_pii_llm(text)
                all_matches.extend(llm_matches)
            except Exception as e:
                logger.error(f"LLM PII detection failed: {e}")

        # 3단계: 중복 제거 및 통합
        return self._merge_and_deduplicate_matches(all_matches)

    def _detect_pii_regex(self, text: str) -> List[PIIMatch]:
        """RegEx 기반 PII 탐지"""
        matches = []

        # PHONE 탐지
        for pattern in self.patterns['PHONE']:
            for match in re.finditer(pattern, text):
                value = match.group()
                if not self._is_whitelisted('PHONE', value):
                    matches.append(PIIMatch('PHONE', value, match.start(), match.end(),
                                          confidence=0.9, source="regex"))

        # EMAIL 탐지
        for pattern in self.patterns['EMAIL']:
            for match in re.finditer(pattern, text):
                value = match.group()
                if not self._is_whitelisted('EMAIL', value):
                    matches.append(PIIMatch('EMAIL', value, match.start(), match.end(),
                                          confidence=0.95, source="regex"))

        # CARD 탐지 (Luhn 검증)
        for pattern in self.patterns['CARD']:
            for match in re.finditer(pattern, text):
                value = match.group().strip()
                if self._validate_luhn(value):
                    matches.append(PIIMatch('CARD', value, match.start(), match.end(),
                                          confidence=0.98, source="regex"))

        # RRN 탐지 (주민등록번호 검증)
        for pattern in self.patterns['RRN']:
            for match in re.finditer(pattern, text):
                value = match.group()
                if self._validate_rrn(value):
                    matches.append(PIIMatch('RRN', value, match.start(), match.end(),
                                          confidence=0.99, source="regex"))

        # ACCOUNT 탐지
        for pattern in self.patterns['ACCOUNT']:
            for match in re.finditer(pattern, text):
                if '계좌' in pattern:
                    if match.groups():
                        value = match.group(1).strip()
                        start = match.start(1)
                        end = match.end(1)
                    else:
                        continue
                else:
                    value = match.group().strip()
                    start = match.start()
                    end = match.end()

                digits_only = re.sub(r'\D', '', value)
                if len(digits_only) >= 10 and not self._is_whitelisted('ACCOUNT', value):
                    matches.append(PIIMatch('ACCOUNT', value, start, end,
                                          confidence=0.85, source="regex"))

        # 새로운 PII 유형들
        self._detect_names_regex(text, matches)
        self._detect_addresses_regex(text, matches)
        self._detect_id_numbers_regex(text, matches)

        return matches

    def _detect_names_regex(self, text: str, matches: List[PIIMatch]):
        """이름 RegEx 탐지"""
        for pattern in self.patterns['NAME']:
            for match in re.finditer(pattern, text):
                if match.groups():
                    # 그룹이 있는 패턴 (이름 맥락 패턴)
                    value = match.group(1)
                    start = match.start(1)
                    end = match.end(1)
                else:
                    # 그룹이 없는 패턴 (영어 이름 등)
                    value = match.group()
                    start = match.start()
                    end = match.end()

                # 매치를 리스트에 추가
                matches.append(PIIMatch('NAME', value, start, end, confidence=0.75, source="regex"))


    def _detect_addresses_regex(self, text: str, matches: List[PIIMatch]):
        """주소 RegEx 탐지"""
        for pattern in self.patterns['ADDRESS']:
            for match in re.finditer(pattern, text):
                value = match.group()
                matches.append(PIIMatch('ADDRESS', value, match.start(), match.end(),
                                      confidence=0.8, source="regex"))

    def _detect_id_numbers_regex(self, text: str, matches: List[PIIMatch]):
        """ID 번호 RegEx 탐지"""
        for pattern in self.patterns['ID_NUMBER']:
            for match in re.finditer(pattern, text):
                value = match.group()
                matches.append(PIIMatch('ID_NUMBER', value, match.start(), match.end(),
                                      confidence=0.6, source="regex"))

    def _detect_pii_llm(self, text: str) -> List[PIIMatch]:
        """LLM 기반 PII 탐지"""
        if not self.llm_detector:
            return []

        try:
            llm_results = self.llm_detector.detect_pii_sync(text)
            matches = []

            for result in llm_results:
                pii_type = result.get('type', '').upper()
                value = result.get('value', '')
                start = result.get('start', 0)
                end = result.get('end', len(value))
                confidence = result.get('confidence', 0.5)

                # LLM 결과 검증
                if pii_type and value and confidence > 0.3:
                    matches.append(PIIMatch(pii_type, value, start, end,
                                          confidence=confidence, source="llm"))

            return matches
        except Exception as e:
            logger.error(f"LLM PII detection error: {e}")
            return []

    def _merge_and_deduplicate_matches(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """매치 중복 제거 및 통합"""
        if not matches:
            return []

        # 위치 기준으로 정렬
        matches.sort(key=lambda x: (x.start, x.end))

        # 중복 제거 로직
        unique_matches = []
        seen_spans = set()

        for match in matches:
            # 정확히 같은 span은 신뢰도가 높은 것으로 선택
            if match.span in seen_spans:
                # 기존 매치를 더 높은 신뢰도로 교체
                for i, existing in enumerate(unique_matches):
                    if existing.span == match.span and match.confidence > existing.confidence:
                        unique_matches[i] = match
                        break
                continue

            # 겹치는 영역 체크
            overlapped = False
            for existing in unique_matches:
                if self._is_overlapping(match, existing):
                    # 신뢰도가 높은 것을 선택
                    if match.confidence > existing.confidence:
                        unique_matches.remove(existing)
                        unique_matches.append(match)
                        seen_spans.add(match.span)
                    overlapped = True
                    break

            if not overlapped:
                unique_matches.append(match)
                seen_spans.add(match.span)

        return unique_matches

    def _is_overlapping(self, match1: PIIMatch, match2: PIIMatch) -> bool:
        """두 매치가 겹치는지 확인"""
        return not (match1.end <= match2.start or match2.end <= match1.start)

    def detect_prompt_injection(self, text: str) -> Dict[str, Any]:
        """프롬프트 인젝션 탐지"""
        if not self.use_llm or not self.llm_detector:
            return {
                "injection_detected": False,
                "attack_types": [],
                "confidence": 0.0,
                "details": "LLM not available"
            }

        try:
            return self.llm_detector.detect_prompt_injection_sync(text)
        except Exception as e:
            logger.error(f"Prompt injection detection error: {e}")
            return {
                "injection_detected": False,
                "attack_types": [],
                "confidence": 0.0,
                "details": f"Error: {str(e)}"
            }

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