# pii_guard/guard.py
from typing import Dict, List, Any
from .detector import PIIDetector


def guard_answer(text: str, detector: PIIDetector = None) -> Dict[str, Any]:
    """
    LLM 답변을 가드하여 PII 체크 및 마스킹/차단 처리

    Args:
        text: LLM 답변 텍스트
        detector: PII 탐지기 (None시 기본 생성)

    Returns:
        {
            "answer": 마스킹된 답변 또는 차단 메시지,
            "pii_score": 위험도 점수(0-100),
            "blocked": 차단 여부,
            "matches": PII 매치 정보 리스트
        }
    """
    if detector is None:
        detector = PIIDetector()

    # PII 탐지
    matches = detector.detect_pii(text)

    # 위험도 점수 계산
    pii_score = detector.calculate_risk_score(matches)

    # 차단 여부 결정 (70점 이상)
    blocked = pii_score >= 70

    if blocked:
        # 차단된 경우
        answer = "죄송합니다. 개인정보가 포함된 내용으로 인해 응답을 제공할 수 없습니다."
    else:
        # 마스킹 처리
        answer = detector.mask_pii(text, matches)

    return {
        "answer": answer,
        "pii_score": pii_score,
        "blocked": blocked,
        "matches": [match.to_dict() for match in matches]
    }


def scrub_ingest(text: str, detector: PIIDetector = None) -> Dict[str, Any]:
    """
    데이터 적재 단계에서 PII 사전 마스킹 처리

    Args:
        text: 원본 콘텐츠 텍스트
        detector: PII 탐지기 (None시 기본 생성)

    Returns:
        {
            "scrubbed": 마스킹 처리된 텍스트,
            "matches": PII 매치 정보 리스트
        }
    """
    if detector is None:
        detector = PIIDetector()

    # PII 탐지
    matches = detector.detect_pii(text)

    # 마스킹 처리
    scrubbed_text = detector.mask_pii(text, matches)

    return {
        "scrubbed": scrubbed_text,
        "matches": [match.to_dict() for match in matches]
    }