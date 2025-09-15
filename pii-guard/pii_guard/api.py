# pii_guard/api.py
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any

from .guard import guard_answer, scrub_ingest
from .detector import PIIDetector

app = FastAPI(
    title="PII Guard API",
    description="""
    ## RAG 챗봇용 PII 탐지 및 마스킹 서비스

    PII Guard는 개인정보(PII)를 자동으로 탐지하고 마스킹하여 RAG 시스템의 보안을 강화하는 서비스입니다.

    ### 주요 기능
    - **PII 탐지**: 주민등록번호, 신용카드번호, 계좌번호, 전화번호, 이메일 자동 탐지
    - **위험도 평가**: 0-100점으로 PII 위험도 점수화
    - **자동 마스킹**: 탐지된 PII를 토큰으로 치환 (`<PHONE>`, `<EMAIL>` 등)
    - **고위험 차단**: 70점 이상 시 답변 자동 차단
    - **화이트리스트**: 공개 번호 등 예외 처리 지원

    ### 사용 시나리오
    1. **LLM 답변 가드** (`/guard`): LLM 답변에서 PII 탐지 후 마스킹/차단
    2. **데이터 적재 전처리** (`/ingest/scrub`): 벡터 DB 저장 전 PII 사전 마스킹

    ### 지원하는 PII 유형
    - **RRN**: 주민등록번호 (YYMMDD-XXXXXXX)
    - **CARD**: 신용카드번호 (Luhn 알고리즘 검증)
    - **ACCOUNT**: 계좌번호 (XXX-XX-XXXXXX)
    - **PHONE**: 전화번호 (01X-XXXX-XXXX, 0XX-XXX-XXXX)
    - **EMAIL**: 이메일 주소 (user@domain.com)
    """,
    version="1.0.0",
    contact={
        "name": "PII Guard Support",
        "email": "support@example.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    },
    servers=[
        {
            "url": "http://localhost:3000",
            "description": "Development server"
        }
    ]
)

# 전역 PII 탐지기 인스턴스
detector = PIIDetector()


class GuardRequest(BaseModel):
    text: str = Field(
        ...,
        title="텍스트",
        description="PII 탐지 및 가드 처리할 LLM 답변 텍스트",
        example="안녕하세요. 제 전화번호는 010-1234-5678이고 이메일은 user@example.com입니다."
    )


class PIIMatchInfo(BaseModel):
    type: str = Field(..., title="PII 유형", description="탐지된 PII의 유형 (PHONE, EMAIL, CARD, RRN, ACCOUNT)")
    value: str = Field(..., title="원본 값", description="탐지된 PII의 원본 값")
    span: List[int] = Field(..., title="위치", description="텍스트 내 PII의 시작/끝 위치 [start, end]")

class GuardResponse(BaseModel):
    answer: str = Field(
        ...,
        title="답변",
        description="PII가 마스킹된 답변 텍스트 (차단된 경우 차단 메시지)",
        example="안녕하세요. 제 전화번호는 <PHONE>이고 이메일은 <EMAIL>입니다."
    )
    pii_score: int = Field(
        ...,
        title="PII 위험도 점수",
        description="0-100점의 PII 위험도 점수 (70점 이상 시 차단)",
        ge=0,
        le=100,
        example=55
    )
    blocked: bool = Field(
        ...,
        title="차단 여부",
        description="PII 위험도가 70점 이상으로 답변이 차단되었는지 여부",
        example=False
    )
    matches: List[PIIMatchInfo] = Field(
        ...,
        title="탐지된 PII 목록",
        description="텍스트에서 탐지된 모든 PII 정보",
        example=[
            {
                "type": "PHONE",
                "value": "010-1234-5678",
                "span": [14, 27]
            },
            {
                "type": "EMAIL",
                "value": "user@example.com",
                "span": [35, 50]
            }
        ]
    )


class ScrubRequest(BaseModel):
    text: str = Field(
        ...,
        title="텍스트",
        description="PII 마스킹 처리할 원본 콘텐츠 텍스트",
        example="고객의 전화번호는 010-9876-5432이며, 계좌번호는 123-45-678901입니다."
    )


class ScrubResponse(BaseModel):
    scrubbed: str = Field(
        ...,
        title="마스킹된 텍스트",
        description="PII가 토큰으로 치환된 텍스트",
        example="고객의 전화번호는 <PHONE>이며, 계좌번호는 <ACCOUNT>입니다."
    )
    matches: List[PIIMatchInfo] = Field(
        ...,
        title="탐지된 PII 목록",
        description="텍스트에서 탐지된 모든 PII 정보",
        example=[
            {
                "type": "PHONE",
                "value": "010-9876-5432",
                "span": [9, 22]
            },
            {
                "type": "ACCOUNT",
                "value": "123-45-678901",
                "span": [30, 43]
            }
        ]
    )


@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    """루트 경로를 Swagger 문서로 리다이렉트"""
    return RedirectResponse(url="/docs")

@app.get("/info",
         summary="API 정보",
         description="PII Guard API의 기본 정보와 엔드포인트 목록을 반환합니다.",
         tags=["정보"])
async def api_info():
    """API 기본 정보"""
    return {
        "service": "PII Guard API",
        "version": "1.0.0",
        "description": "RAG 챗봇용 PII 탐지 및 마스킹 서비스",
        "endpoints": {
            "/guard": "LLM 답변 PII 가드 및 마스킹",
            "/ingest/scrub": "데이터 적재용 PII 사전 마스킹",
            "/health": "서비스 헬스체크"
        },
        "supported_pii_types": ["PHONE", "EMAIL", "CARD", "RRN", "ACCOUNT"],
        "blocking_threshold": 70
    }


@app.post("/guard",
          response_model=GuardResponse,
          summary="LLM 답변 PII 가드",
          description="""
          LLM 답변에서 PII를 탐지하고 위험도에 따라 마스킹 또는 차단 처리합니다.

          **처리 방식:**
          - PII 위험도 70점 이상: 답변 차단 (안전 메시지 반환)
          - PII 위험도 70점 미만: PII 마스킹 후 답변 반환

          **위험도 계산:**
          - RRN(주민번호): 가중치 1.0
          - CARD(신용카드): 가중치 0.9
          - ACCOUNT(계좌): 가중치 0.8
          - PHONE(전화번호): 가중치 0.6
          - EMAIL(이메일): 가중치 0.5
          """,
          tags=["PII 가드"],
          responses={
              200: {
                  "description": "PII 가드 처리 완료",
                  "content": {
                      "application/json": {
                          "examples": {
                              "마스킹_처리": {
                                  "summary": "PII 마스킹 처리 예시",
                                  "value": {
                                      "answer": "안녕하세요. 제 전화번호는 <PHONE>이고 이메일은 <EMAIL>입니다.",
                                      "pii_score": 55,
                                      "blocked": False,
                                      "matches": [
                                          {"type": "PHONE", "value": "010-1234-5678", "span": [14, 27]},
                                          {"type": "EMAIL", "value": "user@example.com", "span": [35, 50]}
                                      ]
                                  }
                              },
                              "차단_처리": {
                                  "summary": "고위험 PII 차단 예시",
                                  "value": {
                                      "answer": "죄송합니다. 개인정보가 포함된 내용으로 인해 응답을 제공할 수 없습니다.",
                                      "pii_score": 85,
                                      "blocked": True,
                                      "matches": [
                                          {"type": "RRN", "value": "991201-1234567", "span": [5, 19]},
                                          {"type": "CARD", "value": "4111-1111-1111-1111", "span": [25, 44]}
                                      ]
                                  }
                              }
                          }
                      }
                  }
              }
          })
async def guard_llm_answer(request: GuardRequest) -> GuardResponse:
    """LLM 답변에서 PII 탐지 및 가드 처리"""
    result = guard_answer(request.text, detector)
    return GuardResponse(**result)


@app.post("/ingest/scrub",
          response_model=ScrubResponse,
          summary="데이터 적재용 PII 마스킹",
          description="""
          벡터 데이터베이스 적재 전에 문서/콘텐츠에서 PII를 사전 마스킹 처리합니다.

          **처리 방식:**
          - 모든 탐지된 PII를 토큰으로 치환 (`<PHONE>`, `<EMAIL>` 등)
          - 위험도에 관계없이 마스킹만 수행 (차단하지 않음)
          - RAG 시스템의 벡터 DB에 안전하게 저장 가능한 형태로 변환

          **사용 시나리오:**
          1. 문서 업로드 시 PII 사전 제거
          2. 웹 크롤링 데이터 전처리
          3. 사용자 입력 데이터 정제
          """,
          tags=["데이터 전처리"],
          responses={
              200: {
                  "description": "PII 마스킹 처리 완료",
                  "content": {
                      "application/json": {
                          "examples": {
                              "문서_마스킹": {
                                  "summary": "문서 PII 마스킹 예시",
                                  "value": {
                                      "scrubbed": "고객의 연락처는 <PHONE>이며, 계좌번호는 <ACCOUNT>입니다.",
                                      "matches": [
                                          {"type": "PHONE", "value": "010-9876-5432", "span": [7, 20]},
                                          {"type": "ACCOUNT", "value": "123-45-678901", "span": [28, 41]}
                                      ]
                                  }
                              }
                          }
                      }
                  }
              }
          })
async def scrub_ingest_data(request: ScrubRequest) -> ScrubResponse:
    """데이터 적재(ingest) 단계에서 PII 사전 마스킹 처리"""
    result = scrub_ingest(request.text, detector)
    return ScrubResponse(**result)


@app.get("/health",
         summary="헬스 체크",
         description="서비스의 상태와 PII 탐지기 준비 상태를 확인합니다.",
         tags=["모니터링"])
async def health_check():
    """서비스 헬스체크"""
    try:
        # PII 탐지기 동작 테스트
        test_result = detector.detect_pii("테스트 010-1234-5678")
        detector_status = "ready" if len(test_result) > 0 else "warning"
    except Exception:
        detector_status = "error"

    return {
        "status": "healthy",
        "service": "pii-guard",
        "version": "1.0.0",
        "detector_status": detector_status,
        "timestamp": "2024-01-01T00:00:00Z"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("pii_guard.api:app", host="0.0.0.0", port=3000, reload=True)