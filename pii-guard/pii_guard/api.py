# pii_guard/api.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Any

from .guard import guard_answer, scrub_ingest
from .detector import PIIDetector

app = FastAPI(
    title="PII Guard API",
    description="RAG 챗봇용 PII 탐지 및 마스킹 서비스",
    version="1.0.0"
)

# 전역 PII 탐지기 인스턴스
detector = PIIDetector()


class GuardRequest(BaseModel):
    text: str

    class Config:
        schema_extra = {
            "example": {
                "text": "안녕하세요. 제 전화번호는 010-1234-5678이고 이메일은 user@example.com입니다."
            }
        }


class GuardResponse(BaseModel):
    answer: str
    pii_score: int
    blocked: bool
    matches: List[Dict[str, Any]]

    class Config:
        schema_extra = {
            "example": {
                "answer": "안녕하세요. 제 전화번호는 <PHONE>이고 이메일은 <EMAIL>입니다.",
                "pii_score": 55,
                "blocked": False,
                "matches": [
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
            }
        }


class ScrubRequest(BaseModel):
    text: str

    class Config:
        schema_extra = {
            "example": {
                "text": "고객의 전화번호는 010-9876-5432이며, 계좌번호는 123-45-678901입니다."
            }
        }


class ScrubResponse(BaseModel):
    scrubbed: str
    matches: List[Dict[str, Any]]

    class Config:
        schema_extra = {
            "example": {
                "scrubbed": "고객의 전화번호는 <PHONE>이며, 계좌번호는 <ACCOUNT>입니다.",
                "matches": [
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
            }
        }


@app.get("/")
async def root():
    """API 루트 엔드포인트"""
    return {
        "message": "PII Guard API",
        "version": "1.0.0",
        "endpoints": {
            "/guard": "LLM 답변 PII 가드 및 마스킹",
            "/ingest/scrub": "데이터 적재용 PII 사전 마스킹"
        }
    }


@app.post("/guard", response_model=GuardResponse)
async def guard_llm_answer(request: GuardRequest) -> GuardResponse:
    """
    LLM 답변에서 PII 탐지 및 가드 처리

    - PII 위험도가 70점 이상이면 답변 차단
    - 70점 미만이면 PII 마스킹 후 반환
    """
    result = guard_answer(request.text, detector)
    return GuardResponse(**result)


@app.post("/ingest/scrub", response_model=ScrubResponse)
async def scrub_ingest_data(request: ScrubRequest) -> ScrubResponse:
    """
    데이터 적재(ingest) 단계에서 PII 사전 마스킹 처리

    - 모든 PII를 토큰으로 치환
    - 차단하지 않고 마스킹만 수행
    """
    result = scrub_ingest(request.text, detector)
    return ScrubResponse(**result)


@app.get("/health")
async def health_check():
    """서비스 헬스체크"""
    return {"status": "healthy", "service": "pii-guard"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("pii_guard.api:app", host="0.0.0.0", port=8787, reload=True)