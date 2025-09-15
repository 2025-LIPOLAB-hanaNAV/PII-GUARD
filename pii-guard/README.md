# PII Guard

RAG 챗봇용 개인정보(PII) 탐지 및 마스킹 미니서비스

## 개요

PII Guard는 LLM 답변과 데이터 적재 단계에서 개인정보를 탐지하고 마스킹하여 보안을 강화하는 서비스입니다.

### 주요 기능

- **PII 탐지**: 주민등록번호, 신용카드번호, 계좌번호, 전화번호, 이메일 탐지
- **위험도 점수화**: 0-100점으로 PII 위험도 산출
- **자동 마스킹**: PII를 토큰으로 치환 (`<PHONE>`, `<EMAIL>` 등)
- **고위험 차단**: 70점 이상 시 답변 차단
- **화이트리스트**: 공개 번호 등 예외 처리

## 설치 및 실행

### 1. 설치

```bash
# 프로젝트 클론 또는 다운로드 후
cd pii-guard

# 가상환경 생성 (권장)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt
```

### 2. 서버 실행

```bash
# 개발 서버 실행 (포트 3000)
uvicorn pii_guard.api:app --reload --port 3000

# 또는 직접 실행
python -m pii_guard.api
```

서버 실행 후 http://localhost:3000 에서 API 문서 확인 가능

## API 문서

PII Guard는 FastAPI 기반으로 구축되어 자동 생성되는 OpenAPI/Swagger 문서를 제공합니다.

### 📖 대화형 API 문서 접속
- **Swagger UI**: http://localhost:3000/docs
- **ReDoc**: http://localhost:3000/redoc
- **OpenAPI 스키마**: http://localhost:3000/openapi.json

### 🔧 API 엔드포인트 개요

| 엔드포인트 | 메서드 | 설명 | 태그 |
|---|---|---|---|
| `/` | GET | Swagger 문서로 리다이렉트 | - |
| `/info` | GET | API 기본 정보 및 설정 | 정보 |
| `/guard` | POST | LLM 답변 PII 가드 및 마스킹 | PII 가드 |
| `/ingest/scrub` | POST | 데이터 적재용 PII 마스킹 | 데이터 전처리 |
| `/health` | GET | 서비스 헬스체크 | 모니터링 |

### 📊 지원하는 PII 유형 및 위험도

| PII 유형 | 설명 | 가중치 | 예시 |
|---|---|---|---|
| **RRN** | 주민등록번호 | 1.0 | `991201-1234567` |
| **CARD** | 신용카드번호 (Luhn 검증) | 0.9 | `4111-1111-1111-1111` |
| **ACCOUNT** | 계좌번호 | 0.8 | `123-45-678901` |
| **PHONE** | 전화번호 | 0.6 | `010-1234-5678` |
| **EMAIL** | 이메일 주소 | 0.5 | `user@example.com` |

**위험도 점수 계산**: `min(100, round(100 * (1 - exp(-위험값/3))))`
**차단 임계값**: 70점 이상

## API 사용법

### 1. 🛡️ LLM 답변 가드 (`POST /guard`)

**용도**: LLM 답변에서 PII 탐지 후 위험도에 따라 마스킹 또는 차단

**요청 스키마**:
```json
{
  "text": "string (required) - PII 탐지할 LLM 답변 텍스트"
}
```

**응답 스키마**:
```json
{
  "answer": "string - 마스킹된 답변 또는 차단 메시지",
  "pii_score": "integer (0-100) - PII 위험도 점수",
  "blocked": "boolean - 차단 여부 (70점 이상 시 true)",
  "matches": [
    {
      "type": "string - PII 유형 (PHONE, EMAIL, CARD, RRN, ACCOUNT)",
      "value": "string - 탐지된 원본 값",
      "span": "[start, end] - 텍스트 내 위치"
    }
  ]
}
```

**curl 예시**:
```bash
curl -X POST "http://localhost:3000/guard" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "안녕하세요. 제 전화번호는 010-1234-5678이고 이메일은 user@example.com입니다."
  }'
```

**응답 예시 (마스킹)**:
```json
{
  "answer": "안녕하세요. 제 전화번호는 <PHONE>이고 이메일은 <EMAIL>입니다.",
  "pii_score": 55,
  "blocked": false,
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
```

**응답 예시 (차단)**:
```json
{
  "answer": "죄송합니다. 개인정보가 포함된 내용으로 인해 응답을 제공할 수 없습니다.",
  "pii_score": 85,
  "blocked": true,
  "matches": [
    {
      "type": "RRN",
      "value": "991201-1234567",
      "span": [5, 19]
    }
  ]
}
```

### 2. 🔧 데이터 적재용 사전 마스킹 (`POST /ingest/scrub`)

**용도**: 벡터 DB 저장 전 문서/콘텐츠의 PII 사전 마스킹 (차단하지 않음)

**요청 스키마**:
```json
{
  "text": "string (required) - PII 마스킹할 원본 콘텐츠 텍스트"
}
```

**응답 스키마**:
```json
{
  "scrubbed": "string - PII가 토큰으로 치환된 텍스트",
  "matches": [
    {
      "type": "string - PII 유형",
      "value": "string - 탐지된 원본 값",
      "span": "[start, end] - 텍스트 내 위치"
    }
  ]
}
```

**curl 예시**:
```bash
curl -X POST "http://localhost:3000/ingest/scrub" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "고객 연락처: 010-9876-5432, 계좌: 123-45-678901"
  }'
```

**응답 예시**:
```json
{
  "scrubbed": "고객 연락처: <PHONE>, 계좌: <ACCOUNT>",
  "matches": [
    {
      "type": "PHONE",
      "value": "010-9876-5432",
      "span": [7, 20]
    },
    {
      "type": "ACCOUNT",
      "value": "123-45-678901",
      "span": [25, 38]
    }
  ]
}
```

### 3. ℹ️ API 정보 조회 (`GET /info`)

**용도**: PII Guard API의 기본 정보와 설정 확인

**응답 예시**:
```json
{
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
```

### 4. ❤️ 헬스 체크 (`GET /health`)

**용도**: 서비스 상태 및 PII 탐지기 동작 확인

**응답 예시**:
```json
{
  "status": "healthy",
  "service": "pii-guard",
  "version": "1.0.0",
  "detector_status": "ready",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 테스트

```bash
# 유닛 테스트 실행
python tests/test_strings.py
```

## PDF 데모 도구

```bash
# PDF 파일의 PII 분석
python tools/pdf_demo.py /path/to/sample.pdf
```

**출력 예시:**
```json
{
  "pdf_path": "/path/to/sample.pdf",
  "pii_score": 75,
  "blocked": true,
  "total_matches": 12,
  "entities": [
    {"type": "PHONE", "value": "010-1234-5678"},
    {"type": "EMAIL", "value": "test@company.com"}
  ],
  "preview": "PDF 내용의 앞 400자 미리보기..."
}
```

## RAG 백엔드 통합

### Python FastAPI 예시

```python
import requests
from fastapi import FastAPI

app = FastAPI()
PII_GUARD_URL = "http://localhost:3000"

@app.post("/chat")
async def chat_endpoint(question: str):
    # LLM으로부터 답변 생성
    llm_answer = generate_llm_answer(question)

    # PII Guard로 답변 검증
    response = requests.post(f"{PII_GUARD_URL}/guard",
                           json={"text": llm_answer})
    guard_result = response.json()

    return {
        "answer": guard_result["answer"],
        "pii_score": guard_result["pii_score"],
        "blocked": guard_result["blocked"]
    }

@app.post("/ingest")
async def ingest_document(content: str):
    # 문서 적재 전 PII 사전 마스킹
    response = requests.post(f"{PII_GUARD_URL}/ingest/scrub",
                           json={"text": content})
    scrub_result = response.json()

    # 마스킹된 내용으로 벡터DB 저장
    save_to_vectordb(scrub_result["scrubbed"])

    return {"status": "ingested", "pii_matches": len(scrub_result["matches"])}
```

### Node.js 예시

```javascript
const express = require('express');
const axios = require('axios');

const app = express();
const PII_GUARD_URL = 'http://localhost:3000';

app.post('/chat', async (req, res) => {
  const llmAnswer = await generateLLMAnswer(req.body.question);

  // PII Guard 호출
  const guardResponse = await axios.post(`${PII_GUARD_URL}/guard`, {
    text: llmAnswer
  });

  res.json({
    answer: guardResponse.data.answer,
    pii_score: guardResponse.data.pii_score,
    blocked: guardResponse.data.blocked
  });
});

app.post('/ingest', async (req, res) => {
  // 사전 마스킹 처리
  const scrubResponse = await axios.post(`${PII_GUARD_URL}/ingest/scrub`, {
    text: req.body.content
  });

  await saveToVectorDB(scrubResponse.data.scrubbed);

  res.json({
    status: 'ingested',
    pii_matches: scrubResponse.data.matches.length
  });
});
```

## 설정

### 화이트리스트 편집

`whitelist.yml` 파일을 편집하여 탐지에서 제외할 번호/이메일을 설정:

```yaml
phones:
  - "1599-1111"  # 고객센터
  - "112"        # 응급전화
  - "1588-1234"  # 회사 대표번호

emails:
  - "support@company.com"
  - "noreply@domain.com"

accounts:
  - "000-000-000-000"  # 테스트 계좌
```

## 아키텍처

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   RAG Bot   │───▶│ PII Guard   │───▶│  Response   │
│             │    │   Service   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ whitelist.yml│
                   └─────────────┘
```

## 라이선스

MIT License