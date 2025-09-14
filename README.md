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
# 개발 서버 실행 (포트 8787)
uvicorn pii_guard.api:app --reload --port 8787

# 또는 직접 실행
python -m pii_guard.api
```

서버 실행 후 http://localhost:8787 에서 API 문서 확인 가능

## API 사용법

### 1. LLM 답변 가드 (`/guard`)

```bash
# curl 예시
curl -X POST "http://localhost:8787/guard" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "안녕하세요. 제 전화번호는 010-1234-5678이고 이메일은 user@example.com입니다."
  }'
```

**응답 예시:**
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

### 2. 데이터 적재용 사전 마스킹 (`/ingest/scrub`)

```bash
curl -X POST "http://localhost:8787/ingest/scrub" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "고객 연락처: 010-9876-5432, 계좌: 123-45-678901"
  }'
```

**응답 예시:**
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
PII_GUARD_URL = "http://localhost:8787"

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
const PII_GUARD_URL = 'http://localhost:8787';

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