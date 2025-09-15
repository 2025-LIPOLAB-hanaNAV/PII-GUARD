# PII 구현해보려고 했어요...
- 개인정보 검출되면 수치가 증가하도록..
- 컨셉은..2중 방어 + 점수화
  - Ingest Scrubber: 문서 벡터화 전에 PII를 <PHONE>, <ACCOUNT> 같은 토큰으로 마스킹(누출 위험↓).
  - Output Guard: 최종 답변을 검출→마스킹→차단 후 UI에 **PII 위험도(%)**를 넘겨 “PII 보호” 수치로 표시.
    - ingest 부분은 사전 마스킹, guard 부분은 llm이 최종 답변 만든 직후 한번 더 검사해서 pii 위험도 점수 계산 (역할 : 화면의 “PII 보호 %” 수치를 찍고, 민감하면 숨김/경고 처리)
- 점수 산식
  - 엔티티 가중치: 주민번호 1.0, 카드 0.9, 계좌 0.8, 개인전화 0.6, 이메일 0.5
  - 위험점수 R = ∑(가중치 × 검출개수) ※ 화이트리스트(대표번호 등)는 제외
  - PII 위험도% = min(100, round(100*(1 - exp(-R/3))))
  - → UI의 **“PII 보호”**는 “이번 응답의 PII 위험도%”로 쓰면 됨(0% 안전, 높을수록 위험).
- 백엔드로 /guard(출력 가드)와 /ingest/scrub(사전 마스킹) 2개 엔드포인트 제공.
- RAG 파이프라인에서 LLM 출력 직전에 /guard를 호출하고, 데이터 적재 직전에 /ingest/scrub 한 번만 호출.
- 응답은 masked_answer, pii_score, matches[] 로 내려서 프론트에서 배지/토스트로 노출.- 
- 흐름도
```
사용자 질문 → 검색(Retriever) → 리랭커 → LLM 생성
                                     └─(우리) Output Guard → 답변(PII% 포함)

데이터 업로드 → (우리) Ingest Scrubber (토큰으로 PI정보 가림) → 임베딩/색인 → KB
```
여튼 이렇게 개인정보 검출에 대한 아이디어를 최대한 구현해보려 했고.. 나름의 테스트는 해봤는데
이게 각자 환경에서 돌아갈지 모르겠네요.. 서버가 안들어가져서 제 개인환경에서 해서
혹시나 바로 붙일수있을만한 부분이 확인된다면 진행하는거로 하고 아니면 뭐.. 없애자........인데 이 부분은 있는게 좋을 것 같긴함..
여튼 부족하지만 이렇게 만들어봤으니 한번 참고해주십시오 ㅠ,, 참고만,,


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

### 0. 파일트리
```
  pii-guard/
  ├── README.md                      # 📖 프로젝트 문서 (설치/사용법/API 가이드)
  ├── requirements.txt               # 📦 Python 의존성 패키지 목록
  ├── whitelist.yml                  # ⚪ PII 탐지 예외 처리용 화이트리스트 설정
  │
  ├── pii_guard/                     # 🏠 메인 패키지 디렉토리
  │   ├── __init__.py               # 📋 패키지 초기화 및 공개 API 정의
  │   ├── api.py                    # 🌐 FastAPI 웹서버 (REST API 엔드포인트)
  │   ├── detector.py               # 🔍 PII 탐지 엔진 (정규식 기반 패턴 매칭)
  │   └── guard.py                  # 🛡️  답변 가드/마스킹 비즈니스 로직
  │
  ├── tests/                        # 🧪 테스트 디렉토리
  │   └── test_strings.py          # ✅ PII 탐지 기능 유닛 테스트
  │
  ├── tools/                        # 🔧 유틸리티 도구 모음
  │   └── pdf_demo.py              # 📄 PDF 파일 PII 분석 데모 도구
  │
  ├── qa_test_runner.py             # 🤖 QA 자동화 테스트 실행기 (API 통합 테스트)
  ├── sample.txt                    # 📝 PII 탐지 테스트용 샘플 텍스트
  ├── test_request.json            # 🔬 API 테스트용 요청 데이터 (guard 엔드포인트)
  └── test_scrub_request.json      # 🔬 API 테스트용 요청 데이터 (scrub 엔드포인트)
```
  주요 컴포넌트별 역할:

  🏠 Core Package (pii_guard/)

  - detector.py: 한국 PII 패턴 탐지 (주민번호, 전화번호, 이메일, 계좌번호 등)
  - guard.py: 위험도 점수화 및 답변 차단/마스킹 로직
  - api.py: RESTful API 서버 (포트 8787, /guard, /ingest/scrub 엔드포인트)

  🧪 Testing & Tools

  - tests/test_strings.py: 탐지 정확성 검증 테스트
  - qa_test_runner.py: 전체 시스템 QA 자동화
  - tools/pdf_demo.py: PDF 문서 PII 분석 유틸리티

  ⚙️ Configuration

  - whitelist.yml: 탐지 제외 대상 (고객센터 번호, 공개 이메일 등)

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
uvicorn pii_guard.api:app --reload --port 3000

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
