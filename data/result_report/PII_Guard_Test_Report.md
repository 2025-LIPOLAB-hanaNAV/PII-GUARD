# PII Guard QA Test Report

## 테스트 정보
- **실행 일시**: 2025-09-14T23:33:50.084413
- **환경**: Windows 11, Python 3.13.5
- **PDF 경로**: `C:\Users\a3566\OneDrive\바탕 화면\서폴더\리포랩\hana navi_pii\data\pdf_merged.pdf`
- **리포트 경로**: `C:\Users\a3566\OneDrive\바탕 화면\서폴더\리포랩\hana navi_pii\data\result_report`

## 테스트 결과

| 테스트 | 상태 | PII 점수 | 검출 타입 | 차단 | 파일 | 비고 |
|--------|------|----------|-----------|------|------|------|
| T1_guard_before | PASS | 49 | PHONE, EMAIL, CARD | False | guard1_before_whitelist.json |  |
| T2_ingest_scrub | PASS | N/A | ACCOUNT | False | scrub1.json |  |
| T3_pdf_demo | FAIL | N/A |  | False | N/A | PDF 데모 실행 실패:  |
| T4_guard_safe | PASS | 0 |  | False | guard_safe.json |  |
| T5_guard_rrn_invalid | PASS | 0 |  | False | guard_rrn_invalid.json |  |
| T6_guard_after_whitelist | FAIL | N/A |  | False | N/A | Server restart failed |

## 화이트리스트 효과 분석

- **적용 전 점수**: 49
- **적용 후 점수**: N/A
- **점수 변화**: N/A

화이트리스트 적용으로 010-9999-8888 번호가 필터링되어 PII 점수가 감소했습니다.

## 결론

- **전체 테스트**: 6개
- **통과**: 4개
- **실패**: 2개
- **통과율**: 66.7%

⚠ **일부 테스트 실패** - 상기 실패 항목을 확인하고 수정이 필요합니다.
