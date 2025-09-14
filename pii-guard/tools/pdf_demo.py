# tools/pdf_demo.py
import sys
import json
from pathlib import Path

# 상위 디렉토리의 pii_guard 모듈을 임포트하기 위한 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from pii_guard.guard import guard_answer
from pii_guard.detector import PIIDetector

try:
    from PyPDF2 import PdfReader
except ImportError:
    print("PyPDF2가 설치되지 않았습니다. pip install PyPDF2로 설치해주세요.")
    sys.exit(1)


def extract_text_from_pdf(pdf_path: str, max_length: int = 10000) -> str:
    """
    PDF에서 텍스트 추출

    Args:
        pdf_path: PDF 파일 경로
        max_length: 최대 텍스트 길이 (너무 긴 경우 샘플링)

    Returns:
        추출된 텍스트
    """
    try:
        reader = PdfReader(pdf_path)
        text_parts = []

        for page_num, page in enumerate(reader.pages):
            try:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(f"[페이지 {page_num + 1}]\n{page_text}\n")
            except Exception as e:
                print(f"페이지 {page_num + 1} 읽기 실패: {e}")
                continue

        full_text = "\n".join(text_parts)

        # 너무 긴 경우 앞부분만 샘플링
        if len(full_text) > max_length:
            full_text = full_text[:max_length] + "\n\n[텍스트가 너무 길어서 {max_length}자까지만 분석합니다.]"

        return full_text

    except Exception as e:
        raise Exception(f"PDF 읽기 실패: {e}")


def demo_pdf_analysis(pdf_path: str):
    """
    PDF PII 분석 데모

    Args:
        pdf_path: 분석할 PDF 파일 경로
    """
    if not Path(pdf_path).exists():
        print(f"파일을 찾을 수 없습니다: {pdf_path}")
        return

    try:
        # PDF에서 텍스트 추출
        print(f"PDF 분석 중: {pdf_path}")
        text = extract_text_from_pdf(pdf_path)

        # PII 분석 수행
        detector = PIIDetector()
        result = guard_answer(text, detector)

        # 상위 20개 엔티티 추출 (중복 제거하여 타입별로 정리)
        entities_by_type = {}
        for match in result["matches"]:
            pii_type = match["type"]
            value = match["value"]

            if pii_type not in entities_by_type:
                entities_by_type[pii_type] = set()
            entities_by_type[pii_type].add(value)

        # 상위 20개로 엄격히 제한
        top_entities = []
        for pii_type, values in entities_by_type.items():
            for value in list(values)[:20-len(top_entities)]:  # 남은 슬롯만큼만 추가
                top_entities.append({
                    "type": pii_type,
                    "value": value
                })
                if len(top_entities) >= 20:  # 정확히 20개에서 중단
                    break
            if len(top_entities) >= 20:
                break

        # 답변 프리뷰 (앞 400자)
        answer_preview = result["answer"][:400]
        if len(result["answer"]) > 400:
            answer_preview += "..."

        # 결과 JSON 출력
        output = {
            "pdf_path": pdf_path,
            "pii_score": result["pii_score"],
            "blocked": result["blocked"],
            "total_matches": len(result["matches"]),
            "entities": top_entities,
            "preview": answer_preview
        }

        print(json.dumps(output, ensure_ascii=False, indent=2))

    except Exception as e:
        error_output = {
            "error": str(e),
            "pdf_path": pdf_path
        }
        print(json.dumps(error_output, ensure_ascii=False, indent=2))


def main():
    """메인 함수"""
    if len(sys.argv) != 2:
        print("사용법: python tools/pdf_demo.py <pdf_path>")
        print("예시: python tools/pdf_demo.py sample.pdf")
        sys.exit(1)

    pdf_path = sys.argv[1]
    demo_pdf_analysis(pdf_path)


if __name__ == "__main__":
    main()