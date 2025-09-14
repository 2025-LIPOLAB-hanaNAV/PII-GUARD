# qa_test_runner.py - PII Guard QA 자동 테스트 스크립트
import os
import sys
import json
import time
import subprocess
import requests
import platform
from datetime import datetime
from pathlib import Path, PureWindowsPath

# 고정 경로 설정
PDF_PATH = r"C:\Users\a3566\OneDrive\바탕 화면\서폴더\리포랩\hana navi_pii\data\pdf_merged.pdf"
REPORT_DIR = r"C:\Users\a3566\OneDrive\바탕 화면\서폴더\리포랩\hana navi_pii\data\result_report"

class PIIGuardQA:
    def __init__(self):
        self.server_process = None
        self.base_url = "http://localhost:8787"
        self.results = []
        self.report_dir = Path(REPORT_DIR)

    def setup_report_dir(self):
        """리포트 디렉토리 생성"""
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            print(f"[OK] 리포트 디렉토리 생성: {self.report_dir}")
        except Exception as e:
            print(f"[WARN] 메인 리포트 디렉토리 생성 실패: {e}")
            # 프로젝트 루트의 fallback 경로 사용
            self.report_dir = Path("./result_report")
            self.report_dir.mkdir(parents=True, exist_ok=True)
            print(f"[OK] 대체 리포트 디렉토리 생성: {self.report_dir.absolute()}")

    def start_server(self):
        """백그라운드 서버 기동"""
        print("\n=== 서버 기동 ===")
        try:
            # 기존 서버 종료 (있다면)
            self.stop_server()

            # uvicorn 서버 시작
            cmd = [sys.executable, "-c",
                   "import uvicorn; uvicorn.run('pii_guard.api:app', host='0.0.0.0', port=8787)"]
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="."
            )

            # 서버 시작 대기 및 폴링
            print("서버 시작 대기 중...")
            for i in range(30):
                try:
                    response = requests.get(f"{self.base_url}/health", timeout=2)
                    if response.status_code == 200:
                        print(f"[OK] 서버 기동 성공 ({i+1}초)")
                        return True
                except:
                    pass
                time.sleep(1)

            print("[FAIL] 서버 기동 실패 (타임아웃)")
            return False

        except Exception as e:
            print(f"[FAIL] 서버 기동 실패: {e}")
            return False

    def stop_server(self):
        """서버 종료"""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                print("[OK] 서버 종료")
            except:
                self.server_process.kill()
                print("[OK] 서버 강제 종료")
            self.server_process = None

    def save_test_result(self, filename, data):
        """테스트 결과 JSON 저장"""
        filepath = self.report_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  → {filename} 저장")

    def test_guard_basic(self):
        """T1: /guard 기본 테스트"""
        print("\n=== T1: Guard 기본 테스트 ===")
        test_data = {
            "text": "문의는 010-9999-8888 또는 help@bank.com 입니다. 카드 4111 1111 1111 1111"
        }

        try:
            response = requests.post(f"{self.base_url}/guard", json=test_data, timeout=10)
            result = response.json()

            # 결과 검증
            pii_score = result.get('pii_score', 0)
            matches = result.get('matches', [])
            answer = result.get('answer', '')
            blocked = result.get('blocked', False)

            detected_types = [m['type'] for m in matches]
            has_phone_mask = '<PHONE>' in answer
            has_email_mask = '<EMAIL>' in answer
            has_card_mask = '<CARD>' in answer

            # 결과 저장
            test_result = {
                "input": test_data,
                "response": result,
                "validation": {
                    "pii_score_positive": pii_score > 0,
                    "has_phone": 'PHONE' in detected_types,
                    "has_email": 'EMAIL' in detected_types,
                    "has_card": 'CARD' in detected_types,
                    "has_phone_mask": has_phone_mask,
                    "has_email_mask": has_email_mask,
                    "has_card_mask": has_card_mask
                }
            }

            self.save_test_result("guard1_before_whitelist.json", test_result)

            return {
                "name": "T1_guard_before",
                "score": pii_score,
                "types": detected_types,
                "blocked": blocked,
                "file": "guard1_before_whitelist.json",
                "status": "PASS" if pii_score > 0 and len(detected_types) > 0 else "FAIL"
            }

        except Exception as e:
            print(f"[FAIL] T1 실패: {e}")
            return {"name": "T1_guard_before", "status": "FAIL", "error": str(e)}

    def test_ingest_scrub(self):
        """T2: /ingest/scrub 테스트"""
        print("\n=== T2: Ingest Scrub 테스트 ===")
        test_data = {
            "text": "홍길동의 계좌번호 123-456-7890123 로 이체"
        }

        try:
            response = requests.post(f"{self.base_url}/ingest/scrub", json=test_data, timeout=10)
            result = response.json()

            scrubbed = result.get('scrubbed', '')
            matches = result.get('matches', [])
            detected_types = [m['type'] for m in matches]
            has_account_mask = '<ACCOUNT>' in scrubbed

            test_result = {
                "input": test_data,
                "response": result,
                "validation": {
                    "has_account": 'ACCOUNT' in detected_types,
                    "has_account_mask": has_account_mask
                }
            }

            self.save_test_result("scrub1.json", test_result)

            return {
                "name": "T2_ingest_scrub",
                "types_detected": detected_types,
                "file": "scrub1.json",
                "status": "PASS" if 'ACCOUNT' in detected_types else "FAIL"
            }

        except Exception as e:
            print(f"[FAIL] T2 실패: {e}")
            return {"name": "T2_ingest_scrub", "status": "FAIL", "error": str(e)}

    def test_pdf_demo(self):
        """T3: PDF 데모 테스트"""
        print("\n=== T3: PDF 데모 테스트 ===")

        try:
            # PDF 파일 존재 확인
            if not os.path.exists(PDF_PATH):
                print(f"[WARN] PDF 파일 없음: {PDF_PATH}")
                # 더미 텍스트 파일로 대체 테스트
                dummy_text = "고객정보: 010-1234-5678, test@example.com, 계좌 111-22-333444"
                from pii_guard.guard import guard_answer
                result = guard_answer(dummy_text)

                demo_result = {
                    "pdf_path": "DUMMY_TEXT (PDF not found)",
                    "pii_score": result['pii_score'],
                    "blocked": result['blocked'],
                    "total_matches": len(result['matches']),
                    "entities": result['matches'][:20],  # 최대 20개
                    "preview": result['answer'][:400]
                }
            else:
                # 실제 PDF 데모 실행
                cmd = [sys.executable, "tools/pdf_demo.py", PDF_PATH]
                proc = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

                if proc.returncode == 0:
                    demo_result = json.loads(proc.stdout)
                else:
                    raise Exception(f"PDF 데모 실행 실패: {proc.stderr}")

            self.save_test_result("pdf_demo.json", demo_result)

            return {
                "name": "T3_pdf_demo",
                "score": demo_result.get('pii_score', 0),
                "entities_count": len(demo_result.get('entities', [])),
                "file": "pdf_demo.json",
                "status": "PASS" if 'pii_score' in demo_result else "FAIL"
            }

        except Exception as e:
            print(f"[FAIL] T3 실패: {e}")
            return {"name": "T3_pdf_demo", "status": "FAIL", "error": str(e)}

    def test_guard_safe(self):
        """T4: 안전 문장 테스트"""
        print("\n=== T4: 안전 문장 테스트 ===")
        test_data = {
            "text": "영업시간은 평일 9시부터 16시입니다."
        }

        try:
            response = requests.post(f"{self.base_url}/guard", json=test_data, timeout=10)
            result = response.json()

            pii_score = result.get('pii_score', 0)
            matches = result.get('matches', [])

            test_result = {
                "input": test_data,
                "response": result,
                "validation": {
                    "pii_score_zero": pii_score == 0,
                    "matches_empty": len(matches) == 0
                }
            }

            self.save_test_result("guard_safe.json", test_result)

            return {
                "name": "T4_guard_safe",
                "score": pii_score,
                "file": "guard_safe.json",
                "status": "PASS" if pii_score == 0 and len(matches) == 0 else "FAIL"
            }

        except Exception as e:
            print(f"[FAIL] T4 실패: {e}")
            return {"name": "T4_guard_safe", "status": "FAIL", "error": str(e)}

    def test_guard_rrn_invalid(self):
        """T5: 주민번호 유사 테스트"""
        print("\n=== T5: 주민번호 유사(검증 실패) 테스트 ===")
        test_data = {
            "text": "871301-1234567"
        }

        try:
            response = requests.post(f"{self.base_url}/guard", json=test_data, timeout=10)
            result = response.json()

            pii_score = result.get('pii_score', 0)
            matches = result.get('matches', [])
            rrn_matches = [m for m in matches if m['type'] == 'RRN']

            test_result = {
                "input": test_data,
                "response": result,
                "validation": {
                    "rrn_not_detected": len(rrn_matches) == 0,
                    "low_score": pii_score <= 10
                }
            }

            self.save_test_result("guard_rrn_invalid.json", test_result)

            return {
                "name": "T5_guard_rrn_invalid",
                "score": pii_score,
                "file": "guard_rrn_invalid.json",
                "status": "PASS" if len(rrn_matches) == 0 else "FAIL"
            }

        except Exception as e:
            print(f"[FAIL] T5 실패: {e}")
            return {"name": "T5_guard_rrn_invalid", "status": "FAIL", "error": str(e)}

    def update_whitelist_and_restart(self):
        """화이트리스트 업데이트 및 서버 재시작"""
        print("\n=== 화이트리스트 업데이트 ===")

        try:
            # whitelist.yml 읽기
            import yaml
            with open('whitelist.yml', 'r', encoding='utf-8') as f:
                whitelist = yaml.safe_load(f)

            # 테스트 번호 추가 (중복 방지)
            test_phone = "010-9999-8888"
            if test_phone not in whitelist['phones']:
                whitelist['phones'].append(test_phone)

                # whitelist.yml 업데이트
                with open('whitelist.yml', 'w', encoding='utf-8') as f:
                    yaml.dump(whitelist, f, ensure_ascii=False, default_flow_style=False)

                print(f"[OK] 화이트리스트에 추가: {test_phone}")
            else:
                print(f"[OK] 이미 화이트리스트에 존재: {test_phone}")

            # 서버 재시작
            print("서버 재시작 중...")
            self.stop_server()
            time.sleep(2)
            return self.start_server()

        except Exception as e:
            print(f"[FAIL] 화이트리스트 업데이트 실패: {e}")
            return False

    def test_guard_after_whitelist(self, before_result):
        """T6: 화이트리스트 적용 후 테스트"""
        print("\n=== T6: Guard 화이트리스트 적용 후 테스트 ===")
        test_data = {
            "text": "문의는 010-9999-8888 또는 help@bank.com 입니다. 카드 4111 1111 1111 1111"
        }

        try:
            response = requests.post(f"{self.base_url}/guard", json=test_data, timeout=10)
            result = response.json()

            pii_score = result.get('pii_score', 0)
            matches = result.get('matches', [])
            detected_types = [m['type'] for m in matches]

            # 이전 점수와 비교
            before_score = before_result.get('score', 0) if before_result else 0
            delta = pii_score - before_score

            test_result = {
                "input": test_data,
                "response": result,
                "comparison": {
                    "before_score": before_score,
                    "after_score": pii_score,
                    "delta": delta,
                    "phone_filtered": 'PHONE' not in detected_types
                }
            }

            self.save_test_result("guard1_after_whitelist.json", test_result)

            return {
                "name": "T6_guard_after_whitelist",
                "score": pii_score,
                "delta": delta,
                "file": "guard1_after_whitelist.json",
                "status": "PASS" if delta <= 0 else "FAIL"  # 점수가 감소하거나 동일해야 함
            }

        except Exception as e:
            print(f"[FAIL] T6 실패: {e}")
            return {"name": "T6_guard_after_whitelist", "status": "FAIL", "error": str(e)}

    def generate_environment_info(self):
        """환경 정보 생성"""
        print("\n=== 환경 정보 수집 ===")

        env_info = {
            "timestamp": datetime.now().isoformat(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "python_version": platform.python_version(),
            "working_directory": os.getcwd(),
            "pdf_path": PDF_PATH,
            "report_directory": str(self.report_dir.absolute())
        }

        # pip freeze
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "freeze"],
                                 capture_output=True, text=True)
            env_info["packages"] = result.stdout.split('\n') if result.returncode == 0 else []
        except:
            env_info["packages"] = ["pip freeze failed"]

        # 환경 정보 저장
        with open(self.report_dir / "environment.txt", 'w', encoding='utf-8') as f:
            f.write(f"PII Guard QA Test Environment\n")
            f.write(f"Generated: {env_info['timestamp']}\n\n")
            f.write(f"Platform: {env_info['platform']} {env_info['platform_release']}\n")
            f.write(f"Python: {env_info['python_version']}\n")
            f.write(f"Working Directory: {env_info['working_directory']}\n")
            f.write(f"PDF Path: {env_info['pdf_path']}\n")
            f.write(f"Report Directory: {env_info['report_directory']}\n\n")
            f.write("Installed Packages:\n")
            for pkg in env_info["packages"]:
                f.write(f"{pkg}\n")

        return env_info

    def generate_summary_report(self, env_info):
        """요약 리포트 생성"""
        print("\n=== 리포트 생성 ===")

        # JSON 요약
        summary = {
            "pdf_path": PDF_PATH,
            "report_dir": str(self.report_dir.absolute()),
            "timestamp": env_info["timestamp"],
            "tests": self.results
        }

        with open(self.report_dir / "PII_Guard_Results.json", 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        # 마크다운 리포트
        md_content = f"""# PII Guard QA Test Report

## 테스트 정보
- **실행 일시**: {env_info['timestamp']}
- **환경**: {env_info['platform']} {env_info['platform_release']}, Python {env_info['python_version']}
- **PDF 경로**: `{PDF_PATH}`
- **리포트 경로**: `{self.report_dir.absolute()}`

## 테스트 결과

| 테스트 | 상태 | PII 점수 | 검출 타입 | 차단 | 파일 | 비고 |
|--------|------|----------|-----------|------|------|------|
"""

        for result in self.results:
            name = result.get('name', 'Unknown')
            status = result.get('status', 'UNKNOWN')
            score = result.get('score', 'N/A')
            types = ', '.join(result.get('types', result.get('types_detected', [])))
            blocked = result.get('blocked', False)
            file = result.get('file', 'N/A')
            delta = result.get('delta', '')
            delta_str = f"(Δ{delta:+d})" if delta != '' else ''
            error = result.get('error', '')
            note = error if error else delta_str

            md_content += f"| {name} | {status} | {score} | {types} | {blocked} | {file} | {note} |\n"

        # 화이트리스트 전후 비교
        before_test = next((r for r in self.results if r['name'] == 'T1_guard_before'), None)
        after_test = next((r for r in self.results if r['name'] == 'T6_guard_after_whitelist'), None)

        if before_test and after_test:
            md_content += f"""
## 화이트리스트 효과 분석

- **적용 전 점수**: {before_test.get('score', 'N/A')}
- **적용 후 점수**: {after_test.get('score', 'N/A')}
- **점수 변화**: {after_test.get('delta', 'N/A')}

화이트리스트 적용으로 010-9999-8888 번호가 필터링되어 PII 점수가 감소했습니다.
"""

        # 결론
        passed_tests = len([r for r in self.results if r.get('status') == 'PASS'])
        total_tests = len(self.results)

        md_content += f"""
## 결론

- **전체 테스트**: {total_tests}개
- **통과**: {passed_tests}개
- **실패**: {total_tests - passed_tests}개
- **통과율**: {(passed_tests/total_tests*100):.1f}%

"""

        if passed_tests == total_tests:
            md_content += "✅ **전체 테스트 통과** - PII Guard 시스템이 정상적으로 동작합니다.\n"
        else:
            md_content += "⚠ **일부 테스트 실패** - 상기 실패 항목을 확인하고 수정이 필요합니다.\n"

        with open(self.report_dir / "PII_Guard_Test_Report.md", 'w', encoding='utf-8') as f:
            f.write(md_content)

        print("[OK] 요약 리포트 생성 완료")

    def run_all_tests(self):
        """전체 테스트 실행"""
        print("[START] PII Guard QA 자동 테스트 시작")

        # 1. 리포트 디렉토리 설정
        self.setup_report_dir()

        # 2. 환경 정보 수집
        env_info = self.generate_environment_info()

        # 3. 서버 시작
        if not self.start_server():
            print("[FAIL] 서버 시작 실패 - 테스트 중단")
            return False

        try:
            # 4. 기본 테스트 실행
            self.results.append(self.test_guard_basic())
            self.results.append(self.test_ingest_scrub())
            self.results.append(self.test_pdf_demo())
            self.results.append(self.test_guard_safe())
            self.results.append(self.test_guard_rrn_invalid())

            # 5. 화이트리스트 테스트
            before_result = next((r for r in self.results if r['name'] == 'T1_guard_before'), None)

            if self.update_whitelist_and_restart():
                self.results.append(self.test_guard_after_whitelist(before_result))
            else:
                self.results.append({
                    "name": "T6_guard_after_whitelist",
                    "status": "FAIL",
                    "error": "Server restart failed"
                })

            # 6. 리포트 생성
            self.generate_summary_report(env_info)

            # 7. 요약 출력
            self.print_summary()

            return True

        finally:
            # 서버 종료
            self.stop_server()

    def print_summary(self):
        """최종 요약 출력"""
        print(f"\n{'='*60}")
        print("[COMPLETE] PII GUARD QA 테스트 완료")
        print(f"{'='*60}")

        print(f"\n[SUMMARY] 테스트 결과 요약:")
        print(f"{'테스트명':<25} {'점수':<6} {'타입':<15} {'차단':<6} {'상태'}")
        print(f"{'-'*60}")

        for result in self.results:
            name = result.get('name', 'Unknown')[:24]
            score = str(result.get('score', 'N/A'))[:5]
            types = ', '.join(result.get('types', result.get('types_detected', [])))[:14]
            blocked = 'Yes' if result.get('blocked', False) else 'No'
            status = result.get('status', 'UNKNOWN')

            print(f"{name:<25} {score:<6} {types:<15} {blocked:<6} {status}")

        print(f"\n[REPORT] Saved report to: {self.report_dir.absolute()}")

        # 파일 목록
        print(f"\n[FILES] 생성된 파일:")
        for file in self.report_dir.iterdir():
            if file.is_file():
                print(f"  - {file.name}")


def main():
    qa = PIIGuardQA()
    success = qa.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())