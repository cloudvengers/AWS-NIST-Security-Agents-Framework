# =============================================================================
# FastAPI 서버 - NIST 보안 분석 API
# =============================================================================

import time
import traceback
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# 로컬 모듈 임포트
from models import AnalysisRequest, AnalysisResponse, HealthResponse, TaskStartResponse, TaskStatusResponse
from workflow import run_nist_workflow, get_task_logs, set_current_task_id

# =============================================================================
# FastAPI 애플리케이션 설정
# =============================================================================

app = FastAPI(
    title="NIST 보안 분석 API",
    description="AWS 클라우드 인프라에 대한 NIST 사이버보안 프레임워크 기반 보안 분석 서비스",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS 설정 (프론트엔드 연동용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 도메인으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# 전역 변수 - 작업 상태 저장
# =============================================================================

# 간단한 메모리 기반 작업 상태 저장소
task_status = {}

def update_task_status(task_id: str, status: str, message: str = "", result: dict = None, error: str = None):
    """작업 상태 업데이트"""
    task_status[task_id] = {
        "status": status,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "result": result,
        "error": error
    }

def run_nist_workflow_background(task_id: str, customer_access_key: str, customer_secret_key: str, target_region: str):
    """백그라운드에서 NIST 워크플로우 실행"""
    try:
        # 현재 task_id 설정 (로그 캡처용)
        set_current_task_id(task_id)
        
        # 처리 중 상태로 업데이트
        update_task_status(task_id, "processing", "NIST 보안 분석 실행 중...")
        
        print(f"\n{'='*80}")
        print(f"🚀 백그라운드 보안 분석 시작 - Task ID: {task_id}")
        print(f"📍 대상 리전: {target_region}")
        print(f"⏰ 시작 시간: {datetime.now().isoformat()}")
        print(f"{'='*80}")
        
        # NIST 워크플로우 실행
        result = run_nist_workflow(
            customer_access_key=customer_access_key,
            customer_secret_key=customer_secret_key,
            target_region=target_region
        )
        
        if result is not None:
            # 성공 상태로 업데이트
            update_task_status(task_id, "completed", "NIST 보안 분석 완료", result=result)
            print(f"\n✅ 백그라운드 분석 완료 - Task ID: {task_id}")
        else:
            # 실패 상태로 업데이트
            update_task_status(task_id, "failed", "NIST 워크플로우 실행 중 오류 발생", error="워크플로우 실행 실패")
            print(f"\n❌ 백그라운드 분석 실패 - Task ID: {task_id}")
            
    except Exception as e:
        # 예외 발생 시 실패 상태로 업데이트
        error_msg = f"백그라운드 처리 중 오류: {str(e)}"
        update_task_status(task_id, "failed", error_msg, error=error_msg)
        print(f"\n❌ 백그라운드 처리 예외 - Task ID: {task_id}, Error: {error_msg}")
        print(f"📋 상세 오류:\n{traceback.format_exc()}")
    finally:
        # task_id 초기화
        set_current_task_id(None)

# =============================================================================
# 전역 예외 처리
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """전역 예외 처리기"""
    error_detail = {
        "error": "Internal Server Error",
        "detail": str(exc),
        "timestamp": datetime.now().isoformat(),
        "path": str(request.url)
    }
    
    # 개발 환경에서는 상세 에러 정보 포함
    if app.debug:
        error_detail["traceback"] = traceback.format_exc()
    
    return JSONResponse(
        status_code=500,
        content=error_detail
    )

# =============================================================================
# API 엔드포인트
# =============================================================================

@app.get("/", response_model=dict)
async def root():
    """루트 엔드포인트 - API 정보"""
    return {
        "service": "NIST 보안 분석 API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "analysis_start": "POST /analysis",
            "analysis_status": "GET /analysis/{task_id}/status",
            "analysis_result": "GET /analysis/{task_id}/result",
            "health": "GET /health",
            "docs": "GET /docs"
        },
        "usage": {
            "1": "POST /analysis로 분석 시작 → task_id 받기",
            "2": "GET /analysis/{task_id}/status로 진행 상황 확인",
            "3": "GET /analysis/{task_id}/result로 완료된 결과 조회"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """헬스체크 엔드포인트"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )

@app.post("/analysis", response_model=TaskStartResponse)
async def analyze_security(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    NIST 보안 분석 시작 (비동기)
    
    고객의 AWS 자격증명을 받아 지정된 리전의 보안 상태를 
    NIST 사이버보안 프레임워크에 따라 분석합니다.
    
    즉시 task_id를 반환하고 백그라운드에서 분석을 실행합니다.
    """
    
    try:
        # 고유한 작업 ID 생성
        task_id = f"nist_analysis_{int(time.time() * 1000)}"
        
        # 초기 상태 설정
        update_task_status(task_id, "started", "NIST 보안 분석 작업이 시작되었습니다.")
        
        # 백그라운드 작업 추가
        background_tasks.add_task(
            run_nist_workflow_background,
            task_id,
            request.customer_access_key,
            request.customer_secret_key,
            request.target_region
        )
        
        print(f"\n{'='*80}")
        print(f"🚀 새로운 보안 분석 요청 접수")
        print(f"📋 Task ID: {task_id}")
        print(f"📍 대상 리전: {request.target_region}")
        print(f"⏰ 접수 시간: {datetime.now().isoformat()}")
        print(f"🔄 상태: 백그라운드 처리 시작")
        print(f"{'='*80}")
        
        # 즉시 응답 반환
        return TaskStartResponse(
            task_id=task_id,
            status="started",
            message="NIST 보안 분석이 백그라운드에서 시작되었습니다. /analysis/{task_id}/status 엔드포인트로 진행 상황을 확인하세요.",
            timestamp=datetime.now().isoformat()
        )
    
    except ValueError as e:
        # 입력값 검증 오류
        error_msg = f"입력값 오류: {str(e)}"
        print(f"\n❌ 입력값 검증 실패: {error_msg}")
        
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Bad Request",
                "message": error_msg
            }
        )
    
    except Exception as e:
        # 기타 예상치 못한 오류
        error_msg = f"서버 내부 오류: {str(e)}"
        print(f"\n❌ 예상치 못한 오류 발생: {error_msg}")
        print(f"📋 상세 오류:\n{traceback.format_exc()}")
        
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal Server Error",
                "message": error_msg
            }
        )

@app.get("/analysis/{task_id}/status", response_model=TaskStatusResponse)
async def get_analysis_status(task_id: str):
    """
    NIST 보안 분석 상태 조회
    
    task_id로 분석 작업의 현재 상태를 확인합니다.
    """
    
    if task_id not in task_status:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Task Not Found",
                "message": f"Task ID '{task_id}'를 찾을 수 없습니다."
            }
        )
    
    status_info = task_status[task_id]
    
    return TaskStatusResponse(
        task_id=task_id,
        status=status_info["status"],
        message=status_info["message"],
        timestamp=status_info["timestamp"],
        progress=f"상태: {status_info['status']}"
    )

@app.get("/analysis/{task_id}/logs")
async def get_analysis_logs(task_id: str):
    """
    NIST 보안 분석 실시간 로그 조회
    
    task_id로 분석 작업의 실시간 로그를 확인합니다.
    백엔드 콘솔에 출력되는 모든 내용을 동일하게 제공합니다.
    """
    
    try:
        logs = get_task_logs(task_id)
        
        return {
            "task_id": task_id,
            "logs": logs,
            "total_lines": len(logs),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        error_msg = f"로그 조회 실패: {str(e)}"
        
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal Server Error",
                "message": error_msg,
                "task_id": task_id
            }
        )


@app.get("/analysis/{task_id}/result")
def get_analysis_result(task_id: str):
    if task_id not in task_status:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Task Not Found",
                "message": f"Task ID '{task_id}'를 찾을 수 없습니다."
            }
        )

    status_info = task_status[task_id]

    if status_info["status"] != "completed":
        raise HTTPException(
            status_code=202,
            detail={
                "error": "Task Not Completed",
                "message": f"작업이 아직 완료되지 않았습니다. 현재 상태: {status_info['status']}"
            }
        )

    result: dict = status_info.get("result", {})

    def extract_response(key):
        entry = result.get(key, {})
        return entry.get("response", None) if isinstance(entry, dict) else None

    grouped_result = {
        "identify": {
            "identify_01_result": extract_response("identify_01_result"),
            "computing_result": extract_response("computing_result"),
            "storage_result": extract_response("storage_result"),
            "db_result": extract_response("db_result")
        },
        "protect": {
            "protect_01_result": extract_response("protect_01_result"),
            "protect_02_result": extract_response("protect_02_result")
        },
        "detect": {
            "detect_01_result": extract_response("detect_01_result"),
            "detect_02_result": extract_response("detect_02_result")
        },
        "respond": {
            "respond_result": extract_response("respond_result")
        },
        "recover": {
            "recover_result": extract_response("recover_result")
        },
        "summary": {
            "summary_result": extract_response("summary_result")
        }
    }

    return {
        "task_id": task_id,
        "grouped_responses": grouped_result,
        "timestamp": datetime.now().isoformat()
    }

# =============================================================================
# 서버 시작 정보
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print(f"\n{'='*80}")
    print(f"🚀 NIST 보안 분석 API 서버 시작")
    print(f"{'='*80}")
    print(f"📍 서버 주소: http://localhost:8000")
    print(f"📖 API 문서: http://localhost:8000/docs")
    print(f"🔍 ReDoc: http://localhost:8000/redoc")
    print(f"💚 헬스체크: http://localhost:8000/health")
    print(f"{'='*80}")
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
