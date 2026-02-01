# =============================================================================
# FastAPI 요청/응답 모델 정의
# =============================================================================

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List

# =============================================================================
# 요청 모델
# =============================================================================

class AnalysisRequest(BaseModel):
    """NIST 보안 분석 요청 모델"""
    
    customer_access_key: str = Field(
        ..., 
        description="고객의 AWS Access Key ID",
        min_length=16,
        max_length=32
    )
    
    customer_secret_key: str = Field(
        ..., 
        description="고객의 AWS Secret Access Key",
        min_length=28,
        max_length=64
    )
    
    target_region: str = Field(
        ..., 
        description="분석할 AWS 리전 (예: us-east-1, us-west-2)",
        pattern="^[a-z0-9-]+$"
    )

# =============================================================================
# 응답 모델
# =============================================================================

class AgentResult(BaseModel):
    """개별 Agent 실행 결과"""
    success: bool
    response: Optional[str] = None
    error: Optional[str] = None
    agent_id: Optional[str] = None
    alias_id: Optional[str] = None
    execution_time: Optional[float] = None
    trace: Optional[Dict[str, Any]] = None

class AnalysisResponse(BaseModel):
    """NIST 보안 분석 응답 모델"""
    
    success: bool = Field(description="분석 성공 여부")
    
    data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="분석 결과 데이터 (성공 시)"
    )
    
    error: Optional[str] = Field(
        default=None,
        description="에러 메시지 (실패 시)"
    )
    
    execution_time: Optional[float] = Field(
        default=None,
        description="전체 실행 시간 (초)"
    )

class DetailedAnalysisResponse(BaseModel):
    """상세한 NIST 보안 분석 응답 모델"""
    
    success: bool
    
    # 메타데이터
    workflow_id: Optional[str] = None
    current_step: Optional[str] = None
    execution_time: Optional[float] = None
    execution_log: Optional[List[str]] = None
    
    # 각 단계별 결과
    identify_results: Optional[Dict[str, AgentResult]] = None
    protect_results: Optional[Dict[str, AgentResult]] = None
    detect_results: Optional[Dict[str, AgentResult]] = None
    respond_result: Optional[AgentResult] = None
    recover_result: Optional[AgentResult] = None
    summary_result: Optional[AgentResult] = None
    
    # 에러 정보
    error: Optional[str] = None

# =============================================================================
# 비동기 작업 모델
# =============================================================================

class TaskStartResponse(BaseModel):
    """비동기 작업 시작 응답 모델"""
    task_id: str = Field(description="작업 고유 ID")
    status: str = Field(default="started", description="작업 상태")
    message: str = Field(description="상태 메시지")
    timestamp: str = Field(description="작업 시작 시간")

class TaskStatusResponse(BaseModel):
    """작업 상태 조회 응답 모델"""
    task_id: str = Field(description="작업 고유 ID")
    status: str = Field(description="작업 상태 (started, processing, completed, failed)")
    message: str = Field(description="상태 메시지")
    timestamp: str = Field(description="상태 확인 시간")
    progress: Optional[str] = Field(default=None, description="진행률 정보")

# =============================================================================
# 헬스체크 모델 (향후 확장용)
# =============================================================================

class HealthResponse(BaseModel):
    """헬스체크 응답 모델"""
    status: str = "healthy"
    timestamp: str
    version: str = "1.0.0"
