# =============================================================================
# AWS NIST 사이버보안 워크플로우 (핵심 기능만)
# =============================================================================
# 
# 이 파일은 AWS Bedrock Agent를 활용한 NIST 사이버보안 프레임워크 구현체입니다.
# 
# 주요 기능:
# - NIST 5단계 (IDENTIFY → PROTECT → DETECT → RESPOND → RECOVER) + SUMMARY
# - 병렬 처리를 통한 성능 최적화
# - Bedrock Agent 기본 Trace 수집
#
# 버전: 3.0 (핵심 기능만)
# 최종 수정일: 2024-06-25
# =============================================================================

# =============================================================================
# 1. 라이브러리 임포트 및 기본 설정
# =============================================================================

import boto3
import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, TypedDict, List, Any, Optional
from langgraph.graph import StateGraph, END
from botocore.config import Config
from botocore.exceptions import ClientError
# =============================================================================
# 2. 환경 설정 및 로그 시스템
# =============================================================================

# ECS Task Role을 사용하여 AWS 자격증명 자동 처리
# 고객의 AWS 자격증명은 API 요청으로 받음

# 전역 로그 저장소 (task_id별 로그 저장)
task_logs = {}
current_task_id = None

def log_print(*args, **kwargs):
    """콘솔 출력과 동시에 로그 저장"""
    # 기존 콘솔 출력
    print(*args, **kwargs)
    
    # 로그 저장 (current_task_id가 설정된 경우에만)
    if current_task_id:
        if current_task_id not in task_logs:
            task_logs[current_task_id] = []
        
        # 출력 내용을 문자열로 변환하여 저장
        log_message = ' '.join(map(str, args))
        task_logs[current_task_id].append(log_message)

def set_current_task_id(task_id):
    """현재 작업 ID 설정"""
    global current_task_id
    current_task_id = task_id

def get_task_logs(task_id):
    """특정 task_id의 로그 반환"""
    return task_logs.get(task_id, [])

# =============================================================================
# 3. 데이터 모델 정의
# =============================================================================

class NISTState(TypedDict):
    """NIST 워크플로우 상태 정의"""
    
    # 고객 자격증명
    customer_access_key: str
    customer_secret_key: str

    # 입력 데이터
    input_data: Dict[str, Any]

    # 각 단계별 결과 (IDENTIFY 단계 - 4개 에이전트)
    identify_01_result: Dict[str, Any]      # 보안 상태 식별
    computing_result: Dict[str, Any]        # 컴퓨팅 서비스 보안
    storage_result: Dict[str, Any]          # 스토리지 서비스 보안
    db_result: Dict[str, Any]               # 데이터베이스 서비스 보안
    
    # PROTECT 단계 결과 (2개 에이전트 병렬)
    protect_01_result: Dict[str, Any]       # 보안 보호 조치 1
    protect_02_result: Dict[str, Any]       # 보안 보호 조치 2
    
    # DETECT 단계 결과 (2개 에이전트 병렬)
    detect_01_result: Dict[str, Any]        # 위협 탐지 1
    detect_02_result: Dict[str, Any]        # 위협 탐지 2
    
    # 나머지 단계 결과 (순차 실행)
    respond_result: Dict[str, Any]          # 보안 사고 대응
    recover_result: Dict[str, Any]          # 복구 작업
    summary_result: Dict[str, Any]          # 최종 보고서

    # 메타데이터
    workflow_id: str                        # 워크플로우 고유 ID
    current_step: str                       # 현재 실행 단계
    execution_log: List[str]                # 실행 로그
# =============================================================================
# 4. Trace 파싱 및 출력 함수들
# =============================================================================

def parse_trace_event(trace_event):
    """TracePart 이벤트 파싱"""
    base_info = {
        'event_time': trace_event.get('eventTime'),
        'trace_id': None,
        'agent_name': None,
        'trace_type': 'Unknown'
    }
    
    trace_data = trace_event.get('trace', {})
    
    if 'preProcessingTrace' in trace_data:
        return parse_preprocessing_trace(base_info, trace_data['preProcessingTrace'])
    elif 'orchestrationTrace' in trace_data:
        return parse_orchestration_trace(base_info, trace_data['orchestrationTrace'])
    elif 'postProcessingTrace' in trace_data:
        return parse_postprocessing_trace(base_info, trace_data['postProcessingTrace'])
    elif 'failureTrace' in trace_data:
        return parse_failure_trace(base_info, trace_data['failureTrace'])
    
    return base_info

def parse_preprocessing_trace(base_info, preprocessing_trace):
    """PreProcessingTrace 완전 파싱 - 토큰 사용량 포함"""
    parsed_info = base_info.copy()
    parsed_info['trace_type'] = 'PreProcessing'
    
    # ModelInvocationInput 파싱
    if 'modelInvocationInput' in preprocessing_trace:
        model_input = preprocessing_trace['modelInvocationInput']
        parsed_info.update({
            'trace_id': model_input.get('traceId'),
            'prompt_text': model_input.get('text'),
            'foundation_model': model_input.get('foundationModel'),
            'prompt_creation_mode': model_input.get('promptCreationMode'),
            'parser_mode': model_input.get('parserMode')
        })
        
        # InferenceConfiguration 파싱
        if 'inferenceConfiguration' in model_input:
            inference_config = model_input['inferenceConfiguration']
            parsed_info.update({
                'temperature': inference_config.get('temperature'),
                'top_k': inference_config.get('topK'),
                'top_p': inference_config.get('topP'),
                'max_length': inference_config.get('maximumLength'),
                'stop_sequences': inference_config.get('stopSequences')
            })
    
    # ModelInvocationOutput 파싱 (토큰 사용량 포함!)
    if 'modelInvocationOutput' in preprocessing_trace:
        model_output = preprocessing_trace['modelInvocationOutput']
        parsed_info.update({
            'output_trace_id': model_output.get('traceId')
        })
        
        # 메타데이터 및 토큰 사용량 파싱
        if 'metadata' in model_output:
            metadata = model_output['metadata']
            parsed_info.update({
                'start_time': metadata.get('startTime'),
                'end_time': metadata.get('endTime'),
                'total_time_ms': metadata.get('totalTimeMs'),
                'operation_total_time_ms': metadata.get('operationTotalTimeMs')
            })
            
            # 토큰 사용량 파싱 (핵심!)
            if 'usage' in metadata:
                usage = metadata['usage']
                parsed_info.update({
                    'input_tokens': usage.get('inputTokens', 0),
                    'output_tokens': usage.get('outputTokens', 0),
                    'total_tokens': (usage.get('inputTokens', 0) + usage.get('outputTokens', 0))
                })
        
        # ParsedResponse 파싱
        if 'parsedResponse' in model_output:
            parsed_response = model_output['parsedResponse']
            parsed_info.update({
                'is_valid': parsed_response.get('isValid'),
                'parsed_rationale': parsed_response.get('rationale')
            })
        
        # RawResponse 파싱
        if 'rawResponse' in model_output:
            raw_response = model_output['rawResponse']
            parsed_info['raw_response'] = raw_response.get('content', '')
    
    return parsed_info

def parse_orchestration_trace(base_info, orchestration_trace):
    """OrchestrationTrace 완전 파싱 - 토큰 사용량 포함"""
    parsed_info = base_info.copy()
    parsed_info['trace_type'] = 'Orchestration'
    
    # ModelInvocationInput 파싱
    if 'modelInvocationInput' in orchestration_trace:
        model_input = orchestration_trace['modelInvocationInput']
        parsed_info.update({
            'trace_id': model_input.get('traceId'),
            'prompt_text': model_input.get('text'),
            'foundation_model': model_input.get('foundationModel'),
            'prompt_creation_mode': model_input.get('promptCreationMode'),
            'parser_mode': model_input.get('parserMode')
        })
        
        # InferenceConfiguration 파싱
        if 'inferenceConfiguration' in model_input:
            inference_config = model_input['inferenceConfiguration']
            parsed_info.update({
                'temperature': inference_config.get('temperature'),
                'top_k': inference_config.get('topK'),
                'top_p': inference_config.get('topP'),
                'max_length': inference_config.get('maximumLength')
            })
    
    # ModelInvocationOutput 파싱 (토큰 사용량 포함!)
    if 'modelInvocationOutput' in orchestration_trace:
        model_output = orchestration_trace['modelInvocationOutput']
        parsed_info.update({
            'output_trace_id': model_output.get('traceId')
        })
        
        # 메타데이터 및 토큰 사용량 파싱
        if 'metadata' in model_output:
            metadata = model_output['metadata']
            parsed_info.update({
                'start_time': metadata.get('startTime'),
                'end_time': metadata.get('endTime'),
                'total_time_ms': metadata.get('totalTimeMs'),
                'operation_total_time_ms': metadata.get('operationTotalTimeMs')
            })
            
            # 토큰 사용량 파싱 (핵심!)
            if 'usage' in metadata:
                usage = metadata['usage']
                parsed_info.update({
                    'input_tokens': usage.get('inputTokens', 0),
                    'output_tokens': usage.get('outputTokens', 0),
                    'total_tokens': (usage.get('inputTokens', 0) + usage.get('outputTokens', 0))
                })
        
        # 추론 내용 파싱
        if 'reasoningContent' in model_output:
            reasoning = model_output['reasoningContent']
            if 'text' in reasoning:
                parsed_info['reasoning_text'] = reasoning['text']
        
        # RawResponse 파싱
        if 'rawResponse' in model_output:
            raw_response = model_output['rawResponse']
            parsed_info['raw_response'] = raw_response.get('content', '')
    
    # Rationale 파싱 (Agent 추론 과정 - 핵심!)
    if 'rationale' in orchestration_trace:
        rationale = orchestration_trace['rationale']
        parsed_info.update({
            'rationale': rationale.get('text', ''),
            'rationale_trace_id': rationale.get('traceId')
        })
    
    # InvocationInput 파싱 (액션 그룹 호출)
    if 'invocationInput' in orchestration_trace:
        invocation_input = orchestration_trace['invocationInput']
        parsed_info.update({
            'invocation_trace_id': invocation_input.get('traceId'),
            'invocation_type': invocation_input.get('invocationType')
        })
        
        # ActionGroup 정보 파싱
        if 'actionGroupInvocationInput' in invocation_input:
            action_group = invocation_input['actionGroupInvocationInput']
            parsed_info.update({
                'action_group_name': action_group.get('actionGroupName'),
                'function': action_group.get('function'),
                'api_path': action_group.get('apiPath'),
                'execution_type': action_group.get('executionType'),
                'verb': action_group.get('verb'),
                'invocation_id': action_group.get('invocationId')
            })
            
            # 파라미터 파싱
            if 'parameters' in action_group:
                params = {}
                for param in action_group['parameters']:
                    params[param.get('name', '')] = param.get('value', '')
                parsed_info['parameters'] = params
            
            # 요청 본문 파싱
            if 'requestBody' in action_group:
                parsed_info['request_body'] = action_group['requestBody']
        
        # KnowledgeBase 정보 파싱
        if 'knowledgeBaseLookupInput' in invocation_input:
            kb_input = invocation_input['knowledgeBaseLookupInput']
            parsed_info.update({
                'knowledge_base_id': kb_input.get('knowledgeBaseId'),
                'kb_query_text': kb_input.get('text')
            })
    
    # Observation 파싱 (실행 결과)
    if 'observation' in orchestration_trace:
        observation = orchestration_trace['observation']
        parsed_info.update({
            'observation_type': observation.get('type'),
            'observation_trace_id': observation.get('traceId')
        })
        
        # ActionGroup 실행 결과
        if 'actionGroupInvocationOutput' in observation:
            output = observation['actionGroupInvocationOutput']
            parsed_info['action_group_output'] = output.get('text', '')
        
        # KnowledgeBase 조회 결과
        if 'knowledgeBaseLookupOutput' in observation:
            kb_output = observation['knowledgeBaseLookupOutput']
            parsed_info['kb_retrieved_references'] = len(kb_output.get('retrievedReferences', []))
        
        # FinalResponse 파싱
        if 'finalResponse' in observation:
            final_response = observation['finalResponse']
            parsed_info['final_response'] = final_response.get('text', '')
    
    return parsed_info

def parse_postprocessing_trace(base_info, postprocessing_trace):
    """PostProcessingTrace 완전 파싱 - 토큰 사용량 포함"""
    parsed_info = base_info.copy()
    parsed_info['trace_type'] = 'PostProcessing'
    
    # ModelInvocationInput 파싱
    if 'modelInvocationInput' in postprocessing_trace:
        model_input = postprocessing_trace['modelInvocationInput']
        parsed_info.update({
            'trace_id': model_input.get('traceId'),
            'prompt_text': model_input.get('text'),
            'foundation_model': model_input.get('foundationModel'),
            'prompt_creation_mode': model_input.get('promptCreationMode'),
            'parser_mode': model_input.get('parserMode')
        })
        
        # InferenceConfiguration 파싱
        if 'inferenceConfiguration' in model_input:
            inference_config = model_input['inferenceConfiguration']
            parsed_info.update({
                'temperature': inference_config.get('temperature'),
                'top_k': inference_config.get('topK'),
                'top_p': inference_config.get('topP'),
                'max_length': inference_config.get('maximumLength')
            })
    
    # ModelInvocationOutput 파싱 (토큰 사용량 포함!)
    if 'modelInvocationOutput' in postprocessing_trace:
        model_output = postprocessing_trace['modelInvocationOutput']
        parsed_info.update({
            'output_trace_id': model_output.get('traceId')
        })
        
        # 메타데이터 및 토큰 사용량 파싱
        if 'metadata' in model_output:
            metadata = model_output['metadata']
            parsed_info.update({
                'start_time': metadata.get('startTime'),
                'end_time': metadata.get('endTime'),
                'total_time_ms': metadata.get('totalTimeMs'),
                'operation_total_time_ms': metadata.get('operationTotalTimeMs')
            })
            
            # 토큰 사용량 파싱 (핵심!)
            if 'usage' in metadata:
                usage = metadata['usage']
                parsed_info.update({
                    'input_tokens': usage.get('inputTokens', 0),
                    'output_tokens': usage.get('outputTokens', 0),
                    'total_tokens': (usage.get('inputTokens', 0) + usage.get('outputTokens', 0))
                })
        
        # ParsedResponse 파싱
        if 'parsedResponse' in model_output:
            parsed_response = model_output['parsedResponse']
            parsed_info.update({
                'is_valid': parsed_response.get('isValid'),
                'parsed_rationale': parsed_response.get('rationale')
            })
        
        # RawResponse 파싱
        if 'rawResponse' in model_output:
            raw_response = model_output['rawResponse']
            parsed_info['raw_response'] = raw_response.get('content', '')
    
    return parsed_info

def parse_failure_trace(base_info, failure_trace):
    """FailureTrace 파싱"""
    parsed_info = base_info.copy()
    parsed_info['trace_type'] = 'Failure'
    
    parsed_info.update({
        'trace_id': failure_trace.get('traceId'),
        'failure_reason': failure_trace.get('failureReason'),
        'failure_code': failure_trace.get('failureCode')
    })
    
    return parsed_info

def print_single_trace_info(agent_name, trace, trace_number):
    """개별 Trace 정보를 즉시 출력"""
    if trace_number == 1:
        log_print(f"\n{'='*80}")
        log_print(f"🤖 {agent_name} - 실시간 AgentOps Trace")
        log_print(f"{'='*80}")
    
    log_print(f"\n--- Trace {trace_number}: {trace.get('trace_type', 'Unknown')} ---")
    
    # 기본 정보
    if trace.get('event_time'):
        log_print(f"⏰ 시간: {trace['event_time']}")
    if trace.get('trace_id'):
        log_print(f"🔍 Trace ID: {trace['trace_id']}")
    
    # 🧠 Agent 추론 과정 (핵심 AgentOps 정보!)
    if trace.get('rationale'):
        rationale_text = trace['rationale']
        if len(rationale_text) > 300:
            rationale_preview = rationale_text[:300] + "..."
        else:
            rationale_preview = rationale_text
        log_print(f"🧠 Agent 추론 과정: {rationale_preview}")
    
    # 🎯 토큰 사용량 (핵심 AgentOps 메트릭!)
    input_tokens = trace.get('input_tokens', 0)
    output_tokens = trace.get('output_tokens', 0)
    if input_tokens > 0 or output_tokens > 0:
        total_tokens = input_tokens + output_tokens
        log_print(f"🎯 토큰 사용량: 입력 {input_tokens:,}개, 출력 {output_tokens:,}개, 총 {total_tokens:,}개")
    
    # ⚡ 처리 시간 (성능 메트릭)
    if trace.get('total_time_ms'):
        processing_time = trace['total_time_ms']
        log_print(f"⚡ 처리 시간: {processing_time:,}ms ({processing_time/1000:.2f}초)")
    
    # 🔧 Lambda 함수 및 액션 그룹 정보 (핵심 AgentOps!)
    if trace.get('action_group_name'):
        log_print(f"🔧 액션 그룹: {trace['action_group_name']}")
        
        if trace.get('function'):
            log_print(f"⚙️ Lambda 함수: {trace['function']}")
        
        if trace.get('execution_type'):
            log_print(f"🏃 실행 타입: {trace['execution_type']}")
        
        if trace.get('api_path'):
            verb = trace.get('verb', 'GET')
            log_print(f"🌐 API 호출: {verb} {trace['api_path']}")
        
        if trace.get('parameters'):
            log_print(f"📋 파라미터: {trace['parameters']}")
        
        if trace.get('invocation_id'):
            log_print(f"🆔 호출 ID: {trace['invocation_id']}")
    
    # ✅ 실행 결과
    if trace.get('action_group_output'):
        output_text = trace['action_group_output']
        try:
            data = json.loads(output_text)
            function_name = data.get('function', 'Unknown')
            
            # 서비스별 리소스 개수 추출
            services = data.get('services_discovered', {})
            service_counts = []
            for service, info in services.items():
                count = info.get('resource_count', 0)
                service_counts.append(f"{service.upper()}({count})")
            
            log_print(f"✅ 실행 결과: {function_name} 완료")
            log_print(f"   📊 발견: {', '.join(service_counts)}")
            
            # 전체 요약 정보
            summary = data.get('collection_summary', {})
            total_services = summary.get('total_services_checked', 0)
            services_with_resources = summary.get('services_with_resources', 0)
            log_print(f"   🛡️ 요약: {total_services}개 서비스 중 {services_with_resources}개에서 리소스 발견")
            
        except:
            # JSON 파싱 실패 시 기존 방식
            if len(output_text) > 200:
                output_preview = output_text[:200] + "..."
            else:
                output_preview = output_text
            log_print(f"✅ 실행 결과: {output_preview}")
    
    # ❌ 실패 정보
    if trace.get('failure_reason'):
        log_print(f"❌ 실패 원인: {trace['failure_reason']}")
        if trace.get('failure_code'):
            log_print(f"🚨 실패 코드: {trace['failure_code']}")
    
    log_print(f"{'-'*60}")

def print_trace_summary(agent_name, trace_data_list):
    """전체 Trace 요약 정보 출력"""
    if not trace_data_list:
        return
    
    total_input_tokens = 0
    total_output_tokens = 0
    total_processing_time = 0
    
    for trace in trace_data_list:
        input_tokens = trace.get('input_tokens', 0)
        output_tokens = trace.get('output_tokens', 0)
        total_input_tokens += input_tokens
        total_output_tokens += output_tokens
        
        if trace.get('total_time_ms'):
            total_processing_time += trace['total_time_ms']
    
    # 📊 전체 요약 통계
    log_print(f"\n📊 {agent_name} - 전체 AgentOps 요약:")
    log_print(f"   🎯 총 토큰 사용량: 입력 {total_input_tokens:,}개, 출력 {total_output_tokens:,}개")
    log_print(f"   ⚡ 총 처리 시간: {total_processing_time:,}ms ({total_processing_time/1000:.2f}초)")
    log_print(f"   📈 Trace 단계 수: {len(trace_data_list)}개")
    log_print(f"{'='*80}\n")

def print_trace_info(agent_name, trace_data_list):
    """완전한 AgentOps Trace 정보를 콘솔에 출력"""
    if not trace_data_list:
        log_print(f"\n{'='*80}")
        log_print(f"🤖 {agent_name} - Trace 정보 없음")
        log_print(f"⚠️ Trace가 비어있습니다. enableTrace=True 설정을 확인하세요.")
        log_print(f"{'='*80}\n")
        return
    
    log_print(f"\n{'='*80}")
    log_print(f"🤖 {agent_name} - 완전한 AgentOps Trace 정보")
    log_print(f"{'='*80}")
    
    total_input_tokens = 0
    total_output_tokens = 0
    total_processing_time = 0
    
    for i, trace in enumerate(trace_data_list, 1):
        log_print(f"\n--- Trace {i}: {trace.get('trace_type', 'Unknown')} ---")
        
        # 기본 정보
        if trace.get('event_time'):
            log_print(f"⏰ 시간: {trace['event_time']}")
        if trace.get('trace_id'):
            log_print(f"🔍 Trace ID: {trace['trace_id']}")
        if trace.get('agent_id'):
            log_print(f"🤖 Agent ID: {trace['agent_id']}")
        
        # 🧠 Agent 추론 과정 (핵심 AgentOps 정보!)
        if trace.get('rationale'):
            rationale_text = trace['rationale']
            if len(rationale_text) > 300:
                rationale_preview = rationale_text[:300] + "..."
            else:
                rationale_preview = rationale_text
            log_print(f"🧠 Agent 추론 과정: {rationale_preview}")
        
        # 🎯 토큰 사용량 (핵심 AgentOps 메트릭!)
        input_tokens = trace.get('input_tokens', 0)
        output_tokens = trace.get('output_tokens', 0)
        if input_tokens > 0 or output_tokens > 0:
            total_tokens = input_tokens + output_tokens
            log_print(f"🎯 토큰 사용량: 입력 {input_tokens:,}개, 출력 {output_tokens:,}개, 총 {total_tokens:,}개")
            total_input_tokens += input_tokens
            total_output_tokens += output_tokens
        else:
            # 디버깅: 토큰 정보가 없는 경우 알림
            log_print(f"⚠️ 토큰 정보 없음 (Trace 타입: {trace.get('trace_type', 'Unknown')})")
        
        # ⚡ 처리 시간 (성능 메트릭)
        if trace.get('total_time_ms'):
            processing_time = trace['total_time_ms']
            log_print(f"⚡ 처리 시간: {processing_time:,}ms ({processing_time/1000:.2f}초)")
            total_processing_time += processing_time
        
        # 🔧 Lambda 함수 및 액션 그룹 정보 (핵심 AgentOps!)
        if trace.get('action_group_name'):
            log_print(f"🔧 액션 그룹: {trace['action_group_name']}")
            
            if trace.get('function'):
                log_print(f"⚙️ Lambda 함수: {trace['function']}")
            
            if trace.get('execution_type'):
                log_print(f"🏃 실행 타입: {trace['execution_type']}")
            
            if trace.get('api_path'):
                verb = trace.get('verb', 'GET')
                log_print(f"🌐 API 호출: {verb} {trace['api_path']}")
            
            if trace.get('parameters'):
                log_print(f"📋 파라미터: {trace['parameters']}")
            
            if trace.get('invocation_id'):
                log_print(f"🆔 호출 ID: {trace['invocation_id']}")
        
        # 📝 프롬프트 정보
        if trace.get('prompt_text'):
            prompt_text = trace['prompt_text']
            if len(prompt_text) > 200:
                prompt_preview = prompt_text[:200] + "..."
            else:
                prompt_preview = prompt_text
            log_print(f"📝 프롬프트: {prompt_preview}")
        
        # ✅ 실행 결과
        if trace.get('action_group_output'):
            output_text = trace['action_group_output']
            try:
                data = json.loads(output_text)
                function_name = data.get('function', 'Unknown')
                
                # 서비스별 리소스 개수 추출
                services = data.get('services_discovered', {})
                service_counts = []
                for service, info in services.items():
                    count = info.get('resource_count', 0)
                    service_counts.append(f"{service.upper()}({count})")
                
                log_print(f"✅ 실행 결과: {function_name} 완료")
                log_print(f"   📊 발견: {', '.join(service_counts)}")
                
                # 전체 요약 정보
                summary = data.get('collection_summary', {})
                total_services = summary.get('total_services_checked', 0)
                services_with_resources = summary.get('services_with_resources', 0)
                log_print(f"   🛡️ 요약: {total_services}개 서비스 중 {services_with_resources}개에서 리소스 발견")
                
            except:
                # JSON 파싱 실패 시 기존 방식
                if len(output_text) > 200:
                    output_preview = output_text[:200] + "..."
                else:
                    output_preview = output_text
                log_print(f"✅ 실행 결과: {output_preview}")
        
        # 🗄️ 지식 베이스 정보
        if trace.get('knowledge_base_id'):
            log_print(f"🗄️ 지식 베이스: {trace['knowledge_base_id']}")
            if trace.get('kb_query_text'):
                log_print(f"🔍 KB 쿼리: {trace['kb_query_text']}")
            if trace.get('kb_retrieved_references'):
                log_print(f"📚 검색된 참조: {trace['kb_retrieved_references']}개")
        
        # ❌ 실패 정보
        if trace.get('failure_reason'):
            log_print(f"❌ 실패 원인: {trace['failure_reason']}")
            if trace.get('failure_code'):
                log_print(f"🚨 실패 코드: {trace['failure_code']}")
        
        # ⚙️ 모델 설정
        if trace.get('foundation_model'):
            log_print(f"🤖 Foundation Model: {trace['foundation_model']}")
        
        if trace.get('temperature') is not None:
            temp = trace.get('temperature')
            top_k = trace.get('top_k')
            top_p = trace.get('top_p')
            log_print(f"⚙️ 모델 파라미터: temp={temp}, topK={top_k}, topP={top_p}")
        
        # 🕐 시간 정보
        if trace.get('start_time') and trace.get('end_time'):
            log_print(f"🕐 시작: {trace['start_time']}")
            log_print(f"🕑 종료: {trace['end_time']}")
        
        log_print(f"{'-'*60}")
    
    # 📊 전체 요약 통계 (항상 표시)
    log_print(f"\n📊 전체 AgentOps 요약:")
    log_print(f"   🎯 총 토큰 사용량: 입력 {total_input_tokens:,}개, 출력 {total_output_tokens:,}개")
    log_print(f"   ⚡ 총 처리 시간: {total_processing_time:,}ms ({total_processing_time/1000:.2f}초)")
    log_print(f"   📈 Trace 단계 수: {len(trace_data_list)}개")
    
    log_print(f"{'='*80}\n")

# =============================================================================
# 5. AWS Bedrock Agent 호출 함수
# =============================================================================

def invoke_bedrock_agent_with_retry(
    agent_id: str,
    alias_id: str,
    input_text: str,
    customer_access_key: str,
    customer_secret_key: str,
    session_id: str = None,
    agent_name: str = None,
    max_retries: int = 3
) -> Dict[str, Any]:
    """
    AWS SDK 기본 재시도를 사용하는 Bedrock Agent 호출 함수
    AWS 권장 사항에 따른 단일 재시도 로직 구현
    
    Args:
        agent_id: Bedrock Agent ID
        alias_id: Agent 별칭 ID  
        input_text: 에이전트에 전달할 입력 텍스트
        customer_access_key: 고객의 AWS Access Key
        customer_secret_key: 고객의 AWS Secret Key
        session_id: 세션 ID (선택사항)
        agent_name: Agent 이름 (출력용, 선택사항)
        max_retries: 최대 재시도 횟수 (기본값: 3)
        
    Returns:
        에이전트 호출 결과 딕셔너리
    """
    # Agent 이름 설정
    if not agent_name:
        agent_name = f"Agent-{agent_id}"
    
    # AWS SDK 기본 재시도 사용 - 이중 재시도 제거
    return invoke_bedrock_agent(
        agent_id=agent_id,
        alias_id=alias_id,
        input_text=input_text,
        customer_access_key=customer_access_key,
        customer_secret_key=customer_secret_key,
        session_id=session_id,
        agent_name=agent_name
    )

def invoke_bedrock_agent(
    agent_id: str,
    alias_id: str,
    input_text: str,
    customer_access_key: str,
    customer_secret_key: str,
    session_id: str = None,
    agent_name: str = None
) -> Dict[str, Any]:
    """
    Bedrock Agent 호출 함수 (Trace 파싱 및 출력 포함)
    
    Args:
        agent_id: Bedrock Agent ID
        alias_id: Agent 별칭 ID  
        input_text: 에이전트에 전달할 입력 텍스트
        customer_access_key: 고객의 AWS Access Key
        customer_secret_key: 고객의 AWS Secret Key
        session_id: 세션 ID (선택사항)
        agent_name: Agent 이름 (출력용, 선택사항)
        
    Returns:
        에이전트 호출 결과 딕셔너리
    """
    # Agent 이름 설정
    if not agent_name:
        agent_name = f"Agent-{agent_id}"
    
    log_print(f"\n🚀 {agent_name} 실행 시작...")
    start_time = time.time()
    
    try:
        # AWS SDK 기본 재시도 설정 (권장사항)
        config = Config(
            read_timeout=600,      # 10분으로 증가
            connect_timeout=180,   # 3분으로 증가
            retries={'max_attempts': 3, 'mode': 'standard'}  # AWS 권장 재시도 설정
        )
        client = boto3.client(
            'bedrock-agent-runtime',
            region_name='us-east-1',
            config=config
        )

        # 세션 ID 생성 (없는 경우)
        if not session_id:
            session_id = f"nist_session_{int(time.time())}"

        # 현재 시간 생성
        current_time = datetime.utcnow().isoformat()

        # AWS SDK 기본 재시도 사용 - 커스텀 백오프 제거
        response = client.invoke_agent(
            agentId=agent_id,
            agentAliasId=alias_id,
            enableTrace=True,
            sessionId=session_id,
            inputText=input_text,
            sessionState={
                'sessionAttributes': {
                    'access_key': customer_access_key,
                    'secret_key': customer_secret_key,
                    'current_time': current_time,
                    'analysis_timestamp': current_time
                }
            }
        )

        # 응답 수집
        completion = ""
        trace_info = []
        parsed_traces = []

        # 스트리밍 응답 처리
        for event in response.get("completion", []):
            # 텍스트 청크 처리
            if 'chunk' in event:
                chunk = event["chunk"]
                if 'bytes' in chunk:
                    chunk_text = chunk["bytes"].decode('utf-8')
                    completion += chunk_text

            # Trace 이벤트 처리 및 파싱 - 실시간 출력
            if 'trace' in event:
                trace_info.append(event['trace'])
                # 실시간 trace 파싱 및 즉시 출력
                try:
                    parsed_trace = parse_trace_event(event['trace'])
                    parsed_traces.append(parsed_trace)
                    # 개별 trace를 즉시 출력
                    print_single_trace_info(agent_name, parsed_trace, len(parsed_traces))
                except Exception as e:
                    log_print(f"⚠️ Trace 파싱 오류: {str(e)}")
                    # 기본 정보라도 저장
                    parsed_traces.append({
                        'trace_type': 'ParseError',
                        'error': str(e),
                        'raw_trace': event['trace']
                    })

        # 실행 시간 계산
        end_time = time.time()
        execution_time = end_time - start_time

        # 전체 요약만 출력
        print_trace_summary(agent_name, parsed_traces)
        
        # 실행 완료 메시지
        log_print(f"✅ {agent_name} 실행 완료 ({execution_time:.2f}초)")
        if completion:
            # 응답을 적절한 길이로 제한 (테이블과 핵심 요약만 표시)
            lines = completion.split('\n')
            filtered_lines = []
            
            for line in lines:
                filtered_lines.append(line)
                # "---" 구분선이 나오면 그 이후는 생략 (상세 설명 부분)
                if line.strip().startswith('---') and len(filtered_lines) > 10:
                    break
                # 또는 1000자 제한
                if len('\n'.join(filtered_lines)) > 1000:
                    break
            
            filtered_response = '\n'.join(filtered_lines)
            
            log_print(f"📄 핵심 응답:")
            log_print(filtered_response)

        return {
            "success": True,
            "response": completion,
            "trace": trace_info,
            "parsed_traces": parsed_traces,
            "session_id": session_id,
            "agent_id": agent_id,
            "alias_id": alias_id,
            "timestamp": current_time,
            "execution_time": execution_time
        }

    except ClientError as e:
        error_msg = f"AWS 클라이언트 오류: {str(e)}"
        log_print(f"❌ {agent_name} 실행 실패: {error_msg}")
        return {
            "success": False,
            "error": error_msg,
            "response": None,
            "agent_id": agent_id,
            "alias_id": alias_id
        }
    except Exception as e:
        error_msg = f"에이전트 호출 실패: {str(e)}"
        log_print(f"❌ {agent_name} 실행 실패: {error_msg}")
        return {
            "success": False,
            "error": error_msg,
            "response": None,
            "agent_id": agent_id,
            "alias_id": alias_id
        }
# =============================================================================
# 5. NIST 워크플로우 단계별 함수들
# =============================================================================

def identify_parallel_step(state: NISTState) -> Dict[str, Any]:
    """IDENTIFY 단계 - 순차적 병렬 실행 (2단계)"""

    log_print(f"\n🔍 IDENTIFY 단계 시작 - 4개 Agent 순차적 병렬 실행")
    log_print(f"{'='*80}")

    # 1단계: 병렬 구조 1 (identify-01 + computing-agent)
    def call_identify_01():
        return invoke_bedrock_agent_with_retry(
            agent_id="6HPTDDKWO0",
            alias_id="S9P51GCNC7",
            input_text=f"{state['input_data'].get('target_region', 'us-east-1')} 리전에서 보안 상태를 조회하고 식별해주세요.",
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="IDENTIFY-01 (보안 상태 식별)"
        )

    def call_computing():
        return invoke_bedrock_agent_with_retry(
            agent_id="4FCDUY5BYV",
            alias_id="KEF7HM3CMD",
            input_text=f"{state['input_data'].get('target_region', 'us-east-1')} 리전에서 컴퓨팅 서비스 보안 상태를 조회하고 식별해주세요.",
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="COMPUTING (컴퓨팅 서비스 보안)"
        )

    # 병렬 구조 1 실행
    log_print(f"\n📋 1단계: IDENTIFY-01 + COMPUTING 병렬 실행")
    start_time_1 = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_identify_01 = executor.submit(call_identify_01)
        future_computing = executor.submit(call_computing)
        identify_01_result = future_identify_01.result()
        computing_result = future_computing.result()
    end_time_1 = time.time()
    parallel_time_1 = end_time_1 - start_time_1

    # 2단계: 병렬 구조 2 (storage-agent + db-agent)
    def call_storage():
        return invoke_bedrock_agent_with_retry(
            agent_id="Z3UMWPXNXA",
            alias_id="5SKTPG00T0",
            input_text=f"{state['input_data'].get('target_region', 'us-east-1')} 리전에서 스토리지 서비스 보안 상태를 조회하고 식별해주세요.",
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="STORAGE (스토리지 서비스 보안)"
        )

    def call_db():
        return invoke_bedrock_agent_with_retry(
            agent_id="8RAXHMZTSZ",
            alias_id="BQCVA1QWIP",
            input_text=f"{state['input_data'].get('target_region', 'us-east-1')} 리전에서 데이터베이스 서비스 보안 상태를 조회하고 식별해주세요.",
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="DATABASE (데이터베이스 서비스 보안)"
        )

    # 병렬 구조 2 실행
    log_print(f"\n📋 2단계: STORAGE + DATABASE 병렬 실행")
    start_time_2 = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_storage = executor.submit(call_storage)
        future_db = executor.submit(call_db)
        storage_result = future_storage.result()
        db_result = future_db.result()
    end_time_2 = time.time()
    parallel_time_2 = end_time_2 - start_time_2

    total_time = parallel_time_1 + parallel_time_2
    log_entry = f"IDENTIFY 완료 ({total_time:.2f}초) - 구조1({parallel_time_1:.2f}초): identify-01({identify_01_result['success']}), computing({computing_result['success']}) | 구조2({parallel_time_2:.2f}초): storage({storage_result['success']}), db({db_result['success']})"

    log_print(f"\n🎯 IDENTIFY 단계 완료!")
    log_print(f"⏱️  총 실행 시간: {total_time:.2f}초")
    log_print(f"📊 성공률: IDENTIFY-01({identify_01_result['success']}), COMPUTING({computing_result['success']}), STORAGE({storage_result['success']}), DATABASE({db_result['success']})")
    log_print(f"{'='*80}")

    return {
        "identify_01_result": identify_01_result,
        "computing_result": computing_result,
        "storage_result": storage_result,
        "db_result": db_result,
        "current_step": "PROTECT",
        "execution_log": state["execution_log"] + [log_entry]
    }


def protect_parallel_step(state: NISTState) -> Dict[str, Any]:
    """PROTECT 단계 - 병렬 실행"""
    
    log_print(f"\n🛡️ PROTECT 단계 시작 - 2개 Agent 병렬 실행")
    log_print(f"{'='*80}")
    
    def call_protect_01():
        identify_summary = {
            "identify_01": {
                "success": state['identify_01_result'].get('success', False),
                "response": state['identify_01_result'].get('response', ''),
                "agent_id": state['identify_01_result'].get('agent_id', '')
            },
            "computing": {
                "success": state['computing_result'].get('success', False),
                "response": state['computing_result'].get('response', ''),
                "agent_id": state['computing_result'].get('agent_id', '')
            },
            "storage": {
                "success": state['storage_result'].get('success', False),
                "response": state['storage_result'].get('response', ''),
                "agent_id": state['storage_result'].get('agent_id', '')
            },
            "db": {
                "success": state['db_result'].get('success', False),
                "response": state['db_result'].get('response', ''),
                "agent_id": state['db_result'].get('agent_id', '')
            }
        }
        return invoke_bedrock_agent_with_retry(
            agent_id="IOH6C3FYNA",
            alias_id="KNWPRKMGU9",
            input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전에서 보안 보호 조치 상태를 조회해주세요.

이전 IDENTIFY 단계에서 다음과 같은 보안 상태 식별이 완료되었습니다:
- IDENTIFY-01 결과: {identify_summary['identify_01']['response']}
- COMPUTING 결과: {identify_summary['computing']['response']}
- STORAGE 결과: {identify_summary['storage']['response']}
- DB 결과: {identify_summary['db']['response']}

위 식별 결과를 참고하여 현재 환경의 보안 보호 조치 상태를 분석해주세요.
            """,
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="PROTECT-01 (보안 보호 조치 1)"
        )

    def call_protect_02():
        identify_summary = {
            "identify_01": {
                "success": state['identify_01_result'].get('success', False),
                "response": state['identify_01_result'].get('response', ''),
                "agent_id": state['identify_01_result'].get('agent_id', '')
            },
            "computing": {
                "success": state['computing_result'].get('success', False),
                "response": state['computing_result'].get('response', ''),
                "agent_id": state['computing_result'].get('agent_id', '')
            },
            "storage": {
                "success": state['storage_result'].get('success', False),
                "response": state['storage_result'].get('response', ''),
                "agent_id": state['storage_result'].get('agent_id', '')
            },
            "db": {
                "success": state['db_result'].get('success', False),
                "response": state['db_result'].get('response', ''),
                "agent_id": state['db_result'].get('agent_id', '')
            }
        }
        return invoke_bedrock_agent_with_retry(
            agent_id="BLGNHSAGGQ",
            alias_id="PKSWQLSLJB",
            input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전에서 보안 보호 조치 상태를 조회해주세요.

이전 IDENTIFY 단계에서 다음과 같은 보안 상태 식별이 완료되었습니다:
- IDENTIFY-01 결과: {identify_summary['identify_01']['response']}
- COMPUTING 결과: {identify_summary['computing']['response']}
- STORAGE 결과: {identify_summary['storage']['response']}
- DB 결과: {identify_summary['db']['response']}

위 식별 결과를 참고하여 현재 환경의 추가 보안 보호 조치 상태를 분석해주세요.
            """,
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="PROTECT-02 (보안 보호 조치 2)"
        )

    # 병렬 실행
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_01 = executor.submit(call_protect_01)
        future_02 = executor.submit(call_protect_02)
        protect_01_result = future_01.result()
        protect_02_result = future_02.result()
    end_time = time.time()
    parallel_time = end_time - start_time

    log_entry = f"PROTECT 완료 ({parallel_time:.2f}초) - PROTECT-01: {protect_01_result['success']}, PROTECT-02: {protect_02_result['success']}"

    log_print(f"\n🎯 PROTECT 단계 완료!")
    log_print(f"⏱️  총 실행 시간: {parallel_time:.2f}초")
    log_print(f"📊 성공률: PROTECT-01({protect_01_result['success']}), PROTECT-02({protect_02_result['success']})")
    log_print(f"{'='*80}")

    return {
        "protect_01_result": protect_01_result,
        "protect_02_result": protect_02_result,
        "current_step": "DETECT",
        "execution_log": state["execution_log"] + [log_entry]
    }
def detect_parallel_step(state: NISTState) -> Dict[str, Any]:
    """DETECT 단계 - 병렬 실행"""
    
    log_print(f"\n🔍 DETECT 단계 시작 - 2개 Agent 병렬 실행")
    log_print(f"{'='*80}")
    
    def call_detect_01():
        protect_summary = {
            "protect_01": {
                "success": state['protect_01_result'].get('success', False),
                "response": state['protect_01_result'].get('response', ''),
                "agent_id": state['protect_01_result'].get('agent_id', '')
            },
            "protect_02": {
                "success": state['protect_02_result'].get('success', False),
                "response": state['protect_02_result'].get('response', ''),
                "agent_id": state['protect_02_result'].get('agent_id', '')
            }
        }
        return invoke_bedrock_agent_with_retry(
            agent_id="HBD7XJ1ZWB",
            alias_id="FRE24DDVAP",
            input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전에서 위협을 조회하고 탐지해주세요.

이전 PROTECT 단계에서 다음과 같은 보호 조치 분석이 완료되었습니다:
- PROTECT-01 결과: {protect_summary['protect_01']['response']}
- PROTECT-02 결과: {protect_summary['protect_02']['response']}

위 보호 조치 상태를 참고하여 현재 환경에서 탐지 가능한 위협을 분석해주세요.
""",
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="DETECT-01 (위협 탐지 1)"
        )

    def call_detect_02():
        protect_summary = {
            "protect_01": {
                "success": state['protect_01_result'].get('success', False),
                "response": state['protect_01_result'].get('response', ''),
                "agent_id": state['protect_01_result'].get('agent_id', '')
            },
            "protect_02": {
                "success": state['protect_02_result'].get('success', False),
                "response": state['protect_02_result'].get('response', ''),
                "agent_id": state['protect_02_result'].get('agent_id', '')
            }
        }
        return invoke_bedrock_agent_with_retry(
            agent_id="XTBZGQCOOQ",
            alias_id="JTAZNRFTNB",
            input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전에서 위협을 조회하고 탐지해주세요.

이전 PROTECT 단계에서 다음과 같은 보호 조치 분석이 완료되었습니다:
- PROTECT-01 결과: {protect_summary['protect_01']['response']}
- PROTECT-02 결과: {protect_summary['protect_02']['response']}

위 보호 조치 상태를 참고하여 현재 환경에서 추가 위협을 탐지하고 분석해주세요.
            """,
            customer_access_key=state['customer_access_key'],
            customer_secret_key=state['customer_secret_key'],
            agent_name="DETECT-02 (위협 탐지 2)"
        )

    # 병렬 실행
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_01 = executor.submit(call_detect_01)
        future_02 = executor.submit(call_detect_02)
        detect_01_result = future_01.result()
        detect_02_result = future_02.result()
    end_time = time.time()
    parallel_time = end_time - start_time

    log_entry = f"DETECT 완료 ({parallel_time:.2f}초) - DETECT-01: {detect_01_result['success']}, DETECT-02: {detect_02_result['success']}"

    log_print(f"\n🎯 DETECT 단계 완료!")
    log_print(f"⏱️  총 실행 시간: {parallel_time:.2f}초")
    log_print(f"📊 성공률: DETECT-01({detect_01_result['success']}), DETECT-02({detect_02_result['success']})")
    log_print(f"{'='*80}")

    return {
        "detect_01_result": detect_01_result,
        "detect_02_result": detect_02_result,
        "current_step": "RESPOND",
        "execution_log": state["execution_log"] + [log_entry]
    }


def respond_step(state: NISTState) -> Dict[str, Any]:
    """RESPOND 단계 - 보안 사고 대응"""
    
    log_print(f"\n🚨 RESPOND 단계 시작 - 보안 사고 대응")
    log_print(f"{'='*80}")
    
    detect_summary = {
        "detect_01": {
            "success": state['detect_01_result'].get('success', False),
            "response": state['detect_01_result'].get('response', ''),
            "agent_id": state['detect_01_result'].get('agent_id', '')
        },
        "detect_02": {
            "success": state['detect_02_result'].get('success', False),
            "response": state['detect_02_result'].get('response', ''),
            "agent_id": state['detect_02_result'].get('agent_id', '')
        }
    }

    result = invoke_bedrock_agent_with_retry(
        agent_id="END1JT0P69",
        alias_id="A9QKQVK053",
        input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전에서 보안 사고 대응 상태를 조회해주세요.

이전 DETECT 단계에서 다음과 같은 위협 탐지 분석이 완료되었습니다:
- DETECT-01 결과: {detect_summary['detect_01']['response']}
- DETECT-02 결과: {detect_summary['detect_02']['response']}

위 위협 탐지 결과를 참고하여 현재 환경의 보안 사고 대응 상태를 분석해주세요.
        """,
        customer_access_key=state['customer_access_key'],
        customer_secret_key=state['customer_secret_key'],
        agent_name="RESPOND (보안 사고 대응)"
    )

    log_entry = f"RESPOND 완료 - 성공: {result['success']}"

    log_print(f"\n🎯 RESPOND 단계 완료!")
    log_print(f"📊 성공률: RESPOND({result['success']})")
    log_print(f"{'='*80}")

    return {
        "respond_result": result,
        "current_step": "RECOVER",
        "execution_log": state["execution_log"] + [log_entry]
    }


def recover_step(state: NISTState) -> Dict[str, Any]:
    """RECOVER 단계 - 복구 작업"""
    
    log_print(f"\n🔄 RECOVER 단계 시작 - 복구 작업")
    log_print(f"{'='*80}")
    
    respond_summary = {
        "success": state['respond_result'].get('success', False),
        "response": state['respond_result'].get('response', ''),
        "agent_id": state['respond_result'].get('agent_id', '')
    }

    result = invoke_bedrock_agent_with_retry(
        agent_id="UGBRHERHGJ",
        alias_id="QAMIWUUCO6",
        input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전에서 복구 상태를 조회해주세요.

이전 RESPOND 단계에서 다음과 같은 보안 사고 대응 분석이 완료되었습니다:
{respond_summary['response']}

위 대응 분석 결과를 참고하여 현재 환경의 복구 상태를 분석해주세요.
        """,
        customer_access_key=state['customer_access_key'],
        customer_secret_key=state['customer_secret_key'],
        agent_name="RECOVER (복구 작업)"
    )

    log_entry = f"RECOVER 완료 - 성공: {result['success']}"

    log_print(f"\n🎯 RECOVER 단계 완료!")
    log_print(f"📊 성공률: RECOVER({result['success']})")
    log_print(f"{'='*80}")

    return {
        "recover_result": result,
        "current_step": "SUMMARY",
        "execution_log": state["execution_log"] + [log_entry]
    }


def summary_step(state: NISTState) -> Dict[str, Any]:
    """SUMMARY 단계 - 전체 NIST 결과 종합 및 최종 보고서 작성"""
    
    log_print(f"\n📋 SUMMARY 단계 시작 - 최종 보고서 작성")
    log_print(f"{'='*80}")
    
    all_results = {
        "identify_01": {
            "success": state['identify_01_result'].get('success', False),
            "response": state['identify_01_result'].get('response', ''),
            "agent_id": state['identify_01_result'].get('agent_id', '')
        },
        "computing": {
            "success": state['computing_result'].get('success', False),
            "response": state['computing_result'].get('response', ''),
            "agent_id": state['computing_result'].get('agent_id', '')
        },
        "storage": {
            "success": state['storage_result'].get('success', False),
            "response": state['storage_result'].get('response', ''),
            "agent_id": state['storage_result'].get('agent_id', '')
        },
        "db": {
            "success": state['db_result'].get('success', False),
            "response": state['db_result'].get('response', ''),
            "agent_id": state['db_result'].get('agent_id', '')
        },
        "protect_01": {
            "success": state['protect_01_result'].get('success', False),
            "response": state['protect_01_result'].get('response', ''),
            "agent_id": state['protect_01_result'].get('agent_id', '')
        },
        "protect_02": {
            "success": state['protect_02_result'].get('success', False),
            "response": state['protect_02_result'].get('response', ''),
            "agent_id": state['protect_02_result'].get('agent_id', '')
        },
        "detect_01": {
            "success": state['detect_01_result'].get('success', False),
            "response": state['detect_01_result'].get('response', ''),
            "agent_id": state['detect_01_result'].get('agent_id', '')
        },
        "detect_02": {
            "success": state['detect_02_result'].get('success', False),
            "response": state['detect_02_result'].get('response', ''),
            "agent_id": state['detect_02_result'].get('agent_id', '')
        },
        "respond": {
            "success": state['respond_result'].get('success', False),
            "response": state['respond_result'].get('response', ''),
            "agent_id": state['respond_result'].get('agent_id', '')
        },
        "recover": {
            "success": state['recover_result'].get('success', False),
            "response": state['recover_result'].get('response', ''),
            "agent_id": state['recover_result'].get('agent_id', '')
        }
    }

    result = invoke_bedrock_agent_with_retry(
        agent_id="7T3LLAYMYH",
        alias_id="52ABUYS5OZ",
        input_text=f"""
{state['input_data'].get('target_region', 'us-east-1')} 리전의 AWS 보안 상태 종합 분석 결과를 바탕으로 최종 보고서를 작성해주세요.

NIST 사이버보안 프레임워크 분석 결과:
{json.dumps(all_results, ensure_ascii=False, indent=2)}

위 분석 결과를 종합하여 다음 형식으로 최종 보고서를 작성해주세요:

## 최종 결과
[전체 NIST 단계별 분석 결과를 종합한 고객 AWS 환경의 현재 보안 상태 요약]

## 솔루션
[구체적이고 실행 가능한 개선 방안을 우선순위별로 제시]
        """,
        customer_access_key=state['customer_access_key'],
        customer_secret_key=state['customer_secret_key'],
        agent_name="SUMMARY (최종 보고서)"
    )

    log_entry = f"SUMMARY 완료 - 성공: {result['success']}"

    log_print(f"\n🎯 SUMMARY 단계 완료!")
    log_print(f"📊 성공률: SUMMARY({result['success']})")
    log_print(f"{'='*80}")
    
    # 최종 보고서 출력
    if result['success'] and result.get('response'):
        log_print(f"\n📄 최종 NIST 사이버보안 보고서")
        log_print(f"{'='*100}")
        log_print(result['response'])
        log_print(f"{'='*100}")
        
        # 전체 워크플로우 AgentOps 요약 계산
        total_input_tokens = 0
        total_output_tokens = 0
        total_processing_time = 0
        total_trace_steps = 0
        
        # 모든 에이전트 결과에서 trace 데이터 수집
        agent_results = [
            state.get('identify_01_result', {}),
            state.get('computing_result', {}),
            state.get('storage_result', {}),
            state.get('db_result', {}),
            state.get('protect_01_result', {}),
            state.get('protect_02_result', {}),
            state.get('detect_01_result', {}),
            state.get('detect_02_result', {}),
            state.get('respond_result', {}),
            state.get('recover_result', {}),
            result  # SUMMARY 결과
        ]
        
        for agent_result in agent_results:
            if agent_result.get('parsed_traces'):
                for trace in agent_result['parsed_traces']:
                    total_input_tokens += trace.get('input_tokens', 0)
                    total_output_tokens += trace.get('output_tokens', 0)
                    total_processing_time += trace.get('total_time_ms', 0)
                    total_trace_steps += 1
        
        # 전체 워크플로우 AgentOps 요약 출력
        log_print(f"\n📊 전체 워크플로우 AgentOps 요약:")
        log_print(f"   🎯 총 토큰 사용량: 입력 {total_input_tokens:,}개, 출력 {total_output_tokens:,}개, 총 {total_input_tokens + total_output_tokens:,}개")
        log_print(f"   ⚡ 총 처리 시간: {total_processing_time:,}ms ({total_processing_time/1000:.2f}초)")
        log_print(f"   📈 총 Trace 단계 수: {total_trace_steps}개")
        log_print(f"   🤖 실행된 Agent 수: 11개 (IDENTIFY:4, PROTECT:2, DETECT:2, RESPOND:1, RECOVER:1, SUMMARY:1)")
        log_print(f"{'='*100}")

    return {
        "summary_result": result,
        "current_step": "COMPLETED",
        "execution_log": state["execution_log"] + [log_entry]
    }
# =============================================================================
# 6. LangGraph 워크플로우 생성
# =============================================================================

def create_nist_workflow():
    """NIST 워크플로우 그래프 생성"""
    workflow = StateGraph(NISTState)

    # 노드 추가
    workflow.add_node("identify", identify_parallel_step)
    workflow.add_node("protect", protect_parallel_step)
    workflow.add_node("detect", detect_parallel_step)
    workflow.add_node("respond", respond_step)
    workflow.add_node("recover", recover_step)
    workflow.add_node("summary", summary_step)

    # 실행 순서 정의
    workflow.add_edge("identify", "protect")
    workflow.add_edge("protect", "detect")
    workflow.add_edge("detect", "respond")
    workflow.add_edge("respond", "recover")
    workflow.add_edge("recover", "summary")
    workflow.add_edge("summary", END)

    # 시작점 설정
    workflow.set_entry_point("identify")

    return workflow.compile()


# =============================================================================
# 7. 메인 실행 함수
# =============================================================================

def run_nist_workflow(
    customer_access_key: str,
    customer_secret_key: str,
    target_region: str,
    input_data: Dict[str, Any] = None
) -> Optional[Dict[str, Any]]:
    """
    기본 NIST 워크플로우 실행 (Trace 모니터링 포함)
    
    Args:
        input_data: 워크플로우 입력 데이터
        
    Returns:
        워크플로우 실행 결과 또는 None (실패 시)
    """
    
    log_print(f"\n{'='*100}")
    log_print(f"🚀 NIST 사이버보안 워크플로우 시작")
    log_print(f"{'='*100}")
    log_print(f"📋 워크플로우 구성: IDENTIFY(4) → PROTECT(2) → DETECT(2) → RESPOND(1) → RECOVER(1) → SUMMARY(1)")
    log_print(f"🔍 Trace 모니터링: 활성화 (모든 Agent의 추론 과정 실시간 표시)")
    log_print(f"{'='*100}")
    
    # 입력 데이터 기본값 설정
    if input_data is None:
        input_data = {
            "target_region": target_region,
            "target_system": "AWS 클라우드 인프라",
            "scan_type": "종합 보안 점검",
            "priority": "high",
            "compliance_frameworks": ["NIST", "SOC2", "ISO27001"]
        }

    # 초기 상태 설정
    initial_state = {
        "customer_access_key": customer_access_key,
        "customer_secret_key": customer_secret_key,
        "input_data": input_data,
        "identify_01_result": {},
        "computing_result": {},
        "storage_result": {},
        "db_result": {},
        "protect_01_result": {},
        "protect_02_result": {},
        "detect_01_result": {},
        "detect_02_result": {},
        "respond_result": {},
        "recover_result": {},
        "summary_result": {},
        "workflow_id": f"nist_workflow_{int(time.time())}",
        "current_step": "IDENTIFY",
        "execution_log": []
    }

    # 워크플로우 생성 및 실행
    workflow = create_nist_workflow()

    try:
        # 전체 워크플로우 시작 시간
        workflow_start_time = time.time()
        
        # 워크플로우 실행
        final_state = workflow.invoke(initial_state)
        
        # 전체 워크플로우 완료 시간
        workflow_end_time = time.time()
        total_workflow_time = workflow_end_time - workflow_start_time
        
        # 최종 완료 메시지
        log_print(f"\n{'='*100}")
        log_print(f"🎉 NIST 사이버보안 워크플로우 완료!")
        log_print(f"{'='*100}")
        log_print(f"⏱️  전체 실행 시간: {total_workflow_time:.2f}초")
        log_print(f"📊 실행 로그:")
        for i, log in enumerate(final_state.get('execution_log', []), 1):
            log_print(f"   {i}. {log}")
        log_print(f"{'='*100}")
        
        return final_state

    except Exception as e:
        log_print(f"\n❌ 워크플로우 실행 중 오류 발생: {str(e)}")
        log_print(f"{'='*100}")
        return None



# =============================================================================
# 8. 테스트 실행
# =============================================================================

if __name__ == "__main__":
    log_print("NIST 사이버보안 워크플로우 with AgentOps Trace 모니터링")
    log_print("=" * 60)
    
    # 워크플로우 실행
    result = run_nist_workflow()
    
    if result:
        log_print("\n✅ 워크플로우 실행 성공!")
        log_print(f"📋 최종 단계: {result.get('current_step', 'Unknown')}")
    else:
        log_print("\n❌ 워크플로우 실행 실패!")
