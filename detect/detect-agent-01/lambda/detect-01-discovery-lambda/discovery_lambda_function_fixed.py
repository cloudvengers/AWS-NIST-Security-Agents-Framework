import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    DETECT-AGENT-01 Discovery Lambda 함수
    GuardDuty, Macie, Inspector 서비스의 리소스 존재 여부 확인
    """
    try:
        # 파라미터 추출
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region', 'us-east-1')
        
        # 세션 속성에서 고객 자격증명 및 현재 시간 획득
        session_attributes = event.get('sessionAttributes', {})
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다. 세션을 다시 시작해주세요.")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        # 서비스별 리소스 발견 병렬 실행
        discovery_results = discover_security_services_parallel(session, target_region)
        
        # 응답 데이터 구성
        response_data = {
            'function': 'analyzeDetectAgent01Discovery',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_timestamp': context.aws_request_id,
            'services_discovered': discovery_results,
            'collection_summary': {
                'total_services_checked': len(discovery_results),
                'services_with_resources': sum(1 for service in discovery_results.values() if service.get('has_resources', False)),
                'discovery_method': 'parallel_processing',
                'agent_type': 'detect-agent-01',
                'focus': 'threat_detection_and_anomaly_analysis'
            }
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"Discovery 과정에서 오류 발생: {str(e)}"
        print(f"Error in detect-agent-01 discovery lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def discover_security_services_parallel(session, target_region):
    """
    보안 서비스들의 리소스를 병렬로 발견
    """
    services_to_check = [
        ('guardduty', check_guardduty_resources),
        ('macie', check_macie_resources),
        ('inspector', check_inspector_resources)
    ]
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_service = {
            executor.submit(check_func, session, target_region): service_name 
            for service_name, check_func in services_to_check
        }
        
        for future in concurrent.futures.as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                result = future.result()
                results[service_name] = result
            except Exception as e:
                print(f"Error checking {service_name}: {str(e)}")
                results[service_name] = {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def check_guardduty_resources(session, target_region):
    """
    GuardDuty 탐지기 존재 여부 확인
    """
    try:
        guardduty_client = session.client('guardduty', region_name=target_region)
        
        # 탐지기 목록 조회
        response = guardduty_client.list_detectors()
        detector_ids = response.get('DetectorIds', [])
        
        if not detector_ids:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['detectors'],
                'status': 'no_detectors',
                'details': {
                    'note': 'GuardDuty 탐지기가 생성되지 않았습니다.'
                }
            }
        
        # 활성화된 탐지기 확인
        active_detectors = []
        for detector_id in detector_ids:
            try:
                detector_response = guardduty_client.get_detector(DetectorId=detector_id)
                if detector_response.get('Status') == 'ENABLED':
                    active_detectors.append(detector_id)
            except Exception as e:
                print(f"Error checking detector {detector_id}: {str(e)}")
                continue
        
        return {
            'has_resources': len(active_detectors) > 0,
            'resource_count': len(active_detectors),
            'resource_types': ['detectors'],
            'status': 'active' if active_detectors else 'inactive',
            'details': {
                'total_detectors': len(detector_ids),
                'active_detectors': len(active_detectors),
                'detector_ids': active_detectors
            }
        }
        
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'access_denied',
                'error_message': 'GuardDuty 접근 권한이 없습니다.'
            }
        # 다른 모든 에러는 정상적으로 처리하고 계속 진행
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': f'GuardDuty 확인 중 오류: {str(e)}'
        }

def check_macie_resources(session, target_region):
    """
    Macie 세션 활성화 상태 확인 (수정된 에러 처리)
    """
    try:
        macie_client = session.client('macie2', region_name=target_region)
        
        # Macie 세션 상태 조회
        response = macie_client.get_macie_session()
        
        status = response.get('status', 'DISABLED')
        is_active = status == 'ENABLED'
        
        return {
            'has_resources': is_active,
            'resource_count': 1 if is_active else 0,
            'resource_types': ['macie_session'],
            'status': status.lower(),
            'details': {
                'service_role': response.get('serviceRole'),
                'created_at': response.get('createdAt'),
                'updated_at': response.get('updatedAt')
            }
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        # AccessDeniedException이면서 "Macie is not enabled" 메시지인 경우
        if error_code == 'AccessDeniedException' and 'not enabled' in error_message:
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'not_enabled',
                'details': {
                    'note': 'Macie 서비스가 활성화되지 않았습니다.',
                    'error_code': error_code,
                    'error_message': error_message
                }
            }
        # 일반적인 권한 부족
        elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'access_denied',
                'error_message': 'Macie 접근 권한이 없습니다.'
            }
        # ResourceNotFoundException - Macie 세션이 존재하지 않음
        elif error_code == 'ResourceNotFoundException':
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'not_enabled',
                'details': {
                    'note': 'Macie 세션이 생성되지 않았습니다.'
                }
            }
        # 기타 모든 에러는 정상적으로 처리하고 계속 진행
        else:
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'error',
                'error_message': f'Macie 확인 중 오류: {str(e)}'
            }

def check_inspector_resources(session, target_region):
    """
    Inspector 활성화 상태 확인
    """
    try:
        inspector_client = session.client('inspector2', region_name=target_region)
        
        # Inspector 활성화 상태 확인
        response = inspector_client.batch_get_account_status(accountIds=[])
        
        # 현재 계정의 상태 확인
        account_states = response.get('accounts', [])
        if not account_states:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['inspector_account'],
                'status': 'not_configured',
                'details': {
                    'note': 'Inspector 계정 상태를 확인할 수 없습니다.'
                }
            }
        
        account_state = account_states[0]
        state = account_state.get('state', {})
        status = state.get('status', 'DISABLED')
        
        is_active = status in ['ENABLED', 'ENABLING']
        
        return {
            'has_resources': is_active,
            'resource_count': 1 if is_active else 0,
            'resource_types': ['inspector_account'],
            'status': status.lower(),
            'details': {
                'account_id': account_state.get('accountId'),
                'resource_state': account_state.get('resourceState', {}),
                'state_details': state
            }
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'access_denied',
                'error_message': 'Inspector 접근 권한이 없습니다.'
            }
        # 기타 모든 에러는 정상적으로 처리하고 계속 진행
        else:
            return {
                'has_resources': False,
                'resource_count': 0,
                'status': 'error',
                'error_message': f'Inspector 확인 중 오류: {str(e)}'
            }

def create_bedrock_success_response(event, response_data):
    """
    Bedrock Agent 성공 응답 생성
    """
    response_body = {
        'TEXT': {
            'body': json.dumps(response_data, ensure_ascii=False, indent=2, default=str)
        }
    }
    
    function_response = {
        'actionGroup': event['actionGroup'],
        'function': event['function'],
        'functionResponse': {
            'responseBody': response_body
        }
    }
    
    return {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': event.get('sessionAttributes', {}),
        'promptSessionAttributes': event.get('promptSessionAttributes', {})
    }

def create_bedrock_error_response(event, error_message):
    """
    Bedrock Agent 에러 응답 생성
    """
    error_data = {
        'function': event.get('function', 'discoverAllResources'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'discovery-action-group'),
        'function': event.get('function', 'discoverAllResources'),
        'functionResponse': {
            'responseState': 'FAILURE',
            'responseBody': response_body
        }
    }
    
    return {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': event.get('sessionAttributes', {}),
        'promptSessionAttributes': event.get('promptSessionAttributes', {})
    }
