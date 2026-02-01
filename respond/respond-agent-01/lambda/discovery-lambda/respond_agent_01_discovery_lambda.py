import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    try:
        # 파라미터 추출
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region')
        
        if not target_region:
            return create_bedrock_error_response(event, "target_region parameter is required")
        
        # 세션 속성에서 고객 자격증명 획득
        session_attributes = event.get('sessionAttributes', {})
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "Customer credentials not found in session")
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        stepfunctions_client = session.client('stepfunctions')
        
        # Step Functions 리소스 발견 (병렬 처리)
        discovery_data = discover_stepfunctions_resources_parallel(stepfunctions_client)
        
        # 수집 요약 정보 추가
        discovery_data['collection_summary'] = {
            'function': 'analyzeRespondAgent01Discovery',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_timestamp': context.aws_request_id,
            'services_checked': ['stepfunctions'],
            'total_resources_found': discovery_data.get('state_machines_count', 0) + discovery_data.get('activities_count', 0)
        }
        
        return create_bedrock_success_response(event, discovery_data)
        
    except Exception as e:
        print(f"Error in discovery lambda: {str(e)}")
        return create_bedrock_error_response(event, f"Discovery failed: {str(e)}")

def discover_stepfunctions_resources_parallel(client):
    """Step Functions 리소스를 병렬로 발견"""
    
    # 병렬 처리할 함수들
    discovery_functions = [
        ('state_machines', get_state_machines_count),
        ('activities', get_activities_count)
    ]
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        # 각 리소스 타입별로 병렬 실행
        future_to_resource = {
            executor.submit(func, client): resource_type 
            for resource_type, func in discovery_functions
        }
        
        for future in concurrent.futures.as_completed(future_to_resource):
            resource_type = future_to_resource[future]
            try:
                result = future.result()
                results.update(result)
            except Exception as e:
                print(f"Error discovering {resource_type}: {str(e)}")
                # 개별 리소스 실패 시에도 계속 진행
                if resource_type == 'state_machines':
                    results['state_machines_count'] = 0
                    results['state_machines_error'] = str(e)
                elif resource_type == 'activities':
                    results['activities_count'] = 0
                    results['activities_error'] = str(e)
    
    return results

def get_state_machines_count(client):
    """State Machine 개수 조회"""
    try:
        response = client.list_state_machines()
        state_machines = response.get('stateMachines', [])
        
        return {
            'state_machines_count': len(state_machines),
            'state_machines_found': len(state_machines) > 0,
            'state_machines_sample': [sm.get('name', 'Unknown') for sm in state_machines[:5]]  # 처음 5개만 샘플로
        }
    except Exception as e:
        print(f"Error listing state machines: {str(e)}")
        return {
            'state_machines_count': 0,
            'state_machines_found': False,
            'state_machines_error': str(e)
        }

def get_activities_count(client):
    """Activity 개수 조회"""
    try:
        response = client.list_activities()
        activities = response.get('activities', [])
        
        return {
            'activities_count': len(activities),
            'activities_found': len(activities) > 0,
            'activities_sample': [act.get('name', 'Unknown') for act in activities[:5]]  # 처음 5개만 샘플로
        }
    except Exception as e:
        print(f"Error listing activities: {str(e)}")
        return {
            'activities_count': 0,
            'activities_found': False,
            'activities_error': str(e)
        }

def create_bedrock_success_response(event, response_data):
    """Bedrock Agent 성공 응답 생성"""
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
    """Bedrock Agent 에러 응답 생성"""
    error_data = {
        'function': event.get('function', 'unknown'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'unknown'),
        'function': event.get('function', 'unknown'),
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
