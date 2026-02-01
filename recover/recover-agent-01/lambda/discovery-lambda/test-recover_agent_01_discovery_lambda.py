import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    RECOVER-AGENT-01 Discovery Lambda 함수
    EBS 스냅샷 리소스 존재 여부 확인
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
        
        # EBS 스냅샷 리소스 발견
        discovery_results = discover_snapshot_resources(session, target_region, current_time)
        
        # 응답 데이터 구성
        response_data = {
            'function': 'discoverAllResources',
            'target_region': target_region,
            'discovery_timestamp': current_time,
            'analysis_time': current_time,
            'services_discovered': discovery_results,
            'collection_summary': {
                'total_services_checked': len(discovery_results),
                'services_with_resources': sum(1 for service in discovery_results.values() if service.get('has_resources', False)),
                'discovery_method': 'parallel_processing',
                'agent_type': 'recover-agent-01',
                'focus': 'ebs_snapshot_block_level_analysis'
            }
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"Discovery 과정에서 오류 발생: {str(e)}"
        print(f"Error in recover-agent-01 discovery lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def discover_snapshot_resources(session, target_region, current_time):
    """
    EBS 스냅샷 리소스 발견
    """
    try:
        ec2_client = session.client('ec2', region_name=target_region)
        
        # EBS 스냅샷 목록 조회 (소유자 기준)
        response = ec2_client.describe_snapshots(OwnerIds=['self'])
        snapshots = response.get('Snapshots', [])
        
        if not snapshots:
            return {
                'ebs_snapshots': {
                    'has_resources': False,
                    'resource_count': 0,
                    'resource_types': ['snapshots'],
                    'status': 'no_snapshots',
                    'details': {
                        'note': 'EBS 스냅샷이 존재하지 않습니다.'
                    }
                }
            }
        
        # 스냅샷 상태별 분류
        completed_snapshots = [s for s in snapshots if s.get('State') == 'completed']
        pending_snapshots = [s for s in snapshots if s.get('State') == 'pending']
        error_snapshots = [s for s in snapshots if s.get('State') == 'error']
        
        return {
            'ebs_snapshots': {
                'has_resources': len(completed_snapshots) > 0,
                'resource_count': len(snapshots),
                'resource_types': ['snapshots'],
                'status': 'active' if completed_snapshots else 'no_completed_snapshots',
                'details': {
                    'total_snapshots': len(snapshots),
                    'completed_snapshots': len(completed_snapshots),
                    'pending_snapshots': len(pending_snapshots),
                    'error_snapshots': len(error_snapshots),
                    'snapshot_ids': [s['SnapshotId'] for s in completed_snapshots[:10]]  # 최대 10개만 표시
                }
            }
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'ebs_snapshots': {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'access_denied',
                    'error_message': 'EBS 스냅샷 접근 권한이 없습니다.'
                }
            }
        else:
            return {
                'ebs_snapshots': {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'error',
                    'error_message': f'EBS 스냅샷 확인 중 오류: {str(e)}'
                }
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
