import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
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
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다.")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        # 서비스별 리소스 발견 병렬 실행
        discovery_results = discover_all_resources_parallel(session, target_region)
        
        # 수집 요약 정보 추가
        collection_summary = {
            'total_services_checked': 4,
            'target_region': target_region,
            'services_with_resources': sum(1 for result in discovery_results.values() if result.get('resource_count', 0) > 0),
            'timestamp': context.aws_request_id if context else 'unknown'
        }
        
        response_data = {
            'function': 'analyzeProtectAgent02Discovery',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_results': discovery_results,
            'collection_summary': collection_summary
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"Discovery 함수 실행 중 오류 발생: {str(e)}"
        print(error_message)
        return create_bedrock_error_response(event, error_message)

def discover_all_resources_parallel(session, target_region):
    """모든 대상 서비스의 리소스를 병렬로 발견"""
    
    # 서비스별 발견 함수 매핑
    service_discovery_map = {
        'iam': discover_iam_resources,
        'transit_gateway': discover_transit_gateway_resources,
        'vpc': discover_vpc_resources,
        'privatelink': discover_privatelink_resources
    }
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        # 각 서비스별 발견 작업 제출
        future_to_service = {
            executor.submit(discovery_func, session, target_region): service_name
            for service_name, discovery_func in service_discovery_map.items()
        }
        
        # 결과 수집
        for future in concurrent.futures.as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                result = future.result()
                results[service_name] = result
            except Exception as e:
                print(f"Error discovering {service_name} resources: {str(e)}")
                results[service_name] = {
                    'service': service_name,
                    'resource_count': 0,
                    'error': str(e),
                    'status': 'error'
                }
    
    return results

def discover_iam_resources(session, target_region):
    """IAM 리소스 발견 (글로벌 서비스)"""
    try:
        iam_client = session.client('iam')
        
        # IAM은 글로벌 서비스이므로 기본적인 리소스 개수만 확인
        users_response = iam_client.list_users(MaxItems=1000)
        roles_response = iam_client.list_roles(MaxItems=1000)
        groups_response = iam_client.list_groups(MaxItems=1000)
        policies_response = iam_client.list_policies(Scope='Local', MaxItems=1000)
        
        total_resources = (
            len(users_response.get('Users', [])) +
            len(roles_response.get('Roles', [])) +
            len(groups_response.get('Groups', [])) +
            len(policies_response.get('Policies', []))
        )
        
        return {
            'service': 'iam',
            'resource_count': total_resources,
            'resource_breakdown': {
                'users': len(users_response.get('Users', [])),
                'roles': len(roles_response.get('Roles', [])),
                'groups': len(groups_response.get('Groups', [])),
                'policies': len(policies_response.get('Policies', []))
            },
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error discovering IAM resources: {str(e)}")
        return {
            'service': 'iam',
            'resource_count': 0,
            'error': str(e),
            'status': 'error'
        }

def discover_transit_gateway_resources(session, target_region):
    """Transit Gateway 리소스 발견"""
    try:
        ec2_client = session.client('ec2', region_name=target_region)
        
        # Transit Gateway 목록 조회
        tgw_response = ec2_client.describe_transit_gateways()
        tgw_count = len(tgw_response.get('TransitGateways', []))
        
        # 연결된 리소스 개수도 확인
        attachments_response = ec2_client.describe_transit_gateway_attachments()
        attachments_count = len(attachments_response.get('TransitGatewayAttachments', []))
        
        total_resources = tgw_count + attachments_count
        
        return {
            'service': 'transit_gateway',
            'resource_count': total_resources,
            'resource_breakdown': {
                'transit_gateways': tgw_count,
                'attachments': attachments_count
            },
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error discovering Transit Gateway resources: {str(e)}")
        return {
            'service': 'transit_gateway',
            'resource_count': 0,
            'error': str(e),
            'status': 'error'
        }

def discover_vpc_resources(session, target_region):
    """VPC 리소스 발견"""
    try:
        ec2_client = session.client('ec2', region_name=target_region)
        
        # VPC 관련 주요 리소스 개수 확인
        vpcs_response = ec2_client.describe_vpcs()
        subnets_response = ec2_client.describe_subnets()
        security_groups_response = ec2_client.describe_security_groups()
        nacls_response = ec2_client.describe_network_acls()
        
        total_resources = (
            len(vpcs_response.get('Vpcs', [])) +
            len(subnets_response.get('Subnets', [])) +
            len(security_groups_response.get('SecurityGroups', [])) +
            len(nacls_response.get('NetworkAcls', []))
        )
        
        return {
            'service': 'vpc',
            'resource_count': total_resources,
            'resource_breakdown': {
                'vpcs': len(vpcs_response.get('Vpcs', [])),
                'subnets': len(subnets_response.get('Subnets', [])),
                'security_groups': len(security_groups_response.get('SecurityGroups', [])),
                'network_acls': len(nacls_response.get('NetworkAcls', []))
            },
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error discovering VPC resources: {str(e)}")
        return {
            'service': 'vpc',
            'resource_count': 0,
            'error': str(e),
            'status': 'error'
        }

def discover_privatelink_resources(session, target_region):
    """PrivateLink 리소스 발견"""
    try:
        ec2_client = session.client('ec2', region_name=target_region)
        
        # VPC 엔드포인트 및 엔드포인트 서비스 개수 확인
        endpoints_response = ec2_client.describe_vpc_endpoints()
        endpoint_services_response = ec2_client.describe_vpc_endpoint_service_configurations()
        
        total_resources = (
            len(endpoints_response.get('VpcEndpoints', [])) +
            len(endpoint_services_response.get('ServiceConfigurations', []))
        )
        
        return {
            'service': 'privatelink',
            'resource_count': total_resources,
            'resource_breakdown': {
                'vpc_endpoints': len(endpoints_response.get('VpcEndpoints', [])),
                'endpoint_services': len(endpoint_services_response.get('ServiceConfigurations', []))
            },
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error discovering PrivateLink resources: {str(e)}")
        return {
            'service': 'privatelink',
            'resource_count': 0,
            'error': str(e),
            'status': 'error'
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
