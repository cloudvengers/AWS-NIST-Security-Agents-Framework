import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-01 리소스 발견용 Lambda 함수 - 병렬 처리 구조
    AWS 보안 상태 식별 서비스들의 리소스 존재 여부와 개수를 확인
    """
    
    print(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        # Bedrock Agent에서 전달된 파라미터 추출
        function_name = event.get('function', '')
        parameters = event.get('parameters', [])
        session_attributes = event.get('sessionAttributes', {})
        
        if function_name != 'discoverAllResources':
            return create_bedrock_error_response(event, f"Unknown function: {function_name}")
        
        # 파라미터를 딕셔너리로 변환
        param_dict = {}
        for param in parameters:
            param_dict[param['name']] = param['value']
        
        # 필수 파라미터 확인
        target_region = param_dict.get('target_region')
        if not target_region:
            return create_bedrock_error_response(event, "target_region parameter is required")
        
        # 세션 속성에서 고객 자격증명 및 현재 시간 획득
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "Customer AWS credentials not found in session attributes")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        # 병렬로 모든 서비스 리소스 발견 수행
        discovery_results = discover_all_services_parallel(session, target_region, current_time)
        
        # Bedrock Agent 형식에 맞는 성공 응답 반환
        return create_bedrock_success_response(event, discovery_results)
        
    except Exception as e:
        error_msg = f"Discovery failed: {str(e)}"
        print(f"Error: {error_msg}")
        return create_bedrock_error_response(event, error_msg)

def discover_all_services_parallel(session, target_region, current_time):
    """
    모든 AWS 보안 상태 식별 서비스의 리소스 존재 여부를 병렬로 확인
    """
    services = [
        ('securityhub', 'describe_hub'),
        ('config', 'describe_configuration_recorders'),
        ('support', 'describe_trusted_advisor_checks'),
        ('ssm', 'describe_instance_information')
    ]
    
    # 병렬로 모든 서비스 확인
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(check_service_resources, session, service, api, target_region): service 
            for service, api in services
        }
        
        results = {}
        for future in concurrent.futures.as_completed(futures):
            service = futures[future]
            try:
                results[service] = future.result()
            except Exception as e:
                print(f"Error checking {service}: {str(e)}")
                results[service] = {
                    "service_name": service,
                    "resource_count": 0,
                    "resources_found": False,
                    "status": "error",
                    "error": str(e)
                }
    
    # 발견 결과 요약 생성
    summary = create_discovery_summary(results)
    
    return {
        "function": "discoverAllResources",
        "target_region": target_region,
        "collection_timestamp": current_time,
        "analysis_time": current_time,
        "discovery_results": results,
        "summary": summary,
        "processing_method": "parallel"
    }

def check_service_resources(session, service_name, api_name, region):
    """
    개별 서비스의 리소스 존재 확인
    """
    try:
        if service_name == 'securityhub':
            client = session.client('securityhub', region_name=region)
            try:
                response = client.describe_hub()
                return {
                    "service_name": "AWS Security Hub",
                    "resource_count": 1,
                    "resources_found": True,
                    "status": "success",
                    "hub_arn": response.get('HubArn', ''),
                    "subscribed_at": response.get('SubscribedAt', '')
                }
            except client.exceptions.InvalidAccessException:
                return {
                    "service_name": "AWS Security Hub",
                    "resource_count": 0,
                    "resources_found": False,
                    "status": "not_enabled",
                    "message": "Security Hub is not enabled in this region"
                }
        
        elif service_name == 'config':
            client = session.client('config', region_name=region)
            response = client.describe_configuration_recorders()
            recorders = response.get('ConfigurationRecorders', [])
            return {
                "service_name": "AWS Config",
                "resource_count": len(recorders),
                "resources_found": len(recorders) > 0,
                "status": "success",
                "configuration_recorders": len(recorders)
            }
        
        elif service_name == 'support':
            # Trusted Advisor는 us-east-1에서만 사용 가능
            if region != 'us-east-1':
                return {
                    "service_name": "AWS Trusted Advisor",
                    "resource_count": 0,
                    "resources_found": False,
                    "status": "region_not_supported",
                    "message": "Trusted Advisor is only available in us-east-1"
                }
            
            client = session.client('support', region_name='us-east-1')
            try:
                response = client.describe_trusted_advisor_checks(language='en')
                checks = response.get('checks', [])
                security_checks = [check for check in checks if 'security' in check.get('category', '').lower()]
                return {
                    "service_name": "AWS Trusted Advisor",
                    "resource_count": len(security_checks),
                    "resources_found": len(security_checks) > 0,
                    "status": "success",
                    "total_checks": len(checks),
                    "security_checks": len(security_checks)
                }
            except Exception as e:
                return {
                    "service_name": "AWS Trusted Advisor",
                    "resource_count": 0,
                    "resources_found": False,
                    "status": "access_denied",
                    "message": "Trusted Advisor requires Business or Enterprise support plan"
                }
        
        elif service_name == 'ssm':
            client = session.client('ssm', region_name=region)
            response = client.describe_instance_information()
            instances = response.get('InstanceInformationList', [])
            return {
                "service_name": "AWS Systems Manager",
                "resource_count": len(instances),
                "resources_found": len(instances) > 0,
                "status": "success",
                "managed_instances": len(instances)
            }
            
    except Exception as e:
        service_name_mapping = {
            'securityhub': 'AWS Security Hub',
            'config': 'AWS Config',
            'support': 'AWS Trusted Advisor',
            'ssm': 'AWS Systems Manager'
        }
        
        return {
            "service_name": service_name_mapping.get(service_name, service_name),
            "resource_count": 0,
            "resources_found": False,
            "status": "error",
            "error": str(e)
        }

def create_discovery_summary(results):
    """
    발견 결과 요약 생성
    """
    total_services = len(results)
    services_with_resources = sum(1 for service in results.values() if service.get('resources_found', False))
    total_resources = sum(service.get('resource_count', 0) for service in results.values())
    
    summary = {
        'total_services_checked': total_services,
        'services_with_resources': services_with_resources,
        'total_resources_found': total_resources,
        'services_requiring_analysis': []
    }
    
    # 분석이 필요한 서비스 목록
    for service_key, service_data in results.items():
        if service_data.get('resources_found', False):
            summary['services_requiring_analysis'].append({
                'service': service_key,
                'service_name': service_data.get('service_name'),
                'resource_count': service_data.get('resource_count', 0)
            })
    
    return summary

def create_bedrock_success_response(event, response_data):
    """
    Bedrock Agent 성공 응답 생성 (Function Details 방식)
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
    
    session_attributes = event.get('sessionAttributes', {})
    prompt_session_attributes = event.get('promptSessionAttributes', {})
    
    bedrock_response = {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': session_attributes,
        'promptSessionAttributes': prompt_session_attributes
    }
    
    return bedrock_response

def create_bedrock_error_response(event, error_message):
    """
    Bedrock Agent 에러 응답 생성 (Function Details 방식)
    """
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
    
    session_attributes = event.get('sessionAttributes', {})
    prompt_session_attributes = event.get('promptSessionAttributes', {})
    
    bedrock_response = {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': session_attributes,
        'promptSessionAttributes': prompt_session_attributes
    }
    
    return bedrock_response
