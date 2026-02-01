import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    PROTECT-AGENT 리소스 발견용 Lambda 함수 - 병렬 처리 구조
    AWS 보안 서비스들의 리소스 존재 여부와 개수를 확인
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
    모든 AWS 보안 서비스의 리소스 존재 여부를 병렬로 확인
    """
    services = [
        ('acm', 'list_certificates'),
        ('kms', 'list_keys'),
        ('wafv2', 'list_web_acls'),
        ('secretsmanager', 'list_secrets'),
        ('network-firewall', 'list_firewalls')
    ]
    
    # 병렬로 모든 서비스 확인
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
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
        client = session.client(service_name, region_name=region)
        
        if service_name == 'wafv2':
            # WAF는 REGIONAL과 CLOUDFRONT 스코프 모두 확인
            regional_response = client.list_web_acls(Scope='REGIONAL')
            total_count = len(regional_response.get('WebACLs', []))
            
            # us-east-1에서만 CLOUDFRONT 스코프 확인
            if region == 'us-east-1':
                try:
                    cloudfront_response = client.list_web_acls(Scope='CLOUDFRONT')
                    total_count += len(cloudfront_response.get('WebACLs', []))
                except Exception as e:
                    print(f"Error checking CloudFront WAF: {str(e)}")
            
            return {
                "service_name": "AWS WAF v2",
                "resource_count": total_count,
                "resources_found": total_count > 0,
                "status": "success",
                "scopes_checked": ["REGIONAL"] + (["CLOUDFRONT"] if region == 'us-east-1' else [])
            }
        else:
            # 다른 서비스들
            response = getattr(client, api_name)()
            
            # 서비스별 응답 키 매핑
            resource_key_mapping = {
                'acm': 'CertificateSummaryList',
                'kms': 'Keys',
                'secretsmanager': 'SecretList',
                'network-firewall': 'Firewalls'
            }
            
            resource_key = resource_key_mapping.get(service_name, 'Items')
            resources = response.get(resource_key, [])
            
            service_name_mapping = {
                'acm': 'AWS Certificate Manager',
                'kms': 'AWS Key Management Service',
                'secretsmanager': 'AWS Secrets Manager',
                'network-firewall': 'AWS Network Firewall'
            }
            
            return {
                "service_name": service_name_mapping.get(service_name, service_name),
                "resource_count": len(resources),
                "resources_found": len(resources) > 0,
                "status": "success"
            }
            
    except Exception as e:
        service_name_mapping = {
            'acm': 'AWS Certificate Manager',
            'kms': 'AWS Key Management Service',
            'wafv2': 'AWS WAF v2',
            'secretsmanager': 'AWS Secrets Manager',
            'network-firewall': 'AWS Network Firewall'
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
