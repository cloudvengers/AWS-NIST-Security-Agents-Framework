import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    PROTECT-AGENT Secrets Manager Lambda 함수 - 병렬 처리 구조
    단순히 Secrets Manager API 호출 결과만 반환, 분석은 Agent가 수행
    """
    
    print(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        # Bedrock Agent에서 전달된 파라미터 추출
        function_name = event.get('function', '')
        parameters = event.get('parameters', [])
        session_attributes = event.get('sessionAttributes', {})
        
        if function_name != 'analyzeSecretsSecurity':
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
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        secrets_client = session.client('secretsmanager', region_name=target_region)
        
        # Secrets Manager API 호출 - 병렬 원시 데이터 수집
        raw_data = collect_secrets_raw_data_parallel(secrets_client, target_region, current_time)
        
        # Bedrock Agent 형식에 맞는 성공 응답 반환
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_msg = f"Secrets Manager data collection failed: {str(e)}"
        print(f"Error: {error_msg}")
        return create_bedrock_error_response(event, error_msg)

def collect_secrets_raw_data_parallel(secrets_client, target_region, current_time):
    """
    Secrets Manager 원시 데이터 수집 - 병렬 처리
    """
    raw_data = {
        "function": "analyzeSecretsSecurity",
        "target_region": target_region,
        "collection_timestamp": current_time,
        "analysis_time": current_time,
        "secrets": [],
        "secret_details": [],
        "secret_versions": [],
        "resource_policies": [],
        "policy_validations": []
    }
    
    try:
        # 1. 시크릿 목록 조회
        list_response = secrets_client.list_secrets()
        secrets = list_response.get('SecretList', [])
        raw_data["secrets"] = secrets
        
        if not secrets:
            return raw_data
        
        # 2. 각 시크릿별 상세 정보 병렬 수집
        raw_data["secret_details"] = process_secrets_parallel(
            secrets_client, secrets, get_secret_details, max_workers=5
        )
        
        raw_data["secret_versions"] = process_secrets_parallel(
            secrets_client, secrets, get_secret_versions, max_workers=5
        )
        
        raw_data["resource_policies"] = process_secrets_parallel(
            secrets_client, secrets, get_secret_resource_policy, max_workers=5
        )
        
        raw_data["policy_validations"] = process_secrets_parallel(
            secrets_client, secrets, validate_secret_policy, max_workers=5
        )
        
        # 3. 데이터 수집 요약
        raw_data["collection_summary"] = {
            "total_secrets_found": len(secrets),
            "successful_details": len(raw_data["secret_details"]),
            "successful_versions": len(raw_data["secret_versions"]),
            "successful_policies": len(raw_data["resource_policies"]),
            "successful_validations": len(raw_data["policy_validations"]),
            "target_region": secrets_client.meta.region_name,
            "processing_method": "parallel"
        }
        
    except Exception as e:
        print(f"Error collecting Secrets Manager data: {str(e)}")
        raw_data["error"] = str(e)
    
    return raw_data

def process_secrets_parallel(secrets_client, secrets, process_func, max_workers=5):
    """
    시크릿 목록을 병렬로 처리하는 함수
    """
    if not secrets:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, secrets_client, secret) for secret in secrets]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing secret: {str(e)}")
                continue
    
    return results

def get_secret_details(secrets_client, secret):
    """
    개별 시크릿 상세 정보 조회
    """
    try:
        secret_arn = secret['ARN']
        secret_name = secret['Name']
        
        describe_response = secrets_client.describe_secret(SecretId=secret_arn)
        return {
            "secret_arn": secret_arn,
            "secret_name": secret_name,
            "details": describe_response
        }
    except Exception as e:
        print(f"Error getting details for secret {secret.get('Name', 'unknown')}: {str(e)}")
        return None

def get_secret_versions(secrets_client, secret):
    """
    개별 시크릿 버전 목록 조회
    """
    try:
        secret_arn = secret['ARN']
        secret_name = secret['Name']
        
        versions_response = secrets_client.list_secret_version_ids(SecretId=secret_arn)
        return {
            "secret_arn": secret_arn,
            "secret_name": secret_name,
            "versions": versions_response.get('Versions', [])
        }
    except Exception as e:
        print(f"Error getting versions for secret {secret.get('Name', 'unknown')}: {str(e)}")
        return None

def get_secret_resource_policy(secrets_client, secret):
    """
    개별 시크릿 리소스 정책 조회
    """
    try:
        secret_arn = secret['ARN']
        secret_name = secret['Name']
        
        policy_response = secrets_client.get_resource_policy(SecretId=secret_arn)
        return {
            "secret_arn": secret_arn,
            "secret_name": secret_name,
            "resource_policy": policy_response.get('ResourcePolicy', ''),
            "policy_name": policy_response.get('Name', ''),
            "policy_arn": policy_response.get('ARN', '')
        }
    except Exception as e:
        # 정책이 없는 경우는 정상적인 상황이므로 에러 로그 생략
        if "ResourceNotFoundException" not in str(e):
            print(f"Error getting resource policy for secret {secret.get('Name', 'unknown')}: {str(e)}")
        return {
            "secret_arn": secret['ARN'],
            "secret_name": secret['Name'],
            "resource_policy": None,
            "policy_name": None,
            "policy_arn": None
        }

def validate_secret_policy(secrets_client, secret):
    """
    개별 시크릿 정책 검증
    """
    try:
        secret_arn = secret['ARN']
        secret_name = secret['Name']
        
        # 먼저 리소스 정책이 있는지 확인
        try:
            policy_response = secrets_client.get_resource_policy(SecretId=secret_arn)
            resource_policy = policy_response.get('ResourcePolicy', '')
            
            if resource_policy:
                # 정책이 있으면 검증 수행
                validation_response = secrets_client.validate_resource_policy(
                    SecretId=secret_arn,
                    ResourcePolicy=resource_policy
                )
                return {
                    "secret_arn": secret_arn,
                    "secret_name": secret_name,
                    "validation_errors": validation_response.get('ValidationErrors', []),
                    "policy_validation_passed": validation_response.get('PolicyValidationPassed', False)
                }
            else:
                return {
                    "secret_arn": secret_arn,
                    "secret_name": secret_name,
                    "validation_errors": [],
                    "policy_validation_passed": True,
                    "note": "No resource policy to validate"
                }
                
        except Exception as policy_error:
            if "ResourceNotFoundException" in str(policy_error):
                return {
                    "secret_arn": secret_arn,
                    "secret_name": secret_name,
                    "validation_errors": [],
                    "policy_validation_passed": True,
                    "note": "No resource policy to validate"
                }
            else:
                raise policy_error
                
    except Exception as e:
        print(f"Error validating policy for secret {secret.get('Name', 'unknown')}: {str(e)}")
        return None

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
