import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    PROTECT-AGENT KMS Lambda 함수 - 병렬 처리 구조
    단순히 KMS API 호출 결과만 반환, 분석은 Agent가 수행
    """
    
    print(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        # Bedrock Agent에서 전달된 파라미터 추출
        function_name = event.get('function', '')
        parameters = event.get('parameters', [])
        session_attributes = event.get('sessionAttributes', {})
        
        if function_name != 'analyzeKmsSecurity':
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
        
        kms_client = session.client('kms', region_name=target_region)
        
        # KMS API 호출 - 병렬 원시 데이터 수집
        raw_data = collect_kms_raw_data_parallel(kms_client, target_region, current_time)
        
        # Bedrock Agent 형식에 맞는 성공 응답 반환
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_msg = f"KMS data collection failed: {str(e)}"
        print(f"Error: {error_msg}")
        return create_bedrock_error_response(event, error_msg)

def collect_kms_raw_data_parallel(kms_client, target_region, current_time):
    """
    KMS 원시 데이터 수집 - 병렬 처리
    """
    raw_data = {
        "function": "analyzeKmsSecurity",
        "target_region": target_region,
        "collection_timestamp": current_time,
        "analysis_time": current_time,
        "keys": [],
        "key_details": [],
        "key_policies": [],
        "key_rotation_status": [],
        "key_rotations": [],
        "grants": [],
        "retirable_grants": [],
        "public_keys": [],
        "aliases": [],
        "custom_key_stores": [],
        "resource_tags": []
    }
    
    try:
        # 1. 키 목록 조회
        list_response = kms_client.list_keys()
        keys = list_response.get('Keys', [])
        raw_data["keys"] = keys
        
        if not keys:
            return raw_data
        
        # 2. 각 키별 상세 정보 병렬 수집
        raw_data["key_details"] = process_keys_parallel(
            kms_client, keys, get_key_details, max_workers=5
        )
        
        raw_data["key_policies"] = process_keys_parallel(
            kms_client, keys, get_key_policies, max_workers=5
        )
        
        raw_data["key_rotation_status"] = process_keys_parallel(
            kms_client, keys, get_key_rotation_status, max_workers=5
        )
        
        raw_data["key_rotations"] = process_keys_parallel(
            kms_client, keys, get_key_rotations, max_workers=5
        )
        
        raw_data["grants"] = process_keys_parallel(
            kms_client, keys, get_key_grants, max_workers=5
        )
        
        raw_data["public_keys"] = process_keys_parallel(
            kms_client, keys, get_public_keys, max_workers=5
        )
        
        raw_data["resource_tags"] = process_keys_parallel(
            kms_client, keys, get_key_tags, max_workers=5
        )
        
        # 3. 별칭 목록 조회
        try:
            aliases_response = kms_client.list_aliases()
            raw_data["aliases"] = aliases_response.get('Aliases', [])
        except Exception as e:
            print(f"Error listing aliases: {str(e)}")
        
        # 4. 사용자 정의 키 스토어 조회
        try:
            custom_stores_response = kms_client.describe_custom_key_stores()
            raw_data["custom_key_stores"] = custom_stores_response.get('CustomKeyStores', [])
        except Exception as e:
            print(f"Error describing custom key stores: {str(e)}")
        
        # 5. 데이터 수집 요약
        raw_data["collection_summary"] = {
            "total_keys_found": len(keys),
            "successful_key_details": len(raw_data["key_details"]),
            "successful_policies": len(raw_data["key_policies"]),
            "successful_rotation_status": len(raw_data["key_rotation_status"]),
            "successful_tags": len(raw_data["resource_tags"]),
            "total_aliases": len(raw_data["aliases"]),
            "custom_key_stores": len(raw_data["custom_key_stores"]),
            "target_region": kms_client.meta.region_name,
            "processing_method": "parallel"
        }
        
    except Exception as e:
        print(f"Error collecting KMS data: {str(e)}")
        raw_data["error"] = str(e)
    
    return raw_data

def process_keys_parallel(kms_client, keys, process_func, max_workers=5):
    """
    키 목록을 병렬로 처리하는 함수
    """
    if not keys:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, kms_client, key) for key in keys]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing key: {str(e)}")
                continue
    
    return results

def get_key_details(kms_client, key):
    """
    개별 키 상세 정보 조회
    """
    try:
        key_id = key['KeyId']
        describe_response = kms_client.describe_key(KeyId=key_id)
        return {
            "key_id": key_id,
            "details": describe_response.get('KeyMetadata', {})
        }
    except Exception as e:
        print(f"Error getting details for key {key.get('KeyId', 'unknown')}: {str(e)}")
        return None

def get_key_policies(kms_client, key):
    """
    개별 키 정책 조회 (고객 관리형 키만)
    """
    try:
        key_id = key['KeyId']
        # 먼저 키 정보를 확인하여 고객 관리형 키인지 확인
        describe_response = kms_client.describe_key(KeyId=key_id)
        key_metadata = describe_response.get('KeyMetadata', {})
        
        if key_metadata.get('KeyManager') == 'CUSTOMER':
            policy_response = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')
            return {
                "key_id": key_id,
                "policy": policy_response.get('Policy', '')
            }
    except Exception as e:
        print(f"Error getting policy for key {key.get('KeyId', 'unknown')}: {str(e)}")
    return None

def get_key_rotation_status(kms_client, key):
    """
    개별 키 회전 상태 조회
    """
    try:
        key_id = key['KeyId']
        rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
        return {
            "key_id": key_id,
            "rotation_enabled": rotation_response.get('KeyRotationEnabled', False)
        }
    except Exception as e:
        print(f"Error getting rotation status for key {key.get('KeyId', 'unknown')}: {str(e)}")
        return None

def get_key_rotations(kms_client, key):
    """
    개별 키 회전 목록 조회
    """
    try:
        key_id = key['KeyId']
        rotations_response = kms_client.list_key_rotations(KeyId=key_id)
        return {
            "key_id": key_id,
            "rotations": rotations_response.get('Rotations', [])
        }
    except Exception as e:
        print(f"Error listing rotations for key {key.get('KeyId', 'unknown')}: {str(e)}")
        return None

def get_key_grants(kms_client, key):
    """
    개별 키 권한 부여 목록 조회
    """
    try:
        key_id = key['KeyId']
        grants_response = kms_client.list_grants(KeyId=key_id)
        return {
            "key_id": key_id,
            "grants": grants_response.get('Grants', [])
        }
    except Exception as e:
        print(f"Error listing grants for key {key.get('KeyId', 'unknown')}: {str(e)}")
        return None

def get_public_keys(kms_client, key):
    """
    개별 키 공개 키 조회 (비대칭 키만)
    """
    try:
        key_id = key['KeyId']
        # 먼저 키 정보를 확인하여 비대칭 키인지 확인
        describe_response = kms_client.describe_key(KeyId=key_id)
        key_metadata = describe_response.get('KeyMetadata', {})
        
        key_usage = key_metadata.get('KeyUsage')
        key_spec = key_metadata.get('KeySpec', '')
        
        if (key_usage == 'SIGN_VERIFY' or 
            key_spec.startswith('RSA') or 
            key_spec.startswith('ECC')):
            
            public_key_response = kms_client.get_public_key(KeyId=key_id)
            return {
                "key_id": key_id,
                "public_key_info": {
                    "key_usage": public_key_response.get('KeyUsage'),
                    "key_spec": public_key_response.get('KeySpec'),
                    "signing_algorithms": public_key_response.get('SigningAlgorithms', []),
                    "encryption_algorithms": public_key_response.get('EncryptionAlgorithms', [])
                }
            }
    except Exception as e:
        print(f"Error getting public key for key {key.get('KeyId', 'unknown')}: {str(e)}")
    return None

def get_key_tags(kms_client, key):
    """
    개별 키 태그 조회
    """
    try:
        key_id = key['KeyId']
        tags_response = kms_client.list_resource_tags(KeyId=key_id)
        return {
            "key_id": key_id,
            "tags": tags_response.get('Tags', [])
        }
    except Exception as e:
        print(f"Error listing tags for key {key.get('KeyId', 'unknown')}: {str(e)}")
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
