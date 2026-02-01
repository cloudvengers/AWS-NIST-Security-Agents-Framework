import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    PROTECT-AGENT ACM Lambda 함수 - 병렬 처리 구조
    단순히 ACM API 호출 결과만 반환, 분석은 Agent가 수행
    """
    
    print(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        # Bedrock Agent에서 전달된 파라미터 추출
        function_name = event.get('function', '')
        parameters = event.get('parameters', [])
        session_attributes = event.get('sessionAttributes', {})
        
        if function_name != 'analyzeAcmSecurity':
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
        
        acm_client = session.client('acm', region_name=target_region)
        
        # ACM API 호출 - 병렬 원시 데이터 수집
        raw_data = collect_acm_raw_data_parallel(acm_client, target_region, current_time)
        
        # Bedrock Agent 형식에 맞는 성공 응답 반환
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_msg = f"ACM data collection failed: {str(e)}"
        print(f"Error: {error_msg}")
        return create_bedrock_error_response(event, error_msg)

def collect_acm_raw_data_parallel(acm_client, target_region, current_time):
    """
    ACM 원시 데이터 수집 - 병렬 처리
    """
    raw_data = {
        "function": "analyzeAcmSecurity",
        "target_region": target_region,
        "collection_timestamp": current_time,
        "analysis_time": current_time,
        "certificates": [],
        "certificate_details": [],
        "certificate_tags": [],
        "account_configuration": None
    }
    
    try:
        # 1. 인증서 목록 조회
        list_response = acm_client.list_certificates()
        certificates = list_response.get('CertificateSummaryList', [])
        raw_data["certificates"] = certificates
        
        if not certificates:
            return raw_data
        
        # 2. 각 인증서별 상세 정보 병렬 수집
        raw_data["certificate_details"] = process_certificates_parallel(
            acm_client, certificates, get_certificate_details, max_workers=5
        )
        
        raw_data["certificate_tags"] = process_certificates_parallel(
            acm_client, certificates, get_certificate_tags, max_workers=5
        )
        
        # 3. 계정 설정 조회
        try:
            account_config = acm_client.get_account_configuration()
            raw_data["account_configuration"] = account_config
        except Exception as e:
            print(f"Error getting account configuration: {str(e)}")
        
        # 4. 데이터 수집 요약
        raw_data["collection_summary"] = {
            "total_certificates_found": len(certificates),
            "successful_details": len(raw_data["certificate_details"]),
            "successful_tags": len(raw_data["certificate_tags"]),
            "target_region": acm_client.meta.region_name,
            "processing_method": "parallel"
        }
        
    except Exception as e:
        print(f"Error collecting ACM data: {str(e)}")
        raw_data["error"] = str(e)
    
    return raw_data

def process_certificates_parallel(acm_client, certificates, process_func, max_workers=5):
    """
    인증서 목록을 병렬로 처리하는 함수
    """
    if not certificates:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, acm_client, cert) for cert in certificates]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing certificate: {str(e)}")
                continue
    
    return results

def get_certificate_details(acm_client, certificate):
    """
    개별 인증서 상세 정보 조회
    """
    try:
        cert_arn = certificate['CertificateArn']
        detail_response = acm_client.describe_certificate(CertificateArn=cert_arn)
        return {
            "certificate_arn": cert_arn,
            "details": detail_response.get('Certificate', {})
        }
    except Exception as e:
        print(f"Error getting details for certificate {certificate.get('CertificateArn', 'unknown')}: {str(e)}")
        return None

def get_certificate_tags(acm_client, certificate):
    """
    개별 인증서 태그 조회
    """
    try:
        cert_arn = certificate['CertificateArn']
        tags_response = acm_client.list_tags_for_certificate(CertificateArn=cert_arn)
        return {
            "certificate_arn": cert_arn,
            "tags": tags_response.get('Tags', [])
        }
    except Exception as e:
        print(f"Error getting tags for certificate {certificate.get('CertificateArn', 'unknown')}: {str(e)}")
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
