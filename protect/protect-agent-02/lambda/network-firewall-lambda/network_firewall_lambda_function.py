import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    PROTECT-AGENT Network Firewall Lambda 함수 - 병렬 처리 구조
    단순히 Network Firewall API 호출 결과만 반환, 분석은 Agent가 수행
    """
    
    print(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        # Bedrock Agent에서 전달된 파라미터 추출
        function_name = event.get('function', '')
        parameters = event.get('parameters', [])
        session_attributes = event.get('sessionAttributes', {})
        
        if function_name != 'analyzeNetworkFirewallSecurity':
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
        
        network_firewall_client = session.client('network-firewall', region_name=target_region)
        
        # Network Firewall API 호출 - 병렬 원시 데이터 수집
        raw_data = collect_network_firewall_raw_data_parallel(network_firewall_client, target_region, current_time)
        
        # Bedrock Agent 형식에 맞는 성공 응답 반환
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_msg = f"Network Firewall data collection failed: {str(e)}"
        print(f"Error: {error_msg}")
        return create_bedrock_error_response(event, error_msg)

def collect_network_firewall_raw_data_parallel(network_firewall_client, target_region, current_time):
    """
    Network Firewall 원시 데이터 수집 - 병렬 처리
    """
    raw_data = {
        "function": "analyzeNetworkFirewallSecurity",
        "target_region": target_region,
        "collection_timestamp": current_time,
        "analysis_time": current_time,
        "firewalls": [],
        "firewall_details": [],
        "firewall_policies": [],
        "firewall_policy_details": [],
        "rule_groups": [],
        "rule_group_details": [],
        "tls_inspection_configurations": [],
        "tls_inspection_details": [],
        "logging_configurations": []
    }
    
    try:
        # 1. 방화벽 목록 조회
        list_response = network_firewall_client.list_firewalls()
        firewalls = list_response.get('Firewalls', [])
        raw_data["firewalls"] = firewalls
        
        # 2. 각 방화벽별 상세 정보 병렬 수집
        if firewalls:
            raw_data["firewall_details"] = process_firewalls_parallel(
                network_firewall_client, firewalls, get_firewall_details, max_workers=5
            )
            
            raw_data["logging_configurations"] = process_firewalls_parallel(
                network_firewall_client, firewalls, get_firewall_logging_config, max_workers=5
            )
        
        # 3. 방화벽 정책 목록 조회
        policies_response = network_firewall_client.list_firewall_policies()
        firewall_policies = policies_response.get('FirewallPolicies', [])
        raw_data["firewall_policies"] = firewall_policies
        
        # 4. 각 방화벽 정책별 상세 정보 병렬 수집
        if firewall_policies:
            raw_data["firewall_policy_details"] = process_firewall_policies_parallel(
                network_firewall_client, firewall_policies, get_firewall_policy_details, max_workers=5
            )
        
        # 5. 규칙 그룹 목록 조회
        rule_groups_response = network_firewall_client.list_rule_groups()
        rule_groups = rule_groups_response.get('RuleGroups', [])
        raw_data["rule_groups"] = rule_groups
        
        # 6. 각 규칙 그룹별 상세 정보 병렬 수집
        if rule_groups:
            raw_data["rule_group_details"] = process_rule_groups_parallel(
                network_firewall_client, rule_groups, get_rule_group_details, max_workers=5
            )
        
        # 7. TLS 검사 설정 목록 조회
        try:
            tls_response = network_firewall_client.list_tls_inspection_configurations()
            tls_configurations = tls_response.get('TLSInspectionConfigurations', [])
            raw_data["tls_inspection_configurations"] = tls_configurations
            
            # 8. 각 TLS 검사 설정별 상세 정보 병렬 수집
            if tls_configurations:
                raw_data["tls_inspection_details"] = process_tls_configurations_parallel(
                    network_firewall_client, tls_configurations, get_tls_inspection_details, max_workers=5
                )
        except Exception as e:
            print(f"Error listing TLS inspection configurations: {str(e)}")
            # TLS 검사 기능이 지원되지 않는 리전일 수 있음
        
        # 9. 데이터 수집 요약
        raw_data["collection_summary"] = {
            "total_firewalls": len(firewalls),
            "total_firewall_policies": len(firewall_policies),
            "total_rule_groups": len(rule_groups),
            "total_tls_configurations": len(raw_data["tls_inspection_configurations"]),
            "successful_firewall_details": len(raw_data["firewall_details"]),
            "successful_policy_details": len(raw_data["firewall_policy_details"]),
            "successful_rule_group_details": len(raw_data["rule_group_details"]),
            "successful_logging_configs": len(raw_data["logging_configurations"]),
            "target_region": network_firewall_client.meta.region_name,
            "processing_method": "parallel"
        }
        
    except Exception as e:
        print(f"Error collecting Network Firewall data: {str(e)}")
        raw_data["error"] = str(e)
    
    return raw_data

def process_firewalls_parallel(network_firewall_client, firewalls, process_func, max_workers=5):
    """방화벽 목록을 병렬로 처리"""
    if not firewalls:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, network_firewall_client, firewall) for firewall in firewalls]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing firewall: {str(e)}")
                continue
    
    return results

def process_firewall_policies_parallel(network_firewall_client, policies, process_func, max_workers=5):
    """방화벽 정책 목록을 병렬로 처리"""
    if not policies:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, network_firewall_client, policy) for policy in policies]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing firewall policy: {str(e)}")
                continue
    
    return results

def process_rule_groups_parallel(network_firewall_client, rule_groups, process_func, max_workers=5):
    """규칙 그룹 목록을 병렬로 처리"""
    if not rule_groups:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, network_firewall_client, rule_group) for rule_group in rule_groups]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing rule group: {str(e)}")
                continue
    
    return results

def process_tls_configurations_parallel(network_firewall_client, tls_configs, process_func, max_workers=5):
    """TLS 검사 설정 목록을 병렬로 처리"""
    if not tls_configs:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, network_firewall_client, tls_config) for tls_config in tls_configs]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing TLS configuration: {str(e)}")
                continue
    
    return results

def get_firewall_details(network_firewall_client, firewall):
    """개별 방화벽 상세 정보 조회"""
    try:
        firewall_name = firewall['FirewallName']
        firewall_arn = firewall['FirewallArn']
        
        describe_response = network_firewall_client.describe_firewall(
            FirewallName=firewall_name
        )
        
        # 메타데이터도 함께 조회
        metadata_response = network_firewall_client.describe_firewall_metadata(
            FirewallName=firewall_name
        )
        
        return {
            "firewall_name": firewall_name,
            "firewall_arn": firewall_arn,
            "details": describe_response,
            "metadata": metadata_response
        }
    except Exception as e:
        print(f"Error getting firewall details for {firewall.get('FirewallName', 'unknown')}: {str(e)}")
        return None

def get_firewall_logging_config(network_firewall_client, firewall):
    """개별 방화벽 로깅 설정 조회"""
    try:
        firewall_name = firewall['FirewallName']
        firewall_arn = firewall['FirewallArn']
        
        logging_response = network_firewall_client.describe_logging_configuration(
            FirewallName=firewall_name
        )
        
        return {
            "firewall_name": firewall_name,
            "firewall_arn": firewall_arn,
            "logging_configuration": logging_response.get('LoggingConfiguration', {})
        }
    except Exception as e:
        print(f"Error getting logging config for firewall {firewall.get('FirewallName', 'unknown')}: {str(e)}")
        return None

def get_firewall_policy_details(network_firewall_client, policy):
    """개별 방화벽 정책 상세 정보 조회"""
    try:
        policy_name = policy['Name']
        policy_arn = policy['Arn']
        
        describe_response = network_firewall_client.describe_firewall_policy(
            FirewallPolicyName=policy_name
        )
        
        return {
            "policy_name": policy_name,
            "policy_arn": policy_arn,
            "details": describe_response
        }
    except Exception as e:
        print(f"Error getting firewall policy details for {policy.get('Name', 'unknown')}: {str(e)}")
        return None

def get_rule_group_details(network_firewall_client, rule_group):
    """개별 규칙 그룹 상세 정보 조회"""
    try:
        rule_group_name = rule_group['Name']
        rule_group_arn = rule_group['Arn']
        rule_group_type = rule_group.get('Type', 'STATEFUL')  # 기본값 설정
        
        describe_response = network_firewall_client.describe_rule_group(
            RuleGroupName=rule_group_name,
            Type=rule_group_type
        )
        
        return {
            "rule_group_name": rule_group_name,
            "rule_group_arn": rule_group_arn,
            "rule_group_type": rule_group_type,
            "details": describe_response
        }
    except Exception as e:
        print(f"Error getting rule group details for {rule_group.get('Name', 'unknown')}: {str(e)}")
        return None

def get_tls_inspection_details(network_firewall_client, tls_config):
    """개별 TLS 검사 설정 상세 정보 조회"""
    try:
        tls_config_name = tls_config['Name']
        tls_config_arn = tls_config['Arn']
        
        describe_response = network_firewall_client.describe_tls_inspection_configuration(
            TLSInspectionConfigurationName=tls_config_name
        )
        
        return {
            "tls_config_name": tls_config_name,
            "tls_config_arn": tls_config_arn,
            "details": describe_response
        }
    except Exception as e:
        print(f"Error getting TLS inspection details for {tls_config.get('Name', 'unknown')}: {str(e)}")
        return None

def create_bedrock_success_response(event, response_data):
    """Bedrock Agent 성공 응답 생성 (Function Details 방식)"""
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
    """Bedrock Agent 에러 응답 생성 (Function Details 방식)"""
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
