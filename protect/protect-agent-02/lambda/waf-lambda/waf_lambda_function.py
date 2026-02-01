import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    PROTECT-AGENT WAF Lambda 함수 - 병렬 처리 구조
    단순히 WAF API 호출 결과만 반환, 분석은 Agent가 수행
    """
    
    print(f"Received event: {json.dumps(event, indent=2)}")
    
    try:
        # Bedrock Agent에서 전달된 파라미터 추출
        function_name = event.get('function', '')
        parameters = event.get('parameters', [])
        session_attributes = event.get('sessionAttributes', {})
        
        if function_name != 'analyzeWafSecurity':
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
        
        wafv2_client = session.client('wafv2', region_name=target_region)
        
        # WAF API 호출 - 병렬 원시 데이터 수집
        raw_data = collect_waf_raw_data_parallel(wafv2_client, target_region, current_time)
        
        # Bedrock Agent 형식에 맞는 성공 응답 반환
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_msg = f"WAF data collection failed: {str(e)}"
        print(f"Error: {error_msg}")
        return create_bedrock_error_response(event, error_msg)

def collect_waf_raw_data_parallel(wafv2_client, target_region, current_time):
    """
    WAF 원시 데이터 수집 - 병렬 처리
    """
    raw_data = {
        "function": "analyzeWafSecurity",
        "target_region": target_region,
        "collection_timestamp": current_time,
        "analysis_time": current_time,
        "web_acls": [],
        "web_acl_details": [],
        "rule_groups": [],
        "rule_group_details": [],
        "ip_sets": [],
        "ip_set_details": [],
        "regex_pattern_sets": [],
        "regex_pattern_details": [],
        "logging_configurations": [],
        "resource_tags": []
    }
    
    try:
        # 1. 스코프별 Web ACL 목록 조회 (병렬)
        scopes = ['REGIONAL']
        if target_region == 'us-east-1':
            scopes.append('CLOUDFRONT')
        
        all_web_acls = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            scope_futures = {
                executor.submit(get_web_acls_by_scope, wafv2_client, scope): scope 
                for scope in scopes
            }
            
            for future in concurrent.futures.as_completed(scope_futures):
                scope = scope_futures[future]
                try:
                    web_acls = future.result()
                    for acl in web_acls:
                        acl['Scope'] = scope  # 스코프 정보 추가
                        all_web_acls.append(acl)
                except Exception as e:
                    print(f"Error getting Web ACLs for scope {scope}: {str(e)}")
        
        raw_data["web_acls"] = all_web_acls
        
        # 2. Web ACL 상세 정보 병렬 수집
        if all_web_acls:
            raw_data["web_acl_details"] = process_web_acls_parallel(
                wafv2_client, all_web_acls, get_web_acl_details, max_workers=5
            )
            
            raw_data["resource_tags"] = process_web_acls_parallel(
                wafv2_client, all_web_acls, get_web_acl_tags, max_workers=5
            )
        
        # 3. 스코프별 Rule Group 목록 조회 (병렬)
        all_rule_groups = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            scope_futures = {
                executor.submit(get_rule_groups_by_scope, wafv2_client, scope): scope 
                for scope in scopes
            }
            
            for future in concurrent.futures.as_completed(scope_futures):
                scope = scope_futures[future]
                try:
                    rule_groups = future.result()
                    for rg in rule_groups:
                        rg['Scope'] = scope  # 스코프 정보 추가
                        all_rule_groups.append(rg)
                except Exception as e:
                    print(f"Error getting Rule Groups for scope {scope}: {str(e)}")
        
        raw_data["rule_groups"] = all_rule_groups
        
        # 4. Rule Group 상세 정보 병렬 수집
        if all_rule_groups:
            raw_data["rule_group_details"] = process_rule_groups_parallel(
                wafv2_client, all_rule_groups, get_rule_group_details, max_workers=5
            )
        
        # 5. 스코프별 IP Set 목록 조회 (병렬)
        all_ip_sets = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            scope_futures = {
                executor.submit(get_ip_sets_by_scope, wafv2_client, scope): scope 
                for scope in scopes
            }
            
            for future in concurrent.futures.as_completed(scope_futures):
                scope = scope_futures[future]
                try:
                    ip_sets = future.result()
                    for ip_set in ip_sets:
                        ip_set['Scope'] = scope  # 스코프 정보 추가
                        all_ip_sets.append(ip_set)
                except Exception as e:
                    print(f"Error getting IP Sets for scope {scope}: {str(e)}")
        
        raw_data["ip_sets"] = all_ip_sets
        
        # 6. IP Set 상세 정보 병렬 수집
        if all_ip_sets:
            raw_data["ip_set_details"] = process_ip_sets_parallel(
                wafv2_client, all_ip_sets, get_ip_set_details, max_workers=5
            )
        
        # 7. 스코프별 Regex Pattern Set 목록 조회 (병렬)
        all_regex_patterns = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            scope_futures = {
                executor.submit(get_regex_patterns_by_scope, wafv2_client, scope): scope 
                for scope in scopes
            }
            
            for future in concurrent.futures.as_completed(scope_futures):
                scope = scope_futures[future]
                try:
                    regex_patterns = future.result()
                    for pattern in regex_patterns:
                        pattern['Scope'] = scope  # 스코프 정보 추가
                        all_regex_patterns.append(pattern)
                except Exception as e:
                    print(f"Error getting Regex Patterns for scope {scope}: {str(e)}")
        
        raw_data["regex_pattern_sets"] = all_regex_patterns
        
        # 8. Regex Pattern 상세 정보 병렬 수집
        if all_regex_patterns:
            raw_data["regex_pattern_details"] = process_regex_patterns_parallel(
                wafv2_client, all_regex_patterns, get_regex_pattern_details, max_workers=5
            )
        
        # 9. 로깅 설정 조회
        try:
            logging_response = wafv2_client.list_logging_configurations()
            raw_data["logging_configurations"] = logging_response.get('LoggingConfigurations', [])
        except Exception as e:
            print(f"Error listing logging configurations: {str(e)}")
        
        # 10. 데이터 수집 요약
        raw_data["collection_summary"] = {
            "total_web_acls": len(all_web_acls),
            "total_rule_groups": len(all_rule_groups),
            "total_ip_sets": len(all_ip_sets),
            "total_regex_patterns": len(all_regex_patterns),
            "successful_web_acl_details": len(raw_data["web_acl_details"]),
            "successful_tags": len(raw_data["resource_tags"]),
            "logging_configurations": len(raw_data["logging_configurations"]),
            "scopes_checked": scopes,
            "target_region": target_region,
            "processing_method": "parallel"
        }
        
    except Exception as e:
        print(f"Error collecting WAF data: {str(e)}")
        raw_data["error"] = str(e)
    
    return raw_data

def get_web_acls_by_scope(wafv2_client, scope):
    """스코프별 Web ACL 목록 조회"""
    try:
        response = wafv2_client.list_web_acls(Scope=scope)
        return response.get('WebACLs', [])
    except Exception as e:
        print(f"Error listing Web ACLs for scope {scope}: {str(e)}")
        return []

def get_rule_groups_by_scope(wafv2_client, scope):
    """스코프별 Rule Group 목록 조회"""
    try:
        response = wafv2_client.list_rule_groups(Scope=scope)
        return response.get('RuleGroups', [])
    except Exception as e:
        print(f"Error listing Rule Groups for scope {scope}: {str(e)}")
        return []

def get_ip_sets_by_scope(wafv2_client, scope):
    """스코프별 IP Set 목록 조회"""
    try:
        response = wafv2_client.list_ip_sets(Scope=scope)
        return response.get('IPSets', [])
    except Exception as e:
        print(f"Error listing IP Sets for scope {scope}: {str(e)}")
        return []

def get_regex_patterns_by_scope(wafv2_client, scope):
    """스코프별 Regex Pattern Set 목록 조회"""
    try:
        response = wafv2_client.list_regex_pattern_sets(Scope=scope)
        return response.get('RegexPatternSets', [])
    except Exception as e:
        print(f"Error listing Regex Pattern Sets for scope {scope}: {str(e)}")
        return []

def process_web_acls_parallel(wafv2_client, web_acls, process_func, max_workers=5):
    """Web ACL 목록을 병렬로 처리"""
    if not web_acls:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, wafv2_client, acl) for acl in web_acls]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing Web ACL: {str(e)}")
                continue
    
    return results

def process_rule_groups_parallel(wafv2_client, rule_groups, process_func, max_workers=5):
    """Rule Group 목록을 병렬로 처리"""
    if not rule_groups:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, wafv2_client, rg) for rg in rule_groups]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing Rule Group: {str(e)}")
                continue
    
    return results

def process_ip_sets_parallel(wafv2_client, ip_sets, process_func, max_workers=5):
    """IP Set 목록을 병렬로 처리"""
    if not ip_sets:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, wafv2_client, ip_set) for ip_set in ip_sets]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing IP Set: {str(e)}")
                continue
    
    return results

def process_regex_patterns_parallel(wafv2_client, regex_patterns, process_func, max_workers=5):
    """Regex Pattern Set 목록을 병렬로 처리"""
    if not regex_patterns:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_func, wafv2_client, pattern) for pattern in regex_patterns]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing Regex Pattern: {str(e)}")
                continue
    
    return results

def get_web_acl_details(wafv2_client, web_acl):
    """개별 Web ACL 상세 정보 조회"""
    try:
        response = wafv2_client.get_web_acl(
            Name=web_acl['Name'],
            Scope=web_acl['Scope'],
            Id=web_acl['Id']
        )
        return {
            "web_acl_id": web_acl['Id'],
            "web_acl_name": web_acl['Name'],
            "scope": web_acl['Scope'],
            "details": response.get('WebACL', {})
        }
    except Exception as e:
        print(f"Error getting Web ACL details for {web_acl.get('Name', 'unknown')}: {str(e)}")
        return None

def get_web_acl_tags(wafv2_client, web_acl):
    """개별 Web ACL 태그 조회"""
    try:
        response = wafv2_client.list_tags_for_resource(
            ResourceARN=web_acl['ARN']
        )
        return {
            "web_acl_id": web_acl['Id'],
            "web_acl_name": web_acl['Name'],
            "scope": web_acl['Scope'],
            "tags": response.get('TagList', {}).get('Tags', [])
        }
    except Exception as e:
        print(f"Error getting Web ACL tags for {web_acl.get('Name', 'unknown')}: {str(e)}")
        return None

def get_rule_group_details(wafv2_client, rule_group):
    """개별 Rule Group 상세 정보 조회"""
    try:
        response = wafv2_client.get_rule_group(
            Name=rule_group['Name'],
            Scope=rule_group['Scope'],
            Id=rule_group['Id']
        )
        return {
            "rule_group_id": rule_group['Id'],
            "rule_group_name": rule_group['Name'],
            "scope": rule_group['Scope'],
            "details": response.get('RuleGroup', {})
        }
    except Exception as e:
        print(f"Error getting Rule Group details for {rule_group.get('Name', 'unknown')}: {str(e)}")
        return None

def get_ip_set_details(wafv2_client, ip_set):
    """개별 IP Set 상세 정보 조회"""
    try:
        response = wafv2_client.get_ip_set(
            Name=ip_set['Name'],
            Scope=ip_set['Scope'],
            Id=ip_set['Id']
        )
        return {
            "ip_set_id": ip_set['Id'],
            "ip_set_name": ip_set['Name'],
            "scope": ip_set['Scope'],
            "details": response.get('IPSet', {})
        }
    except Exception as e:
        print(f"Error getting IP Set details for {ip_set.get('Name', 'unknown')}: {str(e)}")
        return None

def get_regex_pattern_details(wafv2_client, regex_pattern):
    """개별 Regex Pattern Set 상세 정보 조회"""
    try:
        response = wafv2_client.get_regex_pattern_set(
            Name=regex_pattern['Name'],
            Scope=regex_pattern['Scope'],
            Id=regex_pattern['Id']
        )
        return {
            "regex_pattern_id": regex_pattern['Id'],
            "regex_pattern_name": regex_pattern['Name'],
            "scope": regex_pattern['Scope'],
            "details": response.get('RegexPatternSet', {})
        }
    except Exception as e:
        print(f"Error getting Regex Pattern details for {regex_pattern.get('Name', 'unknown')}: {str(e)}")
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
