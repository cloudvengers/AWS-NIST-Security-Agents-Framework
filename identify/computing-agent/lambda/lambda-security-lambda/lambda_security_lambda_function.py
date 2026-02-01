import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 Lambda Security Analysis Lambda 함수
    15개 Lambda API를 통한 종합적인 Lambda 보안 상태 분석
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
        
        lambda_client = session.client('lambda', region_name=target_region)
        
        # Lambda 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_lambda_security_data_parallel(lambda_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeLambdaSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Lambda 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in Lambda security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_lambda_security_data_parallel(client, target_region, current_time):
    """
    Lambda 보안 데이터를 병렬로 수집 - 15개 API 활용
    """
    # 먼저 계정 설정 및 함수 목록 조회
    try:
        account_settings = client.get_account_settings()
        functions_response = client.list_functions()
        all_functions = functions_response.get('Functions', [])
    except Exception as e:
        print(f"Error getting basic Lambda info: {str(e)}")
        return {
            'function': 'analyzeLambdaSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'Lambda 기본 정보 조회 실패: {str(e)}',
            'collection_summary': {
                'functions_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not all_functions:
        return {
            'function': 'analyzeLambdaSecurity',
            'target_region': target_region,
            'status': 'no_functions',
            'message': 'Lambda 함수가 존재하지 않습니다.',
            'account_settings': account_settings,
            'collection_summary': {
                'functions_found': 0,
                'apis_called': 2,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('functions_security_analysis', lambda: analyze_functions_security_parallel(client, all_functions)),
        ('account_level_settings', lambda: get_account_level_security_settings(client, account_settings)),
        ('global_security_configs', lambda: get_global_security_configurations(client)),
    ]
    
    # 병렬 처리 실행
    results = process_lambda_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'functions_analyzed': len(all_functions),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': calculate_total_lambda_apis_called(all_functions),
        'collection_method': 'parallel_processing',
        'function_names_analyzed': [f['FunctionName'] for f in all_functions[:10]]  # 최대 10개만 표시
    }
    
    return {
        'function': 'analyzeLambdaSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'functions_data': results.get('functions_security_analysis', {}),
        'account_settings': results.get('account_level_settings', {}),
        'global_configs': results.get('global_security_configs', {}),
        'collection_summary': collection_summary
    }

def process_lambda_parallel(tasks, max_workers=3):
    """Lambda 데이터 수집 작업을 병렬로 처리"""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                results[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                results[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def analyze_functions_security_parallel(client, functions, max_workers=5):
    """함수들의 보안 설정을 병렬로 분석"""
    function_analyses = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_function_security, client, function) for function in functions]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    function_analyses.append(result)
            except Exception as e:
                print(f"Error analyzing function: {str(e)}")
                continue
    
    return {
        'total_functions_analyzed': len(function_analyses),
        'function_security_details': function_analyses
    }

def analyze_single_function_security(client, function):
    """개별 함수의 보안 설정 종합 분석 - 11개 API 사용"""
    function_name = function['FunctionName']
    
    try:
        # 함수 기본 보안 설정 (2개 API)
        basic_security_data = get_function_basic_security_parallel(client, function_name)
        
        # 접근 제어 및 권한 관리 (2개 API)
        access_control_data = get_function_access_control_parallel(client, function_name)
        
        # 외부 노출 및 URL 보안 (2개 API)
        url_security_data = get_function_url_security_parallel(client, function_name)
        
        # 이벤트 및 호출 보안 (3개 API)
        event_security_data = get_function_event_security_parallel(client, function_name)
        
        # 코드 무결성 및 서명 (1개 API)
        code_security_data = get_function_code_security_parallel(client, function_name)
        
        # 런타임 및 재귀 보안 (2개 API)
        runtime_security_data = get_function_runtime_security_parallel(client, function_name)
        
        return {
            'function_name': function_name,
            'function_arn': function.get('FunctionArn'),
            'runtime': function.get('Runtime'),
            'state': function.get('State'),
            'basic_security': basic_security_data,
            'access_control': access_control_data,
            'url_security': url_security_data,
            'event_security': event_security_data,
            'code_security': code_security_data,
            'runtime_security': runtime_security_data
        }
        
    except Exception as e:
        print(f"Error analyzing function {function_name}: {str(e)}")
        return {
            'function_name': function_name,
            'status': 'error',
            'error_message': str(e)
        }
def get_function_basic_security_parallel(client, function_name):
    """함수 기본 보안 설정 API (2개) 병렬 수집"""
    basic_tasks = [
        ('function_details', lambda: get_function_safe(client, function_name)),
        ('function_configuration', lambda: get_function_configuration_safe(client, function_name))
    ]
    
    return execute_parallel_tasks(basic_tasks, max_workers=2)

def get_function_access_control_parallel(client, function_name):
    """접근 제어 및 권한 관리 API (2개) 병렬 수집"""
    access_tasks = [
        ('policy', lambda: get_policy_safe(client, function_name)),
        ('tags', lambda: list_tags_safe(client, function_name))
    ]
    
    return execute_parallel_tasks(access_tasks, max_workers=2)

def get_function_url_security_parallel(client, function_name):
    """외부 노출 및 URL 보안 API (2개) 병렬 수집"""
    url_tasks = [
        ('function_url_config', lambda: get_function_url_config_safe(client, function_name)),
        ('function_url_list', lambda: list_function_url_configs_safe(client, function_name))
    ]
    
    return execute_parallel_tasks(url_tasks, max_workers=2)

def get_function_event_security_parallel(client, function_name):
    """이벤트 및 호출 보안 API (3개) 병렬 수집"""
    event_tasks = [
        ('event_invoke_config', lambda: get_function_event_invoke_config_safe(client, function_name)),
        ('event_source_mappings', lambda: list_event_source_mappings_safe(client, function_name)),
        ('event_source_mapping_details', lambda: get_event_source_mapping_details_safe(client, function_name))
    ]
    
    return execute_parallel_tasks(event_tasks, max_workers=3)

def get_function_code_security_parallel(client, function_name):
    """코드 무결성 및 서명 API (1개) 수집"""
    code_tasks = [
        ('code_signing_config', lambda: get_function_code_signing_config_safe(client, function_name))
    ]
    
    return execute_parallel_tasks(code_tasks, max_workers=1)

def get_function_runtime_security_parallel(client, function_name):
    """런타임 및 재귀 보안 API (2개) 병렬 수집"""
    runtime_tasks = [
        ('runtime_management_config', lambda: get_runtime_management_config_safe(client, function_name)),
        ('recursion_config', lambda: get_function_recursion_config_safe(client, function_name))
    ]
    
    return execute_parallel_tasks(runtime_tasks, max_workers=2)

def execute_parallel_tasks(tasks, max_workers=5):
    """병렬 작업 실행 헬퍼 함수"""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                results[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                results[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

# 계정 및 함수 기본 보안 API 안전 호출 함수들
def get_function_safe(client, function_name):
    """GetFunction 안전 호출"""
    try:
        response = client.get_function(FunctionName=function_name)
        return {
            'configuration': response.get('Configuration', {}),
            'code': response.get('Code', {}),
            'tags': response.get('Tags', {}),
            'concurrency': response.get('Concurrency', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_function_configuration_safe(client, function_name):
    """GetFunctionConfiguration 안전 호출"""
    try:
        response = client.get_function_configuration(FunctionName=function_name)
        return {
            'function_arn': response.get('FunctionArn'),
            'role': response.get('Role'),
            'vpc_config': response.get('VpcConfig', {}),
            'environment': response.get('Environment', {}),
            'kms_key_arn': response.get('KMSKeyArn'),
            'tracing_config': response.get('TracingConfig', {}),
            'dead_letter_config': response.get('DeadLetterConfig', {}),
            'logging_config': response.get('LoggingConfig', {}),
            'layers': response.get('Layers', []),
            'file_system_configs': response.get('FileSystemConfigs', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 접근 제어 및 권한 관리 API 안전 호출 함수들
def get_policy_safe(client, function_name):
    """GetPolicy 안전 호출"""
    try:
        response = client.get_policy(FunctionName=function_name)
        policy_text = response.get('Policy', '{}')
        return {
            'has_policy': True,
            'policy': json.loads(policy_text) if policy_text else {},
            'policy_text': policy_text,
            'revision_id': response.get('RevisionId')
        }
    except client.exceptions.ResourceNotFoundException:
        return {'has_policy': False, 'message': '리소스 기반 정책이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_tags_safe(client, function_name):
    """ListTags 안전 호출"""
    try:
        response = client.list_tags(Resource=f"arn:aws:lambda:{client.meta.region_name}:{client.meta.service_model.metadata.get('signingName', 'lambda')}:function:{function_name}")
        return {
            'has_tags': True,
            'tags': response.get('Tags', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 외부 노출 및 URL 보안 API 안전 호출 함수들
def get_function_url_config_safe(client, function_name):
    """GetFunctionUrlConfig 안전 호출"""
    try:
        response = client.get_function_url_config(FunctionName=function_name)
        return {
            'has_function_url': True,
            'function_url': response.get('FunctionUrl'),
            'auth_type': response.get('AuthType'),
            'cors': response.get('Cors', {}),
            'creation_time': response.get('CreationTime'),
            'invoke_mode': response.get('InvokeMode')
        }
    except client.exceptions.ResourceNotFoundException:
        return {'has_function_url': False, 'message': '함수 URL이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_function_url_configs_safe(client, function_name):
    """ListFunctionUrlConfigs 안전 호출"""
    try:
        response = client.list_function_url_configs(FunctionName=function_name)
        return {
            'function_url_configs': response.get('FunctionUrlConfigs', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 이벤트 및 호출 보안 API 안전 호출 함수들
def get_function_event_invoke_config_safe(client, function_name):
    """GetFunctionEventInvokeConfig 안전 호출"""
    try:
        response = client.get_function_event_invoke_config(FunctionName=function_name)
        return {
            'has_event_invoke_config': True,
            'maximum_retry_attempts': response.get('MaximumRetryAttempts'),
            'maximum_event_age': response.get('MaximumEventAgeInSeconds'),
            'destination_config': response.get('DestinationConfig', {})
        }
    except client.exceptions.ResourceNotFoundException:
        return {'has_event_invoke_config': False, 'message': '이벤트 호출 구성이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_event_source_mappings_safe(client, function_name):
    """ListEventSourceMappings 안전 호출"""
    try:
        response = client.list_event_source_mappings(FunctionName=function_name)
        return {
            'event_source_mappings': response.get('EventSourceMappings', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_event_source_mapping_details_safe(client, function_name):
    """GetEventSourceMapping 상세 정보 안전 호출"""
    try:
        # 먼저 이벤트 소스 매핑 목록 조회
        mappings_response = client.list_event_source_mappings(FunctionName=function_name)
        mappings = mappings_response.get('EventSourceMappings', [])
        
        if not mappings:
            return {'has_event_source_mappings': False, 'message': '이벤트 소스 매핑이 없음'}
        
        # 각 매핑의 상세 정보 조회 (최대 5개)
        mapping_details = []
        for mapping in mappings[:5]:
            try:
                uuid = mapping.get('UUID')
                detail_response = client.get_event_source_mapping(UUID=uuid)
                mapping_details.append(detail_response)
            except Exception as e:
                print(f"Error getting event source mapping detail {uuid}: {str(e)}")
                continue
        
        return {
            'has_event_source_mappings': True,
            'total_mappings': len(mappings),
            'mapping_details': mapping_details
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
# 코드 무결성 및 서명 API 안전 호출 함수들
def get_function_code_signing_config_safe(client, function_name):
    """GetFunctionCodeSigningConfig 안전 호출"""
    try:
        response = client.get_function_code_signing_config(FunctionName=function_name)
        return {
            'has_code_signing_config': True,
            'code_signing_config_arn': response.get('CodeSigningConfigArn'),
            'function_name': response.get('FunctionName')
        }
    except client.exceptions.ResourceNotFoundException:
        return {'has_code_signing_config': False, 'message': '코드 서명 구성이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 런타임 및 재귀 보안 API 안전 호출 함수들
def get_runtime_management_config_safe(client, function_name):
    """GetRuntimeManagementConfig 안전 호출"""
    try:
        response = client.get_runtime_management_config(FunctionName=function_name)
        return {
            'update_runtime_on': response.get('UpdateRuntimeOn'),
            'runtime_version_arn': response.get('RuntimeVersionArn')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_function_recursion_config_safe(client, function_name):
    """GetFunctionRecursionConfig 안전 호출"""
    try:
        response = client.get_function_recursion_config(FunctionName=function_name)
        return {
            'recursive_loop': response.get('RecursiveLoop')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 계정 레벨 및 글로벌 설정 함수들
def get_account_level_security_settings(client, account_settings):
    """계정 레벨 보안 설정 조회"""
    try:
        return {
            'account_limit': account_settings.get('AccountLimit', {}),
            'account_usage': account_settings.get('AccountUsage', {}),
            'security_analysis': {
                'concurrent_executions_limit': account_settings.get('AccountLimit', {}).get('ConcurrentExecutions', 0),
                'unreserved_concurrent_executions': account_settings.get('AccountLimit', {}).get('UnreservedConcurrentExecutions', 0),
                'total_code_size_limit': account_settings.get('AccountLimit', {}).get('TotalCodeSize', 0),
                'current_function_count': account_settings.get('AccountUsage', {}).get('FunctionCount', 0),
                'current_total_code_size': account_settings.get('AccountUsage', {}).get('TotalCodeSize', 0)
            }
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_global_security_configurations(client):
    """글로벌 보안 구성 조회"""
    try:
        # 코드 서명 구성 목록 조회
        code_signing_configs = []
        try:
            response = client.list_code_signing_configs()
            code_signing_configs = response.get('CodeSigningConfigs', [])
        except Exception as e:
            print(f"Error listing code signing configs: {str(e)}")
        
        # 각 코드 서명 구성의 상세 정보 조회
        code_signing_details = []
        for config in code_signing_configs[:5]:  # 최대 5개만
            try:
                config_arn = config.get('CodeSigningConfigArn')
                detail_response = client.get_code_signing_config(CodeSigningConfigArn=config_arn)
                code_signing_details.append(detail_response.get('CodeSigningConfig', {}))
            except Exception as e:
                print(f"Error getting code signing config detail: {str(e)}")
                continue
        
        return {
            'code_signing_configs': {
                'total_configs': len(code_signing_configs),
                'config_details': code_signing_details
            }
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 헬퍼 함수들
def calculate_total_lambda_apis_called(functions):
    """총 API 호출 수 계산"""
    # 기본 API: GetAccountSettings(1) + ListFunctions(1) + ListCodeSigningConfigs(1)
    base_apis = 3
    
    # 함수당 API: 11개 (기본보안 2 + 접근제어 2 + URL보안 2 + 이벤트보안 3 + 코드보안 1 + 런타임보안 2)
    # 추가로 이벤트 소스 매핑이 있는 경우 추가 API 호출
    function_apis = len(functions) * 11
    
    # 코드 서명 구성 상세 조회 (최대 5개)
    code_signing_apis = min(5, len(functions))
    
    return base_apis + function_apis + code_signing_apis

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
        'function': event.get('function', 'analyzeLambdaSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'lambda-security-analysis'),
        'function': event.get('function', 'analyzeLambdaSecurity'),
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
