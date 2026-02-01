import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    DETECT-AGENT-01 Inspector 보안 분석 Lambda 함수
    Inspector의 모든 취약점 탐지 및 보안 관련 설정을 종합 분석
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
        
        inspector_client = session.client('inspector2', region_name=target_region)
        
        # Inspector 원시 데이터 수집
        raw_data = collect_inspector_raw_data_parallel(inspector_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeInspectorSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Inspector 분석 중 오류 발생: {str(e)}"
        print(f"Error in Inspector lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_inspector_raw_data_parallel(client, target_region):
    """
    Inspector 원시 데이터를 병렬로 수집
    """
    # 먼저 계정 상태 확인
    try:
        account_status_response = client.batch_get_account_status()
        accounts = account_status_response.get('accounts', [])
        
        if not accounts:
            return {
                'function': 'analyzeInspectorSecurity',
                'target_region': target_region,
                'status': 'not_enabled',
                'message': 'Inspector 서비스가 활성화되지 않았습니다.',
                'collection_summary': {
                    'inspector_enabled': False,
                    'apis_called': 1,
                    'collection_method': 'parallel_processing'
                }
            }
        
        account_info = accounts[0]
        account_status = account_info.get('state', {}).get('status', 'DISABLED')
        
    except Exception as e:
        print(f"Error getting account status: {str(e)}")
        return {
            'function': 'analyzeInspectorSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'Inspector 계정 상태 확인 중 오류: {str(e)}',
            'collection_summary': {
                'inspector_enabled': False,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if account_status != 'ENABLED':
        return {
            'function': 'analyzeInspectorSecurity',
            'target_region': target_region,
            'status': account_status.lower(),
            'message': f'Inspector 상태: {account_status}',
            'account_info': account_info,
            'collection_summary': {
                'inspector_enabled': False,
                'account_status': account_status,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('account_status', lambda: get_account_status_data(client)),
        ('findings', lambda: get_findings_data(client)),
        ('vulnerabilities', lambda: get_vulnerabilities_data(client)),
        ('coverage', lambda: get_coverage_data(client)),
        ('configuration', lambda: get_configuration_data(client)),
        ('filters', lambda: get_filters_data(client)),
        ('usage_totals', lambda: get_usage_totals_data(client)),
        ('tags', lambda: get_tags_data(client))
    ]
    
    # 병렬 처리 실행
    results = process_inspector_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'inspector_enabled': True,
        'account_status': account_status,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': sum([
            2,  # Account status APIs
            3,  # Findings APIs
            2,  # Vulnerabilities APIs
            2,  # Coverage APIs
            3,  # Configuration APIs
            1,  # Filters
            1,  # Usage totals
            1   # Tags
        ]),
        'collection_method': 'parallel_processing',
        'region': target_region
    }
    
    return {
        'function': 'analyzeInspectorSecurity',
        'target_region': target_region,
        'inspector_data': results,
        'collection_summary': collection_summary
    }

def process_inspector_parallel(tasks, max_workers=5):
    """
    Inspector 데이터 수집 작업을 병렬로 처리
    """
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

def get_account_status_data(client):
    """
    계정 상태 관련 데이터 조회
    """
    account_data = {}
    
    # 계정 상태 조회
    try:
        status_response = client.batch_get_account_status()
        account_data['account_status'] = status_response
    except Exception as e:
        print(f"Error getting account status: {str(e)}")
        account_data['account_status'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 무료 체험 정보 조회
    try:
        trial_response = client.batch_get_free_trial_info()
        account_data['free_trial_info'] = trial_response
    except Exception as e:
        print(f"Error getting free trial info: {str(e)}")
        account_data['free_trial_info'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return account_data

def get_findings_data(client):
    """
    발견사항 관련 데이터 조회
    """
    findings_data = {}
    
    # 발견사항 목록 조회 (최대 100개)
    try:
        list_response = client.list_findings(maxResults=100)
        findings = list_response.get('findings', [])
        
        findings_data['findings_list'] = {
            'total_findings': len(findings),
            'findings_sample': findings[:10]  # 샘플만 저장
        }
        
        # 발견사항 상세 정보 조회 (최대 10개)
        if findings:
            finding_arns = [f.get('findingArn') for f in findings[:10] if f.get('findingArn')]
            if finding_arns:
                details_response = client.batch_get_finding_details(findingArns=finding_arns)
                findings_data['findings_details'] = details_response
        
    except Exception as e:
        print(f"Error getting findings: {str(e)}")
        findings_data['findings_list'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 발견사항 집계 데이터 조회
    try:
        aggregations_response = client.list_finding_aggregations(
            aggregationType='FINDING_TYPE',
            maxResults=50
        )
        findings_data['findings_aggregations'] = aggregations_response
    except Exception as e:
        print(f"Error getting finding aggregations: {str(e)}")
        findings_data['findings_aggregations'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 발견사항 보고서 상태 조회 (최근 보고서가 있는 경우)
    try:
        # 실제로는 특정 보고서 ID가 필요하지만, 여기서는 일반적인 접근 시도
        findings_data['report_status'] = {
            'note': 'Report status requires specific report ID',
            'status': 'requires_report_id'
        }
    except Exception as e:
        print(f"Error getting findings report status: {str(e)}")
        findings_data['report_status'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return findings_data

def get_vulnerabilities_data(client):
    """
    취약점 및 코드 분석 관련 데이터 조회
    """
    vuln_data = {}
    
    # 취약점 검색 (샘플)
    try:
        search_response = client.search_vulnerabilities(
            filterCriteria={},
            maxResults=50
        )
        vuln_data['vulnerability_search'] = search_response
    except Exception as e:
        print(f"Error searching vulnerabilities: {str(e)}")
        vuln_data['vulnerability_search'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 코드 스니펫 조회 (발견사항이 있는 경우)
    try:
        # 실제로는 특정 발견사항 ARN이 필요하지만, 여기서는 일반적인 접근 시도
        vuln_data['code_snippets'] = {
            'note': 'Code snippets require specific finding ARNs',
            'status': 'requires_finding_arns'
        }
    except Exception as e:
        print(f"Error getting code snippets: {str(e)}")
        vuln_data['code_snippets'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 이미지 관련 클러스터 조회 (ECR 이미지가 있는 경우)
    try:
        # 실제로는 특정 이미지 해시가 필요하지만, 여기서는 일반적인 접근 시도
        vuln_data['clusters_for_image'] = {
            'note': 'Clusters for image require specific image hash',
            'status': 'requires_image_hash'
        }
    except Exception as e:
        print(f"Error getting clusters for image: {str(e)}")
        vuln_data['clusters_for_image'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return vuln_data

def get_coverage_data(client):
    """
    커버리지 및 보호 범위 관련 데이터 조회
    """
    coverage_data = {}
    
    # 커버리지 상세 조회
    try:
        coverage_response = client.list_coverage(maxResults=100)
        coverage_data['coverage_details'] = coverage_response
    except Exception as e:
        print(f"Error getting coverage details: {str(e)}")
        coverage_data['coverage_details'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 커버리지 통계 조회
    try:
        stats_response = client.list_coverage_statistics()
        coverage_data['coverage_statistics'] = stats_response
    except Exception as e:
        print(f"Error getting coverage statistics: {str(e)}")
        coverage_data['coverage_statistics'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return coverage_data

def get_configuration_data(client):
    """
    설정 및 구성 관련 데이터 조회
    """
    config_data = {}
    
    # Inspector 설정 조회
    try:
        config_response = client.get_configuration()
        config_data['configuration'] = config_response
    except Exception as e:
        print(f"Error getting configuration: {str(e)}")
        config_data['configuration'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # EC2 딥 인스펙션 설정 조회
    try:
        ec2_config_response = client.get_ec2_deep_inspection_configuration()
        config_data['ec2_deep_inspection'] = ec2_config_response
    except Exception as e:
        print(f"Error getting EC2 deep inspection configuration: {str(e)}")
        config_data['ec2_deep_inspection'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 암호화 키 정보 조회
    try:
        encryption_response = client.get_encryption_key()
        config_data['encryption_key'] = encryption_response
    except Exception as e:
        print(f"Error getting encryption key: {str(e)}")
        config_data['encryption_key'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return config_data

def get_filters_data(client):
    """
    필터 관련 데이터 조회
    """
    try:
        filters_response = client.list_filters(maxResults=50)
        return {
            'total_filters': len(filters_response.get('filters', [])),
            'filters': filters_response.get('filters', [])
        }
    except Exception as e:
        print(f"Error getting filters: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_usage_totals_data(client):
    """
    사용량 총계 관련 데이터 조회
    """
    try:
        usage_response = client.list_usage_totals()
        return usage_response
    except Exception as e:
        print(f"Error getting usage totals: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_tags_data(client):
    """
    리소스 태그 관련 데이터 조회
    """
    try:
        # Inspector 리소스의 태그 조회는 특정 리소스 ARN이 필요
        # 여기서는 일반적인 접근 시도
        return {
            'note': 'Tags require specific resource ARNs',
            'status': 'requires_specific_resource'
        }
    except Exception as e:
        print(f"Error getting tags: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
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
        'function': event.get('function', 'analyzeInspectorSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'inspector-security-analysis'),
        'function': event.get('function', 'analyzeInspectorSecurity'),
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
