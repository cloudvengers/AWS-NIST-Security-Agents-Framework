import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    DETECT-AGENT-01 Macie 보안 분석 Lambda 함수
    Macie의 모든 민감 데이터 탐지 및 보안 관련 설정을 종합 분석
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
        
        macie_client = session.client('macie2', region_name=target_region)
        
        # Macie 원시 데이터 수집
        raw_data = collect_macie_raw_data_parallel(macie_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeMacieSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Macie 분석 중 오류 발생: {str(e)}"
        print(f"Error in Macie lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_macie_raw_data_parallel(client, target_region):
    """
    Macie 원시 데이터를 병렬로 수집
    """
    # 먼저 Macie 세션 상태 확인
    try:
        session_response = client.get_macie_session()
        session_status = session_response.get('status', 'DISABLED')
    except Exception as e:
        print(f"Error getting Macie session: {str(e)}")
        return {
            'function': 'analyzeMacieSecurity',
            'target_region': target_region,
            'status': 'not_enabled',
            'message': f'Macie 서비스가 활성화되지 않았습니다. ({str(e)})',
            'error_details': {
                'error_message': str(e)
            },
            'collection_summary': {
                'macie_enabled': False,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if session_status != 'ENABLED':
        return {
            'function': 'analyzeMacieSecurity',
            'target_region': target_region,
            'status': session_status.lower(),
            'message': f'Macie 상태: {session_status}',
            'session_info': session_response,
            'collection_summary': {
                'macie_enabled': False,
                'session_status': session_status,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('session_info', lambda: get_session_info(client)),
        ('findings', lambda: get_findings_data(client)),
        ('classification_jobs', lambda: get_classification_jobs_data(client)),
        ('data_identifiers', lambda: get_data_identifiers_data(client)),
        ('data_sources', lambda: get_data_sources_data(client)),
        ('filters_and_settings', lambda: get_filters_and_settings_data(client)),
        ('automated_discovery', lambda: get_automated_discovery_data(client)),
        ('resource_profiles', lambda: get_resource_profiles_data(client)),
        ('sensitivity_templates', lambda: get_sensitivity_templates_data(client)),
        ('usage_statistics', lambda: get_usage_statistics_data(client)),
        ('tags', lambda: get_tags_data(client))
    ]
    
    # 병렬 처리 실행
    results = process_macie_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'macie_enabled': True,
        'session_status': session_status,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': sum([
            1,  # GetMacieSession
            3,  # Findings APIs
            2,  # Classification jobs
            3,  # Data identifiers
            3,  # Data sources
            5,  # Filters and settings
            2,  # Automated discovery
            3,  # Resource profiles
            2,  # Sensitivity templates
            2,  # Usage statistics
            1   # Tags
        ]),
        'collection_method': 'parallel_processing',
        'region': target_region
    }
    
    return {
        'function': 'analyzeMacieSecurity',
        'target_region': target_region,
        'macie_data': results,
        'collection_summary': collection_summary
    }

def process_macie_parallel(tasks, max_workers=5):
    """
    Macie 데이터 수집 작업을 병렬로 처리
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

def get_session_info(client):
    """
    Macie 세션 정보 조회
    """
    try:
        response = client.get_macie_session()
        return {
            'status': response.get('status'),
            'service_role': response.get('serviceRole'),
            'created_at': response.get('createdAt'),
            'updated_at': response.get('updatedAt'),
            'finding_publishing_frequency': response.get('findingPublishingFrequency')
        }
    except Exception as e:
        print(f"Error getting session info: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_findings_data(client):
    """
    발견사항 관련 데이터 조회
    """
    findings_data = {}
    
    # 발견사항 목록 조회 (최대 50개)
    try:
        list_response = client.list_findings(maxResults=50)
        finding_ids = list_response.get('findingIds', [])
        
        findings_data['findings_list'] = {
            'total_findings': len(finding_ids),
            'finding_ids_sample': finding_ids[:10]  # 샘플만 저장
        }
        
        # 발견사항 상세 정보 조회 (최대 10개)
        if finding_ids:
            get_response = client.get_findings(findingIds=finding_ids[:10])
            findings_data['findings_details'] = {
                'findings_sample': get_response.get('findings', [])
            }
    except Exception as e:
        print(f"Error getting findings: {str(e)}")
        findings_data['findings_list'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 발견사항 통계 조회
    try:
        stats_response = client.get_finding_statistics()
        findings_data['findings_statistics'] = stats_response
    except Exception as e:
        print(f"Error getting finding statistics: {str(e)}")
        findings_data['findings_statistics'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return findings_data

def get_classification_jobs_data(client):
    """
    분류 작업 관련 데이터 조회
    """
    jobs_data = {}
    
    # 분류 작업 목록 조회
    try:
        list_response = client.list_classification_jobs(maxResults=50)
        jobs = list_response.get('items', [])
        
        jobs_data['jobs_list'] = {
            'total_jobs': len(jobs),
            'jobs': jobs
        }
        
        # 각 작업의 상세 정보 조회 (최대 5개)
        job_details = []
        for job in jobs[:5]:
            job_id = job.get('jobId')
            try:
                job_response = client.describe_classification_job(jobId=job_id)
                job_details.append(job_response)
            except Exception as e:
                print(f"Error getting job {job_id}: {str(e)}")
                job_details.append({
                    'job_id': job_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        jobs_data['jobs_details'] = job_details
        
    except Exception as e:
        print(f"Error getting classification jobs: {str(e)}")
        jobs_data['jobs_list'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 분류 결과 내보내기 설정 조회
    try:
        export_response = client.get_classification_export_configuration()
        jobs_data['export_configuration'] = export_response
    except Exception as e:
        print(f"Error getting export configuration: {str(e)}")
        jobs_data['export_configuration'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 분류 범위 조회
    try:
        scopes_response = client.list_classification_scopes()
        scope_ids = scopes_response.get('classificationScopes', [])
        
        scope_details = []
        for scope_info in scope_ids:
            scope_id = scope_info.get('id')
            try:
                scope_response = client.get_classification_scope(id=scope_id)
                scope_details.append(scope_response)
            except Exception as e:
                print(f"Error getting scope {scope_id}: {str(e)}")
                scope_details.append({
                    'scope_id': scope_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        jobs_data['classification_scopes'] = {
            'total_scopes': len(scope_ids),
            'scopes': scope_details
        }
        
    except Exception as e:
        print(f"Error getting classification scopes: {str(e)}")
        jobs_data['classification_scopes'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return jobs_data

def get_data_identifiers_data(client):
    """
    데이터 식별자 관련 데이터 조회
    """
    identifiers_data = {}
    
    # 사용자 정의 데이터 식별자 목록 조회
    try:
        custom_list_response = client.list_custom_data_identifiers(maxResults=100)
        custom_ids = custom_list_response.get('items', [])
        
        # 상세 정보 일괄 조회
        if custom_ids:
            custom_id_list = [item.get('id') for item in custom_ids if item.get('id')]
            batch_response = client.batch_get_custom_data_identifiers(ids=custom_id_list[:20])
            identifiers_data['custom_identifiers'] = {
                'total_identifiers': len(custom_ids),
                'identifiers_details': batch_response.get('customDataIdentifiers', [])
            }
        else:
            identifiers_data['custom_identifiers'] = {
                'total_identifiers': 0,
                'identifiers_details': []
            }
            
    except Exception as e:
        print(f"Error getting custom data identifiers: {str(e)}")
        identifiers_data['custom_identifiers'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 관리형 데이터 식별자 조회
    try:
        managed_response = client.list_managed_data_identifiers()
        identifiers_data['managed_identifiers'] = managed_response
    except Exception as e:
        print(f"Error getting managed data identifiers: {str(e)}")
        identifiers_data['managed_identifiers'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return identifiers_data

def get_data_sources_data(client):
    """
    데이터 소스 관련 데이터 조회
    """
    data_sources = {}
    
    # S3 버킷 정보 조회
    try:
        buckets_response = client.describe_buckets(maxResults=100)
        data_sources['s3_buckets'] = buckets_response
    except Exception as e:
        print(f"Error getting S3 buckets: {str(e)}")
        data_sources['s3_buckets'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # S3 버킷 통계 조회
    try:
        stats_response = client.get_bucket_statistics()
        data_sources['bucket_statistics'] = stats_response
    except Exception as e:
        print(f"Error getting bucket statistics: {str(e)}")
        data_sources['bucket_statistics'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 리소스 검색
    try:
        search_response = client.search_resources(maxResults=50)
        data_sources['resource_search'] = search_response
    except Exception as e:
        print(f"Error searching resources: {str(e)}")
        data_sources['resource_search'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return data_sources

def get_filters_and_settings_data(client):
    """
    필터 및 설정 관련 데이터 조회
    """
    filters_data = {}
    
    # 허용 목록 조회
    try:
        allow_lists_response = client.list_allow_lists(maxResults=50)
        allow_lists = allow_lists_response.get('allowLists', [])
        
        # 각 허용 목록의 상세 정보 조회
        allow_list_details = []
        for allow_list in allow_lists:
            allow_list_id = allow_list.get('id')
            try:
                detail_response = client.get_allow_list(id=allow_list_id)
                allow_list_details.append(detail_response)
            except Exception as e:
                print(f"Error getting allow list {allow_list_id}: {str(e)}")
                allow_list_details.append({
                    'id': allow_list_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        filters_data['allow_lists'] = {
            'total_lists': len(allow_lists),
            'lists': allow_list_details
        }
        
    except Exception as e:
        print(f"Error getting allow lists: {str(e)}")
        filters_data['allow_lists'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 발견사항 필터 조회
    try:
        filters_response = client.list_findings_filters(maxResults=50)
        filters = filters_response.get('findingsFilters', [])
        
        # 각 필터의 상세 정보 조회
        filter_details = []
        for filter_info in filters:
            filter_id = filter_info.get('id')
            try:
                detail_response = client.get_findings_filter(id=filter_id)
                filter_details.append(detail_response)
            except Exception as e:
                print(f"Error getting filter {filter_id}: {str(e)}")
                filter_details.append({
                    'id': filter_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        filters_data['findings_filters'] = {
            'total_filters': len(filters),
            'filters': filter_details
        }
        
    except Exception as e:
        print(f"Error getting findings filters: {str(e)}")
        filters_data['findings_filters'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 발견사항 게시 설정 조회
    try:
        publication_response = client.get_findings_publication_configuration()
        filters_data['publication_configuration'] = publication_response
    except Exception as e:
        print(f"Error getting publication configuration: {str(e)}")
        filters_data['publication_configuration'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 민감 데이터 조회 설정 확인
    try:
        reveal_response = client.get_reveal_configuration()
        filters_data['reveal_configuration'] = reveal_response
    except Exception as e:
        print(f"Error getting reveal configuration: {str(e)}")
        filters_data['reveal_configuration'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return filters_data

def get_automated_discovery_data(client):
    """
    자동화된 민감 데이터 탐지 관련 데이터 조회
    """
    discovery_data = {}
    
    # 자동 탐지 구성 조회
    try:
        config_response = client.get_automated_discovery_configuration()
        discovery_data['configuration'] = config_response
    except Exception as e:
        print(f"Error getting automated discovery configuration: {str(e)}")
        discovery_data['configuration'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return discovery_data

def get_resource_profiles_data(client):
    """
    리소스 민감도 프로필 관련 데이터 조회
    """
    profiles_data = {}
    
    # 리소스 프로필 아티팩트 조회 (샘플)
    try:
        artifacts_response = client.list_resource_profile_artifacts(maxResults=20)
        profiles_data['profile_artifacts'] = artifacts_response
    except Exception as e:
        print(f"Error getting profile artifacts: {str(e)}")
        profiles_data['profile_artifacts'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 리소스 프로필 탐지 결과 조회 (샘플)
    try:
        detections_response = client.list_resource_profile_detections(maxResults=20)
        profiles_data['profile_detections'] = detections_response
    except Exception as e:
        print(f"Error getting profile detections: {str(e)}")
        profiles_data['profile_detections'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return profiles_data

def get_sensitivity_templates_data(client):
    """
    민감도 검사 템플릿 관련 데이터 조회
    """
    templates_data = {}
    
    # 민감도 검사 템플릿 목록 조회
    try:
        templates_response = client.list_sensitivity_inspection_templates()
        templates = templates_response.get('sensitivityInspectionTemplates', [])
        
        # 각 템플릿의 상세 정보 조회
        template_details = []
        for template in templates:
            template_id = template.get('id')
            try:
                detail_response = client.get_sensitivity_inspection_template(id=template_id)
                template_details.append(detail_response)
            except Exception as e:
                print(f"Error getting template {template_id}: {str(e)}")
                template_details.append({
                    'id': template_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        templates_data['templates'] = {
            'total_templates': len(templates),
            'templates': template_details
        }
        
    except Exception as e:
        print(f"Error getting sensitivity templates: {str(e)}")
        templates_data['templates'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return templates_data

def get_usage_statistics_data(client):
    """
    사용량 및 통계 관련 데이터 조회
    """
    usage_data = {}
    
    # 사용량 통계 조회
    try:
        stats_response = client.get_usage_statistics()
        usage_data['usage_statistics'] = stats_response
    except Exception as e:
        print(f"Error getting usage statistics: {str(e)}")
        usage_data['usage_statistics'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 사용량 총계 조회
    try:
        totals_response = client.get_usage_totals()
        usage_data['usage_totals'] = totals_response
    except Exception as e:
        print(f"Error getting usage totals: {str(e)}")
        usage_data['usage_totals'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return usage_data

def get_tags_data(client):
    """
    리소스 태그 관련 데이터 조회
    """
    try:
        # Macie 세션 리소스의 ARN 구성 (예시)
        # 실제로는 특정 리소스 ARN이 필요하지만, 여기서는 일반적인 접근 시도
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
        'function': event.get('function', 'analyzeMacieSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'macie-security-analysis'),
        'function': event.get('function', 'analyzeMacieSecurity'),
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
