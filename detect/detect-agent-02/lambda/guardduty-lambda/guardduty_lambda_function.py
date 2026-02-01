import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    DETECT-AGENT-01 GuardDuty 보안 분석 Lambda 함수
    GuardDuty의 모든 보안 관련 설정과 발견사항을 종합 분석
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
        
        guardduty_client = session.client('guardduty', region_name=target_region)
        
        # GuardDuty 원시 데이터 수집
        raw_data = collect_guardduty_raw_data_parallel(guardduty_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeGuardDutySecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"GuardDuty 분석 중 오류 발생: {str(e)}"
        print(f"Error in GuardDuty lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_guardduty_raw_data_parallel(client, target_region):
    """
    GuardDuty 원시 데이터를 병렬로 수집
    """
    # 먼저 탐지기 목록 조회
    try:
        detector_response = client.list_detectors()
        detector_ids = detector_response.get('DetectorIds', [])
    except Exception as e:
        print(f"Error listing detectors: {str(e)}")
        detector_ids = []
    
    if not detector_ids:
        return {
            'function': 'analyzeGuardDutySecurity',
            'target_region': target_region,
            'status': 'no_detectors',
            'message': 'GuardDuty 탐지기가 활성화되지 않았습니다.',
            'collection_summary': {
                'detectors_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 주 탐지기 ID (첫 번째 탐지기 사용)
    primary_detector_id = detector_ids[0]
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('detectors', lambda: get_detector_details(client, detector_ids)),
        ('findings_statistics', lambda: get_findings_statistics(client, primary_detector_id)),
        ('findings_list', lambda: get_recent_findings(client, primary_detector_id)),
        ('filters', lambda: get_filters_data(client, primary_detector_id)),
        ('ip_sets', lambda: get_ip_sets_data(client, primary_detector_id)),
        ('threat_intel_sets', lambda: get_threat_intel_sets_data(client, primary_detector_id)),
        ('malware_protection', lambda: get_malware_protection_data(client, primary_detector_id)),
        ('coverage_statistics', lambda: get_coverage_data(client, primary_detector_id)),
        ('usage_statistics', lambda: get_usage_data(client, primary_detector_id)),
        ('publishing_destinations', lambda: get_publishing_destinations_data(client, primary_detector_id)),
        ('tags', lambda: get_tags_data(client, primary_detector_id))
    ]
    
    # 병렬 처리 실행
    results = process_guardduty_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'detectors_found': len(detector_ids),
        'primary_detector_id': primary_detector_id,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': sum([
            len(detector_ids),  # GetDetector calls
            1,  # GetFindingsStatistics
            1,  # ListFindings
            2,  # ListFilters + GetFilter
            2,  # ListIPSets + GetIPSet
            2,  # ListThreatIntelSets + GetThreatIntelSet
            4,  # Malware protection APIs
            2,  # Coverage APIs
            2,  # Usage APIs
            2,  # Publishing destinations
            1   # Tags
        ]),
        'collection_method': 'parallel_processing',
        'region': target_region
    }
    
    return {
        'function': 'analyzeGuardDutySecurity',
        'target_region': target_region,
        'detector_ids': detector_ids,
        'guardduty_data': results,
        'collection_summary': collection_summary
    }

def process_guardduty_parallel(tasks, max_workers=5):
    """
    GuardDuty 데이터 수집 작업을 병렬로 처리
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

def get_detector_details(client, detector_ids):
    """
    모든 탐지기의 상세 정보 조회
    """
    detectors = []
    
    for detector_id in detector_ids:
        try:
            response = client.get_detector(DetectorId=detector_id)
            detector_info = {
                'detector_id': detector_id,
                'status': response.get('Status'),
                'service_role': response.get('ServiceRole'),
                'finding_publishing_frequency': response.get('FindingPublishingFrequency'),
                'created_at': response.get('CreatedAt'),
                'updated_at': response.get('UpdatedAt'),
                'data_sources': response.get('DataSources', {}),
                'features': response.get('Features', []),
                'tags': response.get('Tags', {})
            }
            detectors.append(detector_info)
        except Exception as e:
            print(f"Error getting detector {detector_id}: {str(e)}")
            detectors.append({
                'detector_id': detector_id,
                'status': 'error',
                'error_message': str(e)
            })
    
    return {
        'total_detectors': len(detector_ids),
        'detectors': detectors
    }

def get_findings_statistics(client, detector_id):
    """
    발견사항 통계 조회
    """
    try:
        response = client.get_findings_statistics(DetectorId=detector_id)
        return {
            'finding_statistics': response.get('FindingStatistics', {}),
            'detector_id': detector_id
        }
    except Exception as e:
        print(f"Error getting findings statistics: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_recent_findings(client, detector_id):
    """
    최근 발견사항 목록 조회 (최대 50개)
    """
    try:
        # 최근 발견사항 ID 조회
        list_response = client.list_findings(
            DetectorId=detector_id,
            MaxResults=50
        )
        finding_ids = list_response.get('FindingIds', [])
        
        if not finding_ids:
            return {
                'total_findings': 0,
                'findings': [],
                'detector_id': detector_id
            }
        
        # 발견사항 상세 정보 조회
        get_response = client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids[:10]  # 최대 10개만 상세 조회
        )
        
        return {
            'total_findings': len(finding_ids),
            'findings_sample': get_response.get('Findings', []),
            'detector_id': detector_id
        }
    except Exception as e:
        print(f"Error getting findings: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_filters_data(client, detector_id):
    """
    필터 데이터 조회
    """
    try:
        # 필터 목록 조회
        list_response = client.list_filters(DetectorId=detector_id)
        filter_names = list_response.get('FilterNames', [])
        
        filters = []
        for filter_name in filter_names:
            try:
                filter_response = client.get_filter(
                    DetectorId=detector_id,
                    FilterName=filter_name
                )
                filters.append({
                    'name': filter_name,
                    'description': filter_response.get('Description'),
                    'action': filter_response.get('Action'),
                    'finding_criteria': filter_response.get('FindingCriteria'),
                    'rank': filter_response.get('Rank'),
                    'tags': filter_response.get('Tags', {})
                })
            except Exception as e:
                print(f"Error getting filter {filter_name}: {str(e)}")
                filters.append({
                    'name': filter_name,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        return {
            'total_filters': len(filter_names),
            'filters': filters,
            'detector_id': detector_id
        }
    except Exception as e:
        print(f"Error getting filters: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_ip_sets_data(client, detector_id):
    """
    IP 세트 데이터 조회
    """
    try:
        # IP 세트 목록 조회
        list_response = client.list_ip_sets(DetectorId=detector_id)
        ip_set_ids = list_response.get('IpSetIds', [])
        
        ip_sets = []
        for ip_set_id in ip_set_ids:
            try:
                ip_set_response = client.get_ip_set(
                    DetectorId=detector_id,
                    IpSetId=ip_set_id
                )
                ip_sets.append({
                    'ip_set_id': ip_set_id,
                    'name': ip_set_response.get('Name'),
                    'format': ip_set_response.get('Format'),
                    'location': ip_set_response.get('Location'),
                    'status': ip_set_response.get('Status'),
                    'tags': ip_set_response.get('Tags', {})
                })
            except Exception as e:
                print(f"Error getting IP set {ip_set_id}: {str(e)}")
                ip_sets.append({
                    'ip_set_id': ip_set_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        return {
            'total_ip_sets': len(ip_set_ids),
            'ip_sets': ip_sets,
            'detector_id': detector_id
        }
    except Exception as e:
        print(f"Error getting IP sets: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_threat_intel_sets_data(client, detector_id):
    """
    위협 인텔리전스 세트 데이터 조회
    """
    try:
        # 위협 인텔리전스 세트 목록 조회
        list_response = client.list_threat_intel_sets(DetectorId=detector_id)
        threat_intel_set_ids = list_response.get('ThreatIntelSetIds', [])
        
        threat_intel_sets = []
        for threat_intel_set_id in threat_intel_set_ids:
            try:
                threat_intel_response = client.get_threat_intel_set(
                    DetectorId=detector_id,
                    ThreatIntelSetId=threat_intel_set_id
                )
                threat_intel_sets.append({
                    'threat_intel_set_id': threat_intel_set_id,
                    'name': threat_intel_response.get('Name'),
                    'format': threat_intel_response.get('Format'),
                    'location': threat_intel_response.get('Location'),
                    'status': threat_intel_response.get('Status'),
                    'tags': threat_intel_response.get('Tags', {})
                })
            except Exception as e:
                print(f"Error getting threat intel set {threat_intel_set_id}: {str(e)}")
                threat_intel_sets.append({
                    'threat_intel_set_id': threat_intel_set_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        return {
            'total_threat_intel_sets': len(threat_intel_set_ids),
            'threat_intel_sets': threat_intel_sets,
            'detector_id': detector_id
        }
    except Exception as e:
        print(f"Error getting threat intel sets: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_malware_protection_data(client, detector_id):
    """
    멀웨어 보호 관련 데이터 조회
    """
    malware_data = {}
    
    # 멀웨어 보호 계획 목록 조회
    try:
        plans_response = client.list_malware_protection_plans()
        malware_protection_plans = plans_response.get('MalwareProtectionPlans', [])
        
        # 각 계획의 상세 정보 조회
        plan_details = []
        for plan in malware_protection_plans:
            plan_id = plan.get('MalwareProtectionPlanId')
            try:
                plan_response = client.get_malware_protection_plan(
                    MalwareProtectionPlanId=plan_id
                )
                plan_details.append(plan_response)
            except Exception as e:
                print(f"Error getting malware protection plan {plan_id}: {str(e)}")
                plan_details.append({
                    'malware_protection_plan_id': plan_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        malware_data['protection_plans'] = {
            'total_plans': len(malware_protection_plans),
            'plans': plan_details
        }
    except Exception as e:
        print(f"Error getting malware protection plans: {str(e)}")
        malware_data['protection_plans'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 멀웨어 스캔 설정 조회
    try:
        scan_settings_response = client.get_malware_scan_settings(DetectorId=detector_id)
        malware_data['scan_settings'] = scan_settings_response
    except Exception as e:
        print(f"Error getting malware scan settings: {str(e)}")
        malware_data['scan_settings'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 멀웨어 스캔 기록 조회
    try:
        scans_response = client.describe_malware_scans(DetectorId=detector_id)
        malware_data['scan_history'] = scans_response
    except Exception as e:
        print(f"Error getting malware scans: {str(e)}")
        malware_data['scan_history'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return malware_data

def get_coverage_data(client, detector_id):
    """
    커버리지 관련 데이터 조회
    """
    coverage_data = {}
    
    # 커버리지 통계 조회
    try:
        stats_response = client.get_coverage_statistics(DetectorId=detector_id)
        coverage_data['statistics'] = stats_response
    except Exception as e:
        print(f"Error getting coverage statistics: {str(e)}")
        coverage_data['statistics'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 커버리지 목록 조회 (최대 50개)
    try:
        list_response = client.list_coverage(
            DetectorId=detector_id,
            MaxResults=50
        )
        coverage_data['coverage_list'] = list_response
    except Exception as e:
        print(f"Error getting coverage list: {str(e)}")
        coverage_data['coverage_list'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return coverage_data

def get_usage_data(client, detector_id):
    """
    사용량 관련 데이터 조회
    """
    usage_data = {}
    
    # 사용량 통계 조회
    try:
        stats_response = client.get_usage_statistics(DetectorId=detector_id)
        usage_data['statistics'] = stats_response
    except Exception as e:
        print(f"Error getting usage statistics: {str(e)}")
        usage_data['statistics'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    # 무료 체험 잔여 일수 조회
    try:
        trial_response = client.get_remaining_free_trial_days(DetectorId=detector_id)
        usage_data['free_trial'] = trial_response
    except Exception as e:
        print(f"Error getting free trial days: {str(e)}")
        usage_data['free_trial'] = {
            'status': 'error',
            'error_message': str(e)
        }
    
    return usage_data

def get_publishing_destinations_data(client, detector_id):
    """
    게시 대상 데이터 조회
    """
    try:
        # 게시 대상 목록 조회
        list_response = client.list_publishing_destinations(DetectorId=detector_id)
        destinations = list_response.get('Destinations', [])
        
        # 각 게시 대상의 상세 정보 조회
        destination_details = []
        for destination in destinations:
            destination_id = destination.get('DestinationId')
            try:
                detail_response = client.describe_publishing_destination(
                    DetectorId=detector_id,
                    DestinationId=destination_id
                )
                destination_details.append(detail_response)
            except Exception as e:
                print(f"Error getting publishing destination {destination_id}: {str(e)}")
                destination_details.append({
                    'destination_id': destination_id,
                    'status': 'error',
                    'error_message': str(e)
                })
        
        return {
            'total_destinations': len(destinations),
            'destinations': destination_details,
            'detector_id': detector_id
        }
    except Exception as e:
        print(f"Error getting publishing destinations: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def get_tags_data(client, detector_id):
    """
    리소스 태그 데이터 조회
    """
    try:
        # 탐지기 리소스의 태그 조회
        detector_arn = f"arn:aws:guardduty:{client.meta.region_name}:{client.meta.service_model.metadata.get('signingName', 'guardduty')}:detector/{detector_id}"
        
        response = client.list_tags_for_resource(ResourceArn=detector_arn)
        return {
            'resource_arn': detector_arn,
            'tags': response.get('Tags', {}),
            'detector_id': detector_id
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
        'function': event.get('function', 'analyzeGuardDutySecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'guardduty-security-analysis'),
        'function': event.get('function', 'analyzeGuardDutySecurity'),
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
