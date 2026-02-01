import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    DETECT-AGENT-02 Discovery Lambda 함수
    Detective, CloudWatch, CloudWatch Logs, CloudTrail 서비스의 리소스 존재 여부 확인
    """
    try:
        # 파라미터 추출
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region', 'us-east-1')
        
        # 세션 속성에서 고객 자격증명 획득
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
        
        # 서비스별 리소스 발견 병렬 실행
        discovery_results = discover_log_services_parallel(session, target_region)
        
        # 응답 데이터 구성
        response_data = {
            'function': 'analyzeDetectAgent02Discovery',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_timestamp': context.aws_request_id,
            'services_discovered': discovery_results,
            'collection_summary': {
                'total_services_checked': len(discovery_results),
                'services_with_resources': sum(1 for service in discovery_results.values() if service.get('has_resources', False)),
                'discovery_method': 'parallel_processing',
                'agent_type': 'detect-agent-02',
                'focus': 'log_based_analysis_and_forensics'
            }
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"Discovery 과정에서 오류 발생: {str(e)}"
        print(f"Error in detect-agent-02 discovery lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def discover_log_services_parallel(session, target_region):
    """
    로그 기반 분석 서비스들의 리소스를 병렬로 발견 (CloudWatch와 CloudWatch Logs 분리)
    """
    services_to_check = [
        ('detective', check_detective_resources),
        ('cloudwatch', check_cloudwatch_resources),
        ('cloudwatch_logs', check_cloudwatch_logs_resources),
        ('cloudtrail', check_cloudtrail_resources)
    ]
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_service = {
            executor.submit(check_func, session, target_region): service_name 
            for service_name, check_func in services_to_check
        }
        
        for future in concurrent.futures.as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                result = future.result()
                results[service_name] = result
            except Exception as e:
                print(f"Error checking {service_name}: {str(e)}")
                results[service_name] = {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def check_detective_resources(session, target_region):
    """
    Detective 그래프 존재 여부 확인 (수정된 에러 처리)
    """
    try:
        detective_client = session.client('detective', region_name=target_region)
        
        # 그래프 목록 조회
        response = detective_client.list_graphs()
        graphs = response.get('GraphList', [])
        
        # 활성화된 그래프만 카운트
        active_graphs = [graph for graph in graphs if graph.get('Status') == 'ACTIVE']
        
        return {
            'has_resources': len(active_graphs) > 0,
            'resource_count': len(active_graphs),
            'resource_types': ['behavior_graphs'],
            'status': 'active' if active_graphs else 'inactive',
            'details': {
                'total_graphs': len(graphs),
                'active_graphs': len(active_graphs),
                'graph_arns': [graph.get('Arn') for graph in active_graphs]
            }
        }
        
    except Exception as e:
        # 모든 에러를 안전하게 처리
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': f'Detective 확인 중 오류: {str(e)}'
        }

def check_cloudwatch_resources(session, target_region):
    """
    CloudWatch 메트릭, 알람, 대시보드 존재 여부 확인 (수정된 에러 처리)
    """
    try:
        cloudwatch_client = session.client('cloudwatch', region_name=target_region)
        
        resource_counts = {}
        
        # 메트릭 알람 확인
        try:
            alarms_response = cloudwatch_client.describe_alarms(MaxRecords=50)
            alarms = alarms_response.get('MetricAlarms', [])
            resource_counts['metric_alarms'] = len(alarms)
        except Exception as e:
            print(f"Error checking metric alarms: {str(e)}")
            resource_counts['metric_alarms'] = 0
        
        # 대시보드 확인
        try:
            dashboards_response = cloudwatch_client.list_dashboards()
            dashboards = dashboards_response.get('DashboardEntries', [])
            resource_counts['dashboards'] = len(dashboards)
        except Exception as e:
            print(f"Error checking dashboards: {str(e)}")
            resource_counts['dashboards'] = 0
        
        # 이상 탐지기 확인
        try:
            anomaly_response = cloudwatch_client.describe_anomaly_detectors(MaxRecords=50)
            anomaly_detectors = anomaly_response.get('AnomalyDetectors', [])
            resource_counts['anomaly_detectors'] = len(anomaly_detectors)
        except Exception as e:
            print(f"Error checking anomaly detectors: {str(e)}")
            resource_counts['anomaly_detectors'] = 0
        
        total_resources = sum(resource_counts.values())
        
        return {
            'has_resources': total_resources > 0,
            'resource_count': total_resources,
            'resource_types': ['metric_alarms', 'dashboards', 'anomaly_detectors'],
            'status': 'active' if total_resources > 0 else 'inactive',
            'details': {
                'metric_alarms_count': resource_counts['metric_alarms'],
                'dashboards_count': resource_counts['dashboards'],
                'anomaly_detectors_count': resource_counts['anomaly_detectors'],
                'note': 'CloudWatch 메트릭 및 모니터링 리소스 확인 (로그 제외)'
            }
        }
        
    except Exception as e:
        # 모든 에러를 안전하게 처리
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': f'CloudWatch 확인 중 오류: {str(e)}'
        }

def check_cloudwatch_logs_resources(session, target_region):
    """
    CloudWatch Logs 로그 그룹, 스트림, 필터 존재 여부 확인 (수정된 에러 처리)
    """
    try:
        logs_client = session.client('logs', region_name=target_region)
        
        resource_counts = {}
        
        # 로그 그룹 확인
        try:
            log_groups_response = logs_client.describe_log_groups(limit=50)
            log_groups = log_groups_response.get('logGroups', [])
            resource_counts['log_groups'] = len(log_groups)
        except Exception as e:
            print(f"Error checking log groups: {str(e)}")
            resource_counts['log_groups'] = 0
        
        # 메트릭 필터 확인 (첫 번째 로그 그룹에서)
        try:
            if log_groups:
                first_log_group = log_groups[0]['logGroupName']
                metric_filters_response = logs_client.describe_metric_filters(
                    logGroupName=first_log_group,
                    limit=10
                )
                metric_filters = metric_filters_response.get('metricFilters', [])
                resource_counts['metric_filters'] = len(metric_filters)
            else:
                resource_counts['metric_filters'] = 0
        except Exception as e:
            print(f"Error checking metric filters: {str(e)}")
            resource_counts['metric_filters'] = 0
        
        # 구독 필터 확인 (첫 번째 로그 그룹에서)
        try:
            if log_groups:
                first_log_group = log_groups[0]['logGroupName']
                subscription_filters_response = logs_client.describe_subscription_filters(
                    logGroupName=first_log_group,
                    limit=10
                )
                subscription_filters = subscription_filters_response.get('subscriptionFilters', [])
                resource_counts['subscription_filters'] = len(subscription_filters)
            else:
                resource_counts['subscription_filters'] = 0
        except Exception as e:
            print(f"Error checking subscription filters: {str(e)}")
            resource_counts['subscription_filters'] = 0
        
        total_resources = sum(resource_counts.values())
        
        return {
            'has_resources': total_resources > 0,
            'resource_count': total_resources,
            'resource_types': ['log_groups', 'metric_filters', 'subscription_filters'],
            'status': 'active' if total_resources > 0 else 'inactive',
            'details': {
                'log_groups_count': resource_counts['log_groups'],
                'metric_filters_count': resource_counts['metric_filters'],
                'subscription_filters_count': resource_counts['subscription_filters'],
                'note': 'CloudWatch Logs 리소스 확인 (메트릭 제외)'
            }
        }
        
    except Exception as e:
        # 모든 에러를 안전하게 처리
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': f'CloudWatch Logs 확인 중 오류: {str(e)}'
        }

def check_cloudtrail_resources(session, target_region):
    """
    CloudTrail 트레일 존재 여부 확인 (수정된 에러 처리)
    """
    try:
        cloudtrail_client = session.client('cloudtrail', region_name=target_region)
        
        # 트레일 목록 조회
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        # 활성화된 트레일 확인
        active_trails = []
        for trail in trails:
            try:
                status_response = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                if status_response.get('IsLogging', False):
                    active_trails.append(trail)
            except Exception as e:
                print(f"Error checking trail status for {trail.get('Name', 'unknown')}: {str(e)}")
                continue
        
        return {
            'has_resources': len(trails) > 0,
            'resource_count': len(trails),
            'resource_types': ['trails'],
            'status': 'active' if active_trails else 'inactive',
            'details': {
                'total_trails': len(trails),
                'active_trails': len(active_trails),
                'trail_names': [trail.get('Name') for trail in trails],
                'active_trail_names': [trail.get('Name') for trail in active_trails]
            }
        }
        
    except Exception as e:
        # 모든 에러를 안전하게 처리
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': f'CloudTrail 확인 중 오류: {str(e)}'
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
        'function': event.get('function', 'discoverAllResources'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'discovery-action-group'),
        'function': event.get('function', 'discoverAllResources'),
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
