import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

def lambda_handler(event, context):
    """
    DETECT-AGENT-02 CloudWatch Lambda 함수
    Amazon CloudWatch 메트릭, 알람, 대시보드, 이상 탐지 보안 분석
    """
    try:
        # 파라미터 추출 및 검증
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
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        cloudwatch_client = session.client('cloudwatch', region_name=target_region)
        
        # CloudWatch 원시 데이터 병렬 수집
        raw_data = collect_cloudwatch_raw_data_parallel(cloudwatch_client, target_region, current_time)
        
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_message = f"CloudWatch 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in cloudwatch lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_cloudwatch_raw_data_parallel(client, target_region, current_time):
    """
    CloudWatch 16개 API를 병렬로 호출하여 원시 데이터 수집
    """
    # 병렬 처리할 데이터 수집 작업 정의
    data_collection_tasks = [
        # 알람 관련 (3개)
        ('alarm_history', lambda: get_alarm_history(client)),
        ('alarms', lambda: get_alarms(client)),
        ('alarms_for_metrics', lambda: get_alarms_for_metrics(client)),
        
        # 이상 탐지 및 인사이트 (4개)
        ('anomaly_detectors', lambda: get_anomaly_detectors(client)),
        ('insight_rules', lambda: get_insight_rules(client)),
        ('insight_rule_reports', lambda: get_insight_rule_reports(client)),
        ('managed_insight_rules', lambda: get_managed_insight_rules(client)),
        
        # 메트릭 데이터 (3개)
        ('metric_data', lambda: get_metric_data(client)),
        ('metric_statistics', lambda: get_metric_statistics(client)),
        ('metrics_list', lambda: get_metrics_list(client)),
        
        # 대시보드 및 시각화 (3개)
        ('dashboards', lambda: get_dashboards(client)),
        ('dashboard_details', lambda: get_dashboard_details(client)),
        ('metric_widget_images', lambda: get_metric_widget_images(client)),
        
        # 스트리밍 및 기타 (3개)
        ('metric_streams', lambda: get_metric_streams(client)),
        ('metric_stream_details', lambda: get_metric_stream_details(client)),
        ('resource_tags', lambda: get_resource_tags(client))
    ]
    
    collected_data = {
        'function': 'analyzeCloudWatchSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
    }
    
    # 병렬로 데이터 수집
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {
            executor.submit(task_func): task_name 
            for task_name, task_func in data_collection_tasks
        }
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                collected_data[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                collected_data[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    # 수집 요약 정보 추가
    collected_data['collection_summary'] = {
        'total_apis_called': len(data_collection_tasks),
        'successful_collections': sum(1 for key, value in collected_data.items() 
                                    if isinstance(value, dict) and value.get('status') == 'success'),
        'processing_method': 'parallel_processing',
        'api_categories': {
            'alarm_apis': 3,
            'anomaly_insight_apis': 4,
            'metric_data_apis': 3,
            'dashboard_apis': 3,
            'streaming_other_apis': 3
        }
    }
    
    return collected_data

# 알람 관련 API (3개)
def get_alarm_history(client):
    """DescribeAlarmHistory - 알람 상태 변경 히스토리 조회"""
    try:
        # 최근 7일간의 알람 히스토리 조회
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=7)
        
        response = client.describe_alarm_history(
            StartDate=start_time,
            EndDate=end_time,
            MaxRecords=100
        )
        
        return {
            'status': 'success',
            'alarm_history_items': response.get('AlarmHistoryItems', []),
            'next_token': response.get('NextToken'),
            'query_period': f"{start_time.isoformat()} to {end_time.isoformat()}"
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_alarms(client):
    """DescribeAlarms - 알람 목록 및 현재 상태 조회"""
    try:
        response = client.describe_alarms(MaxRecords=100)
        
        metric_alarms = response.get('MetricAlarms', [])
        composite_alarms = response.get('CompositeAlarms', [])
        
        return {
            'status': 'success',
            'metric_alarms': metric_alarms,
            'composite_alarms': composite_alarms,
            'total_alarms': len(metric_alarms) + len(composite_alarms),
            'next_token': response.get('NextToken')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_alarms_for_metrics(client):
    """DescribeAlarmsForMetric - 특정 메트릭의 알람 조회"""
    try:
        # 일반적인 메트릭들에 대한 알람 확인
        common_metrics = [
            {'Namespace': 'AWS/EC2', 'MetricName': 'CPUUtilization'},
            {'Namespace': 'AWS/ApplicationELB', 'MetricName': 'TargetResponseTime'},
            {'Namespace': 'AWS/RDS', 'MetricName': 'DatabaseConnections'}
        ]
        
        alarms_for_metrics = []
        for metric in common_metrics:
            try:
                response = client.describe_alarms_for_metric(
                    MetricName=metric['MetricName'],
                    Namespace=metric['Namespace']
                )
                alarms_for_metrics.append({
                    'metric': metric,
                    'alarms': response.get('MetricAlarms', [])
                })
            except Exception as e:
                print(f"Error checking alarms for {metric}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'alarms_for_metrics': alarms_for_metrics,
            'checked_metrics_count': len(common_metrics)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 이상 탐지 및 인사이트 API (4개)
def get_anomaly_detectors(client):
    """DescribeAnomalyDetectors - 이상 탐지기 설정 조회"""
    try:
        response = client.describe_anomaly_detectors(MaxRecords=100)
        
        return {
            'status': 'success',
            'anomaly_detectors': response.get('AnomalyDetectors', []),
            'next_token': response.get('NextToken')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_insight_rules(client):
    """DescribeInsightRules - Contributor Insights 규칙 조회"""
    try:
        response = client.describe_insight_rules(MaxResults=100)
        
        return {
            'status': 'success',
            'insight_rules': response.get('InsightRules', []),
            'next_token': response.get('NextToken')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_insight_rule_reports(client):
    """GetInsightRuleReport - 인사이트 규칙 보고서 조회"""
    try:
        # 먼저 인사이트 규칙 목록을 가져와서 보고서 조회
        rules_response = client.describe_insight_rules(MaxResults=10)
        rules = rules_response.get('InsightRules', [])
        
        if not rules:
            return {
                'status': 'success',
                'insight_rule_reports': [],
                'message': '인사이트 규칙이 없어 보고서를 조회할 수 없습니다.'
            }
        
        reports = []
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        for rule in rules[:5]:  # 성능을 위해 최대 5개만 조회
            try:
                report_response = client.get_insight_rule_report(
                    RuleName=rule['Name'],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600  # 1시간 단위
                )
                reports.append({
                    'rule_name': rule['Name'],
                    'report': report_response
                })
            except Exception as e:
                print(f"Error getting report for rule {rule['Name']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'insight_rule_reports': reports,
            'total_rules_checked': len(rules),
            'reports_retrieved': len(reports)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_managed_insight_rules(client):
    """ListManagedInsightRules - 관리형 인사이트 규칙 조회"""
    try:
        response = client.list_managed_insight_rules(
            ResourceARN='*',  # 모든 리소스
            MaxResults=100
        )
        
        return {
            'status': 'success',
            'managed_insight_rules': response.get('ManagedRules', []),
            'next_token': response.get('NextToken')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 메트릭 데이터 API (3개)
def get_metric_data(client):
    """GetMetricData - 메트릭 데이터 조회"""
    try:
        # 최근 1시간의 기본 메트릭 데이터 조회
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        # 일반적인 메트릭 쿼리
        metric_data_queries = [
            {
                'Id': 'ec2_cpu',
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/EC2',
                        'MetricName': 'CPUUtilization'
                    },
                    'Period': 300,
                    'Stat': 'Average'
                }
            }
        ]
        
        response = client.get_metric_data(
            MetricDataQueries=metric_data_queries,
            StartTime=start_time,
            EndTime=end_time
        )
        
        return {
            'status': 'success',
            'metric_data_results': response.get('MetricDataResults', []),
            'next_token': response.get('NextToken'),
            'query_period': f"{start_time.isoformat()} to {end_time.isoformat()}"
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_metric_statistics(client):
    """GetMetricStatistics - 메트릭 통계 조회"""
    try:
        # 최근 1시간의 EC2 CPU 사용률 통계
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        response = client.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            StartTime=start_time,
            EndTime=end_time,
            Period=300,
            Statistics=['Average', 'Maximum', 'Minimum']
        )
        
        return {
            'status': 'success',
            'metric_statistics': response.get('Datapoints', []),
            'metric_info': {
                'namespace': 'AWS/EC2',
                'metric_name': 'CPUUtilization',
                'period': 300,
                'statistics': ['Average', 'Maximum', 'Minimum']
            }
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_metrics_list(client):
    """ListMetrics - 사용 가능한 메트릭 목록 조회"""
    try:
        response = client.list_metrics(MaxRecords=500)
        
        return {
            'status': 'success',
            'metrics': response.get('Metrics', []),
            'next_token': response.get('NextToken'),
            'total_metrics_found': len(response.get('Metrics', []))
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 대시보드 및 시각화 API (3개)
def get_dashboards(client):
    """ListDashboards - 대시보드 목록 조회"""
    try:
        response = client.list_dashboards()
        
        return {
            'status': 'success',
            'dashboards': response.get('DashboardEntries', []),
            'next_token': response.get('NextToken')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_dashboard_details(client):
    """GetDashboard - 대시보드 설정 조회"""
    try:
        # 먼저 대시보드 목록을 가져와서 상세 정보 조회
        dashboards_response = client.list_dashboards()
        dashboards = dashboards_response.get('DashboardEntries', [])
        
        if not dashboards:
            return {
                'status': 'success',
                'dashboard_details': [],
                'message': '대시보드가 없어 상세 정보를 조회할 수 없습니다.'
            }
        
        dashboard_details = []
        for dashboard in dashboards[:5]:  # 성능을 위해 최대 5개만 조회
            try:
                detail_response = client.get_dashboard(
                    DashboardName=dashboard['DashboardName']
                )
                dashboard_details.append({
                    'dashboard_name': dashboard['DashboardName'],
                    'dashboard_body': detail_response.get('DashboardBody'),
                    'dashboard_arn': detail_response.get('DashboardArn')
                })
            except Exception as e:
                print(f"Error getting dashboard {dashboard['DashboardName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'dashboard_details': dashboard_details,
            'total_dashboards': len(dashboards),
            'details_retrieved': len(dashboard_details)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_metric_widget_images(client):
    """GetMetricWidgetImage - 메트릭 위젯 이미지 조회"""
    try:
        # 간단한 메트릭 위젯 이미지 생성
        metric_widget = json.dumps({
            "metrics": [
                ["AWS/EC2", "CPUUtilization"]
            ],
            "period": 300,
            "stat": "Average",
            "region": "us-east-1",
            "title": "EC2 CPU Utilization"
        })
        
        response = client.get_metric_widget_image(
            MetricWidget=metric_widget
        )
        
        return {
            'status': 'success',
            'widget_image_size': len(response.get('MetricWidgetImage', b'')),
            'widget_config': metric_widget,
            'note': '이미지 데이터는 크기만 반환 (실제 이미지 데이터는 제외)'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 스트리밍 및 기타 API (3개)
def get_metric_streams(client):
    """ListMetricStreams - 메트릭 스트림 목록 조회"""
    try:
        response = client.list_metric_streams(MaxResults=100)
        
        return {
            'status': 'success',
            'metric_streams': response.get('Entries', []),
            'next_token': response.get('NextToken')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_metric_stream_details(client):
    """GetMetricStream - 메트릭 스트림 설정 조회"""
    try:
        # 먼저 메트릭 스트림 목록을 가져와서 상세 정보 조회
        streams_response = client.list_metric_streams(MaxResults=10)
        streams = streams_response.get('Entries', [])
        
        if not streams:
            return {
                'status': 'success',
                'metric_stream_details': [],
                'message': '메트릭 스트림이 없어 상세 정보를 조회할 수 없습니다.'
            }
        
        stream_details = []
        for stream in streams[:5]:  # 성능을 위해 최대 5개만 조회
            try:
                detail_response = client.get_metric_stream(
                    Name=stream['Name']
                )
                stream_details.append({
                    'stream_name': stream['Name'],
                    'stream_details': detail_response
                })
            except Exception as e:
                print(f"Error getting stream {stream['Name']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'metric_stream_details': stream_details,
            'total_streams': len(streams),
            'details_retrieved': len(stream_details)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_resource_tags(client):
    """ListTagsForResource - 리소스 태그 조회"""
    try:
        # CloudWatch 알람의 태그 조회 (예시)
        alarms_response = client.describe_alarms(MaxRecords=10)
        alarms = alarms_response.get('MetricAlarms', [])
        
        if not alarms:
            return {
                'status': 'success',
                'resource_tags': [],
                'message': '알람이 없어 태그를 조회할 수 없습니다.'
            }
        
        resource_tags = []
        for alarm in alarms[:5]:  # 성능을 위해 최대 5개만 조회
            try:
                tags_response = client.list_tags_for_resource(
                    ResourceARN=alarm['AlarmArn']
                )
                resource_tags.append({
                    'resource_arn': alarm['AlarmArn'],
                    'resource_name': alarm['AlarmName'],
                    'tags': tags_response.get('Tags', [])
                })
            except Exception as e:
                print(f"Error getting tags for alarm {alarm['AlarmName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'resource_tags': resource_tags,
            'total_resources_checked': len(alarms),
            'tags_retrieved': len(resource_tags)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

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
        'function': event.get('function', 'analyzeCloudWatchSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'cloudwatch-security-analysis'),
        'function': event.get('function', 'analyzeCloudWatchSecurity'),
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
