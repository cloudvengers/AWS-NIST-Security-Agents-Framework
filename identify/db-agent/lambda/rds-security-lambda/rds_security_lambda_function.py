import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    DB-AGENT RDS Security Analysis Lambda 함수
    15개 RDS API를 통한 종합적인 RDS 보안 상태 분석
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
        
        rds_client = session.client('rds', region_name=target_region)
        
        # RDS 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_rds_security_data_parallel(rds_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeRdsSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"RDS 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in RDS security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_rds_security_data_parallel(client, target_region, current_time):
    """
    RDS 보안 데이터를 병렬로 수집 - 15개 API 활용
    """
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('instance_configuration', lambda: analyze_instance_configuration_parallel(client)),
        ('network_security', lambda: analyze_network_security_parallel(client)),
        ('configuration_parameters', lambda: analyze_configuration_parameters_parallel(client)),
        ('data_protection', lambda: analyze_data_protection_parallel(client)),
        ('access_management', lambda: analyze_access_management_parallel(client)),
        ('monitoring_auditing', lambda: analyze_monitoring_auditing_parallel(client)),
    ]
    
    # 병렬 처리 실행
    results = process_rds_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': 15,
        'collection_method': 'parallel_processing',
        'rds_security_categories': [
            'instance_configuration',
            'network_security', 
            'configuration_parameters',
            'data_protection',
            'access_management',
            'monitoring_auditing'
        ]
    }
    
    return {
        'function': 'analyzeRdsSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'instance_configuration': results.get('instance_configuration', {}),
        'network_security': results.get('network_security', {}),
        'configuration_parameters': results.get('configuration_parameters', {}),
        'data_protection': results.get('data_protection', {}),
        'access_management': results.get('access_management', {}),
        'monitoring_auditing': results.get('monitoring_auditing', {}),
        'collection_summary': collection_summary
    }

def process_rds_parallel(tasks, max_workers=6):
    """RDS 데이터 수집 작업을 병렬로 처리"""
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

# 1. 인스턴스 및 기본 구성 관련 API (1개)
def analyze_instance_configuration_parallel(client):
    """인스턴스 구성 분석"""
    try:
        # DescribeDBInstances
        response = client.describe_db_instances()
        instances = response.get('DBInstances', [])
        
        if not instances:
            return {
                'total_instances': 0,
                'status': 'no_instances',
                'message': 'RDS 인스턴스가 존재하지 않습니다.'
            }
        
        # 인스턴스 보안 설정 분석
        instance_analyses = []
        for instance in instances:
            analysis = {
                'db_instance_identifier': instance.get('DBInstanceIdentifier'),
                'engine': instance.get('Engine'),
                'engine_version': instance.get('EngineVersion'),
                'storage_encrypted': instance.get('StorageEncrypted', False),
                'kms_key_id': instance.get('KmsKeyId'),
                'publicly_accessible': instance.get('PubliclyAccessible', False),
                'vpc_security_groups': instance.get('VpcSecurityGroups', []),
                'db_subnet_group': instance.get('DBSubnetGroup', {}),
                'backup_retention_period': instance.get('BackupRetentionPeriod', 0),
                'multi_az': instance.get('MultiAZ', False),
                'auto_minor_version_upgrade': instance.get('AutoMinorVersionUpgrade', False),
                'deletion_protection': instance.get('DeletionProtection', False),
                'performance_insights_enabled': instance.get('PerformanceInsightsEnabled', False),
                'monitoring_interval': instance.get('MonitoringInterval', 0),
                'db_instance_status': instance.get('DBInstanceStatus')
            }
            instance_analyses.append(analysis)
        
        return {
            'total_instances': len(instances),
            'instance_details': instance_analyses,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 2. 네트워크 보안 관련 API (2개)
def analyze_network_security_parallel(client):
    """네트워크 보안 분석"""
    network_tasks = [
        ('db_security_groups', lambda: describe_db_security_groups_safe(client)),
        ('db_subnet_groups', lambda: describe_db_subnet_groups_safe(client))
    ]
    
    return execute_parallel_tasks(network_tasks, max_workers=2)

def describe_db_security_groups_safe(client):
    """DescribeDBSecurityGroups 안전 호출"""
    try:
        response = client.describe_db_security_groups()
        security_groups = response.get('DBSecurityGroups', [])
        
        return {
            'total_db_security_groups': len(security_groups),
            'db_security_groups': security_groups,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_db_subnet_groups_safe(client):
    """DescribeDBSubnetGroups 안전 호출"""
    try:
        response = client.describe_db_subnet_groups()
        subnet_groups = response.get('DBSubnetGroups', [])
        
        return {
            'total_db_subnet_groups': len(subnet_groups),
            'db_subnet_groups': subnet_groups,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 3. 설정 및 파라미터 관련 API (2개)
def analyze_configuration_parameters_parallel(client):
    """구성 및 파라미터 분석"""
    config_tasks = [
        ('db_parameters', lambda: describe_db_parameters_safe(client)),
        ('option_groups', lambda: describe_option_groups_safe(client))
    ]
    
    return execute_parallel_tasks(config_tasks, max_workers=2)

def describe_db_parameters_safe(client):
    """DescribeDBParameters 안전 호출"""
    try:
        # 먼저 파라미터 그룹 목록 조회
        pg_response = client.describe_db_parameter_groups()
        parameter_groups = pg_response.get('DBParameterGroups', [])
        
        if not parameter_groups:
            return {'status': 'no_parameter_groups', 'message': 'DB 파라미터 그룹이 없습니다.'}
        
        # 각 파라미터 그룹의 파라미터 조회 (최대 3개)
        parameter_details = []
        for pg in parameter_groups[:3]:
            try:
                params_response = client.describe_db_parameters(
                    DBParameterGroupName=pg['DBParameterGroupName']
                )
                parameter_details.append({
                    'parameter_group_name': pg['DBParameterGroupName'],
                    'parameters': params_response.get('Parameters', [])[:20]  # 최대 20개 파라미터
                })
            except Exception as e:
                print(f"Error getting parameters for {pg['DBParameterGroupName']}: {str(e)}")
                continue
        
        return {
            'total_parameter_groups': len(parameter_groups),
            'parameter_group_details': parameter_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_option_groups_safe(client):
    """DescribeOptionGroups 안전 호출"""
    try:
        response = client.describe_option_groups()
        option_groups = response.get('OptionGroupsList', [])
        
        return {
            'total_option_groups': len(option_groups),
            'option_groups': option_groups,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 4. 데이터 보호 관련 API (4개)
def analyze_data_protection_parallel(client):
    """데이터 보호 분석"""
    protection_tasks = [
        ('db_snapshots', lambda: describe_db_snapshots_safe(client)),
        ('db_snapshot_attributes', lambda: describe_db_snapshot_attributes_safe(client)),
        ('db_instance_automated_backups', lambda: describe_db_instance_automated_backups_safe(client)),
        ('db_cluster_automated_backups', lambda: describe_db_cluster_automated_backups_safe(client))
    ]
    
    return execute_parallel_tasks(protection_tasks, max_workers=4)

def describe_db_snapshots_safe(client):
    """DescribeDBSnapshots 안전 호출"""
    try:
        response = client.describe_db_snapshots()
        snapshots = response.get('DBSnapshots', [])
        
        # 암호화 상태 분석
        encrypted_snapshots = [s for s in snapshots if s.get('Encrypted', False)]
        
        return {
            'total_snapshots': len(snapshots),
            'encrypted_snapshots': len(encrypted_snapshots),
            'snapshots_sample': snapshots[:10],  # 최대 10개만
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_db_snapshot_attributes_safe(client):
    """DescribeDBSnapshotAttributes 안전 호출"""
    try:
        # 먼저 스냅샷 목록 조회
        snapshots_response = client.describe_db_snapshots()
        snapshots = snapshots_response.get('DBSnapshots', [])
        
        if not snapshots:
            return {'status': 'no_snapshots', 'message': '스냅샷이 없습니다.'}
        
        # 첫 번째 스냅샷의 속성 확인
        snapshot_id = snapshots[0]['DBSnapshotIdentifier']
        response = client.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snapshot_id
        )
        
        return {
            'sample_snapshot_id': snapshot_id,
            'snapshot_attributes': response.get('DBSnapshotAttributesResult', {}),
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_db_instance_automated_backups_safe(client):
    """DescribeDBInstanceAutomatedBackups 안전 호출"""
    try:
        response = client.describe_db_instance_automated_backups()
        automated_backups = response.get('DBInstanceAutomatedBackups', [])
        
        return {
            'total_automated_backups': len(automated_backups),
            'automated_backups': automated_backups,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_db_cluster_automated_backups_safe(client):
    """DescribeDBClusterAutomatedBackups 안전 호출"""
    try:
        response = client.describe_db_cluster_automated_backups()
        cluster_backups = response.get('DBClusterAutomatedBackups', [])
        
        return {
            'total_cluster_automated_backups': len(cluster_backups),
            'cluster_automated_backups': cluster_backups,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 5. 접근 관리 관련 API (2개)
def analyze_access_management_parallel(client):
    """접근 관리 분석"""
    access_tasks = [
        ('db_proxies', lambda: describe_db_proxies_safe(client)),
        ('db_proxy_endpoints', lambda: describe_db_proxy_endpoints_safe(client))
    ]
    
    return execute_parallel_tasks(access_tasks, max_workers=2)

def describe_db_proxies_safe(client):
    """DescribeDBProxies 안전 호출"""
    try:
        response = client.describe_db_proxies()
        proxies = response.get('DBProxies', [])
        
        return {
            'total_db_proxies': len(proxies),
            'db_proxies': proxies,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_db_proxy_endpoints_safe(client):
    """DescribeDBProxyEndpoints 안전 호출"""
    try:
        # 먼저 프록시 목록 조회
        proxies_response = client.describe_db_proxies()
        proxies = proxies_response.get('DBProxies', [])
        
        if not proxies:
            return {'status': 'no_proxies', 'message': 'DB 프록시가 없습니다.'}
        
        # 각 프록시의 엔드포인트 조회
        proxy_endpoints = []
        for proxy in proxies[:3]:  # 최대 3개만
            try:
                endpoints_response = client.describe_db_proxy_endpoints(
                    DBProxyName=proxy['DBProxyName']
                )
                proxy_endpoints.append({
                    'proxy_name': proxy['DBProxyName'],
                    'endpoints': endpoints_response.get('DBProxyEndpoints', [])
                })
            except Exception as e:
                print(f"Error getting endpoints for proxy {proxy['DBProxyName']}: {str(e)}")
                continue
        
        return {
            'proxy_endpoints': proxy_endpoints,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 6. 모니터링 및 감사 관련 API (4개)
def analyze_monitoring_auditing_parallel(client):
    """모니터링 및 감사 분석"""
    monitoring_tasks = [
        ('db_log_files', lambda: describe_db_log_files_safe(client)),
        ('events', lambda: describe_events_safe(client)),
        ('event_subscriptions', lambda: describe_event_subscriptions_safe(client)),
        ('pending_maintenance_actions', lambda: describe_pending_maintenance_actions_safe(client))
    ]
    
    return execute_parallel_tasks(monitoring_tasks, max_workers=4)

def describe_db_log_files_safe(client):
    """DescribeDBLogFiles 안전 호출"""
    try:
        # 먼저 인스턴스 목록 조회
        instances_response = client.describe_db_instances()
        instances = instances_response.get('DBInstances', [])
        
        if not instances:
            return {'status': 'no_instances', 'message': '인스턴스가 없습니다.'}
        
        # 첫 번째 인스턴스의 로그 파일 조회
        instance_id = instances[0]['DBInstanceIdentifier']
        response = client.describe_db_log_files(
            DBInstanceIdentifier=instance_id
        )
        
        return {
            'sample_instance_id': instance_id,
            'log_files': response.get('DescribeDBLogFiles', []),
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_events_safe(client):
    """DescribeEvents 안전 호출"""
    try:
        response = client.describe_events(
            SourceType='db-instance',
            MaxRecords=50
        )
        events = response.get('Events', [])
        
        return {
            'total_events': len(events),
            'recent_events': events,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_event_subscriptions_safe(client):
    """DescribeEventSubscriptions 안전 호출"""
    try:
        response = client.describe_event_subscriptions()
        subscriptions = response.get('EventSubscriptionsList', [])
        
        return {
            'total_event_subscriptions': len(subscriptions),
            'event_subscriptions': subscriptions,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_pending_maintenance_actions_safe(client):
    """DescribePendingMaintenanceActions 안전 호출"""
    try:
        response = client.describe_pending_maintenance_actions()
        maintenance_actions = response.get('PendingMaintenanceActions', [])
        
        return {
            'total_pending_maintenance_actions': len(maintenance_actions),
            'pending_maintenance_actions': maintenance_actions,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

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
        'function': event.get('function', 'analyzeRdsSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'rds-security-analysis'),
        'function': event.get('function', 'analyzeRdsSecurity'),
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
