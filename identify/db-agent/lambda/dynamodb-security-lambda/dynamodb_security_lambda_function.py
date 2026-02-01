import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    DB-AGENT DynamoDB Security Analysis Lambda 함수
    15개 API를 통한 종합적인 DynamoDB 보안 상태 분석
    - DynamoDB: 8개 API
    - DAX: 5개 API  
    - DynamoDB Streams: 2개 API
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
        
        # DynamoDB 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_dynamodb_security_data_parallel(session, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeDynamodbSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"DynamoDB 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in DynamoDB security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_dynamodb_security_data_parallel(session, target_region, current_time):
    """
    DynamoDB 보안 데이터를 병렬로 수집 - 15개 API 활용
    """
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('dynamodb_security', lambda: analyze_dynamodb_security_parallel(session, target_region)),
        ('dax_security', lambda: analyze_dax_security_parallel(session, target_region)),
        ('dynamodb_streams_security', lambda: analyze_dynamodb_streams_security_parallel(session, target_region)),
    ]
    
    # 병렬 처리 실행
    results = process_dynamodb_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': 15,
        'collection_method': 'parallel_processing',
        'dynamodb_security_categories': [
            'dynamodb_core_security',
            'dax_security', 
            'dynamodb_streams_security'
        ]
    }
    
    return {
        'function': 'analyzeDynamodbSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'dynamodb_security': results.get('dynamodb_security', {}),
        'dax_security': results.get('dax_security', {}),
        'dynamodb_streams_security': results.get('dynamodb_streams_security', {}),
        'collection_summary': collection_summary
    }

def process_dynamodb_parallel(tasks, max_workers=3):
    """DynamoDB 데이터 수집 작업을 병렬로 처리"""
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

# DynamoDB 보안 분석 (8개 API)
def analyze_dynamodb_security_parallel(session, target_region):
    """DynamoDB 보안 분석"""
    dynamodb_client = session.client('dynamodb', region_name=target_region)
    
    dynamodb_tasks = [
        ('encryption_data_protection', lambda: analyze_dynamodb_encryption_data_protection(dynamodb_client)),
        ('access_control', lambda: analyze_dynamodb_access_control(dynamodb_client)),
        ('backup_recovery', lambda: analyze_dynamodb_backup_recovery(dynamodb_client)),
        ('resource_management', lambda: analyze_dynamodb_resource_management(dynamodb_client))
    ]
    
    return execute_parallel_tasks(dynamodb_tasks, max_workers=4)

# 1. 암호화 및 데이터 보호 (3개 API)
def analyze_dynamodb_encryption_data_protection(client):
    """DynamoDB 암호화 및 데이터 보호 분석"""
    encryption_tasks = [
        ('describe_table', lambda: describe_table_safe(client)),
        ('describe_backup', lambda: describe_backup_safe(client)),
        ('list_backups', lambda: list_backups_safe(client))
    ]
    
    return execute_parallel_tasks(encryption_tasks, max_workers=3)

def describe_table_safe(client):
    """DescribeTable 안전 호출"""
    try:
        # 먼저 테이블 목록 조회
        tables_response = client.list_tables()
        table_names = tables_response.get('TableNames', [])
        
        if not table_names:
            return {'status': 'no_tables', 'message': '테이블이 없습니다.'}
        
        # 각 테이블의 상세 정보 조회 (최대 5개)
        table_details = []
        for table_name in table_names[:5]:
            try:
                table_response = client.describe_table(TableName=table_name)
                table_info = table_response.get('Table', {})
                
                # 암호화 정보 추출
                sse_description = table_info.get('SSEDescription', {})
                
                table_analysis = {
                    'table_name': table_name,
                    'table_status': table_info.get('TableStatus'),
                    'encryption_enabled': sse_description.get('Status') == 'ENABLED',
                    'sse_type': sse_description.get('SSEType'),
                    'kms_master_key_arn': sse_description.get('KMSMasterKeyArn'),
                    'billing_mode': table_info.get('BillingModeSummary', {}).get('BillingMode'),
                    'deletion_protection_enabled': table_info.get('DeletionProtectionEnabled', False),
                    'point_in_time_recovery_status': table_info.get('RestoreSummary', {}).get('RestoreInProgress', False),
                    'stream_specification': table_info.get('StreamSpecification', {}),
                    'global_table_version': table_info.get('GlobalTableVersion')
                }
                table_details.append(table_analysis)
                
            except Exception as e:
                print(f"Error describing table {table_name}: {str(e)}")
                continue
        
        return {
            'total_tables': len(table_names),
            'analyzed_tables': len(table_details),
            'table_details': table_details,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_backup_safe(client):
    """DescribeBackup 안전 호출"""
    try:
        # 먼저 백업 목록 조회
        backups_response = client.list_backups()
        backup_summaries = backups_response.get('BackupSummaries', [])
        
        if not backup_summaries:
            return {'status': 'no_backups', 'message': '백업이 없습니다.'}
        
        # 첫 번째 백업의 상세 정보 조회
        backup_arn = backup_summaries[0]['BackupArn']
        backup_response = client.describe_backup(BackupArn=backup_arn)
        backup_details = backup_response.get('BackupDescription', {})
        
        return {
            'sample_backup_arn': backup_arn,
            'backup_details': backup_details,
            'backup_status': backup_details.get('BackupDetails', {}).get('BackupStatus'),
            'backup_type': backup_details.get('BackupDetails', {}).get('BackupType'),
            'backup_size_bytes': backup_details.get('BackupDetails', {}).get('BackupSizeBytes'),
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_backups_safe(client):
    """ListBackups 안전 호출"""
    try:
        response = client.list_backups()
        backup_summaries = response.get('BackupSummaries', [])
        
        # 백업 암호화 상태 분석
        encrypted_backups = 0
        backup_types = {}
        
        for backup in backup_summaries:
            backup_type = backup.get('BackupType', 'unknown')
            backup_types[backup_type] = backup_types.get(backup_type, 0) + 1
            
            # 백업 암호화 상태는 테이블 암호화 상태를 따름
            # 실제로는 DescribeBackup으로 확인해야 하지만 여기서는 추정
        
        return {
            'total_backups': len(backup_summaries),
            'backup_types': backup_types,
            'backup_summaries': backup_summaries[:10],  # 최대 10개만
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 2. 접근 제어 및 권한 관리 (1개 API)
def analyze_dynamodb_access_control(client):
    """DynamoDB 접근 제어 분석"""
    access_tasks = [
        ('get_resource_policy', lambda: get_resource_policy_safe(client))
    ]
    
    return execute_parallel_tasks(access_tasks, max_workers=1)

def get_resource_policy_safe(client):
    """GetResourcePolicy 안전 호출"""
    try:
        # 먼저 테이블 목록 조회
        tables_response = client.list_tables()
        table_names = tables_response.get('TableNames', [])
        
        if not table_names:
            return {'status': 'no_tables', 'message': '테이블이 없습니다.'}
        
        # 각 테이블의 리소스 정책 조회 (최대 3개)
        resource_policies = []
        for table_name in table_names[:3]:
            try:
                # 테이블 ARN 구성
                table_arn = f"arn:aws:dynamodb:{client.meta.region_name}:{client.meta.service_model.metadata.get('signingName', 'dynamodb')}:table/{table_name}"
                
                policy_response = client.get_resource_policy(ResourceArn=table_arn)
                policy_info = {
                    'table_name': table_name,
                    'resource_arn': table_arn,
                    'policy': policy_response.get('Policy'),
                    'revision_id': policy_response.get('RevisionId')
                }
                resource_policies.append(policy_info)
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'PolicyNotFoundException':
                    resource_policies.append({
                        'table_name': table_name,
                        'resource_arn': table_arn,
                        'policy': None,
                        'message': 'No resource policy found'
                    })
                else:
                    print(f"Error getting resource policy for {table_name}: {str(e)}")
                    continue
            except Exception as e:
                print(f"Error getting resource policy for {table_name}: {str(e)}")
                continue
        
        return {
            'analyzed_tables': len(resource_policies),
            'resource_policies': resource_policies,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 3. 백업 및 복구 정책 (2개 API)
def analyze_dynamodb_backup_recovery(client):
    """DynamoDB 백업 및 복구 정책 분석"""
    backup_tasks = [
        ('describe_continuous_backups', lambda: describe_continuous_backups_safe(client)),
        ('describe_time_to_live', lambda: describe_time_to_live_safe(client))
    ]
    
    return execute_parallel_tasks(backup_tasks, max_workers=2)

def describe_continuous_backups_safe(client):
    """DescribeContinuousBackups 안전 호출"""
    try:
        # 먼저 테이블 목록 조회
        tables_response = client.list_tables()
        table_names = tables_response.get('TableNames', [])
        
        if not table_names:
            return {'status': 'no_tables', 'message': '테이블이 없습니다.'}
        
        # 각 테이블의 연속 백업 상태 조회 (최대 5개)
        continuous_backup_details = []
        for table_name in table_names[:5]:
            try:
                backup_response = client.describe_continuous_backups(TableName=table_name)
                continuous_backups = backup_response.get('ContinuousBackupsDescription', {})
                
                backup_info = {
                    'table_name': table_name,
                    'continuous_backups_status': continuous_backups.get('ContinuousBackupsStatus'),
                    'point_in_time_recovery_description': continuous_backups.get('PointInTimeRecoveryDescription', {}),
                    'pitr_status': continuous_backups.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus'),
                    'earliest_restorable_datetime': continuous_backups.get('PointInTimeRecoveryDescription', {}).get('EarliestRestorableDateTime'),
                    'latest_restorable_datetime': continuous_backups.get('PointInTimeRecoveryDescription', {}).get('LatestRestorableDateTime')
                }
                continuous_backup_details.append(backup_info)
                
            except Exception as e:
                print(f"Error describing continuous backups for {table_name}: {str(e)}")
                continue
        
        return {
            'analyzed_tables': len(continuous_backup_details),
            'continuous_backup_details': continuous_backup_details,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_time_to_live_safe(client):
    """DescribeTimeToLive 안전 호출"""
    try:
        # 먼저 테이블 목록 조회
        tables_response = client.list_tables()
        table_names = tables_response.get('TableNames', [])
        
        if not table_names:
            return {'status': 'no_tables', 'message': '테이블이 없습니다.'}
        
        # 각 테이블의 TTL 설정 조회 (최대 5개)
        ttl_details = []
        for table_name in table_names[:5]:
            try:
                ttl_response = client.describe_time_to_live(TableName=table_name)
                ttl_description = ttl_response.get('TimeToLiveDescription', {})
                
                ttl_info = {
                    'table_name': table_name,
                    'time_to_live_status': ttl_description.get('TimeToLiveStatus'),
                    'attribute_name': ttl_description.get('AttributeName')
                }
                ttl_details.append(ttl_info)
                
            except Exception as e:
                print(f"Error describing TTL for {table_name}: {str(e)}")
                continue
        
        return {
            'analyzed_tables': len(ttl_details),
            'ttl_details': ttl_details,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 4. 리소스 관리 및 분류 (2개 API)
def analyze_dynamodb_resource_management(client):
    """DynamoDB 리소스 관리 분석"""
    resource_tasks = [
        ('list_tables', lambda: list_tables_safe(client)),
        ('list_tags_of_resource', lambda: list_tags_of_resource_safe(client))
    ]
    
    return execute_parallel_tasks(resource_tasks, max_workers=2)

def list_tables_safe(client):
    """ListTables 안전 호출"""
    try:
        response = client.list_tables()
        table_names = response.get('TableNames', [])
        
        return {
            'total_tables': len(table_names),
            'table_names': table_names,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_tags_of_resource_safe(client):
    """ListTagsOfResource 안전 호출"""
    try:
        # 먼저 테이블 목록 조회
        tables_response = client.list_tables()
        table_names = tables_response.get('TableNames', [])
        
        if not table_names:
            return {'status': 'no_tables', 'message': '테이블이 없습니다.'}
        
        # 각 테이블의 태그 조회 (최대 3개)
        table_tags = []
        for table_name in table_names[:3]:
            try:
                # 테이블 ARN 구성
                table_arn = f"arn:aws:dynamodb:{client.meta.region_name}:{client.meta.service_model.metadata.get('signingName', 'dynamodb')}:table/{table_name}"
                
                tags_response = client.list_tags_of_resource(ResourceArn=table_arn)
                tags_info = {
                    'table_name': table_name,
                    'resource_arn': table_arn,
                    'tags': tags_response.get('Tags', [])
                }
                table_tags.append(tags_info)
                
            except Exception as e:
                print(f"Error listing tags for {table_name}: {str(e)}")
                continue
        
        return {
            'analyzed_tables': len(table_tags),
            'table_tags': table_tags,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# DAX 보안 분석 (5개 API)
def analyze_dax_security_parallel(session, target_region):
    """DAX 보안 분석"""
    dax_client = session.client('dax', region_name=target_region)
    
    dax_tasks = [
        ('cluster_security', lambda: describe_clusters_safe(dax_client)),
        ('network_security', lambda: describe_subnet_groups_safe(dax_client)),
        ('configuration_security', lambda: describe_parameters_safe(dax_client)),
        ('event_monitoring', lambda: describe_events_safe(dax_client)),
        ('governance_compliance', lambda: list_tags_safe(dax_client))
    ]
    
    return execute_parallel_tasks(dax_tasks, max_workers=5)

def describe_clusters_safe(client):
    """DescribeClusters 안전 호출"""
    try:
        response = client.describe_clusters()
        clusters = response.get('Clusters', [])
        
        if not clusters:
            return {'status': 'no_clusters', 'message': 'DAX 클러스터가 없습니다.'}
        
        # 클러스터 보안 설정 분석
        cluster_analyses = []
        for cluster in clusters:
            analysis = {
                'cluster_name': cluster.get('ClusterName'),
                'status': cluster.get('Status'),
                'node_type': cluster.get('NodeType'),
                'total_nodes': cluster.get('TotalNodes'),
                'active_nodes': cluster.get('ActiveNodes'),
                'cluster_arn': cluster.get('ClusterArn'),
                'cluster_discovery_endpoint': cluster.get('ClusterDiscoveryEndpoint', {}),
                'subnet_group': cluster.get('SubnetGroup'),
                'security_groups': cluster.get('SecurityGroups', []),
                'iam_role_arn': cluster.get('IamRoleArn'),
                'parameter_group': cluster.get('ParameterGroup', {}),
                'sse_description': cluster.get('SSEDescription', {}),
                'cluster_endpoint_encryption_type': cluster.get('ClusterEndpointEncryptionType')
            }
            cluster_analyses.append(analysis)
        
        return {
            'total_clusters': len(clusters),
            'cluster_details': cluster_analyses,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_subnet_groups_safe(client):
    """DescribeSubnetGroups 안전 호출"""
    try:
        response = client.describe_subnet_groups()
        subnet_groups = response.get('SubnetGroups', [])
        
        return {
            'total_subnet_groups': len(subnet_groups),
            'subnet_groups': subnet_groups,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_parameters_safe(client):
    """DescribeParameters 안전 호출"""
    try:
        # 먼저 파라미터 그룹 목록 조회
        pg_response = client.describe_parameter_groups()
        parameter_groups = pg_response.get('ParameterGroups', [])
        
        if not parameter_groups:
            return {'status': 'no_parameter_groups', 'message': 'DAX 파라미터 그룹이 없습니다.'}
        
        # 각 파라미터 그룹의 파라미터 조회 (최대 3개)
        parameter_details = []
        for pg in parameter_groups[:3]:
            try:
                params_response = client.describe_parameters(
                    ParameterGroupName=pg['ParameterGroupName']
                )
                parameter_details.append({
                    'parameter_group_name': pg['ParameterGroupName'],
                    'parameters': params_response.get('Parameters', [])
                })
            except Exception as e:
                print(f"Error getting DAX parameters for {pg['ParameterGroupName']}: {str(e)}")
                continue
        
        return {
            'total_parameter_groups': len(parameter_groups),
            'parameter_group_details': parameter_details,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_events_safe(client):
    """DescribeEvents 안전 호출"""
    try:
        response = client.describe_events(MaxResults=50)
        events = response.get('Events', [])
        
        return {
            'total_events': len(events),
            'recent_events': events,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_tags_safe(client):
    """ListTags 안전 호출"""
    try:
        # 먼저 클러스터 목록 조회
        clusters_response = client.describe_clusters()
        clusters = clusters_response.get('Clusters', [])
        
        if not clusters:
            return {'status': 'no_clusters', 'message': 'DAX 클러스터가 없습니다.'}
        
        # 각 클러스터의 태그 조회 (최대 3개)
        cluster_tags = []
        for cluster in clusters[:3]:
            try:
                cluster_arn = cluster['ClusterArn']
                tags_response = client.list_tags(ResourceName=cluster_arn)
                tags_info = {
                    'cluster_name': cluster['ClusterName'],
                    'cluster_arn': cluster_arn,
                    'tags': tags_response.get('Tags', [])
                }
                cluster_tags.append(tags_info)
                
            except Exception as e:
                print(f"Error listing DAX tags for {cluster['ClusterName']}: {str(e)}")
                continue
        
        return {
            'analyzed_clusters': len(cluster_tags),
            'cluster_tags': cluster_tags,
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# DynamoDB Streams 보안 분석 (2개 API)
def analyze_dynamodb_streams_security_parallel(session, target_region):
    """DynamoDB Streams 보안 분석"""
    streams_client = session.client('dynamodbstreams', region_name=target_region)
    
    streams_tasks = [
        ('list_streams', lambda: list_streams_safe(streams_client)),
        ('describe_stream', lambda: describe_stream_safe(streams_client))
    ]
    
    return execute_parallel_tasks(streams_tasks, max_workers=2)

def list_streams_safe(client):
    """ListStreams 안전 호출"""
    try:
        response = client.list_streams()
        streams = response.get('Streams', [])
        
        if not streams:
            return {'status': 'no_streams', 'message': 'DynamoDB Streams가 없습니다.'}
        
        # 스트림 상태별 분류
        stream_statuses = {}
        table_names = set()
        
        for stream in streams:
            status = stream.get('StreamStatus', 'unknown')
            stream_statuses[status] = stream_statuses.get(status, 0) + 1
            
            table_name = stream.get('TableName')
            if table_name:
                table_names.add(table_name)
        
        return {
            'total_streams': len(streams),
            'stream_statuses': stream_statuses,
            'connected_tables': len(table_names),
            'streams_sample': streams[:10],  # 최대 10개만
            'status': 'success'
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_stream_safe(client):
    """DescribeStream 안전 호출"""
    try:
        # 먼저 스트림 목록 조회
        streams_response = client.list_streams()
        streams = streams_response.get('Streams', [])
        
        if not streams:
            return {'status': 'no_streams', 'message': 'DynamoDB Streams가 없습니다.'}
        
        # 첫 번째 스트림의 상세 정보 조회
        stream_arn = streams[0]['StreamArn']
        stream_response = client.describe_stream(StreamArn=stream_arn)
        stream_description = stream_response.get('StreamDescription', {})
        
        # 보안 관련 정보 추출
        stream_analysis = {
            'stream_arn': stream_arn,
            'stream_status': stream_description.get('StreamStatus'),
            'stream_view_type': stream_description.get('StreamViewType'),
            'table_name': stream_description.get('TableName'),
            'creation_request_datetime': stream_description.get('CreationRequestDateTime'),
            'shard_count': len(stream_description.get('Shards', [])),
            'shards_sample': stream_description.get('Shards', [])[:3]  # 최대 3개 샤드만
        }
        
        return {
            'sample_stream_arn': stream_arn,
            'stream_analysis': stream_analysis,
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
        'function': event.get('function', 'analyzeDynamodbSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'dynamodb-security-analysis'),
        'function': event.get('function', 'analyzeDynamodbSecurity'),
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
