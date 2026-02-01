import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 S3 Security Analysis Lambda 함수
    22개 S3 API를 통한 종합적인 S3 보안 상태 분석
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
        
        s3_client = session.client('s3', region_name=target_region)
        
        # S3 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_s3_security_data_parallel(s3_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeS3Security',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"S3 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in S3 security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_s3_security_data_parallel(client, target_region, current_time):
    """
    S3 보안 데이터를 병렬로 수집 - 22개 API 활용
    """
    # 먼저 버킷 목록 조회
    try:
        buckets_response = client.list_buckets()
        all_buckets = buckets_response.get('Buckets', [])
    except Exception as e:
        print(f"Error listing buckets: {str(e)}")
        return {
            'function': 'analyzeS3Security',
            'target_region': target_region,
            'status': 'error',
            'message': f'S3 버킷 목록 조회 실패: {str(e)}',
            'collection_summary': {
                'buckets_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not all_buckets:
        return {
            'function': 'analyzeS3Security',
            'target_region': target_region,
            'status': 'no_buckets',
            'message': 'S3 버킷이 존재하지 않습니다.',
            'collection_summary': {
                'buckets_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 대상 리전의 버킷만 필터링
    target_buckets = filter_buckets_by_region(client, all_buckets, target_region)
    
    if not target_buckets:
        return {
            'function': 'analyzeS3Security',
            'target_region': target_region,
            'status': 'no_regional_buckets',
            'message': f'{target_region} 리전에 S3 버킷이 존재하지 않습니다.',
            'all_buckets_count': len(all_buckets),
            'collection_summary': {
                'buckets_found': 0,
                'total_account_buckets': len(all_buckets),
                'apis_called': len(all_buckets) + 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('bucket_security_analysis', lambda: analyze_buckets_security_parallel(client, target_buckets)),
        ('account_level_settings', lambda: get_account_level_settings(client)),
    ]
    
    # 병렬 처리 실행
    results = process_s3_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'buckets_analyzed': len(target_buckets),
        'total_account_buckets': len(all_buckets),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': calculate_total_apis_called(target_buckets),
        'collection_method': 'parallel_processing',
        'bucket_names_analyzed': [b['Name'] for b in target_buckets[:10]]  # 최대 10개만 표시
    }
    
    return {
        'function': 'analyzeS3Security',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'buckets_data': results.get('bucket_security_analysis', {}),
        'account_settings': results.get('account_level_settings', {}),
        'collection_summary': collection_summary
    }

def filter_buckets_by_region(client, buckets, target_region):
    """대상 리전의 버킷만 필터링"""
    target_buckets = []
    
    for bucket in buckets[:20]:  # 성능을 위해 최대 20개만 확인
        try:
            location_response = client.get_bucket_location(Bucket=bucket['Name'])
            bucket_region = location_response.get('LocationConstraint')
            # LocationConstraint가 None이면 us-east-1
            if bucket_region is None:
                bucket_region = 'us-east-1'
            
            if bucket_region == target_region:
                target_buckets.append(bucket)
        except Exception as e:
            print(f"Error getting bucket location for {bucket['Name']}: {str(e)}")
            continue
    
    return target_buckets

def process_s3_parallel(tasks, max_workers=2):
    """S3 데이터 수집 작업을 병렬로 처리"""
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

def analyze_buckets_security_parallel(client, buckets, max_workers=3):
    """버킷들의 보안 설정을 병렬로 분석"""
    bucket_analyses = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_bucket_security, client, bucket) for bucket in buckets]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    bucket_analyses.append(result)
            except Exception as e:
                print(f"Error analyzing bucket: {str(e)}")
                continue
    
    return {
        'total_buckets_analyzed': len(bucket_analyses),
        'bucket_security_details': bucket_analyses
    }

def analyze_single_bucket_security(client, bucket):
    """개별 버킷의 보안 설정 종합 분석 - 18개 API 사용"""
    bucket_name = bucket['Name']
    
    try:
        # 버킷 레벨 접근 제어 API (5개)
        access_control_data = get_bucket_access_control_parallel(client, bucket_name)
        
        # 버킷 레벨 보안 설정 API (7개)
        security_settings_data = get_bucket_security_settings_parallel(client, bucket_name)
        
        # 데이터 관리 및 컴플라이언스 API (2개)
        compliance_data = get_bucket_compliance_settings_parallel(client, bucket_name)
        
        # 버킷 레벨 고급 보안 설정 API (2개)
        advanced_security_data = get_bucket_advanced_security_parallel(client, bucket_name)
        
        # 객체 레벨 보안 API (4개) - 샘플 객체들에 대해
        object_security_data = get_object_level_security_parallel(client, bucket_name)
        
        return {
            'bucket_name': bucket_name,
            'creation_date': bucket.get('CreationDate'),
            'access_control': access_control_data,
            'security_settings': security_settings_data,
            'compliance_settings': compliance_data,
            'advanced_security': advanced_security_data,
            'object_security_sample': object_security_data
        }
        
    except Exception as e:
        print(f"Error analyzing bucket {bucket_name}: {str(e)}")
        return {
            'bucket_name': bucket_name,
            'status': 'error',
            'error_message': str(e)
        }

def get_bucket_access_control_parallel(client, bucket_name):
    """버킷 레벨 접근 제어 API (5개) 병렬 수집"""
    access_control_tasks = [
        ('bucket_policy', lambda: get_bucket_policy_safe(client, bucket_name)),
        ('bucket_policy_status', lambda: get_bucket_policy_status_safe(client, bucket_name)),
        ('bucket_acl', lambda: get_bucket_acl_safe(client, bucket_name)),
        ('public_access_block', lambda: get_public_access_block_safe(client, bucket_name)),
        ('ownership_controls', lambda: get_ownership_controls_safe(client, bucket_name))
    ]
    
    return execute_parallel_tasks(access_control_tasks, max_workers=5)

def get_bucket_security_settings_parallel(client, bucket_name):
    """버킷 레벨 보안 설정 API (7개) 병렬 수집"""
    security_tasks = [
        ('encryption', lambda: get_bucket_encryption_safe(client, bucket_name)),
        ('versioning', lambda: get_bucket_versioning_safe(client, bucket_name)),
        ('website', lambda: get_bucket_website_safe(client, bucket_name)),
        ('cors', lambda: get_bucket_cors_safe(client, bucket_name)),
        ('accelerate', lambda: get_bucket_accelerate_safe(client, bucket_name)),
        ('logging', lambda: get_bucket_logging_safe(client, bucket_name)),
        ('tagging', lambda: get_bucket_tagging_safe(client, bucket_name))
    ]
    
    return execute_parallel_tasks(security_tasks, max_workers=5)

def get_bucket_compliance_settings_parallel(client, bucket_name):
    """데이터 관리 및 컴플라이언스 API (2개) 병렬 수집"""
    compliance_tasks = [
        ('lifecycle', lambda: get_bucket_lifecycle_safe(client, bucket_name)),
        ('inventory', lambda: get_bucket_inventory_safe(client, bucket_name))
    ]
    
    return execute_parallel_tasks(compliance_tasks, max_workers=2)

def get_bucket_advanced_security_parallel(client, bucket_name):
    """버킷 레벨 고급 보안 설정 API (2개) 병렬 수집"""
    advanced_tasks = [
        ('notification', lambda: get_bucket_notification_safe(client, bucket_name)),
        ('replication', lambda: get_bucket_replication_safe(client, bucket_name))
    ]
    
    return execute_parallel_tasks(advanced_tasks, max_workers=2)

def get_object_level_security_parallel(client, bucket_name):
    """객체 레벨 보안 API (4개) - 샘플 객체들에 대해 수집"""
    try:
        # 먼저 버킷의 객체 목록 조회 (최대 10개)
        objects_response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
        objects = objects_response.get('Contents', [])
        
        if not objects:
            return {
                'object_count': 0,
                'message': '버킷에 객체가 없습니다.',
                'object_lock_config': get_object_lock_config_safe(client, bucket_name)
            }
        
        # 첫 번째 객체에 대해서만 상세 분석 (성능 고려)
        sample_object = objects[0]
        object_key = sample_object['Key']
        
        object_tasks = [
            ('object_acl', lambda: get_object_acl_safe(client, bucket_name, object_key)),
            ('object_legal_hold', lambda: get_object_legal_hold_safe(client, bucket_name, object_key)),
            ('object_retention', lambda: get_object_retention_safe(client, bucket_name, object_key)),
            ('object_metadata', lambda: get_object_head_safe(client, bucket_name, object_key))
        ]
        
        object_security_data = execute_parallel_tasks(object_tasks, max_workers=4)
        
        return {
            'object_count': len(objects),
            'sample_object_key': object_key,
            'sample_object_security': object_security_data,
            'object_lock_config': get_object_lock_config_safe(client, bucket_name)
        }
        
    except Exception as e:
        print(f"Error getting object level security for {bucket_name}: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e),
            'object_lock_config': get_object_lock_config_safe(client, bucket_name)
        }

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
# 버킷 레벨 접근 제어 API 안전 호출 함수들
def get_bucket_policy_safe(client, bucket_name):
    """GetBucketPolicy 안전 호출"""
    try:
        response = client.get_bucket_policy(Bucket=bucket_name)
        policy_text = response.get('Policy', '{}')
        return {
            'has_policy': True,
            'policy': json.loads(policy_text) if policy_text else {},
            'policy_text': policy_text
        }
    except client.exceptions.NoSuchBucketPolicy:
        return {'has_policy': False, 'message': '버킷 정책이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_policy_status_safe(client, bucket_name):
    """GetBucketPolicyStatus 안전 호출"""
    try:
        response = client.get_bucket_policy_status(Bucket=bucket_name)
        return {
            'is_public': response.get('PolicyStatus', {}).get('IsPublic', False)
        }
    except client.exceptions.NoSuchBucketPolicy:
        return {'is_public': False, 'message': '버킷 정책이 없어 퍼블릭 아님'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_acl_safe(client, bucket_name):
    """GetBucketAcl 안전 호출"""
    try:
        response = client.get_bucket_acl(Bucket=bucket_name)
        grants = response.get('Grants', [])
        
        # Everyone 또는 AuthenticatedUsers 권한 확인
        public_grants = []
        for grant in grants:
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    public_grants.append(grant)
        
        return {
            'owner': response.get('Owner', {}),
            'grants': grants,
            'public_grants': public_grants,
            'has_public_access': len(public_grants) > 0
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_public_access_block_safe(client, bucket_name):
    """GetPublicAccessBlock 안전 호출"""
    try:
        response = client.get_public_access_block(Bucket=bucket_name)
        config = response.get('PublicAccessBlockConfiguration', {})
        return {
            'block_public_acls': config.get('BlockPublicAcls', False),
            'ignore_public_acls': config.get('IgnorePublicAcls', False),
            'block_public_policy': config.get('BlockPublicPolicy', False),
            'restrict_public_buckets': config.get('RestrictPublicBuckets', False),
            'is_configured': True
        }
    except client.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {
            'is_configured': False,
            'message': '퍼블릭 액세스 차단 설정이 구성되지 않음',
            'block_public_acls': False,
            'ignore_public_acls': False,
            'block_public_policy': False,
            'restrict_public_buckets': False
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_ownership_controls_safe(client, bucket_name):
    """GetBucketOwnershipControls 안전 호출"""
    try:
        response = client.get_bucket_ownership_controls(Bucket=bucket_name)
        rules = response.get('OwnershipControls', {}).get('Rules', [])
        return {
            'has_ownership_controls': True,
            'rules': rules
        }
    except client.exceptions.NoSuchBucketOwnershipControls:
        return {'has_ownership_controls': False, 'message': '소유권 제어 설정이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 버킷 레벨 보안 설정 API 안전 호출 함수들
def get_bucket_encryption_safe(client, bucket_name):
    """GetBucketEncryption 안전 호출"""
    try:
        response = client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        return {
            'has_encryption': True,
            'encryption_rules': rules
        }
    except client.exceptions.NoSuchBucketEncryption:
        return {
            'has_encryption': False,
            'message': '기본 SSE-S3 암호화 사용 (명시적 설정 없음)'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_versioning_safe(client, bucket_name):
    """GetBucketVersioning 안전 호출"""
    try:
        response = client.get_bucket_versioning(Bucket=bucket_name)
        return {
            'status': response.get('Status', 'Disabled'),
            'mfa_delete': response.get('MfaDelete', 'Disabled')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_website_safe(client, bucket_name):
    """GetBucketWebsite 안전 호출"""
    try:
        response = client.get_bucket_website(Bucket=bucket_name)
        return {
            'is_website': True,
            'index_document': response.get('IndexDocument', {}),
            'error_document': response.get('ErrorDocument', {}),
            'redirect_all_requests': response.get('RedirectAllRequestsTo', {})
        }
    except client.exceptions.NoSuchWebsiteConfiguration:
        return {'is_website': False, 'message': '정적 웹사이트 호스팅 비활성화'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_cors_safe(client, bucket_name):
    """GetBucketCors 안전 호출"""
    try:
        response = client.get_bucket_cors(Bucket=bucket_name)
        return {
            'has_cors': True,
            'cors_rules': response.get('CORSRules', [])
        }
    except client.exceptions.NoSuchCORSConfiguration:
        return {'has_cors': False, 'message': 'CORS 설정이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_accelerate_safe(client, bucket_name):
    """GetBucketAccelerateConfiguration 안전 호출"""
    try:
        response = client.get_bucket_accelerate_configuration(Bucket=bucket_name)
        return {
            'status': response.get('Status', 'Suspended')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_logging_safe(client, bucket_name):
    """GetBucketLogging 안전 호출"""
    try:
        response = client.get_bucket_logging(Bucket=bucket_name)
        logging_enabled = response.get('LoggingEnabled', {})
        return {
            'is_logging_enabled': bool(logging_enabled),
            'logging_config': logging_enabled
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_tagging_safe(client, bucket_name):
    """GetBucketTagging 안전 호출"""
    try:
        response = client.get_bucket_tagging(Bucket=bucket_name)
        return {
            'has_tags': True,
            'tags': response.get('TagSet', [])
        }
    except client.exceptions.NoSuchTagSet:
        return {'has_tags': False, 'message': '버킷 태그가 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
# 컴플라이언스 및 고급 보안 설정 API 안전 호출 함수들
def get_bucket_lifecycle_safe(client, bucket_name):
    """GetBucketLifecycle 안전 호출"""
    try:
        response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return {
            'has_lifecycle': True,
            'rules': response.get('Rules', [])
        }
    except client.exceptions.NoSuchLifecycleConfiguration:
        return {'has_lifecycle': False, 'message': '생명주기 정책이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_inventory_safe(client, bucket_name):
    """GetBucketInventoryConfiguration 안전 호출"""
    try:
        # 인벤토리 설정 목록 조회
        response = client.list_bucket_inventory_configurations(Bucket=bucket_name)
        configs = response.get('InventoryConfigurationList', [])
        return {
            'has_inventory': len(configs) > 0,
            'inventory_configs': configs
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_notification_safe(client, bucket_name):
    """GetBucketNotificationConfiguration 안전 호출"""
    try:
        response = client.get_bucket_notification_configuration(Bucket=bucket_name)
        return {
            'has_notifications': True,
            'lambda_configurations': response.get('LambdaConfigurations', []),
            'queue_configurations': response.get('QueueConfigurations', []),
            'topic_configurations': response.get('TopicConfigurations', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_bucket_replication_safe(client, bucket_name):
    """GetBucketReplication 안전 호출"""
    try:
        response = client.get_bucket_replication(Bucket=bucket_name)
        return {
            'has_replication': True,
            'replication_configuration': response.get('ReplicationConfiguration', {})
        }
    except client.exceptions.NoSuchBucketReplication:
        return {'has_replication': False, 'message': '복제 설정이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 객체 레벨 보안 API 안전 호출 함수들
def get_object_acl_safe(client, bucket_name, object_key):
    """GetObjectAcl 안전 호출"""
    try:
        response = client.get_object_acl(Bucket=bucket_name, Key=object_key)
        return {
            'owner': response.get('Owner', {}),
            'grants': response.get('Grants', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_object_legal_hold_safe(client, bucket_name, object_key):
    """GetObjectLegalHold 안전 호출"""
    try:
        response = client.get_object_legal_hold(Bucket=bucket_name, Key=object_key)
        return {
            'legal_hold': response.get('LegalHold', {})
        }
    except client.exceptions.NoSuchObjectLegalHold:
        return {'has_legal_hold': False, 'message': '법적 보존 설정이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_object_retention_safe(client, bucket_name, object_key):
    """GetObjectRetention 안전 호출"""
    try:
        response = client.get_object_retention(Bucket=bucket_name, Key=object_key)
        return {
            'retention': response.get('Retention', {})
        }
    except client.exceptions.NoSuchObjectRetention:
        return {'has_retention': False, 'message': '객체 보존 설정이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_object_head_safe(client, bucket_name, object_key):
    """HeadObject 안전 호출"""
    try:
        response = client.head_object(Bucket=bucket_name, Key=object_key)
        return {
            'content_type': response.get('ContentType'),
            'content_length': response.get('ContentLength'),
            'etag': response.get('ETag'),
            'last_modified': response.get('LastModified'),
            'server_side_encryption': response.get('ServerSideEncryption'),
            'sse_kms_key_id': response.get('SSEKMSKeyId'),
            'metadata': response.get('Metadata', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_object_lock_config_safe(client, bucket_name):
    """GetObjectLockConfiguration 안전 호출"""
    try:
        response = client.get_object_lock_configuration(Bucket=bucket_name)
        return {
            'has_object_lock': True,
            'object_lock_configuration': response.get('ObjectLockConfiguration', {})
        }
    except client.exceptions.NoSuchObjectLockConfiguration:
        return {'has_object_lock': False, 'message': '객체 잠금 설정이 없음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 계정 레벨 설정 함수
def get_account_level_settings(client):
    """계정 레벨 S3 설정 조회"""
    try:
        # 계정 레벨 퍼블릭 액세스 블록 설정 조회 (S3 Control API 필요)
        return {
            'message': '계정 레벨 설정은 S3 Control API를 통해 조회 가능',
            'note': '현재 구현에서는 버킷 레벨 설정에 집중'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 헬퍼 함수들
def calculate_total_apis_called(buckets):
    """총 API 호출 수 계산"""
    # 기본 API: ListBuckets(1) + GetBucketLocation(버킷수)
    base_apis = 1 + len(buckets)
    
    # 버킷당 API: 18개 (접근제어 5 + 보안설정 7 + 컴플라이언스 2 + 고급보안 2 + 객체보안 2)
    # 객체가 있는 경우 추가 4개 API
    bucket_apis = len(buckets) * 22  # 평균적으로 22개 API per bucket
    
    return base_apis + bucket_apis

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
        'function': event.get('function', 'analyzeS3Security'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 's3-security-analysis'),
        'function': event.get('function', 'analyzeS3Security'),
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
