import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    STORAGE-AGENT EBS Security Analysis Lambda 함수
    8개 EBS API를 통한 종합적인 EBS 보안 상태 분석
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
        
        ec2_client = session.client('ec2', region_name=target_region)
        
        # EBS 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_ebs_security_data_parallel(ec2_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeEbsSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"EBS 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in EBS security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_ebs_security_data_parallel(client, target_region, current_time):
    """
    EBS 보안 데이터를 병렬로 수집 - 8개 API 활용
    """
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('account_encryption_settings', lambda: get_account_encryption_settings_parallel(client)),
        ('volumes_security_analysis', lambda: analyze_volumes_security_parallel(client)),
        ('snapshots_security_analysis', lambda: analyze_snapshots_security_parallel(client)),
        ('public_access_controls', lambda: get_public_access_controls_parallel(client)),
    ]
    
    # 병렬 처리 실행
    results = process_ebs_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': 8,
        'collection_method': 'parallel_processing',
        'encryption_analysis_completed': results.get('account_encryption_settings', {}).get('status') != 'error',
        'volumes_analysis_completed': results.get('volumes_security_analysis', {}).get('status') != 'error',
        'snapshots_analysis_completed': results.get('snapshots_security_analysis', {}).get('status') != 'error'
    }
    
    return {
        'function': 'analyzeEbsSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'account_encryption_settings': results.get('account_encryption_settings', {}),
        'volumes_security': results.get('volumes_security_analysis', {}),
        'snapshots_security': results.get('snapshots_security_analysis', {}),
        'public_access_controls': results.get('public_access_controls', {}),
        'collection_summary': collection_summary
    }

def process_ebs_parallel(tasks, max_workers=4):
    """EBS 데이터 수집 작업을 병렬로 처리"""
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

def get_account_encryption_settings_parallel(client):
    """계정 수준 암호화 설정 조회 (2개 API)"""
    encryption_tasks = [
        ('default_encryption_enabled', lambda: get_ebs_encryption_by_default_safe(client)),
        ('default_kms_key', lambda: get_ebs_default_kms_key_safe(client))
    ]
    
    return execute_parallel_tasks(encryption_tasks, max_workers=2)

def analyze_volumes_security_parallel(client):
    """볼륨 보안 설정 분석 (2개 API)"""
    try:
        # 볼륨 목록 조회
        volumes_response = client.describe_volumes()
        volumes = volumes_response.get('Volumes', [])
        
        if not volumes:
            return {
                'total_volumes': 0,
                'status': 'no_volumes',
                'message': 'EBS 볼륨이 존재하지 않습니다.'
            }
        
        # 볼륨들의 보안 설정을 병렬로 분석
        volume_analyses = process_volumes_parallel(client, volumes, max_workers=5)
        
        # 암호화 통계 계산
        encrypted_volumes = [v for v in volume_analyses if v.get('encrypted', False)]
        unencrypted_volumes = [v for v in volume_analyses if not v.get('encrypted', False)]
        
        # 볼륨 속성 분석 (샘플)
        volume_attributes = []
        for volume in volumes[:5]:  # 최대 5개만 분석
            try:
                attr_response = client.describe_volume_attribute(
                    VolumeId=volume['VolumeId'],
                    Attribute='autoEnableIO'
                )
                volume_attributes.append({
                    'volume_id': volume['VolumeId'],
                    'auto_enable_io': attr_response.get('AutoEnableIO', {})
                })
            except Exception as e:
                print(f"Error getting volume attributes for {volume['VolumeId']}: {str(e)}")
                continue
        
        return {
            'total_volumes': len(volumes),
            'encrypted_volumes': len(encrypted_volumes),
            'unencrypted_volumes': len(unencrypted_volumes),
            'volume_details': volume_analyses,
            'volume_attributes_sample': volume_attributes,
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error analyzing volumes security: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def analyze_snapshots_security_parallel(client):
    """스냅샷 보안 설정 분석 (3개 API)"""
    snapshot_tasks = [
        ('snapshots_list', lambda: get_snapshots_list_safe(client)),
        ('snapshot_attributes', lambda: get_snapshot_attributes_safe(client)),
        ('locked_snapshots', lambda: get_locked_snapshots_safe(client))
    ]
    
    return execute_parallel_tasks(snapshot_tasks, max_workers=3)

def get_public_access_controls_parallel(client):
    """공개 액세스 제어 설정 조회 (1개 API)"""
    try:
        response = client.get_snapshot_block_public_access_state()
        return {
            'snapshot_block_public_access': {
                'state': response.get('State'),
                'managed_by': response.get('ManagedBy')
            },
            'status': 'success'
        }
    except Exception as e:
        print(f"Error getting public access controls: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

# 개별 API 안전 호출 함수들
def get_ebs_encryption_by_default_safe(client):
    """GetEbsEncryptionByDefault 안전 호출"""
    try:
        response = client.get_ebs_encryption_by_default()
        return {
            'ebs_encryption_by_default': response.get('EbsEncryptionByDefault', False),
            'sse_type': response.get('SseType'),
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_ebs_default_kms_key_safe(client):
    """GetEbsDefaultKmsKeyId 안전 호출"""
    try:
        response = client.get_ebs_default_kms_key_id()
        return {
            'default_kms_key_id': response.get('KmsKeyId'),
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def process_volumes_parallel(client, volumes, max_workers=5):
    """볼륨들을 병렬로 처리"""
    if not volumes:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_volume, client, volume) for volume in volumes]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing volume: {str(e)}")
                continue
    
    return results

def analyze_single_volume(client, volume):
    """개별 볼륨 보안 분석"""
    try:
        return {
            'volume_id': volume['VolumeId'],
            'size': volume.get('Size'),
            'volume_type': volume.get('VolumeType'),
            'state': volume.get('State'),
            'encrypted': volume.get('Encrypted', False),
            'kms_key_id': volume.get('KmsKeyId'),
            'iops': volume.get('Iops'),
            'throughput': volume.get('Throughput'),
            'multi_attach_enabled': volume.get('MultiAttachEnabled', False),
            'availability_zone': volume.get('AvailabilityZone'),
            'create_time': volume.get('CreateTime'),
            'tags': volume.get('Tags', [])
        }
    except Exception as e:
        print(f"Error analyzing volume {volume.get('VolumeId', 'unknown')}: {str(e)}")
        return None

def get_snapshots_list_safe(client):
    """DescribeSnapshots 안전 호출"""
    try:
        response = client.describe_snapshots(OwnerIds=['self'])
        snapshots = response.get('Snapshots', [])
        
        # 암호화 통계 계산
        encrypted_snapshots = [s for s in snapshots if s.get('Encrypted', False)]
        unencrypted_snapshots = [s for s in snapshots if not s.get('Encrypted', False)]
        
        return {
            'total_snapshots': len(snapshots),
            'encrypted_snapshots': len(encrypted_snapshots),
            'unencrypted_snapshots': len(unencrypted_snapshots),
            'snapshots_sample': snapshots[:10],  # 처음 10개만
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_snapshot_attributes_safe(client):
    """DescribeSnapshotAttribute 안전 호출 (샘플 스냅샷)"""
    try:
        # 먼저 스냅샷 목록 조회
        snapshots_response = client.describe_snapshots(OwnerIds=['self'], MaxResults=5)
        snapshots = snapshots_response.get('Snapshots', [])
        
        if not snapshots:
            return {'has_snapshots': False, 'message': '스냅샷이 없습니다.'}
        
        # 첫 번째 스냅샷의 속성 확인
        snapshot_id = snapshots[0]['SnapshotId']
        response = client.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute='createVolumePermission'
        )
        
        return {
            'sample_snapshot_id': snapshot_id,
            'create_volume_permissions': response.get('CreateVolumePermissions', []),
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_locked_snapshots_safe(client):
    """DescribeLockedSnapshots 안전 호출"""
    try:
        response = client.describe_locked_snapshots()
        locked_snapshots = response.get('Snapshots', [])
        
        return {
            'total_locked_snapshots': len(locked_snapshots),
            'locked_snapshots_details': locked_snapshots,
            'status': 'success'
        }
    except Exception as e:
        # 이 API는 일부 리전에서 지원되지 않을 수 있음
        return {
            'status': 'not_supported_or_error',
            'error_message': str(e),
            'note': 'Locked snapshots feature may not be available in this region'
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
        'function': event.get('function', 'analyzeEbsSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'ebs-security-analysis'),
        'function': event.get('function', 'analyzeEbsSecurity'),
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
