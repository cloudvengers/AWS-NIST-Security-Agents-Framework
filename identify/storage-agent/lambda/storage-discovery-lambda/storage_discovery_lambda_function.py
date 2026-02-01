import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    STORAGE-AGENT Storage Resources Discovery Lambda 함수
    스토리지 리소스 (S3, EBS, EFS, AWS Backup) 존재 여부 확인
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
        
        # 스토리지 리소스 발견
        discovery_results = discover_storage_resources_parallel(session, target_region, current_time)
        
        # 응답 데이터 구성
        total_services_with_resources = sum(1 for service in discovery_results.values() if service.get('has_resources', False))
        
        response_data = {
            'function': 'discoverStorageResources',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_timestamp': context.aws_request_id,
            'services_discovered': discovery_results,
            'collection_summary': {
                'total_services_checked': len(discovery_results),
                'services_with_resources': total_services_with_resources,
                'discovery_method': 'parallel_processing',
                'agent_type': 'storage-agent',
                'focus': 'storage_resource_security_identification_s3_ebs_efs_backup'
            }
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"스토리지 리소스 Discovery 과정에서 오류 발생: {str(e)}"
        print(f"Error in storage-agent discovery lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def discover_storage_resources_parallel(session, target_region, current_time):
    """
    스토리지 리소스 (S3 + EBS + EFS + AWS Backup) 병렬 발견
    """
    services_to_check = [
        ('s3', discover_s3_resources),
        ('ebs', discover_ebs_resources),
        ('efs', discover_efs_resources),
        ('backup', discover_backup_resources)
    ]
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_service = {
            executor.submit(discover_func, session, target_region, current_time): service_name 
            for service_name, discover_func in services_to_check
        }
        
        for future in concurrent.futures.as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                result = future.result()
                results[service_name] = result
            except Exception as e:
                print(f"Error discovering {service_name}: {str(e)}")
                results[service_name] = {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def discover_s3_resources(session, target_region, current_time):
    """S3 버킷 리소스 발견"""
    try:
        s3_client = session.client('s3', region_name=target_region)
        
        # S3 버킷 목록 조회 (글로벌 서비스이므로 리전 무관)
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        
        if not buckets:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['buckets'],
                'status': 'no_buckets',
                'details': {
                    'note': 'S3 버킷이 존재하지 않습니다.'
                }
            }
        
        # 버킷별 리전 확인 (샘플링)
        region_buckets = []
        for bucket in buckets[:10]:  # 최대 10개만 확인
            try:
                bucket_location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                bucket_region = bucket_location.get('LocationConstraint') or 'us-east-1'
                if bucket_region == target_region:
                    region_buckets.append(bucket)
            except Exception as e:
                print(f"Error checking bucket {bucket['Name']} location: {str(e)}")
                continue
        
        return {
            'has_resources': len(region_buckets) > 0,
            'resource_count': len(buckets),
            'resource_types': ['buckets'],
            'status': 'active',
            'details': {
                'total_buckets': len(buckets),
                'target_region_buckets': len(region_buckets),
                'sample_bucket_names': [b['Name'] for b in region_buckets[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering S3 resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_ebs_resources(session, target_region, current_time):
    """EBS 볼륨 및 스냅샷 리소스 발견"""
    try:
        ec2_client = session.client('ec2', region_name=target_region)
        
        # EBS 볼륨 목록 조회
        volumes_response = ec2_client.describe_volumes()
        volumes = volumes_response.get('Volumes', [])
        
        # EBS 스냅샷 목록 조회 (자신의 스냅샷만)
        snapshots_response = ec2_client.describe_snapshots(OwnerIds=['self'])
        snapshots = snapshots_response.get('Snapshots', [])
        
        total_resources = len(volumes) + len(snapshots)
        
        if total_resources == 0:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['volumes', 'snapshots'],
                'status': 'no_resources',
                'details': {
                    'note': 'EBS 볼륨 및 스냅샷이 존재하지 않습니다.'
                }
            }
        
        # 암호화 상태 분석
        encrypted_volumes = [v for v in volumes if v.get('Encrypted', False)]
        encrypted_snapshots = [s for s in snapshots if s.get('Encrypted', False)]
        
        return {
            'has_resources': total_resources > 0,
            'resource_count': total_resources,
            'resource_types': ['volumes', 'snapshots'],
            'status': 'active',
            'details': {
                'total_volumes': len(volumes),
                'total_snapshots': len(snapshots),
                'encrypted_volumes': len(encrypted_volumes),
                'encrypted_snapshots': len(encrypted_snapshots),
                'sample_volume_ids': [v['VolumeId'] for v in volumes[:5]],
                'sample_snapshot_ids': [s['SnapshotId'] for s in snapshots[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering EBS resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_efs_resources(session, target_region, current_time):
    """EFS 파일시스템 리소스 발견"""
    try:
        efs_client = session.client('efs', region_name=target_region)
        
        # EFS 파일시스템 목록 조회
        filesystems_response = efs_client.describe_file_systems()
        filesystems = filesystems_response.get('FileSystems', [])
        
        if not filesystems:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['filesystems'],
                'status': 'no_filesystems',
                'details': {
                    'note': 'EFS 파일시스템이 존재하지 않습니다.'
                }
            }
        
        # 암호화 상태 및 상태별 분류
        encrypted_filesystems = [fs for fs in filesystems if fs.get('Encrypted', False)]
        available_filesystems = [fs for fs in filesystems if fs.get('LifeCycleState') == 'available']
        
        return {
            'has_resources': len(available_filesystems) > 0,
            'resource_count': len(filesystems),
            'resource_types': ['filesystems'],
            'status': 'active' if available_filesystems else 'no_available_filesystems',
            'details': {
                'total_filesystems': len(filesystems),
                'available_filesystems': len(available_filesystems),
                'encrypted_filesystems': len(encrypted_filesystems),
                'sample_filesystem_ids': [fs['FileSystemId'] for fs in available_filesystems[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering EFS resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_backup_resources(session, target_region, current_time):
    """AWS Backup 리소스 발견"""
    try:
        backup_client = session.client('backup', region_name=target_region)
        
        # 백업 볼트 목록 조회
        vaults_response = backup_client.list_backup_vaults()
        vaults = vaults_response.get('BackupVaultList', [])
        
        # 백업 계획 목록 조회
        plans_response = backup_client.list_backup_plans()
        plans = plans_response.get('BackupPlansList', [])
        
        # 보호된 리소스 목록 조회
        try:
            protected_resources_response = backup_client.list_protected_resources()
            protected_resources = protected_resources_response.get('Results', [])
        except Exception as e:
            print(f"Error listing protected resources: {str(e)}")
            protected_resources = []
        
        total_resources = len(vaults) + len(plans) + len(protected_resources)
        
        if total_resources == 0:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['vaults', 'plans', 'protected_resources'],
                'status': 'no_backup_resources',
                'details': {
                    'note': 'AWS Backup 리소스가 존재하지 않습니다.'
                }
            }
        
        return {
            'has_resources': total_resources > 0,
            'resource_count': total_resources,
            'resource_types': ['vaults', 'plans', 'protected_resources'],
            'status': 'active',
            'details': {
                'total_vaults': len(vaults),
                'total_plans': len(plans),
                'total_protected_resources': len(protected_resources),
                'sample_vault_names': [v['BackupVaultName'] for v in vaults[:5]],
                'sample_plan_names': [p['BackupPlanName'] for p in plans[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering AWS Backup resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

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
        'function': event.get('function', 'discoverStorageResources'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'storage-discovery'),
        'function': event.get('function', 'discoverStorageResources'),
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
