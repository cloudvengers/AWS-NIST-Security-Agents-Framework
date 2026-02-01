import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    STORAGE-AGENT EFS Security Analysis Lambda 함수
    5개 EFS API를 통한 종합적인 EFS 보안 상태 분석
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
        
        efs_client = session.client('efs', region_name=target_region)
        
        # EFS 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_efs_security_data_parallel(efs_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeEfsSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"EFS 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in EFS security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_efs_security_data_parallel(client, target_region, current_time):
    """
    EFS 보안 데이터를 병렬로 수집 - 5개 API 활용
    """
    # 먼저 파일시스템 목록 조회
    try:
        filesystems_response = client.describe_file_systems()
        filesystems = filesystems_response.get('FileSystems', [])
    except Exception as e:
        print(f"Error listing EFS filesystems: {str(e)}")
        return {
            'function': 'analyzeEfsSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'EFS 파일시스템 목록 조회 실패: {str(e)}',
            'collection_summary': {
                'filesystems_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not filesystems:
        return {
            'function': 'analyzeEfsSecurity',
            'target_region': target_region,
            'status': 'no_filesystems',
            'message': 'EFS 파일시스템이 존재하지 않습니다.',
            'collection_summary': {
                'filesystems_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('filesystems_security_analysis', lambda: analyze_filesystems_security_parallel(client, filesystems)),
        ('access_points_analysis', lambda: analyze_access_points_parallel(client)),
        ('mount_targets_analysis', lambda: analyze_mount_targets_parallel(client, filesystems)),
    ]
    
    # 병렬 처리 실행
    results = process_efs_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'filesystems_analyzed': len(filesystems),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': 5,
        'collection_method': 'parallel_processing',
        'filesystem_ids_analyzed': [fs['FileSystemId'] for fs in filesystems[:10]]  # 최대 10개만 표시
    }
    
    return {
        'function': 'analyzeEfsSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'filesystems_data': results.get('filesystems_security_analysis', {}),
        'access_points_data': results.get('access_points_analysis', {}),
        'mount_targets_data': results.get('mount_targets_analysis', {}),
        'collection_summary': collection_summary
    }

def process_efs_parallel(tasks, max_workers=3):
    """EFS 데이터 수집 작업을 병렬로 처리"""
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

def analyze_filesystems_security_parallel(client, filesystems):
    """파일시스템들의 보안 설정을 병렬로 분석 (2개 API: DescribeFileSystems + DescribeFileSystemPolicy)"""
    filesystem_analyses = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(analyze_single_filesystem_security, client, filesystem) for filesystem in filesystems]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    filesystem_analyses.append(result)
            except Exception as e:
                print(f"Error analyzing filesystem: {str(e)}")
                continue
    
    return {
        'total_filesystems_analyzed': len(filesystem_analyses),
        'filesystem_security_details': filesystem_analyses
    }

def analyze_single_filesystem_security(client, filesystem):
    """개별 파일시스템의 보안 설정 종합 분석"""
    filesystem_id = filesystem['FileSystemId']
    
    try:
        # 파일시스템 기본 보안 설정 분석
        basic_security = analyze_filesystem_basic_security(filesystem)
        
        # 파일시스템 정책 조회
        policy_data = get_filesystem_policy_safe(client, filesystem_id)
        
        return {
            'filesystem_id': filesystem_id,
            'creation_token': filesystem.get('CreationToken'),
            'lifecycle_state': filesystem.get('LifeCycleState'),
            'performance_mode': filesystem.get('PerformanceMode'),
            'throughput_mode': filesystem.get('ThroughputMode'),
            'basic_security': basic_security,
            'filesystem_policy': policy_data
        }
        
    except Exception as e:
        print(f"Error analyzing filesystem {filesystem_id}: {str(e)}")
        return {
            'filesystem_id': filesystem_id,
            'status': 'error',
            'error_message': str(e)
        }

def analyze_filesystem_basic_security(filesystem):
    """파일시스템 기본 보안 설정 분석"""
    return {
        'encrypted': filesystem.get('Encrypted', False),
        'kms_key_id': filesystem.get('KmsKeyId'),
        'creation_time': filesystem.get('CreationTime'),
        'size_in_bytes': filesystem.get('SizeInBytes', {}),
        'number_of_mount_targets': filesystem.get('NumberOfMountTargets', 0),
        'availability_zone_name': filesystem.get('AvailabilityZoneName'),
        'availability_zone_id': filesystem.get('AvailabilityZoneId'),
        'tags': filesystem.get('Tags', []),
        'file_system_protection': filesystem.get('FileSystemProtection', {}),
        'replication_overwrite_protection': filesystem.get('ReplicationOverwriteProtection')
    }

def get_filesystem_policy_safe(client, filesystem_id):
    """DescribeFileSystemPolicy 안전 호출"""
    try:
        response = client.describe_file_system_policy(FileSystemId=filesystem_id)
        policy_text = response.get('Policy', '{}')
        return {
            'has_policy': True,
            'policy': json.loads(policy_text) if policy_text else {},
            'policy_text': policy_text
        }
    except client.exceptions.PolicyNotFound:
        return {'has_policy': False, 'message': '파일시스템 정책이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_access_points_parallel(client):
    """액세스 포인트 보안 설정 분석 (1개 API: DescribeAccessPoints)"""
    try:
        response = client.describe_access_points()
        access_points = response.get('AccessPoints', [])
        
        if not access_points:
            return {
                'total_access_points': 0,
                'status': 'no_access_points',
                'message': 'EFS 액세스 포인트가 존재하지 않습니다.'
            }
        
        # 액세스 포인트 보안 설정 분석
        access_point_analyses = []
        for ap in access_points:
            analysis = {
                'access_point_id': ap.get('AccessPointId'),
                'access_point_arn': ap.get('AccessPointArn'),
                'file_system_id': ap.get('FileSystemId'),
                'lifecycle_state': ap.get('LifeCycleState'),
                'posix_user': ap.get('PosixUser', {}),
                'root_directory': ap.get('RootDirectory', {}),
                'creation_info': ap.get('RootDirectory', {}).get('CreationInfo', {}),
                'tags': ap.get('Tags', [])
            }
            access_point_analyses.append(analysis)
        
        return {
            'total_access_points': len(access_points),
            'access_point_details': access_point_analyses,
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error analyzing access points: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def analyze_mount_targets_parallel(client, filesystems):
    """마운트 타겟 및 보안 그룹 분석 (2개 API: DescribeMountTargets + DescribeMountTargetSecurityGroups)"""
    try:
        all_mount_targets = []
        mount_target_security_groups = []
        
        # 각 파일시스템의 마운트 타겟 조회
        for filesystem in filesystems:
            filesystem_id = filesystem['FileSystemId']
            
            try:
                # 마운트 타겟 목록 조회
                mt_response = client.describe_mount_targets(FileSystemId=filesystem_id)
                mount_targets = mt_response.get('MountTargets', [])
                
                for mt in mount_targets:
                    mt['FileSystemId'] = filesystem_id  # 파일시스템 ID 추가
                    all_mount_targets.append(mt)
                    
                    # 각 마운트 타겟의 보안 그룹 조회
                    try:
                        sg_response = client.describe_mount_target_security_groups(
                            MountTargetId=mt['MountTargetId']
                        )
                        security_groups = sg_response.get('SecurityGroups', [])
                        mount_target_security_groups.append({
                            'mount_target_id': mt['MountTargetId'],
                            'filesystem_id': filesystem_id,
                            'security_groups': security_groups
                        })
                    except Exception as e:
                        print(f"Error getting security groups for mount target {mt['MountTargetId']}: {str(e)}")
                        continue
                        
            except Exception as e:
                print(f"Error getting mount targets for filesystem {filesystem_id}: {str(e)}")
                continue
        
        return {
            'total_mount_targets': len(all_mount_targets),
            'mount_targets_details': all_mount_targets,
            'mount_target_security_groups': mount_target_security_groups,
            'status': 'success'
        }
        
    except Exception as e:
        print(f"Error analyzing mount targets: {str(e)}")
        return {
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
        'function': event.get('function', 'analyzeEfsSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'efs-security-analysis'),
        'function': event.get('function', 'analyzeEfsSecurity'),
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
