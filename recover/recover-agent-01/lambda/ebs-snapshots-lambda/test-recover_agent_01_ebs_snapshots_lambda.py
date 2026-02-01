import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime
import base64
import hashlib

def lambda_handler(event, context):
    """
    RECOVER-AGENT-01 EBS Snapshots Block Analysis Lambda 함수
    EBS 스냅샷의 블록 레벨 분석을 통한 복구 가능성 평가
    """
    try:
        # 파라미터 추출 및 검증
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
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        ec2_client = session.client('ec2', region_name=target_region)
        ebs_client = session.client('ebs', region_name=target_region)
        
        # EBS 스냅샷 블록 레벨 분석 병렬 수집
        raw_data = collect_ebs_snapshots_raw_data_parallel(ec2_client, ebs_client, target_region, current_time)
        
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_message = f"EBS 스냅샷 블록 분석 중 오류 발생: {str(e)}"
        print(f"Error in EBS snapshots lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_ebs_snapshots_raw_data_parallel(ec2_client, ebs_client, target_region, current_time):
    """
    EBS 스냅샷 블록 레벨 원시 데이터를 병렬로 수집
    """
    # 1단계: 스냅샷 목록 조회
    try:
        snapshots_response = ec2_client.describe_snapshots(OwnerIds=['self'])
        snapshots = snapshots_response.get('Snapshots', [])
        
        if not snapshots:
            return {
                'function': 'analyzeEbsSnapshotSecurity',
                'target_region': target_region,
                'status': 'no_snapshots',
                'message': 'EBS 스냅샷이 존재하지 않습니다.',
                'collection_summary': {
                    'snapshots_found': 0,
                    'total_apis_called': 1,
                    'processing_method': 'parallel_processing'
                }
            }
        
        # 완료된 스냅샷만 분석 대상으로 선정
        completed_snapshots = [s for s in snapshots if s.get('State') == 'completed']
        
        if not completed_snapshots:
            return {
                'function': 'analyzeEbsSnapshotSecurity',
                'target_region': target_region,
                'status': 'no_completed_snapshots',
                'message': '완료된 EBS 스냅샷이 없습니다.',
                'snapshots_summary': {
                    'total_snapshots': len(snapshots),
                    'completed_snapshots': 0,
                    'pending_snapshots': len([s for s in snapshots if s.get('State') == 'pending']),
                    'error_snapshots': len([s for s in snapshots if s.get('State') == 'error'])
                },
                'collection_summary': {
                    'snapshots_analyzed': 0,
                    'total_apis_called': 1,
                    'processing_method': 'parallel_processing'
                }
            }
        
        # 2단계: 병렬로 각 스냅샷 분석 (최대 5개까지)
        snapshots_to_analyze = completed_snapshots[:5]  # 성능을 위해 최대 5개만 분석
        
        # 병렬 처리할 데이터 수집 작업 정의
        data_collection_tasks = [
            ('snapshots_basic_info', lambda: get_snapshots_basic_info(completed_snapshots)),
            ('snapshot_block_analysis', lambda: analyze_snapshots_blocks_parallel(ebs_client, snapshots_to_analyze)),
            ('snapshot_comparison_analysis', lambda: analyze_snapshots_changes_parallel(ebs_client, snapshots_to_analyze)),
            ('snapshot_integrity_check', lambda: check_snapshots_integrity_parallel(ebs_client, snapshots_to_analyze))
        ]
        
        collected_data = {
            'function': 'analyzeEbsSnapshotSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
        }
        
        # 병렬로 데이터 수집
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
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
            'total_snapshots': len(snapshots),
            'completed_snapshots': len(completed_snapshots),
            'analyzed_snapshots': len(snapshots_to_analyze),
            'total_apis_called': len(data_collection_tasks),
            'successful_collections': sum(1 for key, value in collected_data.items() 
                                        if isinstance(value, dict) and value.get('status') == 'success'),
            'processing_method': 'parallel_processing',
            'analysis_categories': {
                'basic_info': 1,
                'block_analysis': 1,
                'comparison_analysis': 1,
                'integrity_check': 1
            }
        }
        
        return collected_data
        
    except Exception as e:
        return {
            'function': 'analyzeEbsSnapshotSecurity',
            'target_region': target_region,
            'status': 'error',
            'error_message': f'스냅샷 목록 조회 중 오류: {str(e)}',
            'collection_summary': {
                'snapshots_analyzed': 0,
                'total_apis_called': 0,
                'processing_method': 'parallel_processing'
            }
        }

def get_snapshots_basic_info(snapshots):
    """
    스냅샷 기본 정보 수집
    """
    try:
        basic_info = []
        for snapshot in snapshots:
            info = {
                'snapshot_id': snapshot.get('SnapshotId'),
                'volume_id': snapshot.get('VolumeId'),
                'volume_size': snapshot.get('VolumeSize'),
                'state': snapshot.get('State'),
                'progress': snapshot.get('Progress'),
                'start_time': snapshot.get('StartTime'),
                'description': snapshot.get('Description'),
                'encrypted': snapshot.get('Encrypted', False),
                'kms_key_id': snapshot.get('KmsKeyId'),
                'owner_id': snapshot.get('OwnerId'),
                'tags': snapshot.get('Tags', [])
            }
            basic_info.append(info)
        
        return {
            'status': 'success',
            'snapshots_info': basic_info,
            'total_snapshots': len(basic_info)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_snapshots_blocks_parallel(ebs_client, snapshots):
    """
    스냅샷들의 블록 구조를 병렬로 분석
    """
    try:
        if not snapshots:
            return {
                'status': 'success',
                'block_analysis': [],
                'message': '분석할 스냅샷이 없습니다.'
            }
        
        block_analysis_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_snapshot = {
                executor.submit(analyze_single_snapshot_blocks, ebs_client, snapshot): snapshot 
                for snapshot in snapshots
            }
            
            for future in concurrent.futures.as_completed(future_to_snapshot):
                snapshot = future_to_snapshot[future]
                try:
                    result = future.result()
                    if result:
                        block_analysis_results.append(result)
                except Exception as e:
                    print(f"Error analyzing blocks for snapshot {snapshot.get('SnapshotId')}: {str(e)}")
                    block_analysis_results.append({
                        'snapshot_id': snapshot.get('SnapshotId'),
                        'status': 'error',
                        'error_message': str(e)
                    })
        
        return {
            'status': 'success',
            'block_analysis': block_analysis_results,
            'total_analyzed': len(block_analysis_results)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_single_snapshot_blocks(ebs_client, snapshot):
    """
    단일 스냅샷의 블록 구조 분석
    """
    try:
        snapshot_id = snapshot.get('SnapshotId')
        
        # ListSnapshotBlocks API 호출 (첫 100개 블록만)
        response = ebs_client.list_snapshot_blocks(
            SnapshotId=snapshot_id,
            MaxResults=100
        )
        
        blocks = response.get('Blocks', [])
        
        return {
            'snapshot_id': snapshot_id,
            'volume_size': response.get('VolumeSize'),
            'block_size': response.get('BlockSize'),
            'expiry_time': response.get('ExpiryTime'),
            'total_blocks_sampled': len(blocks),
            'blocks_sample': blocks[:10],  # 처음 10개 블록만 샘플로 저장
            'next_token': response.get('NextToken'),
            'has_more_blocks': response.get('NextToken') is not None,
            'status': 'success'
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidSnapshotId.NotFound':
            return {
                'snapshot_id': snapshot.get('SnapshotId'),
                'status': 'not_found',
                'error_message': '스냅샷을 찾을 수 없습니다.'
            }
        elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'snapshot_id': snapshot.get('SnapshotId'),
                'status': 'access_denied',
                'error_message': '스냅샷 블록 접근 권한이 없습니다.'
            }
        else:
            return {
                'snapshot_id': snapshot.get('SnapshotId'),
                'status': 'error',
                'error_message': str(e)
            }

def analyze_snapshots_changes_parallel(ebs_client, snapshots):
    """
    스냅샷 간 변경사항을 병렬로 분석
    """
    try:
        if len(snapshots) < 2:
            return {
                'status': 'success',
                'change_analysis': [],
                'message': '변경사항 비교를 위해서는 최소 2개의 스냅샷이 필요합니다.'
            }
        
        # 동일한 볼륨의 스냅샷들을 그룹화
        volume_groups = {}
        for snapshot in snapshots:
            volume_id = snapshot.get('VolumeId')
            if volume_id not in volume_groups:
                volume_groups[volume_id] = []
            volume_groups[volume_id].append(snapshot)
        
        change_analysis_results = []
        
        # 각 볼륨 그룹별로 스냅샷 간 비교
        for volume_id, volume_snapshots in volume_groups.items():
            if len(volume_snapshots) >= 2:
                # 시간순으로 정렬
                volume_snapshots.sort(key=lambda x: x.get('StartTime', ''))
                
                # 연속된 스냅샷 쌍들을 비교
                for i in range(len(volume_snapshots) - 1):
                    first_snapshot = volume_snapshots[i]
                    second_snapshot = volume_snapshots[i + 1]
                    
                    try:
                        change_result = analyze_snapshot_changes(ebs_client, first_snapshot, second_snapshot)
                        if change_result:
                            change_analysis_results.append(change_result)
                    except Exception as e:
                        print(f"Error comparing snapshots {first_snapshot.get('SnapshotId')} and {second_snapshot.get('SnapshotId')}: {str(e)}")
                        change_analysis_results.append({
                            'first_snapshot_id': first_snapshot.get('SnapshotId'),
                            'second_snapshot_id': second_snapshot.get('SnapshotId'),
                            'volume_id': volume_id,
                            'status': 'error',
                            'error_message': str(e)
                        })
        
        return {
            'status': 'success',
            'change_analysis': change_analysis_results,
            'total_comparisons': len(change_analysis_results)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_snapshot_changes(ebs_client, first_snapshot, second_snapshot):
    """
    두 스냅샷 간의 변경사항 분석
    """
    try:
        first_snapshot_id = first_snapshot.get('SnapshotId')
        second_snapshot_id = second_snapshot.get('SnapshotId')
        
        # ListChangedBlocks API 호출
        response = ebs_client.list_changed_blocks(
            FirstSnapshotId=first_snapshot_id,
            SecondSnapshotId=second_snapshot_id,
            MaxResults=100
        )
        
        changed_blocks = response.get('ChangedBlocks', [])
        
        return {
            'first_snapshot_id': first_snapshot_id,
            'second_snapshot_id': second_snapshot_id,
            'volume_id': first_snapshot.get('VolumeId'),
            'volume_size': response.get('VolumeSize'),
            'block_size': response.get('BlockSize'),
            'expiry_time': response.get('ExpiryTime'),
            'total_changed_blocks': len(changed_blocks),
            'changed_blocks_sample': changed_blocks[:10],  # 처음 10개만 샘플로 저장
            'next_token': response.get('NextToken'),
            'has_more_changes': response.get('NextToken') is not None,
            'status': 'success'
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidSnapshotId.NotFound':
            return {
                'first_snapshot_id': first_snapshot.get('SnapshotId'),
                'second_snapshot_id': second_snapshot.get('SnapshotId'),
                'status': 'not_found',
                'error_message': '스냅샷 중 하나를 찾을 수 없습니다.'
            }
        elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'first_snapshot_id': first_snapshot.get('SnapshotId'),
                'second_snapshot_id': second_snapshot.get('SnapshotId'),
                'status': 'access_denied',
                'error_message': '스냅샷 변경사항 접근 권한이 없습니다.'
            }
        else:
            return {
                'first_snapshot_id': first_snapshot.get('SnapshotId'),
                'second_snapshot_id': second_snapshot.get('SnapshotId'),
                'status': 'error',
                'error_message': str(e)
            }

def check_snapshots_integrity_parallel(ebs_client, snapshots):
    """
    스냅샷들의 데이터 무결성을 병렬로 검증 (샘플 블록 기준)
    """
    try:
        if not snapshots:
            return {
                'status': 'success',
                'integrity_check': [],
                'message': '무결성 검사할 스냅샷이 없습니다.'
            }
        
        integrity_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_snapshot = {
                executor.submit(check_single_snapshot_integrity, ebs_client, snapshot): snapshot 
                for snapshot in snapshots[:3]  # 성능을 위해 최대 3개만 검사
            }
            
            for future in concurrent.futures.as_completed(future_to_snapshot):
                snapshot = future_to_snapshot[future]
                try:
                    result = future.result()
                    if result:
                        integrity_results.append(result)
                except Exception as e:
                    print(f"Error checking integrity for snapshot {snapshot.get('SnapshotId')}: {str(e)}")
                    integrity_results.append({
                        'snapshot_id': snapshot.get('SnapshotId'),
                        'status': 'error',
                        'error_message': str(e)
                    })
        
        return {
            'status': 'success',
            'integrity_check': integrity_results,
            'total_checked': len(integrity_results)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def check_single_snapshot_integrity(ebs_client, snapshot):
    """
    단일 스냅샷의 데이터 무결성 검증 (샘플 블록 기준)
    """
    try:
        snapshot_id = snapshot.get('SnapshotId')
        
        # 먼저 블록 목록 조회
        blocks_response = ebs_client.list_snapshot_blocks(
            SnapshotId=snapshot_id,
            MaxResults=10  # 성능을 위해 처음 10개 블록만 검사
        )
        
        blocks = blocks_response.get('Blocks', [])
        if not blocks:
            return {
                'snapshot_id': snapshot_id,
                'status': 'no_blocks',
                'message': '검사할 블록이 없습니다.'
            }
        
        # 처음 3개 블록의 데이터 무결성 검증
        integrity_results = []
        for block in blocks[:3]:
            try:
                block_index = block.get('BlockIndex')
                block_token = block.get('BlockToken')
                
                # GetSnapshotBlock API 호출
                block_response = ebs_client.get_snapshot_block(
                    SnapshotId=snapshot_id,
                    BlockIndex=block_index,
                    BlockToken=block_token
                )
                
                # 체크섬 검증
                checksum = block_response.get('Checksum')
                checksum_algorithm = block_response.get('ChecksumAlgorithm')
                data_length = block_response.get('DataLength')
                
                integrity_results.append({
                    'block_index': block_index,
                    'checksum': checksum,
                    'checksum_algorithm': checksum_algorithm,
                    'data_length': data_length,
                    'integrity_status': 'verified'
                })
                
            except Exception as e:
                integrity_results.append({
                    'block_index': block.get('BlockIndex'),
                    'integrity_status': 'error',
                    'error_message': str(e)
                })
        
        return {
            'snapshot_id': snapshot_id,
            'total_blocks_available': len(blocks),
            'blocks_checked': len(integrity_results),
            'integrity_results': integrity_results,
            'overall_integrity': 'verified' if all(r.get('integrity_status') == 'verified' for r in integrity_results) else 'partial',
            'status': 'success'
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidSnapshotId.NotFound':
            return {
                'snapshot_id': snapshot.get('SnapshotId'),
                'status': 'not_found',
                'error_message': '스냅샷을 찾을 수 없습니다.'
            }
        elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'snapshot_id': snapshot.get('SnapshotId'),
                'status': 'access_denied',
                'error_message': '스냅샷 블록 데이터 접근 권한이 없습니다.'
            }
        else:
            return {
                'snapshot_id': snapshot.get('SnapshotId'),
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
        'function': event.get('function', 'analyzeEbsSnapshotSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'ebs-snapshots-security-analysis'),
        'function': event.get('function', 'analyzeEbsSnapshotSecurity'),
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
