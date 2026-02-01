import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 ECR Security Analysis Lambda 함수
    7개 ECR API를 통한 종합적인 ECR 보안 상태 분석
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
        
        ecr_client = session.client('ecr', region_name=target_region)
        
        # ECR 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_ecr_security_data_parallel(ecr_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeEcrSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"ECR 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in ECR security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_ecr_security_data_parallel(client, target_region, current_time):
    """
    ECR 보안 데이터를 병렬로 수집 - 7개 API 활용
    """
    # 먼저 리포지토리 목록 조회
    try:
        repositories_response = client.describe_repositories()
        repositories = repositories_response.get('repositories', [])
    except Exception as e:
        print(f"Error listing ECR repositories: {str(e)}")
        return {
            'function': 'analyzeEcrSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'ECR 리포지토리 목록 조회 실패: {str(e)}',
            'collection_summary': {
                'repositories_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not repositories:
        return {
            'function': 'analyzeEcrSecurity',
            'target_region': target_region,
            'status': 'no_repositories',
            'message': 'ECR 리포지토리가 존재하지 않습니다.',
            'collection_summary': {
                'repositories_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('repositories_security_analysis', lambda: analyze_repositories_security_parallel(client, repositories)),
        ('registry_scanning_config', lambda: get_registry_scanning_configuration_safe(client)),
    ]
    
    # 병렬 처리 실행
    results = process_ecr_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'repositories_analyzed': len(repositories),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': calculate_total_ecr_apis_called(repositories),
        'collection_method': 'parallel_processing',
        'repository_names_analyzed': [r['repositoryName'] for r in repositories[:10]]  # 최대 10개만 표시
    }
    
    return {
        'function': 'analyzeEcrSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'repositories_data': results.get('repositories_security_analysis', {}),
        'registry_config': results.get('registry_scanning_config', {}),
        'collection_summary': collection_summary
    }

def process_ecr_parallel(tasks, max_workers=2):
    """ECR 데이터 수집 작업을 병렬로 처리"""
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

def analyze_repositories_security_parallel(client, repositories, max_workers=5):
    """리포지토리들의 보안 설정을 병렬로 분석"""
    repository_analyses = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_repository_security, client, repo) for repo in repositories]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    repository_analyses.append(result)
            except Exception as e:
                print(f"Error analyzing repository: {str(e)}")
                continue
    
    return {
        'total_repositories_analyzed': len(repository_analyses),
        'repository_security_details': repository_analyses
    }

def analyze_single_repository_security(client, repository):
    """개별 리포지토리의 보안 설정 종합 분석 - 6개 API 사용"""
    repository_name = repository['repositoryName']
    
    try:
        # 리포지토리 보안 분석 데이터 수집
        security_tasks = [
            ('repository_policy', lambda: get_repository_policy_safe(client, repository_name)),
            ('lifecycle_policy', lambda: get_lifecycle_policy_safe(client, repository_name)),
            ('images_analysis', lambda: analyze_repository_images_security(client, repository_name)),
            ('scan_findings', lambda: get_image_scan_findings_safe(client, repository_name))
        ]
        
        security_data = execute_parallel_tasks(security_tasks, max_workers=4)
        
        # 리포지토리 기본 보안 설정 분석
        basic_security = analyze_repository_basic_security(repository)
        
        return {
            'repository_name': repository_name,
            'repository_arn': repository.get('repositoryArn'),
            'repository_uri': repository.get('repositoryUri'),
            'created_at': repository.get('createdAt'),
            'basic_security': basic_security,
            'repository_policy': security_data.get('repository_policy', {}),
            'lifecycle_policy': security_data.get('lifecycle_policy', {}),
            'images_analysis': security_data.get('images_analysis', {}),
            'scan_findings': security_data.get('scan_findings', {})
        }
        
    except Exception as e:
        print(f"Error analyzing repository {repository_name}: {str(e)}")
        return {
            'repository_name': repository_name,
            'status': 'error',
            'error_message': str(e)
        }

def analyze_repository_basic_security(repository):
    """리포지토리 기본 보안 설정 분석"""
    encryption_config = repository.get('encryptionConfiguration', {})
    scan_config = repository.get('imageScanningConfiguration', {})
    tag_mutability = repository.get('imageTagMutability', 'MUTABLE')
    
    return {
        'encryption_enabled': encryption_config.get('encryptionType') == 'KMS',
        'encryption_type': encryption_config.get('encryptionType', 'AES256'),
        'kms_key': encryption_config.get('kmsKey'),
        'scan_on_push_enabled': scan_config.get('scanOnPush', False),
        'tag_mutability': tag_mutability,
        'tag_immutable': tag_mutability == 'IMMUTABLE',
        'registry_id': repository.get('registryId'),
        'repository_size_bytes': repository.get('repositorySizeInBytes', 0)
    }

def get_repository_policy_safe(client, repository_name):
    """GetRepositoryPolicy 안전 호출"""
    try:
        response = client.get_repository_policy(repositoryName=repository_name)
        policy_text = response.get('policyText', '{}')
        return {
            'has_policy': True,
            'policy': json.loads(policy_text) if policy_text else {},
            'policy_text': policy_text,
            'registry_id': response.get('registryId')
        }
    except client.exceptions.RepositoryPolicyNotFoundException:
        return {'has_policy': False, 'message': '리포지토리 정책이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_lifecycle_policy_safe(client, repository_name):
    """GetLifecyclePolicy 안전 호출"""
    try:
        response = client.get_lifecycle_policy(repositoryName=repository_name)
        policy_text = response.get('lifecyclePolicyText', '{}')
        return {
            'has_lifecycle_policy': True,
            'policy': json.loads(policy_text) if policy_text else {},
            'policy_text': policy_text,
            'registry_id': response.get('registryId'),
            'last_evaluated_at': response.get('lastEvaluatedAt')
        }
    except client.exceptions.LifecyclePolicyNotFoundException:
        return {'has_lifecycle_policy': False, 'message': '생명주기 정책이 설정되지 않음'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_repository_images_security(client, repository_name):
    """리포지토리 이미지 보안 분석 (ListImages + DescribeImages)"""
    try:
        # ListImages - 이미지 목록 조회
        list_response = client.list_images(repositoryName=repository_name, maxResults=50)
        image_ids = list_response.get('imageIds', [])
        
        if not image_ids:
            return {
                'has_images': False,
                'message': '이미지가 없습니다.'
            }
        
        # DescribeImages - 이미지 상세 정보 조회 (최대 10개)
        images_to_describe = image_ids[:10]
        describe_response = client.describe_images(
            repositoryName=repository_name,
            imageIds=images_to_describe
        )
        
        images = describe_response.get('imageDetails', [])
        
        # 이미지 보안 분석
        security_analysis = {
            'total_images': len(image_ids),
            'analyzed_images': len(images),
            'images_with_tags': 0,
            'images_without_tags': 0,
            'latest_push_date': None,
            'oldest_push_date': None,
            'vulnerability_scan_status': {},
            'image_size_analysis': {
                'total_size_bytes': 0,
                'average_size_bytes': 0,
                'largest_image_size': 0,
                'smallest_image_size': float('inf')
            }
        }
        
        push_dates = []
        total_size = 0
        
        for image in images:
            # 태그 분석
            if image.get('imageTags'):
                security_analysis['images_with_tags'] += 1
            else:
                security_analysis['images_without_tags'] += 1
            
            # 푸시 날짜 분석
            if image.get('imagePushedAt'):
                push_dates.append(image['imagePushedAt'])
            
            # 크기 분석
            size = image.get('imageSizeInBytes', 0)
            total_size += size
            security_analysis['image_size_analysis']['largest_image_size'] = max(
                security_analysis['image_size_analysis']['largest_image_size'], size
            )
            if size > 0:
                security_analysis['image_size_analysis']['smallest_image_size'] = min(
                    security_analysis['image_size_analysis']['smallest_image_size'], size
                )
            
            # 스캔 상태 분석
            scan_status = image.get('imageScanFindingsSummary', {}).get('findingCounts', {})
            for severity, count in scan_status.items():
                if severity not in security_analysis['vulnerability_scan_status']:
                    security_analysis['vulnerability_scan_status'][severity] = 0
                security_analysis['vulnerability_scan_status'][severity] += count
        
        # 날짜 분석 완료
        if push_dates:
            security_analysis['latest_push_date'] = max(push_dates)
            security_analysis['oldest_push_date'] = min(push_dates)
        
        # 크기 분석 완료
        security_analysis['image_size_analysis']['total_size_bytes'] = total_size
        if len(images) > 0:
            security_analysis['image_size_analysis']['average_size_bytes'] = total_size // len(images)
        
        if security_analysis['image_size_analysis']['smallest_image_size'] == float('inf'):
            security_analysis['image_size_analysis']['smallest_image_size'] = 0
        
        return {
            'has_images': True,
            'security_analysis': security_analysis
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_image_scan_findings_safe(client, repository_name):
    """DescribeImageScanFindings 안전 호출"""
    try:
        # 먼저 이미지 목록에서 최신 이미지 선택
        list_response = client.list_images(repositoryName=repository_name, maxResults=1)
        image_ids = list_response.get('imageIds', [])
        
        if not image_ids:
            return {'has_scan_findings': False, 'message': '스캔할 이미지가 없습니다.'}
        
        # 최신 이미지의 스캔 결과 조회
        latest_image = image_ids[0]
        response = client.describe_image_scan_findings(
            repositoryName=repository_name,
            imageId=latest_image
        )
        
        scan_status = response.get('imageScanStatus', {})
        scan_findings = response.get('imageScanFindings', {})
        
        return {
            'has_scan_findings': True,
            'image_id': latest_image,
            'scan_status': scan_status.get('status'),
            'scan_completed_at': scan_status.get('completedAt'),
            'findings_summary': scan_findings.get('findingCounts', {}),
            'findings_details': scan_findings.get('findings', [])[:10],  # 최대 10개만
            'enhanced_findings': scan_findings.get('enhancedFindings', [])[:5]  # 최대 5개만
        }
        
    except client.exceptions.ScanNotFoundException:
        return {'has_scan_findings': False, 'message': '스캔 결과가 없습니다.'}
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_registry_scanning_configuration_safe(client):
    """GetRegistryScanningConfiguration 안전 호출"""
    try:
        response = client.get_registry_scanning_configuration()
        scanning_config = response.get('scanningConfiguration', {})
        
        return {
            'has_scanning_config': True,
            'registry_id': response.get('registryId'),
            'scan_type': scanning_config.get('scanType'),
            'rules': scanning_config.get('rules', []),
            'enhanced_scanning_enabled': scanning_config.get('scanType') == 'ENHANCED'
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

def calculate_total_ecr_apis_called(repositories):
    """총 API 호출 수 계산"""
    # 기본 API: DescribeRepositories(1) + GetRegistryScanningConfiguration(1)
    base_apis = 2
    
    # 리포지토리당 API: GetRepositoryPolicy(1) + GetLifecyclePolicy(1) + ListImages(1) + DescribeImages(1) + DescribeImageScanFindings(1)
    repository_apis = len(repositories) * 5
    
    return base_apis + repository_apis

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
        'function': event.get('function', 'analyzeEcrSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'ecr-security-analysis'),
        'function': event.get('function', 'analyzeEcrSecurity'),
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
